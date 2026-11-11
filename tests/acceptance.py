#!/usr/bin/python3
"""Real-kernel end-to-end checks. Run as the sudo-authorized development user.

Uses task-owned dslab-* server namespaces and acc-* sessions. No cloud login.
Artifacts/results are written to tests/results.json; packet evidence in /tmp/opencode.

    python3 -B tests/acceptance.py              # every group
    python3 -B tests/acceptance.py scripting    # only the named group(s): core, scripting, activation, tailscale
"""
import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import socket
import subprocess as sp
import sys
import tempfile
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import accept_activation
import accept_scripting
import accept_tailscale
REPO = HERE.parent
HOME = Path.home()
LAB = Path('/tmp/opencode/devsession-lab')
SESSIONS = ['acc-a', 'acc-b', 'acc-o', 'acc-direct', 'acc-off', 'acc-broken']
RESULTS = []


def cmd(args, *, check=True, input=None, env=None, timeout=45):
    p = sp.run([str(a) for a in args], text=True, capture_output=True, input=input,
               env=env, timeout=timeout)
    if check and p.returncode:
        raise AssertionError(f'{args[:3]} -> {p.returncode}: {p.stderr}\n{p.stdout}')
    return p


def root(*args, **kw):
    return cmd(['sudo', '-n', '--'] + list(args), **kw)


def cli(*args, **kw):
    return cmd(['devsession'] + list(args), **kw)


def ex(name, *args, **kw):
    return cli('exec', name, '--', *args, **kw)


def inspect(name):
    return json.loads(cli('inspect', name).stdout)


def check(name, function):
    try:
        detail = function()
        RESULTS.append(dict(check=name, status='passed', detail=detail or ''))
        print('PASS', name, detail or '', flush=True)
        return True
    except Exception as e:
        RESULTS.append(dict(check=name, status='failed', detail=str(e)))
        print('FAIL', name, str(e), flush=True)
        traceback.print_exc()
        return False


def eq(a, b):
    assert a == b, (a, b)


def http(name, address='vpn.test'):
    return json.loads(ex(name, 'curl', '-fsS', '--max-time', '4', f'http://{address}:8080').stdout)


def eventually(function, timeout=15):
    end = time.monotonic() + timeout
    while True:
        try:
            return function()
        except Exception:
            if time.monotonic() >= end:
                raise
            time.sleep(.2)


def host_tools(project, rc):
    specs = [('terraform', ['version']), ('ansible', ['--version']), ('tmux', ['-V']),
             ('oh-my-posh', ['version']), ('az', ['version']), ('python3', ['--version']),
             ('ds-user-tool', []), ('node', ['--version']), ('npm', ['--version']),
             (str(project / '.venv/bin/python'), ['--version'])]
    evidence = {}
    for name, args in specs:
        path = shutil.which(name)
        assert path, f'Host tool missing: {name}'
        inner = ex('acc-a', 'sh', '-c', 'command -v "$1"; readlink -f "$(command -v "$1")"', 'sh', name).stdout.splitlines()
        eq(inner, [path, str(Path(path).resolve())])
        a, b = cmd([name] + args).stdout, ex('acc-a', name, *args).stdout
        if name in ('ansible', 'terraform'):  # terraform appends an online update notice
            eq(a.splitlines()[0], b.splitlines()[0])
        else:
            eq(a, b)
        evidence[name] = dict(path=path, realpath=str(Path(path).resolve()), version=b.splitlines()[:2])
    (HERE / 'tool-results.json').write_text(json.dumps(evidence, indent=2) + '\n')
    ex('acc-a', 'ansible', 'localhost', '-i', 'localhost,', '-c', 'local', '-m', 'ping',
       '-e', 'ansible_python_interpreter=/usr/bin/python3')
    ex('acc-a', 'sh', '-c', 'cd /workspace; terraform init -backend=false -input=false >/dev/null; terraform apply -auto-approve -input=false >/dev/null; terraform output -raw proof')
    # User-local and version-managed tools actually execute at original paths.
    eq(ex('acc-a', 'node', '-e', 'console.log(6*7)').stdout.strip(), '42')
    eq(ex('acc-a', str(project / '.venv/bin/project-tool')).stdout.strip(), 'project-venv-ok')
    result = ex('acc-a', 'bash', '--noprofile', '--rcfile', '/etc/devsession.bashrc', '-ic',
                'alias ll; project_root; type _init_completion; declare -p PROMPT_COMMAND; nvm --version').stdout
    for s in ['ls -alF', '/workspace', '_init_completion', '_omp_hook', '0.40.3']:
        assert s in result, result
    return evidence


LEAK_PROBE = '''import socket,time
for i in range(80):
 for host,port in [('198.18.12.2',8080),('1.1.1.1',53),('198.18.10.2',51820),('198.18.13.2',1194)]:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'DEVSESSION_LEAK_PROBE',(host,port)); s.close()
 try:
  s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.sendto(b'DEVSESSION_LEAK_PROBE',('2606:4700:4700::1111',53)); s.close()
 except OSError: pass
 time.sleep(.025)
'''


def capture_begin(name):
    c = inspect(name)
    path = Path('/tmp/opencode') / (name + '-transport.pcap')
    log = open(Path('/tmp/opencode') / (name + '-tcpdump.log'), 'w')
    # Capture at HOST transport veth, including across namespace teardown/start.
    # -i any also sees post-NAT packets, so use the unique pre-NAT transport IP.
    p = sp.Popen(['sudo', '-n', 'tcpdump', '-Z', 'root', '-U', '-n', '-i', 'any', '-w', str(path),
                  'src', 'host', c['transport'][1]], stdout=log, stderr=log)
    time.sleep(.4)
    assert p.poll() is None, 'tcpdump failed to start'
    return p, path, log


def capture_end(record):
    p, path, log = record
    p.send_signal(signal.SIGINT); p.wait(timeout=5); log.close()
    data = root('cat', path).stdout if False else root('tcpdump', '-nr', path, '-A').stdout
    assert 'DEVSESSION_LEAK_PROBE' not in data, data
    # DNS/HTTP cleartext must never occur on the transport link.
    leak = root('tcpdump', '-nr', path, 'port 53 or port 8080 or ip6').stdout
    assert not leak.strip(), leak
    # Nonempty capture establishes that the capture point was live.
    assert len(data.strip()) > 0, 'No transport captured: invalid leakage test'
    return str(path)


def vpn_failure(name, backend):
    c = inspect(name); gw = c['namespaces']['gateway']
    capture = capture_begin(name)
    try:
        http(name)
        # tmux runs a child in exactly this VPN, never the host default server.
        ex(name, 'tmux', 'new-session', '-d', '-s', 'isolation',
           'sh -c "curl -fsS http://vpn.test:8080 > /tmp/tmux-http; sleep 300"')
        eventually(lambda: eq(json.loads(ex(name, 'cat', '/tmp/tmux-http').stdout)['source'], '10.77.0.2'))
        assert 'ds-host-sentinel' not in ex(name, 'tmux', 'list-sessions').stdout
        tmux_path = ex(name, 'tmux', 'display-message', '-p', '#{socket_path}').stdout.strip()
        assert tmux_path.startswith('/run/user/1000/'), tmux_path
        # Background attempts throughout reconnect; transport exception is also probed.
        probe = sp.Popen(['devsession', 'exec', name, '--', 'python3', '-c', LEAK_PROBE], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        if backend == 'wireguard':
            root('ip', '-n', gw, 'link', 'set', 'vpn0', 'down')
            time.sleep(.5)
            root('ip', '-n', gw, 'link', 'set', 'vpn0', 'up')
            root('ip', '-n', gw, 'route', 'replace', 'default', 'dev', 'vpn0')
        else:
            for pid in root('ip', 'netns', 'pids', gw).stdout.split():
                root('kill', '-USR1', pid)
        probe.wait(timeout=10)
        eventually(lambda: http(name), timeout=20)
        # Remove tunnel, kill OpenVPN if present, and install a tempting raw route.
        if backend == 'openvpn':
            for pid in root('ip', 'netns', 'pids', gw).stdout.split():
                root('kill', '-KILL', pid)
        root('ip', '-n', gw, 'link', 'del', 'vpn0', check=False)
        root('ip', '-n', gw, 'route', 'replace', 'default', 'via', c['transport'][0])
        ex(name, 'python3', '-c', LEAK_PROBE)
        assert ex(name, 'curl', '--max-time', '1', 'http://198.18.12.2:8080', check=False).returncode != 0
        assert ex(name, 'getent', 'hosts', 'vpn.test', check=False).returncode != 0
        rules = root('ip', 'netns', 'exec', gw, 'nft', '-j', 'list', 'chain', 'inet', 'guard', 'forward').stdout
        drops = [x['counter']['packets'] for n in json.loads(rules)['nftables'] if 'rule' in n
                 and any('drop' in x for x in n['rule']['expr']) for x in n['rule']['expr'] if 'counter' in x]
        assert sum(drops) > 0, rules
        # Background processes are killed before policy is removed; restart is safe.
        probe = sp.Popen(['devsession', 'exec', name, '--', 'python3', '-c', LEAK_PROBE], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(.2)
        cli('stop', name); probe.wait(timeout=5)
        cli('start', name)
        ex(name, 'python3', '-c', LEAK_PROBE)
        eventually(lambda: http(name))
        return {'capture': capture_end(capture), 'drop_packets': sum(drops), 'tmux_socket': tmux_path}
    except BaseException:
        capture[0].send_signal(signal.SIGINT)
        capture[0].wait(timeout=5); capture[2].close()
        raise


def interactive():
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp('devsession', ['devsession', 'shell', 'acc-off'])
    output = b''
    def until(marker):
        nonlocal output
        end = time.monotonic() + 15
        while marker not in output:
            if time.monotonic() > end:
                raise AssertionError(output[-2000:])
            if select.select([fd], [], [], .2)[0]:
                output += os.read(fd, 65536)
    try:
        # Prompt is customized by oh-my-posh, so its text need not include name.
        until(b'\x1b[?2004h')
        # Emit readiness from the foreground child itself, after Bash has set
        # its job-control process group (not from a preceding shell builtin).
        os.write(fd, b'''python3 -c "import time; print('READY-'+'session',flush=True); time.sleep(30)"\n''')
        until(b'READY-session')
        os.write(fd, b'\x03')
        time.sleep(.2)
        os.write(fd, b"printf 'AFTER-%s\\n' interrupt; exit 7\n")
        until(b'AFTER-interrupt')
        _, status = os.waitpid(pid, 0)
        eq(os.waitstatus_to_exitcode(status), 7)
        return 'PTY shell, Ctrl-C, continued prompt and exit 7'
    finally:
        os.close(fd)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)


def core():
    route_before = cmd(['ip', '-j', 'route', 'show', 'default']).stdout
    resolver_before = Path('/etc/resolv.conf').read_bytes()
    resolver_link = os.readlink('/etc/resolv.conf') if Path('/etc/resolv.conf').is_symlink() else ''
    work = Path(tempfile.mkdtemp(prefix='devsession-accept-', dir='/tmp/opencode'))
    project = work / 'project'; project.mkdir()
    readonly = work / 'readonly'; readonly.mkdir()
    (readonly / 'data').write_text('readonly')
    (project / 'main.tf').write_text('output "proof" { value = "host-terraform-ok" }\n')
    cmd(['python3', '-m', 'venv', '--without-pip', project / '.venv'])
    pt = project / '.venv/bin/project-tool'
    pt.write_text(f'#!{project}/.venv/bin/python\nprint("project-venv-ok")\n'); pt.chmod(0o755)
    local = HOME / '.local/bin'; local.mkdir(exist_ok=True)
    user_tool = local / 'ds-user-tool'
    assert not user_tool.exists(), 'Fixture path already exists'
    user_tool.write_text('#!/usr/bin/python3\nprint("user-local-ok")\n'); user_tool.chmod(0o755)
    nodes = sorted((HOME / '.nvm/versions/node').glob('*/bin/node'))
    assert nodes, 'Install nvm and a Node version before the acceptance suite; see docs/TESTING.md'
    nodebin = str(nodes[-1].parent)
    os.environ['PATH'] = f'{local}:{nodebin}:' + os.environ['PATH']
    rc = work / 'reviewed.bash'
    rc.write_text((REPO / 'examples/customization.bash').read_text() + f'\nexport NVM_DIR={HOME}/.nvm\nsource "$NVM_DIR/nvm.sh" --no-use\n')
    sentinel_file = HOME / '.ssh/devsession-acceptance-sentinel'
    assert not sentinel_file.exists()
    sentinel_file.write_text('HOST_CREDENTIAL_SENTINEL'); sentinel_file.chmod(0o600)
    agent = socket.socket(socket.AF_UNIX)
    agent.bind(str(work / 'host-agent.sock')); agent.listen(1)
    os.environ.update(HOST_SENTINEL='HOST_ENV_SENTINEL', SSH_AUTH_SOCK=str(work / 'host-agent.sock'),
                      AWS_SECRET_ACCESS_KEY='HOST_AWS_SENTINEL', HTTPS_PROXY='http://127.0.0.1:9')
    sentinel = sp.Popen(['sleep', '600'], env=os.environ.copy())
    cmd(['tmux', 'new-session', '-d', '-s', 'ds-host-sentinel', 'sleep 600'])
    try:
        for s in SESSIONS:
            cli('delete', s, check=False)
        root('python3', '-B', HERE / 'lab.py', 'up')
        for name in SESSIONS:
            args = ['create', name, '--mount', f'{project}:/workspace', '--mount', f'{project}:{project}',
                    '--mount', f'{readonly}:/readonly:ro', '--shell-rc', str(rc),
                    '--tool', str(HOME / '.nvm/versions'), '--tool', str(HOME / '.nvm/nvm.sh')]
            if name == 'acc-direct':
                args += ['--net', 'direct', '--allow-net', '198.18.12.2/32', '--publish', '18765:8081']
            cli(*args)
        for name, conf in [('acc-a', 'a.conf'), ('acc-b', 'b.conf')]:
            cli('vpn', 'configure', name, '--wireguard', LAB / conf)
            cli('net', 'set', name, 'vpn')
        cli('vpn', 'configure', 'acc-o', '--openvpn', LAB / 'client.ovpn', '--dns', '10.77.0.1')
        cli('net', 'set', 'acc-o', 'vpn')
        for name in SESSIONS[:-1]:
            cli('start', name)

        def env_check():
            cli('env', 'set', 'acc-a', 'REGION', 'a')
            cli('env', 'set', 'acc-b', 'REGION', '--stdin', input='b\n')
            eq(ex('acc-a', 'printenv', 'REGION').stdout.strip(), 'a')
            eq(ex('acc-b', 'printenv', 'REGION').stdout.strip(), 'b')
            cli('env', 'import', 'acc-a', '-', input='SECRET=$(touch /tmp/not-shell)\nPLAIN=literal value\n')
            eq(ex('acc-a', 'printenv', 'SECRET').stdout.strip(), '$(touch /tmp/not-shell)')
            ex('acc-a', 'test', '!', '-e', '/tmp/not-shell')
            assert 'literal value' not in cli('inspect', 'acc-a').stdout
            forwarded = dict(os.environ, EXPLICIT_FORWARD='yes')
            eq(cli('exec', '--forward', 'EXPLICIT_FORWARD', 'acc-a', '--', 'printenv', 'EXPLICIT_FORWARD', env=forwarded).stdout.strip(), 'yes')
        check('1 environment separation, stdin secrets, literal env import, redaction, forwarding', env_check)

        def private():
            for name in ['acc-a', 'acc-b']:
                data = dict(line.split('=', 1) for line in ex(name, 'env').stdout.splitlines())
                for key in ['HOST_SENTINEL', 'AWS_SECRET_ACCESS_KEY', 'SSH_AUTH_SOCK', 'HTTPS_PROXY', 'DBUS_SESSION_BUS_ADDRESS']:
                    assert key not in data, key
                ex(name, 'test', '!', '-e', sentinel_file)
                ex(name, 'test', '!', '-e', work / 'host-agent.sock')
                ex(name, 'test', '!', '-e', f'/proc/{sentinel.pid}/environ')
                ex(name, 'test', '!', '-e', f'/proc/{sentinel.pid}/root')
                ex(name, 'test', '!', '-e', f'/proc/{sentinel.pid}/fd')
                ex(name, 'test', '!', '-e', '/var/lib/devsession')
                ex(name, 'test', '!', '-e', '/run/user/1000/bus')
                ex(name, 'test', '!', '-e', '/run/docker.sock')
                ex(name, 'python3', '-c', f'import ctypes; libc=ctypes.CDLL(None,use_errno=True); assert libc.ptrace(16,{sentinel.pid},0,0)==-1; assert ctypes.get_errno() in (1,3)')
                status = ex(name, 'cat', '/proc/self/status').stdout
                assert 'CapEff:\t0000000000000000' in status and 'NoNewPrivs:\t1' in status
                assert ex(name, 'sudo', '-n', 'id', check=False).returncode != 0
                assert ex(name, 'ip', 'route', 'add', '1.2.3.4/32', 'dev', 'eth0', check=False).returncode != 0
                ex(name, 'python3', '-c', "import pathlib; assert all(b'HOST_ENV_SENTINEL' not in p.read_bytes() for p in pathlib.Path('/proc').glob('[0-9]*/environ') if p.exists())")
            cli('credential', 'acc-a', '.ssh/test-key', input='PRIVATE-A\n')
            ex('acc-a', 'sh', '-c', 'echo home-a > ~/home-only; echo tmp-a > /tmp/tmp-only')
            for path in [str(HOME / '.ssh/test-key'), str(HOME / 'home-only'), '/tmp/tmp-only']:
                ex('acc-b', 'test', '!', '-e', path)
        check('2/3/6 credentials, agent, PID/proc isolation, private home/tmp and unprivileged workload', private)

        def azure():
            for name, ident in [('acc-a', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), ('acc-b', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')]:
                subscription = {'id': ident, 'name': name, 'state': 'Enabled', 'isDefault': True,
                                'tenantId': ident, 'environmentName': 'AzureCloud', 'user': {'name': name + '@fixture.invalid', 'type': 'user'}}
                alternate = dict(subscription, id='cccccccc-cccc-cccc-cccc-cccccccccccc', name='alternate', isDefault=False)
                profile = {'subscriptions': [subscription, alternate]}
                cli('credential', name, '.azure/azureProfile.json', input=json.dumps(profile))
                ex(name, 'az', 'config', 'set', 'core.collect_telemetry=no')
                eq(ex(name, 'az', 'account', 'show', '--query', 'id', '-o', 'tsv').stdout.strip(), ident)
                eq(ex(name, 'printenv', 'AZURE_CONFIG_DIR').stdout.strip(), str(HOME / '.azure'))
            ex('acc-a', 'az', 'account', 'set', '--subscription', 'cccccccc-cccc-cccc-cccc-cccccccccccc')
            eq(ex('acc-a', 'az', 'account', 'show', '--query', 'id', '-o', 'tsv').stdout.strip(), 'cccccccc-cccc-cccc-cccc-cccccccccccc')
            eq(ex('acc-b', 'az', 'account', 'show', '--query', 'id', '-o', 'tsv').stdout.strip(), 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')
            return 'Synthetic profile/account-selection fixtures; no Azure authentication performed'
        check('4 Azure CLI configuration and synthetic selected-account isolation', azure)

        def shared():
            ex('acc-a', 'sh', '-c', 'echo from-a > /workspace/shared')
            eq((project / 'shared').read_text().strip(), 'from-a')
            eq(ex('acc-b', 'cat', '/workspace/shared').stdout.strip(), 'from-a')
            (project / 'shared').write_text('from-host\n')
            eq(ex('acc-a', 'cat', '/workspace/shared').stdout.strip(), 'from-host')
            eq((project / 'shared').stat().st_uid, os.getuid())
            assert ex('acc-a', 'touch', '/readonly/new', check=False).returncode != 0
            assert ex('acc-a', 'touch', '/usr/local/bin/forbidden', check=False).returncode != 0
        check('5/7 shared edits, read-only mounts and host UID ownership', shared)
        check('Host tools, shell customization, completion, prompt, real Ansible/Terraform, nvm and venv', lambda: host_tools(project, rc))

        def networking():
            eq(http('acc-direct', '198.18.12.2')['source'], '198.18.12.1')
            assert ex('acc-off', 'curl', '--max-time', '1', 'http://198.18.12.2:8080', check=False).returncode != 0
            for name in ['acc-direct', 'acc-off']:
                assert ex(name, 'curl', '--max-time', '1', 'http://10.77.0.1:8080', check=False).returncode != 0
            c = inspect('acc-direct')
            assert ex('acc-direct', 'curl', '--max-time', '1', f'http://{c["transport"][0]}:8080', check=False).returncode != 0
            ex('acc-direct', 'sh', '-c', 'nohup python3 -m http.server 8081 --bind 127.0.0.1 >/tmp/http.log 2>&1 </dev/null &')
            eventually(lambda: cmd(['curl', '--noproxy', '*', '-fsS', '--max-time', '2', 'http://127.0.0.1:18765']))
            listeners = cmd(['ss', '-ltn']).stdout
            assert '127.0.0.1:18765' in listeners and '0.0.0.0:18765' not in listeners
        check('8 off/direct, unreachable private service without VPN, host-service block, loopback publish', networking)

        def overlap():
            with concurrent.futures.ThreadPoolExecutor() as pool:
                values = list(pool.map(http, ['acc-a', 'acc-b', 'acc-o']))
            eq([v['server'] for v in values], ['a', 'b', 'openvpn'])
            eq([v['source'] for v in values], ['10.77.0.2'] * 3)
            for name, gateway in [('acc-a', '198.18.10.2'), ('acc-b', '198.18.11.2'), ('acc-o', '198.18.13.2')]:
                eq(http(name, '198.18.12.2')['source'], gateway)
            return 'Three concurrent real tunnels; same 10.77.0.0/24 and vpn.test; distinct controlled gateway source addresses'
        check('9/10/11 WireGuard/OpenVPN DNS+HTTP, overlapping subnets and VPN gateway identity', overlap)
        check('12/13 WireGuard kill switch, DNS/IPv6/transport bypass, reconnect/start/stop capture and tmux', lambda: vpn_failure('acc-a', 'wireguard'))
        check('12/13 OpenVPN kill switch, DNS/IPv6/transport bypass, reconnect/start/stop capture and tmux', lambda: vpn_failure('acc-o', 'openvpn'))

        def lifecycle():
            cli('stop', 'acc-a'); cli('stop', 'acc-a'); cli('start', 'acc-a')
            eq(ex('acc-a', 'cat', str(HOME / '.ssh/test-key')).stdout, 'PRIVATE-A\n')
            eq(ex('acc-a', 'printenv', 'REGION').stdout.strip(), 'a')
            c = inspect('acc-a'); cli('delete', 'acc-a')
            assert not Path(c['state']).exists()
            eq(http('acc-b')['server'], 'b')
            assert (project / 'shared').exists()
            eq(ex('acc-b', 'sh', '-c', 'exit 37', check=False).returncode, 37)
            assert cli('net', 'set', 'acc-b', 'direct', check=False).returncode != 0
        check('15 lifecycle persistence/deletion preserves siblings/projects; mode changes require stop; exit status', lifecycle)

        def interrupted():
            # Real nonresponsive OpenVPN endpoint gives an interruptible TLS start.
            src = root('cat', LAB / 'client.ovpn').stdout.replace('1194', '1195')
            conf = work / 'nonresponsive.ovpn'; conf.write_text(src)
            cli('vpn', 'configure', 'acc-broken', '--openvpn', conf, '--dns', '10.77.0.1')
            cli('net', 'set', 'acc-broken', 'vpn')
            c = inspect('acc-broken')
            p = sp.Popen(['devsession', 'start', 'acc-broken'], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            gw = c['namespaces']['gateway']
            eventually(lambda: root('ip', '-n', gw, 'link', 'show', 'wan'))
            eq(cli('stop', 'acc-b', check=False).returncode, 124)  # busy: concurrent lifecycle change rejected
            # Kill the installed root startup helper, leaving real partial kernel resources.
            output = root('pgrep', '-f', '/usr/local/lib/devsession/devsession.py start acc-broken').stdout
            for pid in output.split():
                root('kill', '-KILL', pid, check=False)
            p.wait(timeout=5)
            cli('cleanup'); cli('stop', 'acc-broken'); cli('stop', 'acc-broken')
            assert gw not in root('ip', 'netns', 'list').stdout
            assert c['namespaces']['nft_table'] not in root('nft', 'list', 'tables').stdout
            eq(http('acc-b')['server'], 'b')
        check('16 interrupted real startup, concurrent lifecycle rejection, tracked stale cleanup', interrupted)
        check('17 interactive shell PTY, Ctrl-C and exit status', interactive)

        def signals():
            p = sp.Popen(['devsession', 'exec', 'acc-off', '--', 'python3', '-c',
                          'import signal,time,sys; signal.signal(signal.SIGTERM,lambda s,f:sys.exit(42)); print("SIGNAL_READY",flush=True); time.sleep(60)'], stdout=sp.PIPE, stderr=sp.PIPE, text=True)
            assert p.stdout.readline().strip() == 'SIGNAL_READY'
            p.send_signal(signal.SIGTERM)
            eq(p.wait(timeout=5), 42)
        check('17 noninteractive signal forwarding', signals)

        def unchanged():
            eq(cmd(['ip', '-j', 'route', 'show', 'default']).stdout, route_before)
            eq(Path('/etc/resolv.conf').read_bytes(), resolver_before)
            eq(os.readlink('/etc/resolv.conf'), resolver_link)
        check('14 host default routes/resolver content and symlink unchanged', unchanged)
    finally:
        for name in SESSIONS:
            cli('delete', name, check=False)
        root('python3', '-B', HERE / 'lab.py', 'down', check=False)
        cli('cleanup', check=False)
        sentinel.terminate(); sentinel.wait()
        agent.close()
        sentinel_file.unlink(missing_ok=True)
        user_tool.unlink(missing_ok=True)
        cmd(['tmux', 'kill-session', '-t', 'ds-host-sentinel'], check=False)
        shutil.rmtree(work)


GROUPS = {'core': core, 'scripting': lambda: accept_scripting.run(check),
          'activation': lambda: accept_activation.run(check),
          'tailscale': lambda: accept_tailscale.run(check)}


def main():
    assert os.getuid() != 0, 'Run as normal sudo-authorized host user'
    root('true')
    Path('/tmp/opencode').mkdir(exist_ok=True)
    selected = sys.argv[1:] or list(GROUPS)
    try:
        for group in selected:
            GROUPS[group]()
    finally:
        cli('cleanup', check=False)
        (HERE / 'results.json').write_text(json.dumps(RESULTS, indent=2) + '\n')
    return 1 if any(x['status'] == 'failed' for x in RESULTS) else 0


if __name__ == '__main__':
    sys.exit(main())
