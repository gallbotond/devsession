#!/usr/bin/python3
"""Tailscale-backend acceptance checks (feature 3). Real installed CLI.

A hermetic tailnet beside the existing fixtures (tests/lab.py): headscale
with its embedded DERP relay and STUN in `dslab-hs`, an ordinary tailscaled
peer in `dslab-ts` that serves HTTP and DNS on the tailnet, advertises a
subnet route and offers an exit node. Nothing here contacts the host's own
tailscaled except to read its status for the "unchanged" assertion.
Run alone with `python3 -B tests/accept_tailscale.py` or via acceptance.py.
"""
import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess as sp
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
LAB = Path('/tmp/opencode/devsession-lab')
URL = 'https://198.18.20.2:8443'
NETS = ['--transport-net', '198.18.20.0/30', '--transport-net', '198.18.21.0/30']
PEER, DETECTOR = '100.64.0.1', '198.18.12.2'
SESSIONS = ['ts-a', 'ts-n', 'ts-x', 'ts-o', 'ts-p', 'ts-w', 'ts-v']
UID = os.getuid()


def cmd(args, *, check=True, input=None, timeout=120):
    p = sp.run([str(a) for a in args], text=True, capture_output=True, input=input, timeout=timeout,
               **({} if input is not None else dict(stdin=sp.DEVNULL)))
    if check and p.returncode:
        raise AssertionError(f'{[str(a) for a in args][:6]} -> {p.returncode}: {p.stderr[-600:]}\n{p.stdout[-300:]}')
    return p


def root(*args, **kw):
    return cmd(['sudo', '-n', '--'] + list(args), **kw)


def cli(*args, **kw):
    return cmd(['devsession'] + list(args), **kw)


def ex(name, *args, **kw):
    return cli('exec', name, '--', *args, **kw)


def lab(*args, **kw):
    return root('python3', '-B', HERE / 'lab.py', *args, **kw)


def inspect(name):
    return json.loads(cli('inspect', name).stdout)


def eq(a, b):
    assert a == b, (a, b)


def eventually(function, timeout=25):
    end = time.monotonic() + timeout
    while True:
        try:
            return function()
        except Exception:
            if time.monotonic() >= end:
                raise
            time.sleep(.3)


def http(name, address, port=8080, timeout=4):
    return json.loads(ex(name, 'curl', '-fsS', '--max-time', str(timeout), f'http://{address}:{port}').stdout)


def fails(name, *args):
    assert ex(name, *args, check=False).returncode != 0, args


def configure(name, *extra, key=None):
    cli('create', name)
    cli('vpn', 'configure', name, '--tailscale', '--auth-key-file', key or LAB / 'ts-authkey',
        '--login-server', URL, '--ca-file', LAB / 'ts-ca.crt', *extra)
    cli('net', 'set', name, 'vpn')


def session_ts(name, *args, check=True):
    """tailscale CLI of one session's own daemon (root, inside its box)."""
    return lab('session', UID, name, *args, check=check)


def node(name):
    self = json.loads(session_ts(name, 'status', '--json').stdout)['Self']
    return self['TailscaleIPs'][0], self['ID']


def daemon(name):
    gw = inspect(name)['namespaces']['gateway']
    for pid in root('ip', 'netns', 'pids', gw).stdout.split():
        if Path(f'/proc/{pid}/comm').read_text().strip() == 'tailscaled':
            return int(pid)
    raise AssertionError(f'no tailscaled in {gw}')


def counters(name, chain):
    gw = inspect(name)['namespaces']['gateway']
    rules = json.loads(root('ip', 'netns', 'exec', gw, 'nft', '-j', 'list', 'chain', 'inet', 'guard', chain).stdout)
    return sum(x['counter']['packets'] for n in rules['nftables'] if 'rule' in n
               and any('drop' in x for x in n['rule']['expr']) for x in n['rule']['expr'] if 'counter' in x)


# ---- host must be byte-for-byte unchanged ---------------------------------
STABLE = ['ID', 'PublicKey', 'HostName', 'DNSName', 'OS', 'UserID', 'TailscaleIPs', 'AllowedIPs',
          'ExitNode', 'ExitNodeOption', 'KeyExpiry']


def host_snapshot():
    """Everything of the host that a tailscaled could disturb, as bytes."""
    status = json.loads(cmd(['tailscale', 'status', '--json']).stdout)
    pick = lambda n: {k: n.get(k) for k in STABLE}
    snap = {
        # Fields that describe this host's node and its tailnet membership. Left
        # out on purpose: traffic counters, handshake/last-seen times and the
        # online flags of other people's devices, which change on their own.
        'tailscale status (node, peers, tailnet)': json.dumps(dict(
            BackendState=status.get('BackendState'), Version=status.get('Version'), TUN=status.get('TUN'),
            MagicDNSSuffix=status.get('MagicDNSSuffix'), CurrentTailnet=status.get('CurrentTailnet'),
            TailscaleIPs=status.get('TailscaleIPs'), Self=pick(status['Self']),
            Peer=sorted((pick(p) for p in (status.get('Peer') or {}).values()), key=lambda p: p['ID'])), sort_keys=True),
        'tailscale status text (address, name, owner, os)': '\n'.join(
            ' '.join(line.split()[:4]) for line in cmd(['tailscale', 'status']).stdout.splitlines()),
        'tailscale prefs': cmd(['tailscale', 'debug', 'prefs']).stdout,
        'tailscaled process': cmd(['systemctl', 'show', 'tailscaled', '-p', 'MainPID,ExecMainStartTimestampMonotonic,ActiveState']).stdout,
        '/etc/resolv.conf': Path('/etc/resolv.conf').read_bytes().decode('latin1'),
        '/etc/resolv.conf link': os.readlink('/etc/resolv.conf') if os.path.islink('/etc/resolv.conf') else '',
    }
    for path in ['/run/systemd/resolve/resolv.conf', '/run/systemd/resolve/stub-resolv.conf']:
        if os.path.exists(path):
            snap[path] = Path(path).read_bytes().decode('latin1')
    for label, command in [('ip rule', ['ip', 'rule']), ('ip -6 rule', ['ip', '-6', 'rule']),
                           ('ip route table all', ['ip', 'route', 'show', 'table', 'all']),
                           ('ip -6 route table all', ['ip', '-6', 'route', 'show', 'table', 'all']),
                           ('ip route table 52', ['ip', 'route', 'show', 'table', '52']),
                           ('nft ruleset', ['sudo', '-n', 'nft', '-s', 'list', 'ruleset']),
                           ('resolvectl dns', ['resolvectl', 'dns']), ('resolvectl domain', ['resolvectl', 'domain'])]:
        snap[label] = cmd(command).stdout
    # The same ruleset without devsession's own named tables, for comparison while sessions run.
    listing = json.loads(cmd(['sudo', '-n', 'nft', '-s', '-j', 'list', 'ruleset']).stdout)['nftables']
    table = lambda item: next(iter(item.values())).get('table' if 'table' not in item else 'name', '')
    snap['nft ruleset (tables not named ds_*)'] = json.dumps([i for i in listing if not str(table(i)).startswith('ds_')], sort_keys=True)
    snap['tailscale status text (verbatim)'] = cmd(['tailscale', 'status']).stdout
    return snap


def host_changes(before, after, ours=()):
    """Names of snapshot entries that differ, ignoring lines about our own named devices."""
    changed = []
    for key in before:
        if key == 'tailscale status text (verbatim)' or (ours and key == 'nft ruleset'):
            continue
        a, b = before[key], after[key]
        if ours:
            strip = lambda text: '\n'.join(line for line in text.splitlines() if not any(o in line for o in ours))
            a, b = strip(a), strip(b)
        if a != b:
            changed.append(key)
    return changed


LEAK_PROBE = '''import socket,time
for i in range(60):
 for host,port in [('198.18.12.2',8080),('1.1.1.1',53),('198.18.20.2',8443),('198.18.21.2',41641),('198.18.20.2',3478)]:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'DEVSESSION_LEAK_PROBE',(host,port)); s.close()
 try:
  s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.sendto(b'DEVSESSION_LEAK_PROBE',('2606:4700:4700::1111',53)); s.close()
 except OSError: pass
 time.sleep(.02)
'''


def capture_begin(name):
    c = inspect(name)
    path = Path('/tmp/opencode') / (name + '-transport.pcap')
    log = open(Path('/tmp/opencode') / (name + '-tcpdump.log'), 'w')
    p = sp.Popen(['sudo', '-n', 'tcpdump', '-Z', 'root', '-U', '-n', '-i', 'any', '-w', str(path),
                  'src', 'host', c['transport'][1]], stdout=log, stderr=log)
    time.sleep(.5)
    assert p.poll() is None, 'tcpdump failed to start'
    return p, path, log, c['transport'][0]


def capture_end(record):
    p, path, log, host_end = record
    root('pkill', '-INT', '-P', str(p.pid), check=False); p.wait(timeout=10); log.close()
    # The daemon must not address the host itself (port-mapping probes to its default gateway).
    to_host = root('tcpdump', '-nr', path, 'ip', 'and', 'dst', 'host', host_end).stdout
    assert not to_host.strip(), to_host[:500]
    data = root('tcpdump', '-nr', path, '-A').stdout
    assert 'DEVSESSION_LEAK_PROBE' not in data, 'cleartext probe on the transport link'
    leak = root('tcpdump', '-nr', path, 'port 53 or port 8080 or ip6').stdout
    assert not leak.strip(), leak
    packets = len(root('tcpdump', '-nr', path).stdout.splitlines())
    assert packets > 20, 'no transport captured: the capture point was not live'
    tls = len(root('tcpdump', '-nr', path, 'tcp port 8443').stdout.splitlines())
    udp = len(root('tcpdump', '-nr', path, 'udp').stdout.splitlines())
    return dict(capture=str(path), packets=packets, control_or_relay_tls=tls, wireguard_or_stun_udp=udp)


# ---- checks ------------------------------------------------------------------
def policy(work):
    """Only safe options exist; secrets stay out of argv, state listings and messages."""
    cli('create', 'ts-p')
    secret = 'hskey-auth-POLICYSENTINEL0123456789'
    for bad in [['--ssh'], ['--advertise-routes', '10.0.0.0/8'], ['--advertise-exit-node'], ['--shields-up=false'],
                ['--netfilter-mode', 'on'], ['--operator', 'user'], ['--auth-key', secret]]:
        p = cli('vpn', 'configure', 'ts-p', '--tailscale', *bad, check=False)
        eq(p.returncode, 121)
    for bad in [['--login-server', 'ftp://198.18.20.2'], ['--login-server', 'https://user:pw@198.18.20.2'],
                ['--login-server', 'https://198.18.20.2/?key=x'], ['--exit-node', 'a b'], ['--hostname', 'Bad_Name'],
                ['--transport-net', 'not-a-net'], ['--dns', 'ns.example']]:
        p = cli('vpn', 'configure', 'ts-p', '--tailscale', *bad, check=False)
        eq(p.returncode, 120)
    (work / 'bad-key').write_text('two words\n'); (work / 'key').write_text(secret + '\n')
    (work / 'ca-with-key').write_text('-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n')
    p = cli('vpn', 'configure', 'ts-p', '--tailscale', '--auth-key-file', work / 'bad-key', check=False)
    assert p.returncode == 120 and 'two words' not in p.stderr
    eq(cli('vpn', 'configure', 'ts-p', '--tailscale', '--ca-file', work / 'ca-with-key', check=False).returncode, 120)
    eq(cli('vpn', 'configure', 'ts-p', '--wireguard', LAB / 'a.conf', '--exit-node', 'x', check=False).returncode, 121)
    # Stored key: via stdin, never shown; a hostname control server is pinned at configuration time.
    cli('vpn', 'configure', 'ts-p', '--tailscale', '--auth-key-stdin', '--login-server', 'https://localhost:8443/',
        '--hostname', 'policy-node', input=secret + '\n')
    c = inspect('ts-p')
    eq((c['vpn']['kind'], c['vpn']['pin'], c['vpn']['login_server'], c['vpn']['dns'], c['vpn']['hostname']),
       ('tailscale', ['localhost', '127.0.0.1'], 'https://localhost:8443', ['100.100.100.100'], 'policy-node'))
    assert secret not in json.dumps(c)
    eq(root('grep', '-rl', secret, c['state']).stdout.split(), [c['state'] + '/vpn/authkey'])
    eq(root('stat', '-c', '%a %U', c['state'] + '/vpn/authkey').stdout.strip(), '600 root')
    cli('vpn', 'configure', 'ts-p', '--tailscale', '--login-server', 'https://localhost:8443')   # key kept
    eq(root('cat', c['state'] + '/vpn/authkey').stdout.strip(), secret)
    cli('delete', 'ts-p', '--no-logout')
    return 'SSH/advertise/shields/netfilter/operator options do not exist (121); malformed values 120; key via stdin, mode 600, absent from inspect'


def join(work, state):
    """Own node, tailnet HTTP, MagicDNS and split DNS through the tunnel, accepted routes only."""
    key = root('cat', LAB / 'ts-authkey').stdout.strip()
    configure('ts-a', *NETS, '--accept-routes')
    configure('ts-n', *NETS, '--dns', PEER)
    listing, stop = [], threading.Event()
    def sample():
        while not stop.is_set():
            listing.append(sp.run(['ps', '-eo', 'args'], capture_output=True, text=True).stdout)
    watcher = threading.Thread(target=sample); watcher.start()
    try:
        t = time.monotonic(); cli('start', 'ts-a'); state['start_seconds'] = round(time.monotonic() - t, 1)
        cli('start', 'ts-n')
    finally:
        stop.set(); watcher.join()
    assert not any(key in text for text in listing), 'auth key visible in a process listing'
    c = inspect('ts-a')
    assert key not in json.dumps(c)
    eq(root('grep', '-rl', key, c['state']).stdout.split(), [c['state'] + '/vpn/authkey'])
    address, _ = node('ts-a')
    assert address.startswith('100.64.0.') and address != PEER, address
    eq(http('ts-a', PEER), dict(server='tailnet', source=address))        # private HTTP over the tailnet
    eq(ex('ts-a', 'cat', '/etc/resolv.conf').stdout.split()[:2], ['nameserver', '100.100.100.100'])
    eq(ex('ts-a', 'getent', 'hosts', 'lab-peer.lab.devsession.test').stdout.split()[0], PEER)   # MagicDNS
    eq(ex('ts-a', 'getent', 'hosts', 'vpn.test').stdout.split()[0], PEER)  # split DNS: tunnel -> peer's resolver
    eq(http('ts-a', 'vpn.test')['server'], 'tailnet')
    eq(http('ts-a', '10.78.0.1')['server'], 'tailnet')                      # accepted subnet route
    # Not a full tunnel: everything else is dropped, never sent direct.
    before = counters('ts-a', 'forward')
    fails('ts-a', 'curl', '--max-time', '2', f'http://{DETECTOR}:8080')
    fails('ts-a', 'curl', '--max-time', '2', 'http://1.1.1.1')
    fails('ts-a', 'getent', 'hosts', 'example.com')
    fails('ts-a', 'curl', '--max-time', '2', f'http://{c["transport"][0]}:8080')   # the host itself
    assert counters('ts-a', 'forward') > before
    # Explicit --dns, and routes that were not accepted stay unreachable.
    eq(ex('ts-n', 'cat', '/etc/resolv.conf').stdout.split()[:2], ['nameserver', PEER])
    eq(http('ts-n', 'vpn.test')['source'], node('ts-n')[0])
    fails('ts-n', 'curl', '--max-time', '2', 'http://10.78.0.1:8080')
    return f'joined in {state["start_seconds"]}s as {address}; tailnet HTTP, MagicDNS, split DNS and accepted route work; other destinations dropped'


def exit_node(work, state):
    configure('ts-x', *NETS, '--exit-node', 'lab-peer')
    cli('start', 'ts-x')
    eq(http('ts-x', DETECTOR), dict(server='direct', source='198.18.21.2'))   # all IPv4 leaves at the exit node
    eq(http('ts-x', PEER)['server'], 'tailnet')
    eq(ex('ts-x', 'getent', 'hosts', 'vpn.test').stdout.split()[0], PEER)     # DNS through the exit node
    eq(http('ts-a', PEER)['server'], 'tailnet')
    fails('ts-a', 'curl', '--max-time', '2', f'http://{DETECTOR}:8080')        # the sibling still has no exit
    c = inspect('ts-x')
    fails('ts-x', 'curl', '--max-time', '2', f'http://{c["transport"][0]}:8080')
    return 'exit node carries all IPv4 (detector sees the exit node\'s address); DNS resolved through it'


def together(work, state):
    cli('create', 'ts-w'); cli('vpn', 'configure', 'ts-w', '--wireguard', LAB / 'a.conf'); cli('net', 'set', 'ts-w', 'vpn')
    cli('create', 'ts-v'); cli('vpn', 'configure', 'ts-v', '--openvpn', LAB / 'client.ovpn', '--dns', '10.77.0.1')
    cli('net', 'set', 'ts-v', 'vpn')
    cli('start', 'ts-w'); cli('start', 'ts-v')
    with concurrent.futures.ThreadPoolExecutor() as pool:
        got = list(pool.map(lambda n: http(n, 'vpn.test'), ['ts-w', 'ts-v', 'ts-a', 'ts-x']))
    eq([g['server'] for g in got], ['a', 'openvpn', 'tailnet', 'tailnet'])      # same name, four tunnels
    eq([http(n, DETECTOR)['source'] for n in ['ts-w', 'ts-v', 'ts-x']], ['198.18.10.2', '198.18.13.2', '198.18.21.2'])
    cli('stop', 'ts-w'); cli('stop', 'ts-v')
    eq(http('ts-a', PEER)['server'], 'tailnet')
    return 'WireGuard, OpenVPN and two Tailscale sessions concurrently, each on its own tunnel and gateway identity'


def isolation(work, state):
    """The daemon cannot reach host DNS configuration, D-Bus or the host's tailscaled; the gateway exposes nothing."""
    host_mnt = os.readlink('/proc/self/ns/mnt')
    seen = {}
    for name in ['ts-a', 'ts-x']:
        pid = daemon(name); c = inspect(name); gw = c['namespaces']['gateway']
        view = f'/proc/{pid}/root'
        assert root('readlink', f'/proc/{pid}/ns/mnt').stdout.strip() != host_mnt
        resolv = root('cat', view + '/etc/resolv.conf').stdout
        assert '127.0.0.53' not in resolv and not root('test', '-L', view + '/etc/resolv.conf', check=False).returncode == 0
        mounts = root('cat', f'/proc/{pid}/mountinfo').stdout
        assert f'{c["state"]}/tailscale/etc /etc ' in mounts and ' /run ' in mounts, 'private /etc and /run not mounted'
        entries = set(root('ls', '-A', view + '/run').stdout.split())
        assert not entries & {'dbus', 'systemd', 'NetworkManager', 'tailscale', 'resolvconf', 'user'}, entries
        assert root('test', '-e', view + '/var/lib/tailscale/tailscaled.state', check=False).returncode != 0
        argv = Path(f'/proc/{pid}/cmdline').read_bytes().decode().split('\0')
        assert f'--socket={c["state"]}/tailscale/tailscaled.sock' in argv and '--tun=vpn0' in argv, argv
        assert f'--statedir={c["state"]}/tailscale/var' in argv and f'--port={c["vpn"]["port"]}' in argv
        seen[name] = c['vpn']['port']
        links = root('ip', '-n', gw, '-br', 'link').stdout
        assert 'vpn0' in links and 'tailscale0' not in links
        # tailscaled keeps its hands off netfilter: only the guard and NAT tables exist.
        eq(sorted(root('ip', 'netns', 'exec', gw, 'nft', 'list', 'tables').stdout.split('\n')[:-1]),
           ['table inet guard', 'table ip nat'])
        prefs = json.loads(session_ts(name, 'debug', 'prefs').stdout)
        eq((prefs['RunSSH'], prefs['ShieldsUp'], prefs.get('AdvertiseRoutes'), prefs['NetfilterMode'], prefs['RunWebClient'],
            prefs['CorpDNS']), (False, True, None, 0, False, True))
        eq(json.loads(session_ts(name, 'serve', 'status', '--json').stdout or '{}'), {})   # nothing served or funnelled
        # Workloads: no socket, no state, and the service address answers DNS only.
        fails(name, 'test', '-e', '/var/lib/devsession'); fails(name, 'test', '-e', c['state'])
        eq(ex(name, 'sh', '-c', 'find / -xdev -name "tailscaled*" 2>/dev/null | head -1').stdout, '')
        before = counters(name, 'forward')
        fails(name, 'curl', '--max-time', '2', 'http://100.100.100.100/')
        assert counters(name, 'forward') > before
        # A daemon that tried cleartext DNS itself would be refused and counted.
        before = counters(name, 'output')
        root('ip', 'netns', 'exec', gw, 'python3', '-c',
             'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,36,0x80000); s.sendto(b"x",("1.1.1.1",53))', check=False)
        assert counters(name, 'output') > before
        # Likewise anything addressed to the host end of the session link (NAT-PMP, PCP) or to multicast (UPnP).
        before = counters(name, 'output')
        for target, port in [(c['transport'][0], 5351), ('239.255.255.250', 1900)]:
            root('ip', 'netns', 'exec', gw, 'python3', '-c',
                 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,36,0x80000); '
                 f's.sendto(b"x",("{target}",{port}))', check=False)   # marked like the daemon's own sockets
        assert counters(name, 'output') >= before + 2
    assert seen['ts-a'] != seen['ts-x'] and 41641 not in seen.values(), seen
    # Inbound from the tailnet: to the gateway (shields up, input drop) and to a workload (no DNAT).
    address, _ = node('ts-a')
    ex('ts-a', 'sh', '-c', 'nohup python3 -m http.server 8081 --bind 0.0.0.0 >/dev/null 2>&1 </dev/null &')
    eventually(lambda: ex('ts-a', 'curl', '-fsS', '--max-time', '2', 'http://127.0.0.1:8081'))
    for probe in [['curl', '--max-time', '3', f'http://{address}:8081'], ['ping', '-c', '1', '-W', '2', address],
                  ['bash', '-c', f'exec 3<>/dev/tcp/{address}/22']]:
        assert root('timeout', '6', 'ip', 'netns', 'exec', 'dslab-ts', *probe, check=False).returncode != 0, probe
    eq(http('ts-a', PEER)['source'], address)                               # outbound still fine
    # The host's resolver and tailscaled are as they were, while two session daemons run.
    eq(host_changes(state['host'], host_snapshot(), ours=['ds', 'dslab']), [])
    return 'private mount namespace with its own /etc and /run; own socket, state, vpn0 and port; no netfilter of its own; SSH/serve/inbound closed; host unchanged mid-run'


def private_block(work, state):
    """Without --transport-net the daemon cannot reach a control server on a private address."""
    configure('ts-p')
    t = time.monotonic()
    p = cli('--json', 'start', 'ts-p', check=False, timeout=150)
    eq(p.returncode, 120)
    assert 'Tailscale login or configuration failed' in p.stderr, p.stderr
    c = inspect('ts-p')
    assert c['namespaces']['gateway'] not in root('ip', 'netns', 'list').stdout       # start left nothing behind
    assert c['namespaces']['nft_table'] not in root('nft', 'list', 'tables').stdout
    key = root('cat', LAB / 'ts-authkey').stdout.strip()
    assert key not in p.stderr and key not in root('cat', c['state'] + '/tailscale/tailscaled.log').stdout
    cli('delete', 'ts-p', '--no-logout')
    return f'control server in a blocked private range unreachable for the daemon: start failed closed after {time.monotonic() - t:.0f}s, nothing left behind'


def failure(name, exit_node):
    c = inspect(name)
    record = capture_begin(name)
    out = {}
    def dead():
        ex(name, 'python3', '-c', LEAK_PROBE)
        fails(name, 'curl', '--max-time', '2', f'http://{DETECTOR}:8080')
        fails(name, 'curl', '--max-time', '2', f'http://{PEER}:8080')
        fails(name, 'getent', 'hosts', 'vpn.test')
        fails(name, 'curl', '--max-time', '2', f'http://{c["transport"][0]}:8080')
    def alive():
        eventually(lambda: eq(http(name, PEER)['server'], 'tailnet'), timeout=40)
        if exit_node:
            eventually(lambda: eq(http(name, DETECTOR)['source'], '198.18.21.2'), timeout=40)
    try:
        alive()
        probe = sp.Popen(['devsession', 'exec', name, '--', 'python3', '-c', LEAK_PROBE], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        # 1. The daemon is killed: its interface and routes vanish, policy stays.
        root('kill', '-KILL', str(daemon(name)))
        probe.wait(timeout=20); dead()
        out['drops_daemon_killed'] = counters(name, 'forward')
        assert out['drops_daemon_killed'] > 0
        cli('stop', name); cli('start', name); alive()                      # node state persisted
        # 2. Logged out.
        session_ts(name, 'logout')
        eventually(dead, timeout=20)
        out['drops_logged_out'] = counters(name, 'forward')
        assert out['drops_logged_out'] > 0
        cli('stop', name); cli('start', name); alive()                      # reusable key logs in again
        # 3. The node key expires (expired by the control server).
        ident = next(n['id'] for n in json.loads(lab('hs', 'nodes', 'list').stdout)
                     if n['given_name'] == c['vpn']['hostname'] and not n.get('expiry', {}).get('seconds'))
        lab('hs', 'nodes', 'expire', '--identifier', str(ident))
        eventually(dead, timeout=30)
        out['drops_key_expired'] = counters(name, 'forward')
        assert out['drops_key_expired'] > 0
        cli('stop', name); cli('start', name); alive()
        if exit_node:
            # 4. The exit node disappears while the session runs: no fallback to direct.
            for pid in root('ip', 'netns', 'pids', 'dslab-ts').stdout.split():
                if Path(f'/proc/{pid}/comm').read_text().strip() == 'tailscaled':
                    root('kill', '-KILL', pid)
            time.sleep(1)
            ex(name, 'python3', '-c', LEAK_PROBE)
            fails(name, 'curl', '--max-time', '3', f'http://{DETECTOR}:8080')
            fails(name, 'curl', '--max-time', '3', 'http://1.1.1.1')
            lab('peer-daemon')
            alive()                                                         # reconnects without a restart
            out['exit_node_lost'] = 'no direct egress; recovered when the exit node returned'
        # Stop with a probe running, then start again.
        probe = sp.Popen(['devsession', 'exec', name, '--', 'python3', '-c', LEAK_PROBE], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(.3); cli('stop', name); probe.wait(timeout=10)
        cli('start', name); ex(name, 'python3', '-c', LEAK_PROBE); alive()
        out.update(capture_end(record))
        return out
    except BaseException:
        root('pkill', '-INT', '-P', str(record[0].pid), check=False)
        with contextlib.suppress(Exception):
            record[0].wait(timeout=10)
        record[2].close()
        raise


def persistence(work, state):
    """Node state survives stop/start (a one-time key is spent only once); delete logs the node out."""
    key = lab('authkey').stdout.strip()                                     # not reusable
    cli('create', 'ts-o')
    cli('vpn', 'configure', 'ts-o', '--tailscale', '--auth-key-stdin', '--login-server', URL, '--ca-file',
        LAB / 'ts-ca.crt', *NETS, '--hostname', 'one-time', input=key + '\n')
    cli('net', 'set', 'ts-o', 'vpn'); cli('start', 'ts-o')
    first = node('ts-o')
    cli('stop', 'ts-o')
    assert not [p for p in sp.run(['pgrep', '-af', 'tailscaled --tun=vpn0'], capture_output=True, text=True).stdout.splitlines()
                if '/ts-o' in p.replace(str(UID) + '-', '/')]
    cli('start', 'ts-o')
    eq(node('ts-o'), first)                                                 # same node, no second login
    eq(http('ts-o', PEER)['source'], first[0])
    registered = lambda: [n for n in json.loads(lab('hs', 'nodes', 'list').stdout) if n['given_name'] == 'one-time']
    eq(len(registered()), 1)
    assert not registered()[0].get('expiry', {}).get('seconds')
    done = json.loads(cli('--json', 'delete', 'ts-o').stdout)
    eq(done.get('tailscale_logout'), True)
    left = registered()
    assert not left or left[0].get('expiry', {}).get('seconds'), left      # logged out in the tailnet
    # Deleting a stopped session still logs out (bounded, best effort).
    key = lab('authkey').stdout.strip()
    cli('create', 'ts-o')
    cli('vpn', 'configure', 'ts-o', '--tailscale', '--auth-key-stdin', '--login-server', URL, '--ca-file',
        LAB / 'ts-ca.crt', *NETS, '--hostname', 'one-time-b', input=key + '\n')
    cli('net', 'set', 'ts-o', 'vpn'); cli('start', 'ts-o'); cli('stop', 'ts-o')
    eq(json.loads(cli('--json', 'delete', 'ts-o').stdout).get('tailscale_logout'), True)
    left = [n for n in json.loads(lab('hs', 'nodes', 'list').stdout) if n['given_name'] == 'one-time-b']
    assert not left or left[0].get('expiry', {}).get('seconds'), left
    return 'one-time key: same node ID and address after stop/start; delete logged the node out, running or stopped'


def unchanged(state):
    after = host_snapshot()
    eq(host_changes(state['host'], after), [])
    verbatim = state['host']['tailscale status text (verbatim)'] == after['tailscale status text (verbatim)']
    leftovers = [root('ip', 'netns', 'list').stdout.strip(), root('nft', 'list', 'tables').stdout.count('ds_'),
                 sp.run(['pgrep', '-f', 'tailscaled --tun=(vpn0|ts0)'], capture_output=True, text=True).stdout.strip(),
                 sp.run(['pgrep', '-x', 'headscale'], capture_output=True, text=True).stdout.strip()]
    eq(leftovers, ['', 0, '', ''])
    return (f'{len(state["host"]) - 1} host snapshots byte-identical (tailscale node/peers/prefs/process, rules, all routes, '
            f'table 52, nft ruleset, resolver files, resolvectl); verbatim `tailscale status` text identical: {verbatim}')


def run(check):
    work = Path(tempfile.mkdtemp(prefix='devsession-tailscale-'))
    Path('/tmp/opencode').mkdir(exist_ok=True)
    state = {}
    try:
        for name in SESSIONS:
            cli('delete', '--if-exists', '--no-logout', name, check=False)
        lab('down', check=False); cli('cleanup', check=False)
        state['host'] = host_snapshot()                                     # before any fixture exists
        lab('up', 'tailscale', timeout=240)
        check('T1 Tailscale configuration policy and secret handling', lambda: policy(work))
        if check('T2 own node: tailnet HTTP, MagicDNS, split DNS, accepted routes; nothing else reachable', lambda: join(work, state)):
            check('T3 exit node: all IPv4 through it, DNS through it', lambda: exit_node(work, state))
            check('T4 concurrent WireGuard, OpenVPN and Tailscale sessions', lambda: together(work, state))
            check('T5 daemon isolation from host DNS/D-Bus/tailscaled; gateway not exposed', lambda: isolation(work, state))
            check('T6 private ranges stay blocked for the daemon', lambda: private_block(work, state))
            check('T7 forced failure without exit node: kill, logout, key expiry, restart; capture and counters', lambda: failure('ts-a', False))
            check('T8 forced failure with exit node, including loss of the exit node; capture and counters', lambda: failure('ts-x', True))
            check('T9 node state persistence, one-time key, logout on delete', lambda: persistence(work, state))
    finally:
        for name in SESSIONS:
            cli('--wait', '60', 'delete', '--if-exists', '--no-logout', name, check=False)
        lab('down', check=False); cli('cleanup', check=False)
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    check('T10 host tailscale status, routes, policy rules, table 52, nftables and resolver unchanged; no leftovers', lambda: unchanged(state))


if __name__ == '__main__':
    failed = []
    def check(name, function):
        try:
            print('PASS', name, function() or '', flush=True)
            return True
        except Exception as e:
            failed.append(name)
            import traceback
            traceback.print_exc()
            print('FAIL', name, e, flush=True)
            return False
    run(check)
    sys.exit(1 if failed else 0)
