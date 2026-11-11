#!/usr/bin/python3
"""Scripting-contract acceptance checks (feature 1). Real installed CLI.

Everything here runs devsession without a controlling terminal (setsid) and,
unless a check feeds data, with stdin closed or /dev/null. Run alone with
`python3 -B tests/accept_scripting.py` or as part of tests/acceptance.py.
"""
import concurrent.futures
import contextlib
import hashlib
import json
import os
from pathlib import Path
import pty
import secrets
import select
import shutil
import signal
import subprocess as sp
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
NAME, OTHER = 'scr-a', 'scr-b'
PWUSER = 'dvs-pwtest'
SUDOERS = Path('/etc/sudoers.d/dvs-pwtest')
KINDS = {120: 'error', 121: 'usage', 122: 'no-such-session', 123: 'privilege', 124: 'busy', 125: 'conflict'}


def ds(*args, input=None, timeout=90, env=None, closed=False, stdout=sp.PIPE):
    """devsession with no controlling terminal; stdin is /dev/null, data, or closed."""
    kw = dict(stdin=sp.DEVNULL) if input is None else dict(input=input)
    if closed:
        kw = dict(stdin=None, preexec_fn=lambda: os.close(0))
    return sp.run(['setsid', '-w', 'devsession'] + [str(a) for a in args], stdout=stdout,
                  stderr=sp.PIPE, timeout=timeout, env=env, **kw)


def root(*args, input=None, check=True, timeout=60):
    p = sp.run(['sudo', '-n', '--'] + [str(a) for a in args], input=input, text=True,
               capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise AssertionError(f'{args[:3]} -> {p.returncode}: {p.stderr}')
    return p


def eq(a, b):
    assert a == b, (a, b)


def want(code, *args, **kw):
    """Run with --json and require this exit status (and error object, if reserved)."""
    p = ds('--json', *args, **kw)
    assert p.returncode == code, (args, p.returncode, p.stderr[-400:])
    if code in KINDS or code in (126, 127):
        error = json.loads(p.stderr.decode().splitlines()[-1])['error']
        eq(error['exit_code'], code)
        assert error['kind'] in {120: ['error', 'working-directory', 'interrupted'], 126: ['not-executable'],
                                 127: ['command-not-found']}.get(code, [KINDS.get(code)]), error
        assert error['message']
    return p


def jout(*args, **kw):
    p = ds('--json', *args, **kw)
    assert p.returncode == 0, (args, p.returncode, p.stderr)
    return json.loads(p.stdout)


@contextlib.contextmanager
def state_lock(seconds):
    """Hold devsession's state lock from outside, as a long start would."""
    p = sp.Popen(['sudo', '-n', 'python3', '-c',
                  'import fcntl,sys,time; f=open("/var/lib/devsession/.lock","a"); fcntl.flock(f,fcntl.LOCK_EX); '
                  f'print("LOCKED",flush=True); time.sleep({seconds})'], stdout=sp.PIPE, text=True)
    assert p.stdout.readline().strip() == 'LOCKED'
    try:
        yield p
    finally:
        root('pkill', '-P', str(p.pid), check=False)
        p.kill(); p.wait()


def codes(work):
    documented = jout('version')['exit_codes']
    for code in ['0', '1', '3', '120', '121', '122', '123', '124', '125', '126', '127', '128+N']:
        assert code in documented, code
    want(121, 'frobnicate')
    want(121, 'exec', '--env', 'NOEQUALS', NAME, '--', 'true')
    want(121, 'exec', NAME)                                    # no command
    for args in [('inspect', 'no-such'), ('start', 'no-such'), ('stop', 'no-such'), ('delete', 'no-such'),
                 ('exec', 'no-such', '--', 'true'), ('env', 'set', 'no-such', 'A', 'b'), ('net', 'set', 'no-such', 'off')]:
        want(122, *args)
    p = ds('--json', 'status', 'no-such')                      # an answer on stdout, not an error
    eq((p.returncode, json.loads(p.stdout)['state'], p.stderr), (122, 'absent', b''))
    want(125, 'create', NAME)                                   # exists
    want(125, 'create', NAME, '--ensure', '--net', 'direct')    # exists, differs
    want(125, 'net', 'set', NAME, 'vpn')                        # no VPN configured
    want(0, 'start', NAME)
    want(125, 'net', 'set', NAME, 'direct')                     # running
    want(0, 'net', 'set', NAME, 'off')                          # unchanged mode needs no stop
    want(0, 'stop', NAME)
    want(125, 'exec', '--no-start', NAME, '--', 'true')
    want(120, 'exec', '--cwd', '/no/such/dir', NAME, '--', 'true')
    want(120, 'create', OTHER, '--mount', '/no/such/source:/x')
    want(127, 'exec', NAME, '--', 'no-such-command')
    want(126, 'exec', NAME, '--', '/etc/hosts')
    want(137, 'exec', NAME, '--', 'sh', '-c', 'kill -KILL $$')
    want(1, 'exists', 'no-such'); want(0, 'exists', NAME)
    want(0, 'status', NAME); want(0, 'stop', NAME); want(3, 'status', NAME)
    eq(ds('status', NAME).stdout, b'stopped\n')
    assert jout('doctor')['ok'] is True
    # 124: a held lock fails at once by default, after --wait if given, and a
    # sufficient --wait succeeds. Read-only queries never wait for the lock.
    with state_lock(3):
        t = time.monotonic(); want(124, 'stop', NAME); assert time.monotonic() - t < 1.5
        t = time.monotonic(); want(124, '--wait', '1', 'exec', NAME, '--', 'true')
        assert 0.9 < time.monotonic() - t < 2.5
        env = dict(os.environ, DEVSESSION_WAIT='0')
        want(124, 'exec', NAME, '--', 'true', env=env)
        t = time.monotonic()
        want(3, 'status', NAME)
        assert any(s['name'] == NAME for s in jout('list')['sessions'])
        jout('inspect', NAME)
        assert time.monotonic() - t < 1.5, 'queries waited for the lock'
        t = time.monotonic(); want(0, '--wait', '30', 'start', NAME)
        assert time.monotonic() - t > 0.5, 'did not wait for the lock'
    return 'statuses 1,3,120,121,122,124,125,126,127,137 each with its JSON error object; 123 in the sudo check'


def privilege(work):
    """sudo that needs a password: fail fast with 123, never hang, never prompt unattended."""
    me = os.getuid()
    root('userdel', '-r', PWUSER, check=False)
    try:
        root('useradd', '--create-home', '--shell', '/bin/bash', PWUSER)
        root('chpasswd', input=f'{PWUSER}:{secrets.token_urlsafe(18)}\n')
        root('install', '-m', '440', '/dev/stdin', SUDOERS, input=f'{PWUSER} ALL=(ALL:ALL) ALL\n')
        base = ['sudo', '-n', '-u', PWUSER, '--', 'setsid', '-w']
        t = time.monotonic()
        p = sp.run(base + ['devsession', '--json', 'list'], capture_output=True, timeout=20,
                   preexec_fn=lambda: os.close(0))
        elapsed = time.monotonic() - t
        eq(p.returncode, 123)
        error = json.loads(p.stderr.decode().splitlines()[-1])['error']
        eq((error['kind'], p.stdout), ('privilege', b''))
        assert elapsed < 5, elapsed
        p = sp.run(base + ['devsession', 'exec', NAME, '--', 'true'], capture_output=True, timeout=20, stdin=sp.DEVNULL)
        eq(p.returncode, 123)
        assert b'sudo needs a password' in p.stderr, p.stderr
        # With a terminal: --non-interactive still refuses; without it the
        # ordinary sudo prompt appears (interactive use is unchanged).
        def on_pty(args):
            pid, fd = pty.fork()
            if pid == 0:
                os.execvp('sudo', ['sudo', '-n', '-u', PWUSER, '--'] + args)
            output, status, end = b'', None, time.monotonic() + 15
            try:
                while time.monotonic() < end:
                    if select.select([fd], [], [], .2)[0]:
                        try:
                            data = os.read(fd, 4096)
                        except OSError:
                            data = b''
                        if not data:
                            break
                        output += data
                        if b'assword:' in output:
                            break
                if b'assword:' in output:
                    os.write(fd, b'\x03')
            finally:
                done = (0, 0)
                while done[0] == 0 and time.monotonic() < end:
                    done = os.waitpid(pid, os.WNOHANG)
                    time.sleep(.05)
                os.close(fd)
                if done[0] == 0:
                    root('pkill', '-KILL', '-u', PWUSER, check=False)
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(pid, signal.SIGKILL)
                    done = os.waitpid(pid, 0)
                status = os.waitstatus_to_exitcode(done[1])
            return output, status
        output, status = on_pty(['devsession', '--non-interactive', 'list'])
        assert b'assword:' not in output and status == 123, (output, status)
        output, status = on_pty(['env', 'DEVSESSION_NONINTERACTIVE=1', 'devsession', 'list'])
        assert b'assword:' not in output and status == 123, (output, status)
        output, status = on_pty(['devsession', 'list'])
        assert b'assword:' in output, (output, status)
    finally:
        root('pkill', '-KILL', '-u', PWUSER, check=False)
        root('rm', '-f', SUDOERS)
        root('userdel', '-r', PWUSER, check=False)
    assert root('getent', 'passwd', PWUSER, check=False).returncode != 0
    assert not SUDOERS.exists() and not Path('/home', PWUSER).exists()
    # Unattended privilege without sudo: a root service names the session owner.
    user = __import__('pwd').getpwuid(me).pw_name
    p = root('systemd-run', '--wait', '--pipe', '--quiet', '--collect',
             '/usr/local/bin/devsession', '--user', user, 'exec', NAME, '--', 'id', '-u')
    eq(p.stdout.strip(), str(me))
    want(121, '--user', user, 'list')                           # not for sudo-mediated calls
    return f'password-required sudo failed in {elapsed:.2f}s with 123; prompt only on a terminal; root service --user ran as uid {me}; throwaway user removed'


def piping(work):
    blob = os.urandom(64 * 1024 * 1024)
    digest = hashlib.sha256(blob).hexdigest()
    (work / 'blob').write_bytes(blob)
    ds('stop', NAME)                                            # include the auto-start in the first call
    p = ds('exec', NAME, '--', 'sha256sum', input=blob)         # host -> session
    eq((p.returncode, p.stdout.split()[0].decode(), p.stderr), (0, digest, b''))
    p = ds('exec', NAME, '--', 'cat', '/data/blob')             # session -> host
    eq((p.returncode, hashlib.sha256(p.stdout).hexdigest(), p.stderr), (0, digest, b''))
    p = ds('exec', NAME, '--', 'cat', input=blob)               # both at once
    eq((p.returncode, hashlib.sha256(p.stdout).hexdigest()), (0, digest))
    every = bytes(range(256)) * 4
    eq(ds('exec', '-T', NAME, '--', 'cat', input=every).stdout, every)
    # stdout and stderr stay separate; stdin closed reads as end of file.
    p = ds('exec', NAME, '--', 'sh', '-c', 'printf out; printf err >&2; wc -c', closed=True)
    eq((p.returncode, p.stdout.split(), p.stderr), (0, [b'out0'], b'err'))
    # An early reader ends the writer by SIGPIPE instead of leaving it running.
    p = sp.run('setsid -w devsession exec scr-a -- yes | head -n 1; echo "${PIPESTATUS[0]}"',
               shell=True, executable='/bin/bash', capture_output=True, stdin=sp.DEVNULL, timeout=30)
    eq(p.stdout, b'y\n141\n')
    eq(ds('exec', NAME, '--', 'grep', 'SigIgn', '/proc/self/status').stdout.split()[1], b'0000000000000000')
    return '64 MiB each way and round trip with matching SHA-256; all 256 byte values; closed stdin; SIGPIPE'


SIGNAL_CHILD = ('import signal,sys,time\n'
                'for n in (1,2,3,10,15): signal.signal(n,lambda s,f:sys.exit(40+s))\n'
                'print("READY",flush=True); time.sleep(60)')


def signals(work):
    for code in [0, 1, 2, 3, 64, 119, 120, 121, 122, 123, 124, 125, 128, 129, 200, 255]:
        status = work / 'status'
        p = ds('exec', '--status-file', status, NAME, '--', 'sh', '-c', f'exit {code}')
        eq((p.returncode, json.loads(status.read_text())), (code, dict(source='command', exit_code=code, signal=None, error=None)))
    p = ds('exec', '--status-file', work / 'status', 'no-such', '--', 'true')
    eq((p.returncode, json.loads((work / 'status').read_text())['source']), (122, 'devsession'))
    p = ds('exec', '--status-file', work / 'status', NAME, '--', 'no-such-command')
    eq((p.returncode, json.loads((work / 'status').read_text())['error']), (127, 'command-not-found'))
    for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGUSR1, signal.SIGTERM]:
        p = sp.Popen(['setsid', '-w', 'devsession', 'exec', NAME, '--', 'python3', '-c', SIGNAL_CHILD],
                     stdin=sp.DEVNULL, stdout=sp.PIPE, text=True)
        eq(p.stdout.readline().strip(), 'READY')
        # setsid -w waits for devsession; signal the devsession process itself.
        child = sp.run(['pgrep', '-P', str(p.pid)], capture_output=True, text=True).stdout.split()[0]
        root('kill', f'-{int(sig)}', child)
        eq(p.wait(timeout=10), 40 + sig)
    status = work / 'status'
    p = sp.Popen(['setsid', '-w', 'devsession', 'exec', '--status-file', str(status), NAME, '--',
                  'sh', '-c', 'echo READY; exec sleep 77'], stdin=sp.DEVNULL, stdout=sp.PIPE, text=True)
    eq(p.stdout.readline().strip(), 'READY')
    child = sp.run(['pgrep', '-P', str(p.pid)], capture_output=True, text=True).stdout.split()[0]
    root('kill', '-TERM', child)
    eq(p.wait(timeout=10), 143)
    eq(json.loads(status.read_text()), dict(source='command', exit_code=143, signal=15, error=None))
    eq(ds('exec', NAME, '--', 'pgrep', '-f', 'sleep 77').returncode, 1)
    return '16 exit statuses attributed to the command; HUP/INT/QUIT/USR1/TERM forwarded; signal death 128+N recorded'


def concurrency(work):
    ds('stop', NAME)
    def one(i):
        p = ds('exec', NAME, '--', 'sh', '-c', f'echo {i}; exit {i}')
        return p.returncode, p.stdout
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        eq(list(pool.map(one, range(16))), [(i, f'{i}\n'.encode()) for i in range(16)])
        ds('delete', '--if-exists', OTHER)
        made = list(pool.map(lambda i: jout('--wait', '60', 'create', OTHER, '--ensure'), range(8)))
        eq(sorted(m['changed'] for m in made), [False] * 7 + [True])
        mixed = list(pool.map(lambda i: ds('--wait', '90', ['start', 'stop', 'start', 'inspect'][i % 4], OTHER).returncode, range(16)))
        eq(mixed, [0] * 16)
        raced = list(pool.map(lambda i: ds('delete' if i % 2 else 'stop', OTHER).returncode, range(8)))
        assert set(raced) <= {0, 122, 124}, raced               # busy and gone are the only other outcomes
    ds('--wait', '30', 'delete', '--if-exists', OTHER)
    want(1, 'exists', OTHER)
    return '16 concurrent execs racing one auto-start; 8 concurrent create --ensure (one created); 16 mixed lifecycle calls with --wait'


def contract(work):
    """Idempotent forms, stdout discipline, per-call options, argv secrecy."""
    ds('stop', NAME)
    eq([jout(*a)['changed'] for a in [('start', NAME), ('start', NAME), ('stop', NAME), ('stop', NAME),
                                      ('stop', 'no-such', '--if-exists'), ('delete', 'no-such', '--if-exists'),
                                      ('create', NAME, '--ensure', '--mount', f'{work}:/data')]],
       [True, False, True, False, False, False, False])
    p = ds('exec', NAME, '--', 'printf', 'only-this')          # auto-start prints nothing
    eq((p.stdout, p.stderr), (b'only-this', b''))
    eq(ds('create', OTHER, '--quiet').stdout, b''); ds('delete', OTHER)
    (work / 'env').write_text('TOKEN=from file $(id)\nSTAGE=file\n')
    env = dict(os.environ, FWD='forwarded', STAGE='host')
    p = ds('exec', '--cwd', '/data', '--forward', 'FWD', '--env-file', work / 'env', '--env', 'STAGE=flag',
           NAME, '--', 'sh', '-c', 'printf "%s|%s|%s|%s" "$PWD" "$FWD" "$TOKEN" "$STAGE"', env=env)
    eq(p.stdout, b'/data|forwarded|from file $(id)|flag')
    eq(ds('exec', NAME, '--', 'sh', '-c', 'printf "%s" "$TOKEN$STAGE"').stdout, b'')   # this call only
    want(120, 'exec', '--env', 'HOME=/elsewhere', NAME, '--', 'true')                    # isolation-reserved
    (work / 'env').write_text('TOKEN=ARGV_SECRET_SENTINEL\n')
    p = sp.Popen(['setsid', '-w', 'devsession', 'exec', '--env-file', str(work / 'env'), NAME, '--',
                  'sh', '-c', 'echo READY; sleep 20'], stdin=sp.DEVNULL, stdout=sp.PIPE, text=True)
    eq(p.stdout.readline().strip(), 'READY')
    listing = sp.run(['ps', '-eo', 'args'], capture_output=True, text=True).stdout
    root('pkill', '-f', 'devsession.py exec --env-file'); p.wait(timeout=10)
    assert 'ARGV_SECRET_SENTINEL' not in listing
    # Pseudo-terminal selection without a terminal on our side.
    eq(ds('exec', NAME, '--', 'sh', '-c', 'test -t 0 || test -t 1').returncode, 1)
    eq(ds('exec', '-t', NAME, '--', 'sh', '-c', 'test -t 0 && test -t 1').returncode, 0)
    p = ds('exec', '--tty', NAME, '--', 'bash', '--norc', '--noprofile', '-i',
           input=b'echo answer-$((6*7))\nexit 5\n')
    assert p.returncode == 5 and b'answer-42' in p.stdout, (p.returncode, p.stdout)
    return 'changed flags; clean stdout; --cwd/--env/--env-file/--forward; secret absent from process listing; -t/-T'


def examples(work):
    out = {}
    for script in ['scripting.sh', 'scripting.py']:
        # No controlling terminal and stdin closed, as under cron or CI.
        p = sp.run(['setsid', '-w', str(REPO / 'examples' / script)], capture_output=True, text=True,
                   timeout=300, preexec_fn=lambda: os.close(0))
        assert p.returncode == 0, (script, p.returncode, p.stdout[-500:], p.stderr[-1500:])
        eq(p.stdout.strip().splitlines()[-1], f'{script}: all checks passed')
        out[script] = 'passed'
    return out


def migration(work):
    """State written before UID-prefixed directories still loads, and is not rewritten."""
    if root('test', '-f', '/var/lib/devsession/prototype/config.json', check=False).returncode:
        return 'no legacy prototype session on this host: not exercised'
    digest = lambda: root('sh', '-c', 'cd /var/lib/devsession/prototype && find . -type f -print0 | sort -z | xargs -0 sha256sum').stdout
    before = digest()
    assert any(s['name'] == 'prototype' for s in jout('list')['sessions'])
    assert b'prototype\tstopped\tvpn' in ds('list').stdout
    c = jout('inspect', 'prototype')
    eq((c['name'], c['mode'], c['running'], c['env'], c['mounts']), ('prototype', 'vpn', False, {}, []))
    want(3, 'status', 'prototype'); want(0, 'exists', 'prototype')
    want(125, 'create', 'prototype')
    # Recovery paths must not rewrite it either (cleanup stops every stale session).
    want(0, 'cleanup'); want(0, 'stop', 'prototype'); want(3, 'status', 'prototype')
    eq(digest(), before)
    return 'legacy prototype listed, inspected, stopped and cleaned up; files byte-identical'


CHECKS = [('S1 every documented failure status with JSON errors; bounded lock wait; lock-free queries', codes),
          ('S2 password-required sudo fails fast (123); prompt only on a terminal; root-service --user', privilege),
          ('S3 binary-clean piping of large data both ways with stdin closed and no TTY', piping),
          ('S4 exit-status attribution and signal propagation', signals),
          ('S5 concurrent invocations', concurrency),
          ('S6 idempotent forms, clean stdout, per-call cwd/env, PTY selection', contract),
          ('S7 Bash and Python examples run unattended', examples),
          ('S8 legacy state migration check (prototype)', migration)]


def run(check):
    work = Path(tempfile.mkdtemp(prefix='devsession-scripting-'))
    try:
        for name in [NAME, OTHER]:
            ds('--wait', '30', 'delete', '--if-exists', name)
        assert ds('create', NAME, '--mount', f'{work}:/data').returncode == 0
        for title, function in CHECKS:
            check(title, lambda: function(work))
    finally:
        for name in [NAME, OTHER, 'script-sh', 'script-py']:
            ds('--wait', '30', 'delete', '--if-exists', name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    failed = []
    def check(name, function):
        try:
            print('PASS', name, function() or '', flush=True)
        except Exception as e:
            failed.append(name)
            import traceback
            traceback.print_exc()
            print('FAIL', name, e, flush=True)
    run(check)
    sp.run(['devsession', 'cleanup'])
    sys.exit(1 if failed else 0)
