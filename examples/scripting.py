#!/usr/bin/python3
"""Unattended use of devsession from Python, through examples/devsession_client.py.

Usage: scripting.py [SESSION]   (creates and deletes SESSION, default "script-py")
Needs no terminal and no stdin. Exits 0 only if every step behaved as documented.
"""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devsession_client import CONFLICT, NO_SESSION, DevsessionError, Session, call


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else 'script-py'
    s = Session(name)
    with tempfile.TemporaryDirectory() as work:
        try:
            demo(s, Path(work))
        finally:
            s.delete()
    print('scripting.py: all checks passed')


def demo(s, work):
    mount = f'{work}:/data'
    # Ensure-style lifecycle: every call can be repeated.
    assert s.ensure(mounts=[mount]) is True
    assert s.ensure(mounts=[mount]) is False
    assert s.state() == 'stopped' and s.exists()
    assert s.start() is True and s.start() is False
    assert s.state() == 'running'
    assert name_listed(s.name)

    # The command's own status, however unusual, is told apart from devsession's.
    for code in (0, 1, 2, 120, 122, 125, 255):
        assert s.run(['sh', '-c', f'exit {code}']).returncode == code
    for kind, argv, kw in [('command-not-found', ['no-such-command'], {}),
                           ('not-executable', ['/etc/hosts'], {}),
                           ('working-directory', ['true'], {'cwd': '/no/such/dir'})]:
        try:
            s.run(argv, **kw)
            raise AssertionError(f'{kind} was not reported')
        except DevsessionError as e:
            assert e.kind == kind, e
    try:
        Session('no-such-session').inspect()
        raise AssertionError('missing session was not reported')
    except DevsessionError as e:
        assert e.exit_code == NO_SESSION and e.kind == 'no-such-session'
    try:
        call('create', s.name)
        raise AssertionError('duplicate create was not reported')
    except DevsessionError as e:
        assert e.exit_code == CONFLICT

    # Binary-clean pipes, both directions at once (16 MiB of random bytes).
    blob = os.urandom(16 * 1024 * 1024)
    digest = hashlib.sha256(blob).hexdigest()
    assert s.run(['sha256sum'], input=blob).stdout.split()[0].decode() == digest
    assert hashlib.sha256(s.run(['cat'], input=blob).stdout).hexdigest() == digest
    (work / 'blob').write_bytes(blob)
    assert hashlib.sha256(s.run(['cat', '/data/blob']).stdout).hexdigest() == digest

    # Per-call directory and environment; a persistent variable set via stdin.
    s.set_env('REGION', 'eu-west-1')
    out = s.run(['sh', '-c', 'printf "%s|%s|%s" "$PWD" "$REGION" "$TOKEN"'],
                cwd='/data', env={'TOKEN': 'call only $(not run)'}).stdout
    assert out == b'/data|eu-west-1|call only $(not run)', out
    assert 'eu-west-1' not in str(s.inspect())  # values are redacted
    assert s.run(['sh', '-c', 'test -t 1']).returncode == 1
    assert s.run(['sh', '-c', 'test -t 1'], tty=True).returncode == 0

    # A signal sent to the client reaches the command; death by signal is 128+N.
    p = subprocess.Popen(['devsession', '--non-interactive', 'exec', s.name, '--', 'sh', '-c',
                          'echo ready; exec sleep 300'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
    assert p.stdout.readline() == b'ready\n'
    threading.Timer(.3, p.send_signal, [signal.SIGTERM]).start()
    assert p.wait(timeout=20) == 128 + signal.SIGTERM
    done = s.run(['sh', '-c', 'kill -KILL $$'])
    assert done.returncode == 137 and done.signal == signal.SIGKILL

    # Concurrent invocations, including a race to start the stopped session.
    assert s.stop() is True and s.stop() is False
    with concurrent.futures.ThreadPoolExecutor(12) as pool:
        results = list(pool.map(lambda i: s.run(['sh', '-c', f'echo {i}; exit {i}']), range(12)))
    assert [(r.returncode, r.stdout) for r in results] == [(i, f'{i}\n'.encode()) for i in range(12)]

    assert s.delete() is True and s.delete() is False
    assert s.state() == 'absent' and not s.exists()


def name_listed(name):
    return any(x['name'] == name and x['running'] for x in call('list')[1]['sessions'])


if __name__ == '__main__':
    main()
