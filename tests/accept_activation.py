#!/usr/bin/python3
"""Directory-activation acceptance checks (feature 2). Real installed CLI.

Resolution checks run without a terminal. Hook checks drive a real
interactive Bash on a PTY: enter, exit, leave, nested, unapproved,
edited-after-approval and hook-disabled. Approval records go to a private
XDG_STATE_HOME, so the invoking user's own approvals are never touched.
Run alone with `python3 -B tests/accept_activation.py` or via acceptance.py.
"""
import contextlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import subprocess as sp
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
A, B = 'act-a', 'act-b'


class Fixture:
    def __init__(self):
        self.work = Path(tempfile.mkdtemp(prefix='devsession-activation-')).resolve()
        self.state = self.work / 'state'
        self.proj, self.solo, self.plain = self.work / 'proj', self.work / 'solo', self.work / 'plain'
        for d in [self.state, self.proj / 'sub' / 'deep', self.proj / 'sub2', self.proj / 'nested' / 'inner',
                  self.solo / 'x', self.plain / 'a' / 'b' / 'c']:
            d.mkdir(parents=True)
        self.env = dict(PATH=os.environ['PATH'], HOME=os.environ['HOME'], TERM='xterm', LANG='C.UTF-8',
                        XDG_STATE_HOME=str(self.state), DEVSESSION_NONINTERACTIVE='1')
        self.marker = self.proj / '.devsession'

    def ds(self, *args, cwd=None, input=None, env=None, timeout=90):
        return sp.run(['setsid', '-w', 'devsession'] + [str(a) for a in args], cwd=cwd or self.work,
                      env=env or self.env, capture_output=True, text=True, timeout=timeout,
                      **(dict(stdin=sp.DEVNULL) if input is None else dict(input=input)))

    def want(self, code, *args, **kw):
        p = self.ds(*args, **kw)
        assert p.returncode == code, (args, p.returncode, p.stdout[-300:], p.stderr[-300:])
        return p

    def setup(self):
        for name in [A, B]:
            self.ds('--wait', '30', 'delete', '--if-exists', name)
        # A: project mounted at a different path. B: mounted at the same paths.
        self.want(0, 'create', A, '--mount', f'{self.proj}:/workspace')
        self.want(0, 'create', B, '--mount', f'{self.solo}:{self.solo}',
                  '--mount', f'{self.proj}/nested:{self.proj}/nested')
        self.marker.write_text(f'# this tree belongs to {A}\nsession = {A}\n')
        (self.proj / 'nested' / '.devsession').write_text(f'session = {B}\n')
        (self.solo / '.devsession').write_text(f'session = {B}\n')

    def approve_all(self):
        for d in [self.proj, self.proj / 'nested', self.solo]:
            self.want(0, 'allow', '--yes', '--quiet', cwd=d)

    def teardown(self):
        for name in [A, B]:
            self.ds('--wait', '30', 'delete', '--if-exists', name)
        shutil.rmtree(self.work, ignore_errors=True)


class Term:
    """An interactive host Bash on a PTY with the hook loaded."""

    def __init__(self, fx, cwd, hook=True):
        self.buffer = b''
        self.log = b''
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(cwd)
            os.execve('/bin/bash', ['bash', '--norc', '--noprofile', '-i'], dict(fx.env, DEVSESSION_NONINTERACTIVE='0'))
        self.send("PS1='HOST<$PWD>\\$ '\n")
        self.until(f'HOST<{cwd}>$ ')
        if hook:
            self.send('eval "$(devsession hook bash)"\n')
            self.until(f'HOST<{cwd}>$ ')

    def send(self, text):
        os.write(self.fd, text.encode())

    def until(self, marker, timeout=25):
        """Consume output up to and including marker; return what was consumed."""
        marker = marker.encode() if isinstance(marker, str) else marker
        end = time.monotonic() + timeout
        while marker not in self.buffer:
            if time.monotonic() > end:
                raise AssertionError(f'no {marker!r} in terminal output: {self.buffer[-600:]!r}')
            if select.select([self.fd], [], [], .2)[0]:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    data = b''
                if not data:
                    raise AssertionError(f'terminal closed before {marker!r}: {self.buffer[-600:]!r}')
                self.buffer += data; self.log += data
        cut = self.buffer.index(marker) + len(marker)
        seen, self.buffer = self.buffer[:cut], self.buffer[cut:]
        return seen

    def run(self, command, prompt, timeout=25):
        self.send(command + '\n')
        return self.until(prompt, timeout)

    def close(self):
        with contextlib.suppress(OSError):
            os.close(self.fd)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(self.pid, signal.SIGKILL); os.waitpid(self.pid, 0)


@contextlib.contextmanager
def terminal(fx, cwd, hook=True):
    t = Term(fx, str(cwd), hook)
    try:
        yield t
    finally:
        t.close()


def host(path):
    return f'HOST<{path}>$ '


def inside(name, path):
    """Default session prompt: [NAME] user@host:DIR$ (DIR is the session's view)."""
    return re.sub(r'^/home/[^/]+', '~', str(path)).join([f'[{name}] {os.environ.get("USER") or os.getlogin()}@{name}:', '$ '])


def resolution(fx):
    tree = lambda: sorted(str(p.relative_to(fx.proj)) for p in fx.proj.rglob('*'))
    before = tree()
    fx.want(121, 'exec', '--', 'true', cwd=fx.plain / 'a')                 # no marker anywhere above
    fx.want(1, 'resolve', cwd=fx.plain / 'a')
    # Unapproved: nothing takes effect, and nothing from the marker runs.
    fx.want(119, 'exec', '--', 'touch', '/workspace/ran', cwd=fx.proj / 'sub')
    eq(json.loads(fx.want(119, '--json', 'resolve', cwd=fx.proj / 'sub').stdout)['state'], 'unapproved')
    assert not (fx.proj / 'ran').exists()
    fx.want(121, 'allow', cwd=fx.proj)                                      # no terminal, no --yes: refuse
    fx.want(0, 'env', 'set', A, 'REGION', 'value-not-shown')
    shown = fx.want(0, 'allow', '--yes', cwd=fx.proj / 'sub').stdout       # approves the nearest marker above
    for text in [str(fx.marker), f'session = {A}', f'{fx.proj} -> /workspace (rw)', 'network      off', 'REGION',
                 'cannot add mounts']:
        assert text in shown, (text, shown)
    assert 'value-not-shown' not in shown
    # The record is outside the tree, an exact copy, private to the user.
    record = fx.state / 'devsession' / 'allow' / str(fx.proj).lstrip('/') / '.devsession'
    eq((record.read_bytes(), record.stat().st_mode & 0o777, tree()), (fx.marker.read_bytes(), 0o600, before))
    # Resolved from scripts, at the same place as the session sees it.
    eq(fx.want(0, 'exec', '--', 'pwd', cwd=fx.proj / 'sub' / 'deep').stdout, '/workspace/sub/deep\n')
    eq(fx.want(0, 'resolve', cwd=fx.proj / 'sub').stdout, A + '\n')
    (fx.work / 'link').symlink_to(fx.proj / 'sub')                          # the physical directory decides
    eq(fx.want(0, 'exec', '--', 'pwd', cwd=fx.work / 'link').stdout, '/workspace/sub\n')
    eq(fx.want(0, 'status', cwd=fx.proj).stdout, 'running\n')
    eq(fx.want(0, 'exec', '.', '--', 'sh', '-c', 'echo $DEVSESSION', cwd=fx.proj).stdout, A + '\n')
    eq(fx.want(0, 'exec', '--cwd', '/', '--', 'pwd', cwd=fx.proj).stdout, '/\n')
    fx.want(0, 'env', 'set', '.', 'VIA_DOT', 'yes', cwd=fx.proj)
    eq(fx.want(0, 'exec', '--', 'printenv', 'VIA_DOT', cwd=fx.proj).stdout, 'yes\n')
    # Nearest marker wins, also when it is the unapproved one.
    fx.want(119, 'exec', '--', 'true', cwd=fx.proj / 'nested' / 'inner')
    fx.want(0, 'allow', '--yes', '-q', cwd=fx.proj / 'nested')
    eq(fx.want(0, 'resolve', cwd=fx.proj / 'nested' / 'inner').stdout, B + '\n')
    eq(fx.want(0, 'exec', '--', 'pwd', cwd=fx.proj / 'nested' / 'inner').stdout, f'{fx.proj}/nested/inner\n')
    eq(fx.want(0, 'resolve', cwd=fx.proj / 'sub').stdout, A + '\n')
    # Any edit revokes; restoring the exact bytes restores; deny revokes.
    original = fx.marker.read_bytes()
    fx.marker.write_bytes(original + b'# harmless-looking comment\n')
    p = fx.want(119, 'exec', '--', 'true', cwd=fx.proj)
    assert 'changed after it was approved' in p.stderr
    fx.marker.write_bytes(original.replace(A.encode(), B.encode()))        # retarget to another session
    fx.want(119, 'exec', '--', 'true', cwd=fx.proj)
    fx.marker.write_bytes(original)
    fx.want(0, 'exec', '--', 'true', cwd=fx.proj)
    eq(json.loads(fx.want(0, '--json', 'deny', cwd=fx.proj).stdout)['changed'], True)
    fx.want(119, 'exec', '--', 'true', cwd=fx.proj)
    assert not record.exists()
    # The marker is data: nothing in it is evaluated, and it cannot declare grants.
    pwned = fx.work / 'pwned'
    for content in [f'session = $(touch {pwned})', f'session = {A}; touch {pwned}', f'session = `touch {pwned}`',
                    f'session = {A}\nmount = /etc:/host-etc', f'session = {A}\nnet = direct', f'session = {A}\nsession = {B}',
                    f'session = {A}\x1b[31m', 'x' * 5000, 'session = ../../etc', '']:
        fx.marker.write_text(content)
        fx.want(120, 'resolve', cwd=fx.proj); fx.want(120, 'exec', '--', 'true', cwd=fx.proj)
        fx.want(120, 'allow', '--yes', cwd=fx.proj)
    assert not pwned.exists()
    fx.marker.unlink(); fx.marker.symlink_to(fx.solo / '.devsession')       # a link to an approved marker
    fx.want(0, 'allow', '--yes', '-q', cwd=fx.solo)
    fx.want(120, 'exec', '--', 'true', cwd=fx.proj)
    fx.marker.unlink(); fx.marker.write_text('session = act-none\n')
    fx.want(122, 'allow', '--yes', cwd=fx.proj)                             # nothing to show: refuse
    fx.marker.write_bytes(original)
    fx.want(0, 'allow', '--yes', '-q', cwd=fx.proj)
    # A marked directory the session does not mount has no "same place".
    other = fx.work / 'unmounted'; other.mkdir()
    (other / '.devsession').write_text(f'session = {A}\n')
    fx.want(0, 'allow', '--yes', '-q', cwd=other)
    p = fx.want(120, 'exec', '--', 'pwd', cwd=other)
    assert 'not inside a mount' in p.stderr
    eq(fx.want(0, 'exec', '--cwd', '/workspace', '--', 'pwd', cwd=other).stdout, '/workspace\n')
    # Never from inside a session, never by root for a user, never the store as a mount.
    p = fx.want(0, 'exec', A, '--', 'sh', '-c', 'cd /workspace && devsession exec -- true; echo "rc=$?"')
    assert p.stdout.strip().endswith('rc=125'), p.stdout
    p = sp.run(['sudo', '-n', 'systemd-run', '--wait', '--pipe', '--quiet', '--collect', f'--working-directory={fx.proj}',
                '/usr/local/bin/devsession', '--user', os.environ.get('USER') or os.getlogin(), 'exec', '--', 'true'],
               capture_output=True, text=True)
    eq(p.returncode, 121)
    fx.want(120, 'create', 'act-c', '--mount', f'{fx.state}/devsession:/store')
    fx.want(120, 'create', 'act-c', '--mount', f'{fx.state}:/store')
    # Non-interactive shells get no hook: scripts behave exactly as without it.
    p = sp.run(['bash', '-c', f'eval "$(devsession hook bash)"; cd {fx.proj}/sub; echo "PC=[${{PROMPT_COMMAND[*]}}]"; '
                'devsession exec -- pwd'], env=fx.env, capture_output=True, text=True, stdin=sp.DEVNULL)
    eq((p.returncode, p.stdout), (0, 'PC=[]\n/workspace/sub\n'))
    return 'no marker 121; unapproved/changed 119; nearest wins; edit, retarget and deny revoke; 10 hostile markers and a symlink refused as data; record outside the tree'


def eq(a, b):
    assert a == b, (a, b)


def enter_exit(fx):
    with terminal(fx, fx.plain) as t:
        t.run('cd a/b', host(fx.plain / 'a' / 'b'))                         # unmarked: stays on the host
        t.run(f'cd {fx.proj}/sub', inside(A, '/workspace/sub'))             # entered, same place as the session sees it
        seen = t.run('echo "in=$DEVSESSION dir=$PWD"', inside(A, '/workspace/sub'))
        assert f'in={A} dir=/workspace/sub'.encode() in seen, seen
        t.run('exit', host(fx.proj / 'sub'))                                # back on the host, same directory
        for _ in range(3):
            t.run('', host(fx.proj / 'sub'))                                # not re-entered at later prompts
        t.run('cd ../sub2', host(fx.proj / 'sub2'))                         # nor elsewhere in the same tree
        t.run(f'cd {fx.plain}', host(fx.plain))
        t.run(f'cd {fx.proj}', inside(A, '/workspace'))                     # re-armed after leaving the tree
        t.run('exit 3', host(fx.proj))
        t.run(f'cd {fx.plain}', host(fx.plain))
        t.run(f'cd {fx.work}/link', inside(A, '/workspace/sub'))            # through a symbolic link
        t.run('exit', host(fx.work / 'link'))
        assert b'not approved' not in t.log and b'changed after' not in t.log
    return 'cd into an approved tree enters at the mapped path; exit returns to the host shell without re-entry until the tree is left'


def leave(fx):
    with terminal(fx, fx.plain) as t:
        t.run(f'cd {fx.proj}/sub/deep', inside(A, '/workspace/sub/deep'))
        t.run('cd ../..', inside(A, '/workspace'))                          # still inside the tree
        t.run('cd /tmp', host('/tmp'))                                      # out of the tree: host shell, same path
        # Same-path mount: the parent of the tree is where the user expects to land.
        t.run(f'cd {fx.solo}/x', inside(B, fx.solo / 'x'))
        t.run('cd ../..', host(fx.work))
        t.run(f'cd {fx.solo}', inside(B, fx.solo))
        # A session-private directory has no host counterpart: stay put, say so once.
        t.run('mkdir -p /tmp/only-in-session && cd /tmp/only-in-session', host(fx.solo))
        assert b'does not exist on the host' in t.log
        t.run('', host(fx.solo))
    return 'leaving the tree inside the session ends its shell and the host shell follows to the mapped directory'


def nested(fx):
    with terminal(fx, fx.plain) as t:
        t.run(f'cd {fx.proj}', inside(A, '/workspace'))
        t.run('cd nested/inner', inside(B, fx.proj / 'nested' / 'inner'))   # nearer marker: other session
        seen = t.run('echo "in=$DEVSESSION"', inside(B, fx.proj / 'nested' / 'inner'))
        assert f'in={B}'.encode() in seen
        t.run('cd ../..', inside(A, '/workspace'))                          # back out: the outer binding again
        t.run('cd nested', inside(B, fx.proj / 'nested'))
        t.run('exit', host(fx.proj / 'nested'))
        t.run('cd ..', inside(A, '/workspace'))                             # exit skipped only the nested tree
        # Inside a session nothing is ever entered: no hook, and the CLI refuses.
        seen = t.run('eval "$(devsession hook bash)"; echo "hooks=[${PROMPT_COMMAND[*]}]"', inside(A, '/workspace'))
        assert b'hooks=[_devsession_leave' in seen and b'_devsession_hook' not in seen.split(b'hooks=[')[-1], seen
        seen = t.run('devsession shell; echo "rc=$?"', inside(A, '/workspace'))
        assert b'rc=125' in seen, seen
        t.run('exit', host(fx.proj))
    return 'nearest marker wins across nesting in both directions; no entry from inside a session'


def unapproved(fx):
    fx.want(0, 'deny', cwd=fx.proj)
    with terminal(fx, fx.plain) as t:
        t.run(f'cd {fx.proj}/sub', host(fx.proj / 'sub'))                   # not entered
        for _ in range(3):
            t.run('', host(fx.proj / 'sub'))
        eq(t.log.count(b'is not approved; review it'), 1)                   # said once, then silent
        seen = t.run('devsession exec -- true; echo "rc=$?"', host(fx.proj / 'sub'))
        assert b'rc=119' in seen, seen
        t.run('devsession allow --yes --quiet', inside(A, '/workspace/sub'))  # approval takes effect at the next prompt
        t.run('exit', host(fx.proj / 'sub'))
    return 'an unapproved marker is reported once and never entered; approval takes effect at the next prompt'


def edited(fx):
    original = fx.marker.read_bytes()
    try:
        with terminal(fx, fx.plain) as t:
            t.run(f'cd {fx.proj}', inside(A, '/workspace'))
            t.run('exit', host(fx.proj))
            t.run(f'cd {fx.plain}', host(fx.plain))
            fx.marker.write_bytes(original + b'\n')                         # one byte more
            t.run(f'cd {fx.proj}', host(fx.proj))
            t.run('', host(fx.proj))
            eq(t.log.count(b'changed after it was approved; review it'), 1)
            seen = t.run('devsession exec -- true; echo "rc=$?"', host(fx.proj))
            assert b'rc=119' in seen, seen
            fx.marker.write_bytes(original)                                 # the approved bytes again
            t.run('', inside(A, '/workspace'))
            t.run('exit', host(fx.proj))
    finally:
        fx.marker.write_bytes(original)
    return 'an edit after approval blocks entry and resolution until the marker is approved again or restored'


def disabled(fx):
    with terminal(fx, fx.plain) as t:
        t.run('DEVSESSION_AUTO_ENTER=0', host(fx.plain))
        t.run(f'cd {fx.proj}/sub', host(fx.proj / 'sub'))                   # approved, but auto-entry is off
        seen = t.run('devsession exec -- pwd', host(fx.proj / 'sub'))       # resolution still works
        assert b'/workspace/sub\r\n' in seen, seen
        t.run('DEVSESSION_AUTO_ENTER=1', inside(A, '/workspace/sub'))
        t.run('exit', host(fx.proj / 'sub'))
    with terminal(fx, fx.plain, hook=False) as t:                           # hook never loaded
        t.run(f'cd {fx.proj}/sub', host(fx.proj / 'sub'))
    return 'DEVSESSION_AUTO_ENTER=0 (or no hook) leaves interactive shells alone; name-less commands still resolve'


def cost(fx):
    """Per-prompt cost of the hook in an unmarked directory, and its process count."""
    deep = fx.plain / 'a' / 'b' / 'c'
    script = fx.work / 'cost.bash'
    script.write_text(f'''eval "$(devsession hook bash)"
cd {deep}
n=$1
(exit 7); _devsession_hook; echo "status=$?"
TIMEFORMAT=%R
t=$( {{ time for ((i=0;i<n;i++)); do _devsession_hook; done; }} 2>&1 )
echo "seconds=$t"
''')
    run = lambda n, prefix=(): sp.run(list(prefix) + ['bash', '--norc', '--noprofile', '-i', str(script), str(n)],
                                      env=fx.env, capture_output=True, text=True, stdin=sp.DEVNULL)
    p = run(20000)
    assert 'status=7' in p.stdout, (p.stdout, p.stderr)                     # the last status is preserved
    micro = float(re.search(r'seconds=([0-9.]+)', p.stdout).group(1)) * 1e6 / 20000
    assert micro < 500, micro
    forks = []
    for n in [1, 2001]:
        p = run(n, ['strace', '-f', '-qq', '-c', '-e', 'trace=clone,clone3,fork,vfork,execve'])
        # strace -c rows: % time, seconds, usecs/call, calls, [errors], syscall
        rows = [line.split() for line in p.stderr.splitlines()]
        counts = {row[-1]: int(row[3]) for row in rows if len(row) in (5, 6) and row[-1] in ('clone', 'clone3', 'fork', 'vfork')}
        assert counts, p.stderr                                             # the fixed start-up cost was observed
        forks.append(sum(counts.values()))
    eq(forks[0], forks[1])                                                   # 2000 more prompts start no process
    depth = len(deep.parts) - 1
    return f'{micro:.0f} microseconds per prompt in an unmarked directory {depth} levels deep; 0 processes started by 2000 prompts'


CHECKS = [('A1 marker resolution, approval by exact path and content, marker is inert data', resolution),
          ('A2 hook on a PTY: enter and exit', enter_exit),
          ('A3 hook on a PTY: leaving the tree from inside the session', leave),
          ('A4 hook on a PTY: nested markers; never re-enter from inside', nested),
          ('A5 hook on a PTY: unapproved marker', unapproved),
          ('A6 hook on a PTY: marker edited after approval', edited),
          ('A7 hook on a PTY: auto-entry disabled', disabled),
          ('A8 measured hook cost on an unmarked directory', cost)]


def run(check):
    fx = Fixture()
    try:
        fx.setup()
        for title, function in CHECKS:
            if function is enter_exit:
                fx.approve_all()
            check(title, lambda: function(fx))
    finally:
        fx.teardown()


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
