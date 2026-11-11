"""Thin Python client for the devsession command line.

This is a client of the CLI contract, not a second implementation: every
method runs `devsession` once and interprets its documented exit status and
JSON output. Standard library only. Copy it next to your script or put its
directory on sys.path.

    from devsession_client import Session, DevsessionError
    s = Session('build')
    s.ensure(mounts=['/srv/app:/workspace'])
    done = s.run(['make', 'test'], cwd='/workspace')
    print(done.returncode, done.stdout)
"""
import json
import os
import subprocess
import tempfile

CLI = os.environ.get('DEVSESSION_CLI', 'devsession')
# Statuses reserved for devsession itself (see `devsession version --json`).
ERROR, USAGE, NO_SESSION, PRIVILEGE, BUSY, CONFLICT = 120, 121, 122, 123, 124, 125
KINDS = {ERROR: 'error', USAGE: 'usage', NO_SESSION: 'no-such-session',
         PRIVILEGE: 'privilege', BUSY: 'busy', CONFLICT: 'conflict'}


class DevsessionError(Exception):
    """devsession itself failed; the command (if any) did not produce this status."""

    def __init__(self, kind, exit_code, message):
        super().__init__(f'{kind} ({exit_code}): {message}')
        self.kind, self.exit_code, self.message = kind, exit_code, message


def _error(returncode, stderr):
    """Build the exception from the one-line JSON error object on stderr."""
    text = stderr.decode('utf-8', 'replace') if isinstance(stderr, bytes) else (stderr or '')
    for line in reversed(text.splitlines()):
        try:
            error = json.loads(line)['error']
            return DevsessionError(error['kind'], error['exit_code'], error['message'])
        except (ValueError, KeyError, TypeError):
            continue
    return DevsessionError(KINDS.get(returncode, 'error'), returncode, text.strip())


def call(*args, input=None, wait=None, ok=(0,)):
    """Run one devsession command unattended. Returns (status, parsed stdout or None)."""
    cmd = [CLI, '--json', '--non-interactive']
    if wait is not None:
        cmd += ['--wait', str(wait)]
    p = subprocess.run(cmd + [str(a) for a in args], input=input, capture_output=True,
                       stdin=subprocess.DEVNULL if input is None else None)
    if p.returncode not in ok:
        raise _error(p.returncode, p.stderr)
    try:
        return p.returncode, json.loads(p.stdout)
    except ValueError:
        return p.returncode, None


class Session:
    def __init__(self, name, wait=60):
        self.name, self.wait = name, wait

    def _call(self, *args, **kw):
        return call(*args, wait=self.wait, **kw)

    def exists(self):
        return self._call('exists', self.name, ok=(0, 1))[0] == 0

    def state(self):
        """'running', 'stopped' or 'absent'."""
        return self._call('status', self.name, ok=(0, 3, NO_SESSION))[1]['state']

    def ensure(self, mounts=(), tools=(), net=None, cwd=None, extra=()):
        """Create the session unless it already exists with these options. True if created."""
        args = ['create', self.name, '--ensure']
        for m in mounts:
            args += ['--mount', m]
        for t in tools:
            args += ['--tool', t]
        if net:
            args += ['--net', net]
        if cwd:
            args += ['--cwd', cwd]
        return self._call(*args, *extra)[1]['changed']

    def start(self):
        return self._call('start', self.name)[1]['changed']

    def stop(self):
        return self._call('stop', self.name, '--if-exists')[1]['changed']

    def delete(self):
        return self._call('delete', self.name, '--if-exists')[1]['changed']

    def inspect(self):
        return self._call('inspect', self.name)[1]

    def set_env(self, key, value):
        """Persistent session variable; the value travels on stdin, never argv."""
        self._call('env', 'set', self.name, key, '--stdin', input=value.encode())

    def run(self, argv, *, cwd=None, env=None, input=None, stdin=None, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, tty=False, start=True, timeout=None):
        """Run argv in the session and return subprocess.CompletedProcess.

        returncode is the command's own status (128+N if a signal killed it).
        DevsessionError is raised when devsession failed instead, including
        "command not found" (127) and "not executable" (126); the status file
        makes that distinction exact even for a command that exits 120-125.
        """
        with tempfile.TemporaryDirectory(prefix='devsession-client-') as private:
            status = os.path.join(private, 'status')
            cmd = [CLI, '--non-interactive', '--json', '--wait', str(self.wait), 'exec',
                   '--status-file', status, '--tty' if tty else '--no-tty']
            if cwd:
                cmd += ['--cwd', cwd]
            if not start:
                cmd.append('--no-start')
            if env:
                # A 0600 file, not argv: values never show up in process listings.
                envfile = os.path.join(private, 'env')
                with open(os.open(envfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as f:
                    for key, value in env.items():
                        if '\n' in value:
                            raise ValueError('newline in environment value')
                        f.write(f'{key}={value}\n')
                cmd += ['--env-file', envfile]
            if input is None and stdin is None:
                stdin = subprocess.DEVNULL
            p = subprocess.run(cmd + [self.name, '--'] + [str(a) for a in argv], input=input,
                               stdin=stdin, stdout=stdout, stderr=stderr, timeout=timeout)
            try:
                with open(status) as f:
                    record = json.load(f)
            except (OSError, ValueError):
                record = None  # nothing recorded: devsession never reached the command
        if record is None or record['source'] != 'command':
            raise _error(p.returncode, p.stderr) if not record else DevsessionError(
                record['error'], record['exit_code'],
                (p.stderr or b'').decode('utf-8', 'replace').strip())
        p.signal = record['signal']
        return p
