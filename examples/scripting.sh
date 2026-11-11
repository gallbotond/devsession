#!/usr/bin/env bash
# Unattended use of devsession from Bash: no terminal, no prompt, every
# decision taken from an exit status or JSON. Exits 0 only if each step
# behaved as documented.
# Usage: scripting.sh [SESSION]   (creates and deletes SESSION, default "script-sh")
set -u
export DEVSESSION_NONINTERACTIVE=1   # never prompt for a sudo password (status 123 instead)
export DEVSESSION_WAIT=60            # wait this long for a concurrent operation (status 124 after)
name=${1:-script-sh}
fail() { printf 'scripting.sh: FAILED: %s\n' "$*" >&2; exit 1; }
expect() { local want=$1; shift; "$@"; local rc=$?; [ "$rc" -eq "$want" ] || fail "expected $want, got $rc: $*"; }
work=$(mktemp -d) || exit 1
trap 'devsession delete --if-exists --quiet "$name"; rm -rf "$work"' EXIT

# 1. Ensure state; each of these can be repeated.
expect 0 devsession create "$name" --ensure --quiet --mount "$work:/data"
expect 0 devsession create "$name" --ensure --quiet --mount "$work:/data"
expect 125 devsession create "$name" --quiet 2>/dev/null            # plain create: already exists
expect 3 devsession status --quiet "$name"                          # 3: exists, stopped
expect 0 devsession start "$name"
expect 0 devsession start "$name"

# 2. Questions answered by exit status alone.
expect 0 devsession exists "$name"
expect 0 devsession status --quiet "$name"                          # 0: running
expect 1 devsession exists no-such-session
expect 122 devsession status --quiet no-such-session

# 3. exec returns the command's status; 120-125 are devsession's own.
expect 7 devsession exec "$name" -- sh -c 'exit 7'
expect 127 devsession exec "$name" -- no-such-command 2>/dev/null
expect 126 devsession exec "$name" -- /etc/hosts 2>/dev/null
expect 122 devsession exec no-such-session -- true 2>/dev/null
expect 120 devsession exec --cwd /no/such/dir "$name" -- true 2>/dev/null
expect 121 devsession exec --no-such-option "$name" -- true 2>/dev/null
# A command may itself exit 122; the status file says whose status it was.
expect 122 devsession exec --status-file "$work/status" "$name" -- sh -c 'exit 122'
grep -q '"source": "command"' "$work/status" || fail "status file: $(cat "$work/status")"
expect 122 devsession exec --status-file "$work/status" no-such-session -- true 2>/dev/null
grep -q '"source": "devsession"' "$work/status" || fail "status file: $(cat "$work/status")"
# stdout carries only the command's output; an error is one JSON object on stderr.
[ "$(devsession exec "$name" -- printf data 2>/dev/null)" = data ] || fail "stdout not clean"
devsession --json inspect no-such-session 2>&1 >/dev/null | grep -q '"kind": "no-such-session"' || fail "JSON error"

# 4. Binary-clean pipes in both directions (8 MiB of random bytes).
head -c 8388608 /dev/urandom > "$work/blob"
want=$(sha256sum < "$work/blob")
[ "$(devsession exec "$name" -- sha256sum < "$work/blob")" = "$want" ] || fail "host to session"
[ "$(devsession exec "$name" -- cat /data/blob | sha256sum)" = "$want" ] || fail "session to host"
[ "$(devsession exec "$name" -- cat < "$work/blob" | sha256sum)" = "$want" ] || fail "round trip"
# A reader that stops early ends the command (SIGPIPE), it does not hang.
[ "$(devsession exec "$name" -- yes | head -n 1)" = y ] || fail "early reader"

# 5. Per-call working directory and environment; secrets go through a file, not argv.
printf 'TOKEN=s3cr3t $(not run)\n' > "$work/env"
out=$(devsession exec --cwd /data --env STAGE=ci --env-file "$work/env" "$name" -- \
      sh -c 'printf "%s|%s|%s" "$PWD" "$STAGE" "$TOKEN"')
[ "$out" = '/data|ci|s3cr3t $(not run)' ] || fail "cwd/env: $out"
expect 1 devsession exec "$name" -- sh -c 'test -t 1'               # no pseudo-terminal by default
expect 0 devsession exec --tty "$name" -- sh -c 'test -t 1'         # one on request

# 6. A signal sent to devsession reaches the command; death by signal is 128+N.
devsession exec "$name" -- sh -c 'echo ready > /data/ready; exec sleep 300' &
pid=$!
until [ -e "$work/ready" ]; do sleep 0.1; done
kill -TERM "$pid"; wait "$pid"; rc=$?
[ "$rc" -eq 143 ] || fail "SIGTERM gave $rc"

# 7. Concurrent invocations, starting from a stopped session.
expect 0 devsession stop "$name"
expect 0 devsession stop "$name"
pids=()
for i in 1 2 3 4 5 6 7 8; do
    devsession exec "$name" -- sh -c "echo $i > /data/out.$i; exit $i" & pids+=($!)
done
i=0
for pid in "${pids[@]}"; do
    i=$((i + 1)); wait "$pid"; rc=$?
    [ "$rc" -eq "$i" ] && [ "$(cat "$work/out.$i")" = "$i" ] || fail "concurrent exec $i gave $rc"
done

# 8. JSON for anything a script parses.
state=$(devsession --json status "$name" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')
[ "$state" = running ] || fail "JSON state: $state"

# 9. Idempotent teardown.
expect 0 devsession delete "$name"
expect 0 devsession delete --if-exists "$name"
expect 122 devsession delete "$name" 2>/dev/null
expect 1 devsession exists "$name"
echo 'scripting.sh: all checks passed'
