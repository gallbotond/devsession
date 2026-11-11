# Executed results

Newest first. Each section separates what was executed from what was not
established. The original build's results (2026-11-03) follow unchanged.

## 2026-11-11: scripting support (feature 1, version 0.2.0)

Host: Ubuntu 26.04, Linux 7.0.0-34, Python 3.14.4, Bash 5.3.9, sudo-rs 0.2.13
(`Defaults use_pty`), user `user` (UID 1000) with passwordless sudo.

**Baseline before the change** (commit 9268a42): parser tests 4 passed;
acceptance 14 groups passed, 0 failed.

**After the change: 22 acceptance groups passed, 0 failed** (the 14 original
groups unchanged in content, plus S1-S8), parser tests **9 passed**. Evidence:
[`tests/acceptance.log`](../tests/acceptance.log),
[`tests/results.json`](../tests/results.json). Source and installed copy match
(`sha256sum devsession.py /usr/local/lib/devsession/devsession.py`).

| Requirement | Executed evidence |
|---|---|
| Distinct statuses for "devsession failed" and "the command's status" | S1: 1, 3, 120, 121, 122, 124, 125, 126, 127, 137 each produced by a real command and matched against its JSON error object; S2: 123. S4: sixteen command statuses including 120-125 attributed to the command by `--status-file`; a missing session and a missing command attributed to devsession |
| No hang on password-required sudo | S2: throwaway user with a password-required sudoers rule, no terminal, stdin closed: status 123 in 0.05 s. On a real PTY, `--non-interactive` and `DEVSESSION_NONINTERACTIVE=1` refused without prompting; the plain call showed sudo's password prompt (interactive path intact). A root systemd service ran `devsession --user user exec` as UID 1000 |
| Bounded lock wait | S1: with the state lock held externally, `stop` failed with 124 in under 1.5 s, `--wait 1` failed after about 1 s, `DEVSESSION_WAIT=0 exec` failed with 124, `--wait 30 start` succeeded after release; `list`/`status`/`inspect` returned without waiting |
| Machine-readable output, existence/running by status | S1/S5/S6: `--json` documents parsed for list, status, inspect, create, start, stop, delete, doctor, version; `exists` 0/1, `status` 0/3/122 |
| Idempotent forms | S6: `changed` true/false sequence for start, stop, `stop --if-exists`, `delete --if-exists`, `create --ensure`; S1: differing `--ensure` is 125; S5: eight concurrent `create --ensure`, exactly one created |
| Per-call cwd/env, PTY choice | S6: `--cwd`, `--forward`, `--env-file`, `--env` precedence; reserved name refused; values literal (`$(id)` unexpanded) and absent from the next call; `-t` gives a terminal without one on the caller's side, a scripted interactive Bash through `-t` returned its exit status |
| stdout discipline | S3/S6: stdout equals the command's bytes exactly, stderr empty, including a call that auto-starts the session; `create --quiet` prints nothing |
| Binary-clean large data, both directions | S3: 64 MiB random data host to session, session to host, and round trip, SHA-256 equal; all 256 byte values; stdin closed reads as EOF; early reader ends the writer with SIGPIPE (141), signal dispositions not ignored |
| Exit-status and signal propagation | S4: HUP, INT, QUIT, USR1, TERM delivered to a handler in the session; default-disposition SIGTERM gives 143 with `signal: 15`; no process left behind |
| Concurrent invocations | S5: sixteen execs racing one auto-start, each with its own status and output; sixteen mixed start/stop/inspect with `--wait`; racing stop/delete yield only 0, 122 or 124 |
| Examples run by the suite, no TTY, stdin closed | S7: `examples/scripting.sh` and `examples/scripting.py` (through `examples/devsession_client.py`) |
| Secrets not in argv | S6: an `--env-file` value was absent from `ps -eo args` while the command ran |
| Existing state keeps loading | S8: legacy `prototype` listed, inspected, reported stopped, `cleanup` and `stop` run against it, files byte-identical |

Defects found by these checks and fixed before the final run:

- Workloads inherited ignored SIGPIPE/SIGXFSZ from the Python supervisor, so
  `exec NAME -- yes | head -n 1` never ended. Dispositions are now reset.
- With stdin closed by the caller, an internal descriptor could become the
  command's stdin and `exec -t` crashed. Closed stdio is now occupied first.
- `exec` of a missing command produced a Python traceback and status 1.
- `inspect prototype` failed although `list` showed the session.
- An intermediate version rewrote the legacy `prototype` configuration with
  defaulted keys during `cleanup`. The file was restored (its SHA-256 equals
  the pre-change snapshot) and `stop` now writes state only when it changes
  it; S8 covers `cleanup` and `stop`.

### Not established (feature 1)

- Real sudo (sudo.ws) was not exercised; this host has sudo-rs. The contract
  uses only `-n`, `--preserve-env=NAME` and `--`, which both implement.
- The probe-to-exec race (a sudo credential expiring between `sudo -n true` and
  the real call) was reasoned about, not reproduced.
- `--status-file` attribution against a deliberately hostile same-UID workload
  that forges the supervisor's report was not attempted; the design note in
  `ARCHITECTURE.md` states what such a workload can and cannot change.
- Lock waiting was tested up to tens of seconds, not under sustained
  contention from many long VPN starts.
- Only Bash and Python callers were executed; cron and a CI runner were
  simulated by `setsid` with stdin closed, and a root service by `systemd-run`.

## 2026-11-03: original build

**Final local acceptance run: 14 check groups passed, 0 failed**, covering all
17 requested acceptance categories. Parser tests: **3 passed**. Python and
shell syntax checks passed. Source and installed implementation SHA256 match:
`cf8df11a1f6c0232f54f16e258e0293f847118b0f075770283e00766a2c51c4a`.

Evidence:
- [`tests/results.json`](../tests/results.json): machine-readable final checks.
- [`tests/acceptance.log`](../tests/acceptance.log): executed final run output.
- [`tests/tool-results.json`](../tests/tool-results.json): host/session resolved
  paths and versions.
- `/tmp/opencode/acc-a-transport.pcap` and
  `/tmp/opencode/acc-o-transport.pcap`: retained real transport captures.
- Reproduction: [`TESTING.md`](TESTING.md).

### Passed

| Requested category | Executed evidence |
|---|---|
| 1. Separate environment | Same REGION name has independent values; stdin secret import; literal env-file `$()` stays data; explicit forwarding and redaction |
| 2. No host secrets/agents | Host environment/cloud/proxy sentinels absent; host Unix agent socket and private SSH sentinel absent |
| 3. Private credentials | Session A imported SSH key absent in B; private home files absent in B |
| 4. Azure configuration | Actual Azure CLI 2.92.0 reads distinct synthetic profiles; `az account set` in A leaves B's selected subscription unchanged |
| 5. Shared projects | A/B/host see changes immediately |
| 6. Private home/tmp | Home and temporary sentinel files are not shared |
| 7. Mount permissions/ownership | Read-only project/tool writes fail; writable project files owned by host UID 1000 |
| 8. Direct/off | Independent direct endpoint works, off fails; private service unreachable without VPN; host-service access blocked; explicit loopback port publishing works |
| 9. Both VPNs | Real kernel WireGuard and TLS OpenVPN reach private HTTP by `vpn.test` through tunnel DNS |
| 10. Overlap/concurrency | Three concurrent sessions (two WireGuard, one OpenVPN) use identical 10.77.0.0/24 and private names, returning their respective server identities |
| 11. Gateway identity | Independent detector observes 198.18.10.2 / .11.2 / .13.2 for VPNs, versus .12.1 for direct; controlled local identities, not public egress claims |
| 12. Forced VPN failure | Tunnel deleted; raw gateway default route restored deliberately; direct/DNS/IPv6/endpoint-exception misuse blocked; 405 forwarding drops per tested backend |
| 13. Transitions | Nonempty transport captures across reconnect, tunnel failure, stop and restart contain no cleartext marker or raw DNS/HTTP/IPv6 bypass; policy installed before workload admission |
| 14. Host routing/DNS | Host default route JSON, resolver bytes and resolver symlink unchanged |
| 15. Independent lifecycle | Stop/start preserves environment/key; delete removes private state; sibling VPN stays functional and project files survive |
| 16. Recovery | Kill real helper during nonresponsive OpenVPN startup; concurrent lifecycle change rejected; cleanup/repeated stop remove tracked partial resources |
| 17. Interactive/status/signals | PTY shell, foreground-child Ctrl-C, continued prompt, shell exit 7, command exit 37; directed SIGTERM reaches command and returns its handler's exit 42 |

Additional boundary checks:
- Separate PID namespace and private `/proc`; host sentinel PID environ/root/fd
  are unavailable; ptrace attach to that host PID fails.
- Effective capabilities zero, no-new-privileges set; host sudo and route
  modification attempts fail. Host state, D-Bus and runtime sockets absent.
- Tmux sockets are `/run/user/1000/tmux-1000/default` in each **private** runtime
  mount. A host tmux server is not visible. Tmux-started HTTP clients reach
  the selected VPN's private service.
- Terraform 1.17.1 local init/apply/output; Ansible core 2.20.1 localhost ping;
  tmux 3.6; oh-my-posh 31.9.1 prompt hook; Python 3.14.4; user-local Python
  executable; nvm 0.40.3 / Node 26.13.0 / npm 11.20.0; project-venv executable.
  Host and session command/resolved paths and versions match.
- Reviewed Ubuntu-style alias, shell function, bash-completion and oh-my-posh
  prompt execute. Host `.bashrc` is not blindly sourced.
- Direct mode separately fetched `https://example.com` headers, receiving
  HTTP/2 200 through the VM's ordinary internet connection.
- `dpkg --audit` was empty; Azure venv `pip check` reported no broken requirements.

The initial prototype gate passed before CLI implementation: the required host
tools/customization, private sentinel state, real WireGuard/private DNS/HTTP,
controlled gateway identity, forced-down drop counters and **zero bypass
packets** captured on its transport link; host default route/resolver unchanged.

### Failures encountered and fixed

No failed checks remain in the final suite. During development:
- Ubuntu AppArmor prevented post-Bubblewrap setuid. Launch now drops UID first
  and uses Bubblewrap's user namespace; the profile was not disabled.
- WireGuard's packaged AppArmor profile initially rejected task-owned key
  paths; a narrow included read rule was installed.
- Fixed nft multiline syntax, test HTTP module shadowing, private `.local`
  parent ownership, explicit OpenVPN `dev-type tun`, socat argument quoting,
  overly aggressive exec lock rejection and directed signal forwarding.
- Added a session-side controlling PTY for interactive job control. The
  Ctrl-C check now waits for readiness emitted by the foreground child itself,
  avoiding a race between a preceding shell builtin and child job creation.

### Unexecuted / not established

- Real Azure login, token refresh and remote Azure operations: no credentials
  supplied. Synthetic profile selection is not authentication.
- Public-internet VPN transport, distinct public VPN egress IP, external VPN
  provider interoperability, and practical WAN MTU/fragmentation: only local
  servers were supplied/created. Direct HTTPS is not proof of those VPN claims.
- OpenVPN TCP transport and every optional import directive were not separately
  integration-tested; the executed backend test uses TLS over UDP with copied
  CA/certificate/key files. Referenced auth-file copying/restrictive permissions
  and rejection of executable directives were unit-tested.
- pyenv/asdf/mise/rustup installations were absent. nvm and a project Python
  venv exercise actual version-managed/interpreter dependency sharing, not
  universal compatibility with every manager.
- Host-daemon/hardware/desktop tools and authenticated OpenCode operation are
  unsupported or unverified under the default socket/device policy.
- Finite capture tests demonstrate the exercised transitions, not a formal
  proof against every kernel/runtime failure or malicious kernel exploit.

### Final cleanup verified

After tests: no network namespaces, no nft tables, no task-owned veths, no
devsession transient services and no surviving Bubblewrap/VPN/DNS/test HTTP
processes. IPv4 forwarding restored to **0**. Private test session homes and
sentinel fixtures removed. `/var/lib/devsession` contains only its root-owned
lock file. Generated test PKI and captures remain under `/tmp/opencode` for
inspection; installed host tools/source remain available. See
[`CLEANUP.md`](CLEANUP.md) for uninstall and artifact removal.
