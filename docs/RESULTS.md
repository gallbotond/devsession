# Executed results

Newest first. Each section separates what was executed from what was not
established. The original build's results (2026-11-03) follow unchanged.

## 2026-11-11: Tailscale backend (feature 3, version 0.4.0)

Host as below, with tailscale 1.104.6 installed and the host's own tailscaled
running and logged in to a real tailnet with 21 peers throughout. Control
server for the tests: headscale 0.29.7.

**40 acceptance groups passed, 0 failed** in one run (14 original, S1-S8, A1-A8,
T1-T10); unit tests **16 passed**; the separate real-internet run **7 passed,
0 failed**. Evidence: [`tests/acceptance.log`](../tests/acceptance.log),
[`tests/results.json`](../tests/results.json),
[`tests/remote.log`](../tests/remote.log),
[`tests/remote-results.json`](../tests/remote-results.json), captures
`/tmp/opencode/ts-a-transport.pcap`, `ts-x-transport.pcap`,
`ts-vm-transport.pcap`. Source and installed copy match.

### Hermetic lab (headscale + DERP/STUN in `dslab-hs`, peer in `dslab-ts`)

| Requirement | Executed evidence |
|---|---|
| Own node through a per-session tailscaled; workloads reach tailnet peers | T2: joined in 2.6 s as 100.64.0.2; HTTP to the peer shows that address as source; T5: socket, state directory, `vpn0` and UDP port are the session's own and differ between two sessions (41700, 41701; never 41641) |
| Not a full tunnel without an exit node | T2: detector, 1.1.1.1, an outside name and the host end of the link unreachable, forward-drop counter rising; a session without `--accept-routes` cannot reach the advertised subnet, one with it can |
| Exit node: all IPv4 through it, loss fails closed | T3: the independent detector sees 198.18.21.2 (the exit node); T8: exit node killed while the session ran: detector and 1.1.1.1 unreachable, recovered without restart when it returned |
| DNS is MagicDNS through the tunnel or explicit `--dns` | T2: workload resolver is 100.100.100.100; a tailnet name and a split-DNS name (answered by the peer's dnsmasq over the tunnel) resolve, an outside name fails; `--dns 100.64.0.1` works through the tunnel; T3: with an exit node names resolve through it. No packet to port 53 in any transport capture |
| Host DNS protected structurally | T5: each daemon's mount namespace differs from the host's; its `/etc` is bound from session state; its `/run` has no dbus, systemd, NetworkManager or tailscale entry; host tailscaled state is not visible to it. The daemon did rewrite `resolv.conf`, its private one |
| Host tailscaled and tailnet untouched | T5 (while two session daemons ran) and T10 (after teardown): 17 snapshots byte-identical, see `TESTING.md` for the list: host prefs, node and peer identity fields, tailscaled PID and start time, `ip rule`, all routing tables, table 52, `nft -s list ruleset`, resolver files and `resolvectl` |
| Transport rule: only the daemon originates transport | T5: only `inet guard` and `ip nat` exist in the gateway (tailscaled added no chains); a marked UDP packet to 1.1.1.1:53 and packets to the host end (5351) and to multicast (1900) sent from the gateway namespace are dropped and counted; T7/T8 captures contain transport only |
| Private ranges stay blocked for the daemon | T6: control server at 198.18.20.2 without `--transport-net`: start failed after the 45 s login timeout with status 120, no namespace or table left, no key in the message or log |
| tailscaled cannot loosen the guard; kill switch on kill, logout, key expiry | T7 (no exit node) and T8 (exit node): after `kill -9`, `tailscale logout` and `headscale nodes expire`, HTTP, DNS and probes fail and the forward-drop counters stand at 620/312/304 and 614/310/180 packets; stop/start recovers each time. Captures (425 and 1206 packets, of which 340 and 372 TLS to control/relay): no probe marker, no port 53, no port 8080, no IPv6, nothing addressed to the host end |
| Concurrent WireGuard and OpenVPN sessions | T4: four tunnels at once; `vpn.test` answered by server a, the OpenVPN server and the tailnet peer; detector sees 198.18.10.2, 198.18.13.2, 198.18.21.2 |
| Nothing that exposes the gateway | T1: `--ssh`, `--advertise-routes`, `--advertise-exit-node`, `--shields-up=false`, `--netfilter-mode`, `--operator`, `--auth-key VALUE` are usage errors; T5: preferences read back (SSH off, shields up, nothing advertised, netfilter off, web client off), serve status empty; from the peer, HTTP to a workload listener, ping and TCP 22 to the node fail; 100.100.100.100 port 80 closed to workloads; workloads see no socket or state |
| Unattended auth; secrets | T1/T2: key from a file and from stdin; stored 0600 root; absent from `inspect`, from every other state file and from process listings sampled throughout start; error messages do not echo a rejected key |
| State persists; delete logs out | T9: a one-time key; same node ID and address after stop/start; `delete` reported `tailscale_logout: true` and headscale showed the node expired or gone, for a running and for a stopped session |
| No leftovers | T10: no namespace, no `ds_*` table, no session or lab tailscaled, no headscale process |

### Real internet (control server, relay and peer on the remote test VM)

Executed once on 2026-11-11 from this host
against GCP VM `free-vm`, us-east1 (temporary public address 35.229.110.22).
All keys and the CA were generated on the VM; the client auth key and the CA
certificate came from there, nothing secret went to it.

| Check | Result |
|---|---|
| R1 join a tailnet whose control server and relay are on the public internet | joined the remote tailnet in 4.6s as 100.64.0.7; HTTP to the peer at 100.64.0.1 |
| R2 distinct public egress IP: all IPv4 leaves at the remote exit node (HTTPS, name resolved through it) | public egress address through the exit node is 35.229.110.22; this host's own public address differs |
| R3 transport path to the remote peer (direct UDP or DERP relay) | peer path: direct to 35.229.110.22:41641 |
| R4 WAN path MTU discovery through the tunnel; bulk transfer integrity | UDP with DF: 1252-byte payload passes, 1253 is refused after the gateway reports the tunnel MTU (path MTU 1280); 20 MiB over TCP through the WAN tunnel in 3.4s with matching SHA-256 |
| R5 kill switch on the real path | daemon killed: no direct egress, 317 forwarded packets dropped; restart resumed with the persisted node |
| R6 transport capture: only encrypted traffic to the control/relay/peer address, no DNS, no cleartext | capture: /tmp/opencode/ts-vm-transport.pcap; packets: 6604; control_or_relay_tls: 138; wireguard_or_stun_udp: 6461; destinations: every packet toward the internet went to 35.229.110.22; private_candidates: 5 encrypted probes to the peer's private address reached the session link; none appeared on the uplink ens18 (host private-range rule, 3 drops since the last start) |
| R7 host unchanged after the real-internet run; node logged out | host tailscale node/peers/prefs/process, rules, routes, table 52, nft ruleset and resolver byte-identical; node logged out on delete: True |

This narrows the gap recorded for the original build: public-internet
transport, a distinct public egress address and path-MTU behaviour over a WAN
are now executed evidence **for the Tailscale backend**. They remain
unverified for WireGuard and OpenVPN.

Found by these runs and fixed before the final results:

- With an exit node, tailscaled's default (LAN access disallowed) routed the
  gateway's own `lan`/`wan` links into the tunnel and replies never returned.
- tailscaled refuses to apply split-DNS routes without some base resolver;
  an empty `resolv.conf` silently disabled them.
- `up --exit-node=NAME` cannot name a peer before the first login.
- The real-internet capture showed the daemon probing its default gateway,
  the host end of the session link, for NAT-PMP port mappings. The host's
  input rule already dropped them; the gateway now refuses traffic to the
  host end and to multicast, and port mapping is disabled. Hermetic captures
  assert it since.
- The same capture showed encrypted probes to the peer's private LAN address
  (a normal Tailscale candidate endpoint). The host's private-range rule
  drops them; a capture on the uplink confirmed none left the machine.

### VM state after the run

Removed and verified: `/tmp/dvs-ts` (binaries, CA, keys, database), headscale,
tailscaled and HTTP processes, the `tsdvs0` interface, the loopback address,
`ip_forward` back to 0, no policy rules or `ts-` chains; firewall rules
`dvs-ts-test-allow`, `dvs-ts-test-iap`, `dvs-ts-test-noadmin`; the temporary
external IPv4 (access config `dvs-ts-test`). No package was installed. The VM
is as found: running, no external IPv4, the original five firewall rules.
Because the VM had no public IPv4, one was attached for about twenty minutes;
a temporary deny rule kept SSH and RDP closed to the internet during that
time while IAP access kept working.

### Not established (feature 3)

- **Tailscale's hosted control plane.** `TS_AUTHKEY` for a throwaway tailnet
  was not set, so interoperability with the hosted service, its DERP network
  and its default DNS behaviour was not executed.
  `tests/hosted_tailscale.py` is prepared for it. One attempt on 2026-11-11
  stopped at its first check: the key supplied belonged to the tailnet of the
  host's own tailscaled, which must not be tested against. The session had
  logged in (so unattended login against the hosted control plane did work),
  was deleted within the same run and its node logged out; no reachability,
  DNS or fail-closed assertion was executed. The check remains unverified.
- Relayed (DERP-only) transport on the real path: the real run connected
  directly. DERP was exercised only as far as each lab daemon's own home
  connection.
- A tailnet that configures DNS-over-HTTPS upstream resolvers: by design the
  daemon would contact them over HTTPS outside the tunnel when no exit node
  is used. Documented, not exercised. Cleartext upstream resolvers are
  blocked by rule; that rule was exercised with an injected packet, not with
  a tailnet configured that way.
- Fragmentation of datagrams larger than the tunnel MTU without DF, and
  ICMP-based tools: workloads have no raw sockets; path-MTU discovery was
  verified with UDP and a bulk TCP transfer only.
- Natural key expiry (waiting out a key's lifetime); expiry was forced from
  the control server.
- Long-running behaviour: daemon restarts by itself are not supervised, a
  dead daemon stays dead until stop/start (fail closed); DERP map or control
  address changes over days were not observed.
- sudo.ws, older tailscale releases and control servers other than headscale
  0.29.7 were not run. A host that itself uses an exit node was not tested.
- The verbatim text of the host's `tailscale status` was not byte-identical
  across runs: its activity column (traffic counters of the user's own live
  peers) changes independently. The identity, preference, routing, firewall
  and resolver snapshots were identical.

## 2026-11-11: directory activation (feature 2, version 0.3.0)

Same host as below. **30 acceptance groups passed, 0 failed** (14 original,
S1-S8, A1-A8); parser and unit tests **13 passed**. Evidence:
[`tests/acceptance.log`](../tests/acceptance.log),
[`tests/results.json`](../tests/results.json). Source and installed copy match.

| Requirement | Executed evidence |
|---|---|
| Resolution from scripts, nearest marker wins | A1: name-less `exec`, `status`, `resolve` and the `.` placeholder resolve from nested subdirectories and through a symbolic-link directory; an unapproved nearer marker is an error (119), not a fall-through; no marker is 121 |
| Nothing takes effect before approval of exact path and content | A1: unapproved marker gives 119 and the command did not run; appending a comment, retargeting to another session and `deny` each revoke; restoring the exact bytes restores |
| Approval shows what is granted; record outside the tree | A1: `allow` output contains the marker path, the session's mount, network mode and environment variable names, never a value; refuses without a terminal or `--yes`; refuses a marker whose session does not exist; the record is a byte copy under the state directory with mode 0600 and the tree's file list is unchanged |
| Marker is declarative data | A1: ten hostile markers (command substitution, `;`, backticks, `mount =`, `net =`, two sessions, escape sequence, 5000 bytes, traversal, empty) and a symbolic link to an approved marker are refused by `resolve`, `exec` and `allow`; the file their payload would create does not exist |
| Hook: enter at the same path | A2 (real PTY): `cd` into an approved tree gives the session prompt at `/workspace/sub` for a project mounted at a different path; also through a symbolic link |
| Hook: exit | A2: `exit` returns to the host prompt in the same directory; three further prompts and a `cd` within the tree do not re-enter; leaving and returning re-enters |
| Hook: leave | A3: `cd /tmp` inside the session ends its shell and the host shell is in `/tmp`; with a same-path mount `cd ../..` lands in the tree's parent; a session-only directory is reported once and the host shell stays |
| Hook: nested | A4: entering a subdirectory with its own marker hands over to that marker's session and back on `cd ../..`; `exit` in the nested session skips only the nested tree |
| Never re-enter from inside | A1/A4: name-less `exec` and `shell` inside a session exit 125; evaluating the hook there installs nothing |
| Hook: unapproved, edited after approval | A5/A6: reported exactly once, never entered, `exec` gives 119; `allow` (or restoring the bytes) takes effect at the next prompt |
| Auto-entry can be switched off; scripts unaffected | A7: `DEVSESSION_AUTO_ENTER=0` and a shell without the hook stay on the host while name-less `exec` still resolves. A1: a non-interactive shell that evaluates the hook has an empty `PROMPT_COMMAND`. S1-S8 unchanged |
| Hook is fast, silent, no sudo | A8: **84 microseconds per prompt** in an unmarked directory six levels deep (20000 calls); `strace -f -c` shows the same number of process creations for 1 and 2001 calls, i.e. none per prompt; A2 asserts no notice text in an approved flow |

Found by these checks and fixed: none in the product beyond first-run test
corrections (a strace column mis-parse and a test that expected re-entry
inside a tree it had just exited).

### Not established (feature 2)

- Only Bash 5.3 was exercised. The hook uses `[[ ]]`, arrays and
  `read -d ''`; older Bash (before 5.1, where `PROMPT_COMMAND` arrays arrived
  for the session side) was not tested. No zsh/fish integration exists.
- Prompt frameworks: the PTY checks use plain prompts. Coexistence with
  oh-my-posh's `PROMPT_COMMAND` on the host and in the session is by
  construction (prepend, preserve `$?`) and was not driven on a PTY.
- A session shell with stopped jobs refuses the first `exit` issued by the
  leave function (Bash's own safeguard); not exercised.
- The hand-back path is validated and only ever passed to `cd`; a hostile
  session steering the host shell into another *approved* tree was reasoned
  about (it can only cause an entry the user already approved), not attacked.
- Sudo credential prompts during hook entry (password-required sudo on a
  terminal) were not driven; this host has passwordless sudo.
- Approval-store behaviour on network home directories or with very long
  paths (near `PATH_MAX`) was not tested.

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
  (2026-11-11: executed for the Tailscale backend against a remote VM, see the
  feature 3 section; still not established for WireGuard and OpenVPN.)
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
