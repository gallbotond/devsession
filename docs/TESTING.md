# Reproduce the checks

Run on a disposable Linux VM as its normal sudo-authorized development user.
The tests allocate local network namespaces, veths and VPN servers. They never
need Azure accounts, a VPN provider or cloud spending.

Prerequisites beyond the runtime:

```sh
sudo apt-get install easy-rsa dnsmasq-base tcpdump socat python3-venv \
  ansible tmux bash-completion curl
```

Install Terraform, oh-my-posh and Azure CLI once on the host, as described in
`INVENTORY.md`. The acceptance test also expects nvm 0.40.3 and a Node runtime:

```sh
git clone --depth 1 --branch v0.40.3 https://github.com/nvm-sh/nvm.git ~/.nvm
bash --noprofile --norc -c 'export NVM_DIR="$HOME/.nvm"; source "$NVM_DIR/nvm.sh"; nvm install --lts'
```

Do not overwrite an existing nvm installation; use it and adjust the explicit
version assertion if needed. The suite creates/removes a temporary
`~/.local/bin/ds-user-tool`, a project virtualenv, a sentinel file under `.ssh`,
a host Unix socket and a host tmux session named `ds-host-sentinel`.

```sh
./install.sh
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
sudo python3 -B tests/prototype.py
python3 -B tests/acceptance.py | tee tests/acceptance.log
python3 -B tests/acceptance.py scripting      # one group only: core, scripting, activation, tailscale
```

The `tailscale` group additionally needs the host `tailscale` package (its
own daemon may be running and logged in; it is only read) and the headscale
release binary, which is a test fixture and not part of the runtime:

```sh
mkdir -p /tmp/opencode/hs && cd /tmp/opencode/hs
curl -fsSLo headscale https://github.com/juanfont/headscale/releases/download/v0.29.7/headscale_0.29.7_linux_amd64
echo 'e827fc9b12d958bc95b081c4401dd63f8e0471d025b45b508535a920532150a8  headscale' | sha256sum -c - && chmod +x headscale
```

Set `HEADSCALE=/path/to/headscale` to use another location. Without the
binary the group fails at lab start; the other groups are unaffected.

`prototype.py` is the initial architecture gate, retained as an executable
demonstration. It exercises the actual host Terraform, Ansible, tmux and
oh-my-posh installations and reviewed Bash customization, private process/home
state, real WireGuard/DNS/private HTTP, gateway identity and forced tunnel
failure with capture/counter evidence. It was run successfully **before** the
full CLI was implemented. The original run used this VM's UID/GID 1000 and
`/home/ubuntu`; adjust those fixture values on another VM.

`acceptance.py` uses the **installed CLI** for user workflows and separate root
commands only for test servers/fault injection/packet evidence. It writes
`tests/results.json` and `tests/tool-results.json`. Assertions distinguish
synthetic Azure selected-account state from actual Azure authentication.
The tests use real commands and real kernel networking; parser unit tests are
additional checks, not replacements for networking tests.

## Scripting checks (group `scripting`, `tests/accept_scripting.py`)

Every call runs under `setsid` (no controlling terminal) with stdin closed or
`/dev/null` unless the check itself feeds data. Sessions `scr-a`/`scr-b` use
network mode off, so this group needs no lab servers.

- S1: each documented failure status (1, 3, 120-127, 128+N) with its JSON
  error object; a state lock held from outside gives 124 at once, 124 after
  `--wait 1`, success with a sufficient `--wait`, and no delay for queries.
- S2: a throwaway user `dvs-pwtest` with a random password and a
  password-required rule in `/etc/sudoers.d/dvs-pwtest`. Without a terminal
  devsession must exit 123 within 5 s; on a real PTY `--non-interactive` and
  `DEVSESSION_NONINTERACTIVE=1` must refuse without prompting, and the plain
  call must show sudo's password prompt. A root systemd service then runs
  `devsession --user USER exec`. The user, its home and the sudoers file are
  removed and their absence asserted.
- S3: 64 MiB of random data host to session, session to host and round trip,
  compared by SHA-256; all 256 byte values; closed stdin; SIGPIPE on an early
  reader.
- S4: 16 exit statuses (including 120-125) attributed to the command by
  `--status-file`; HUP/INT/QUIT/USR1/TERM forwarded to a handler; death by
  SIGTERM reported as 143 with `signal: 15`; no leftover process.
- S5: 16 concurrent execs racing one auto-start; 8 concurrent
  `create --ensure`; 16 mixed lifecycle calls with `--wait`.
- S6: `changed` flags of the idempotent forms; stdout carries only command
  output; `--cwd`/`--env`/`--env-file`/`--forward` precedence; an `--env-file`
  secret absent from the host process listing; `-t`/`-T`.
- S7: `examples/scripting.sh` and `examples/scripting.py` run to completion.
- S8: the legacy `prototype` session is listed, inspected and reported
  stopped, and its files are byte-identical afterwards.

## Directory-activation checks (group `activation`, `tests/accept_activation.py`)

Sessions `act-a` (project mounted at `/workspace`) and `act-b` (two trees
mounted at their own paths), network mode off. Approval records go to a
temporary `XDG_STATE_HOME`; the invoking user's own approvals are untouched.
A1 runs without a terminal. A2-A7 drive an interactive `bash --norc -i` on a
real PTY with the hook evaluated, synchronising on the host and session
prompts.

- A1: no marker (121), unapproved (119, and the command did not run), `allow`
  output lists exactly the session's mounts/network/environment names and no
  values; the record is a byte copy outside the tree with mode 0600 and the
  tree's file list is unchanged; mapped working directory, symbolic-link
  directory, `.` placeholder, `--cwd` override; nearest marker wins when it is
  the unapproved one; edit, retarget and `deny` revoke, restoring the bytes
  restores; ten hostile markers (command substitution, extra keys such as
  `mount =`, two sessions, escape sequences, oversize, traversal, empty) and a
  symbolic-link marker are refused and nothing they name is created; a marker
  for a missing session cannot be approved; an unmounted marked directory
  fails; no resolution from inside a session (125) or for a root service
  (121); the approval store cannot be mounted; a non-interactive shell that
  evaluates the hook gets no prompt function.
- A2 enter/exit, A3 leave (different-path mount, same-path mount, a
  session-only directory), A4 nested in both directions plus the in-session
  refusal, A5 unapproved (reported once, approval effective at the next
  prompt), A6 edited after approval, A7 `DEVSESSION_AUTO_ENTER=0` and no hook.
- A8: 20000 hook calls timed in an unmarked directory six levels deep, and
  `strace -f -c` process-creation counts compared between 1 and 2001 calls.

## Tailscale checks (group `tailscale`, `tests/accept_tailscale.py`)

A private tailnet next to the other fixtures, built by `tests/lab.py`:

- `dslab-hs` (198.18.20.2): headscale 0.29.7 as control server with its
  embedded DERP relay (TCP 8443, TLS from a CA generated for the run) and
  STUN (UDP 3478). MagicDNS base domain `lab.devsession.test`, split DNS for
  `vpn.test` to the peer's resolver, no global resolvers.
- `dslab-ts` (198.18.21.2): an ordinary tailscaled peer `lab-peer`
  (100.64.0.1) with HTTP on 8080 and dnsmasq on its tailnet address,
  advertising subnet 10.78.0.0/24 and offering an exit node, both approved.
  It reaches the control server over a lab-internal link, so the fixture does
  not depend on IPv4 forwarding in the host namespace.
- The peer daemon and every CLI call use the same private-mount launcher as
  session daemons, so the fixture cannot touch the host's tailscaled either.

Sessions: `ts-a` (MagicDNS, `--accept-routes`), `ts-n` (explicit `--dns`, no
routes), `ts-x` (exit node), `ts-o` (one-time key), `ts-p` (policy and
blocked-control cases), `ts-w`/`ts-v` (WireGuard and OpenVPN, concurrently).

- T1: options that would expose the gateway do not exist (121); malformed
  values are refused without echoing them; a key given on stdin is stored
  0600 root, absent from `inspect` and from every other state file.
- T2: the session is its own node; tailnet HTTP, MagicDNS, split DNS through
  the tunnel and an accepted subnet route work; the detector, 1.1.1.1, an
  outside name and the host itself are unreachable with forward-drop
  counters rising; routes not accepted stay unreachable; the auth key never
  appears in a process listing sampled throughout start.
- T3: with an exit node the independent detector sees the exit node's
  address; a sibling session without one still cannot reach it.
- T4: WireGuard, OpenVPN and two Tailscale sessions at once, the same name
  `vpn.test` answered by four different tunnels.
- T5: for each session daemon: a mount namespace different from the host's,
  `/etc` bound from session state, `/run` without dbus/systemd/
  NetworkManager/tailscale, no host tailscaled state visible, own socket,
  state directory, `vpn0` and port; only `inet guard` and `ip nat` tables in
  the gateway; preferences read back (SSH off, shields up, nothing
  advertised, netfilter off, nothing served); no socket or state visible to
  workloads; 100.100.100.100 closed except DNS; a marked UDP packet to
  1.1.1.1:53 sent from the gateway namespace is dropped and counted; from the
  peer, HTTP to a workload listener, ping and TCP 22 to the node all fail;
  the host snapshot is identical while two session daemons run.
- T6: a control server in a blocked private range without `--transport-net`:
  start fails closed and leaves no namespace or table.
- T7/T8: capture at the host transport link across: daemon killed, logged
  out, node key expired by the control server, and (T8) the exit node killed
  and restarted, each followed by probes and by stop/start. Probes are UDP
  with a marker to the detector, 1.1.1.1:53, the control, relay, STUN and peer
  ports and an IPv6 resolver, plus HTTP and DNS attempts. The capture must
  hold transport packets, no marker, no port 53, no port 8080 and no IPv6;
  forward-drop counters must be positive in each state.
- T9: a one-time key: same node ID and address after stop/start; `delete`
  reports `tailscale_logout: true` and the control server shows the node
  expired or gone, for a running and for a stopped session.
- T10: after teardown, seventeen host snapshots taken before any fixture
  existed are compared byte for byte: `tailscale debug prefs`, the host
  node's and every peer's identity fields from `tailscale status --json`, the
  first four columns of `tailscale status`, the tailscaled unit's PID and
  start time, `ip rule`, `ip -6 rule`, all IPv4 and IPv6 routing tables,
  table 52, `nft -s list ruleset` (and, for the mid-run comparison in T5, the
  same ruleset without devsession's own `ds_*` tables), `/etc/resolv.conf`
  (content and link),
  systemd-resolved's two resolver files, `resolvectl dns` and
  `resolvectl domain`. The verbatim `tailscale status` text is also compared
  and its result reported, but not required: its activity column (traffic
  counters, "idle"/"active", last seen) changes on a live tailnet on its own.

## Real-internet run (`tests/remote_tailscale.py`)

Not part of `acceptance.py`; it needs a second machine with a public IPv4
address. `tests/remote_vm_setup.sh PUBLIC_IP` (as root on that machine)
downloads headscale and the static tailscale build with checksums, generates
a CA, server certificate and auth keys there, starts headscale (control,
DERP, STUN) and one peer offering an exit node with a 20 MiB test file, and
prints the CA certificate and a client key. Open TCP 8443, UDP 3478 and UDP
41641 to it from the test host only. Then, on the test host:

```sh
python3 -B tests/remote_tailscale.py --server https://PUBLIC_IP:8443 --ca ca.crt \
    --auth-key-file client.key --peer-ip 100.64.0.1 --vm-ip PUBLIC_IP \\
    --peer-private-ip REMOTE_LAN_IP --blob-sha256 HEX
```

R1 join; R2 public egress address through the exit node equals the remote
machine's and differs from the host's; R3 direct or relayed path; R4 DF pings
at and above the tunnel MTU, a fragmented ping and a 20 MiB transfer checked
by SHA-256; R5 kill switch; R6 capture restricted to the remote address with
no DNS or cleartext; R7 host unchanged. `tests/remote_vm_cleanup.sh PUBLIC_IP`
removes everything on the remote machine and prints what is left.

## Topology

- `dslab-a`: WireGuard UDP/51820 at 198.18.10.2, private 10.77.0.1.
- `dslab-b`: another WireGuard server at 198.18.11.2, same private addresses.
- `dslab-o`: OpenVPN TLS server UDP/1194 at 198.18.13.2, same private addresses.
- `dslab-direct`: independent HTTP detector at 198.18.12.2:8080.
- Each server has its own network namespace, distinct from every workload and
  gateway namespace. Easy-RSA generates a local ephemeral CA/server/client PKI.
- Private HTTP and dnsmasq bind to 10.77.0.1. `vpn.test` resolves there in all
  VPNs but returns the identity of the corresponding separate server.
- The host has no route to 10.77.0.0/24. Off/direct requests cannot reach the
  private service. Each VPN gateway NATs tunnel traffic to its own transport
  address, observed at the independent detector. Direct access has a different
  controlled source address.

Captures at the host transport links cover running, forced failure, reconnect,
stop and restart. The probes attempt ordinary direct HTTP/DNS/IPv6 and misuse
of the exact VPN UDP exception. Captures must contain actual encrypted
transport, no cleartext probe marker, and no raw DNS/HTTP/IPv6; nft counters must
record forwarding drops after tunnel removal. A deliberately restored direct
default route tests that fail-closed behavior does not rely on a missing route.

Tests also kill a real OpenVPN startup helper during a deliberately
nonresponsive handshake, check concurrent lifecycle rejection, then recover
recorded resources with repeated cleanup. Interactive checks use a real PTY.

## Manual lab

```sh
sudo python3 -B tests/lab.py up
devsession create lab-demo
devsession vpn configure lab-demo --wireguard /tmp/opencode/devsession-lab/a.conf
devsession net set lab-demo vpn
devsession exec lab-demo -- curl http://vpn.test:8080
devsession delete lab-demo
sudo python3 -B tests/lab.py down
devsession cleanup
```

With the tailnet fixture (`up tailscale` needs the headscale binary):

```sh
sudo python3 -B tests/lab.py up tailscale
L=/tmp/opencode/devsession-lab
devsession create ts-demo
devsession vpn configure ts-demo --tailscale --auth-key-file $L/ts-authkey \
    --login-server https://198.18.20.2:8443 --ca-file $L/ts-ca.crt \
    --transport-net 198.18.20.0/30 --transport-net 198.18.21.0/30 --exit-node lab-peer
devsession net set ts-demo vpn
devsession exec ts-demo -- curl http://198.18.12.2:8080     # source is the exit node, 198.18.21.2
sudo python3 -B tests/lab.py peer status                    # the lab peer's own tailscale CLI
sudo python3 -B tests/lab.py hs nodes list                  # headscale CLI, JSON
devsession delete ts-demo
sudo python3 -B tests/lab.py down
```

The generated VPN configs/keys are root-only. The CLI's root importer reads
them. Do not run `lab.py up` concurrently with another acceptance run: these
fixtures intentionally have deterministic, task-owned names.

## Scope of evidence

This is real same-VM VPN transport, including WireGuard kernel crypto and
OpenVPN TLS/data channels. Controlled source addresses establish which local
gateway carried traffic. They do **not** prove distinct public egress IPs,
public-internet VPN transport, external-provider interoperability or practical
WAN MTU/fragmentation behavior. Those external integration checks remain
unverified; no external disposable VM was supplied.
