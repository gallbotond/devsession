# devsession

Persistent Linux development sessions with **your host's tools**, private
credentials/home/processes, explicitly shared projects, and isolated off,
direct, WireGuard, OpenVPN or Tailscale networking. No container image or per-session
tool installation.

## Install

Tested on Ubuntu 26.04, Linux 7.0, Python 3.14, Bubblewrap 0.11.1,
util-linux 2.41+, nftables, WireGuard tools, OpenVPN 2.7 and Tailscale 1.104
(against headscale 0.29).

```sh
./install.sh
devsession doctor
```

`install.sh` checks the prerequisites and installs the missing ones with
`apt-get` (bubblewrap, iproute2, nftables, util-linux, wireguard-tools,
openvpn, python3). `./install.sh --no-install` only reports what is missing
and exits 1, for systems where you install packages yourself or that have no
`apt-get`. Optional tools are reported, never installed for you: `socat` for
`--publish` and the `tailscale` package for the Tailscale backend. A
distribution release whose Bubblewrap or util-linux is too old (see below)
cannot be fixed by the script; it says so and stops.

Bubblewrap must support `--bind-fd`; nsenter must support `--wdns`. Publishing
TCP ports additionally needs systemd and socat. An ordinary sudo-authorized
host user runs the CLI; it requests sudo for setup and joins. Workloads run
as that user's UID with **no capabilities and no-new-privileges**. No restricted
sudo delegation/setuid installation is supported.

On Ubuntu with a `wg` AppArmor profile, installation adds an included read rule
for task-owned VPN files; no global profile is disabled. See
[architecture and privileges](docs/ARCHITECTURE.md),
[host inventory/system changes](docs/INVENTORY.md) and
[test instructions](docs/TESTING.md) and [executed results](docs/RESULTS.md).

## Two Azure accounts, one project

Install Azure CLI **once on the host**. This VM has it at
`/opt/devsession-tools/azure` with `/usr/local/bin/az`. That installation is
automatically shared read-only. Other Azure installation layouts, such as
`/opt/az`, can be selected with `--tool /opt/az`.

```sh
devsession create client-a --mount "$HOME/projects/app:/workspace" --net direct
devsession create client-b --mount "$HOME/projects/app:/workspace" --net direct

# Terminal A
devsession shell client-a
az login --use-device-code --tenant TENANT_A
az account set --subscription SUBSCRIPTION_A

# Terminal B
devsession shell client-b
az login --use-device-code --tenant TENANT_B
az account set --subscription SUBSCRIPTION_B

# Also works without entering a shell
devsession exec client-a -- az account show
devsession exec client-b -- az account show
```

Both shells edit the same project immediately; their `HOME`, `.azure`, SSH,
Git credentials, cloud/Kubernetes/registry configuration, caches, temporary
files and runtime sockets are independent. `AZURE_CONFIG_DIR` is pinned to the
private `.azure` directory. Automated tests use synthetic account profiles,
**not real Azure authentication**. Device-code login lets a host browser
complete authentication without exposing a desktop/browser socket.

## Host tools and shell

System installations under `/usr` (including `/usr/local`) and required
libraries/support files are read-only. Existing `~/.local/bin` and
`~/.opencode/bin` are recognized executable trees. The host PATH is preserved;
other environment variables are not copied wholesale. Custom installations
need explicit read-only approval:

```sh
devsession create coding \
  --mount "$HOME/projects/app:$HOME/projects/app" \
  --tool "$HOME/.nvm/versions" --tool "$HOME/.nvm/nvm.sh" \
  --shell-rc ./examples/customization.bash
devsession inspect coding
```

`--host-tools` approves every host `PATH` entry outside `/usr` in one step.
Each directory is mounted read-only as itself; the surrounding installation is
mounted instead only for asdf-style `shims` and symlink farms such as
Homebrew's `bin`, so a sibling file like a tool's `auth.json` is not exposed.
Snap and credential/config paths are skipped. Check the result with `inspect`.

Using the **original project path** preserves project-venv absolute shebangs.
Include full runtime/toolchain trees, not just binary symlinks. Install/update
tools on the host. `inspect` lists every installation and project mount.
`doctor` shows discovered host commands and their resolved paths.

Host `.bashrc`, `.profile`, exported functions, agent sockets and credential
stores are **not implicitly imported**. Review a reusable Bash startup file
and pass `--shell-rc FILE`; the file is snapshotted. Session-local `~/.bashrc`
is sourced afterward. The example preserves familiar Ubuntu aliases,
completion, a sample function and oh-my-posh initialization.

To transfer selected aliases/functions from a running Bash:

```sh
source ./examples/shell-integration.bash
devsession_export ./review-me.bash alias:ll function:my_function
# Inspect review-me.bash for secrets, host-only references and sourced files.
devsession create reviewed --shell-rc ./review-me.bash
```

Only Bash has supplied startup integration. Other shells may be run via
`exec`, with explicit private configuration. Host-daemon-dependent tools
(Docker socket, desktop keyring, systemd user bus, hardware) are unsupported
by default; there is no fallback to executing them on the host. Tmux uses a
session-private socket directory and stays inside the session namespaces.

## Environment and credential import

Default environment: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `TERM`,
private XDG config/data/cache/runtime paths, `TMPDIR`, `TMUX_TMPDIR`,
`AZURE_CONFIG_DIR`, `DEVSESSION`. Invocation may carry `TERM`, `COLORTERM`,
`LANG`. Nothing else is inherited unless explicitly forwarded.

`XDG_STATE_HOME` also points to the private `~/.local/state` directory.

```sh
devsession env set client-a REGION eu-west-1
printf '%s\n' 'a secret value' | devsession env set client-a API_TOKEN --stdin
devsession env set client-a API_TOKEN --file ./private-token.txt
devsession env import client-a ./session.env
devsession env unset client-a API_TOKEN
devsession exec --forward EDITOR client-a -- bash
devsession credential client-a .ssh/id_ed25519 --file ./client-key
devsession credential client-b .kube/config < ./client-b-kubeconfig
```

Env files are literal `NAME=value` lines; blank lines and `#` comments are
ignored. Quotes, `$()`, backticks and variable references are **data**, not
shell syntax. Inspection redacts **all values**. Isolation-defining variables
(HOME/XDG/AZURE_CONFIG_DIR/TMUX etc.) cannot be overridden. Changes affect new
commands, not existing shells or tmux servers. Forwarding sensitive variables
is an explicit credential transfer. Values supplied as positional CLI arguments
can appear in host process listings; use stdin/files for secrets.

Explicit credential imports are copied into private HOME with restrictive
permissions. Narrow file mounts can also be selected with `--mount`, but their
contents are then deliberately shared and writes affect the source.

## VPN and networking

New sessions default to `off` (loopback only). Direct mode uses its own network
and DNS, with private/local/link-local destinations blocked by default.
`--allow-net CIDR` at creation permits an explicit exception. DNS defaults to
1.1.1.1 in direct mode; `--dns IPv4` selects another resolver (use
`--allow-net` too if it is local). Host services are blocked even when a
destination range is permitted. No host route or resolver is replaced.

```sh
devsession stop client-a
devsession vpn configure client-a --wireguard ./wg.conf
devsession net set client-a vpn
devsession start client-a

devsession stop client-b
devsession vpn configure client-b --openvpn ./client.ovpn --dns 10.77.0.1
devsession net set client-b vpn
devsession start client-b

devsession exec client-a -- curl http://private.example
```

WireGuard and OpenVPN require **IPv4 full tunnel**, with IPv6 explicitly blocked
(Tailscale is described below).
DNS goes through the tunnel. Each gateway has its own routes/interfaces;
overlapping private VPN ranges work across sessions. The forwarding kill
switch exists before workloads and remains during failure/reconnect. Only
the separate gateway can use the exact endpoint transport exception.
Endpoint DNS resolves on the host during configuration; reconfigure to refresh
changed addresses. Config files and referenced keys/certificates/credential
files are copied, mode 0600. Mode changes require stop.

Supported configuration policy:
- WireGuard: one interface/peer, PrivateKey, Address (IPv4), DNS (IPv4), MTU,
  PublicKey, optional PresharedKey/PersistentKeepalive, Endpoint,
  AllowedIPs containing `0.0.0.0/0`. Hooks, tables and multiple peers are rejected.
- OpenVPN: one endpoint, IPv4 UDP or TCP client, TUN, TLS CA or peer fingerprint,
  cert/key, tls-auth/tls-crypt, auth-user-pass file/inline data, cipher/TLS
  verification/timing/MTU settings. Inline certificates/keys are supported.
  Explicit `--dns` is required; pushed DNS is ignored. Interactive VPN password
  prompts, TAP, compression, proxies, multiple remotes/connection blocks,
  hooks/plugins, arbitrary scripts, provider modules and config includes are
  rejected. Exact allowlist: `OVPN_VALUES`/`OVPN_FILES` in `devsession.py`.
- Workloads cannot read the root-controlled VPN private keys or control daemon.
- The transport pool is 10.231.0.0/16; conflicting host routes are skipped.
  10.203.0.0/30 is reserved for the inner link and cannot be a VPN service range.

Examples: [WireGuard](examples/wireguard.conf), [OpenVPN](examples/client.ovpn).

### Tailscale

A session can join a tailnet as **its own node**, through its own `tailscaled`
in its gateway namespace. This is independent of any Tailscale on the host:
the host's daemon, login and tailnet are never contacted or changed.

```sh
devsession stop client-c
devsession vpn configure client-c --tailscale --auth-key-file ./authkey   # or --auth-key-stdin
devsession net set client-c vpn
devsession start client-c
devsession exec client-c -- curl http://build-box.tailnet-name.ts.net
```

| Option | Meaning |
|---|---|
| `--auth-key-file FILE`, `--auth-key-stdin` | Auth key for unattended login. Stored root-only (0600), passed to the client as a file, never on a command line, never shown by `inspect`. A reusable key lets the session log in again after logout or key expiry |
| `--login-server URL` | Self-hosted control server (headscale). A host name is resolved once at configuration, like other endpoints; reconfigure to refresh |
| `--ca-file FILE` | Extra PEM CA certificates for a self-hosted control or relay server |
| `--exit-node PEER` | Send all IPv4 through this peer |
| `--accept-routes` | Accept subnet routes advertised in the tailnet |
| `--dns IPv4` | Explicit resolver(s) reached through the tunnel instead of MagicDNS |
| `--hostname NAME` | Node name (default `ds-SESSION`) |
| `--transport-net CIDR` | A private range the gateway daemon (never a workload) may reach, for a control or relay server on a private address |

What workloads can reach:

- **Without an exit node**: tailnet addresses and, with `--accept-routes`,
  advertised subnets. Everything else is dropped at the gateway and counted;
  it is never sent directly. This backend is deliberately not a full tunnel
  unless you select an exit node.
- **With an exit node**: all IPv4 goes through it. If the exit node, the
  daemon, the login or the node key is lost, traffic stops; nothing falls
  back to a direct path. Start fails if the exit node is not in the tailnet.
- **DNS**: MagicDNS at 100.100.100.100, answered by the session's own daemon:
  tailnet names, split-DNS domains through the tunnel, and with an exit node
  everything through the exit node. Names with no route through the tunnel
  fail. With `--dns`, those resolvers are used through the tunnel instead.
  The daemon itself has no system resolver and cleartext DNS from it is
  refused at the gateway. Residual: a tailnet that configures a DNS-over-HTTPS
  upstream is contacted by the daemon over HTTPS outside the tunnel
  (encrypted, but not through the tunnel) when no exit node is in use.
- **IPv6** stays blocked, as for the other backends.
- **Inbound from the tailnet is closed**: shields are up, and Tailscale SSH,
  advertised routes or exit node, serve/funnel, the web client and the peer
  relay cannot be configured and are verified off at every start. Workloads
  cannot see the daemon's socket or state.

Node state persists across stop/start (a one-time key is spent once).
`delete` logs the node out of the tailnet first, best effort and bounded
(`--no-logout` skips it, for example when offline). Requires the `tailscale`
package on the host; `doctor` lists it.

## Scripting

Every operation works unattended: no terminal, stdin closed, from Bash, cron,
CI or Python. Working examples, executed by the acceptance suite:
[`examples/scripting.sh`](examples/scripting.sh),
[`examples/scripting.py`](examples/scripting.py) and the thin client module
[`examples/devsession_client.py`](examples/devsession_client.py) (a client of
this command line, not a second implementation).

**Exit status.** `exec` and `shell` return the command's own status. devsession
reserves 119-125 for itself, so a command exiting 1 or 2 is never mistaken for
a tool failure (`devsession version --json` prints this table):

| Status | Meaning |
|---|---|
| 0 | Success; for `exec`/`shell` the command exited 0 |
| 1 | `exists`: no such session. `resolve`: no marker. `doctor`: a required prerequisite is missing |
| 3 | `status`: the session exists but is stopped |
| 119 | The directory marker is not approved, or changed after approval |
| 120 | devsession failed: operation error, bad working directory, interrupted join |
| 121 | Usage error (was argparse's 2) |
| 122 | No such session |
| 123 | Root privilege unavailable without a prompt |
| 124 | State lock still busy after `--wait` |
| 125 | Conflict with existing state: already exists, running, differs, `--no-start` |
| 126, 127 | `exec`: command not executable / not found |
| 128+N | `exec`/`shell`: the command was killed by signal N |
| other | `exec`/`shell`: the command's own status |

A command can itself exit 119-125. When that matters, `exec --status-file FILE`
writes one JSON record: `{"source": "command"|"devsession", "exit_code": N,
"signal": N|null, "error": KIND|null}`. `source` is `command` only if the
command ran and this is its status. The file is emptied first; if it is still
empty afterwards, devsession never reached the command. Until 0.2.0 every
devsession failure and every usage error exited 2.

**Output.** stdout carries only the command's output or the requested data;
diagnostics go to stderr. `--json` (before or after the subcommand) makes
`list`, `status`, `exists`, `create`, `start`, `stop`, `delete`, `env`, `net`,
`vpn`, `cleanup`, `doctor` and `version` print one JSON document, and turns any
error into a single line on stderr:
`{"error": {"kind": "no-such-session", "exit_code": 122, "message": "..."}}`.
`inspect` always prints JSON. `-q` suppresses informational text.

```sh
devsession status build            # prints running|stopped|absent; exit 0, 3 or 122
devsession exists build            # exit 0 or 1, no output
devsession --json list             # {"sessions": [{"name", "state", "running", "mode", "phase"}]}
```

**Ensure-style operations.** `create --ensure` succeeds if the session already
exists and agrees with every option given (it never modifies an existing
session; a difference is status 125). `stop --if-exists` and
`delete --if-exists` succeed when there is nothing to do. `start`, `stop`,
`env unset` and `net set` to the current mode are repeatable. JSON results
carry `"changed": true|false`.

**Waiting.** Changes take a global state lock. By default a busy lock fails at
once with 124; `--wait SECONDS` (or `DEVSESSION_WAIT`) bounds the wait, a
negative value waits without limit. `exec`, `shell` and `credential` wait
without limit unless told otherwise. `list`, `status`, `exists` and `inspect`
never wait.

**Per-call exec options.**

```sh
devsession exec --cwd /workspace/api build -- make test      # working directory inside the session
devsession exec --env STAGE=ci --env-file ./ci.env build -- ./deploy
devsession exec -T build -- tar -c . > backup.tar            # never a pseudo-terminal
devsession exec -t build -- some-tui < keys.txt              # always a pseudo-terminal
devsession exec --no-start build -- true                     # 125 instead of starting it
```

`--env` values are visible in host process listings, so secrets belong in
`--env-file` (literal `NAME=value` lines, like `env import`). Without `-t`/`-T`
a pseudo-terminal is used only when stdin and stdout are both terminals.
Data through `exec` is binary-clean in both directions, and the command sees
default signal dispositions (a closed reader ends it with SIGPIPE). SIGINT,
SIGTERM, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2 sent to devsession are forwarded.

**Privilege without a human.** Setup still needs root; that does not change.
When no prompt is possible (no controlling terminal, `--non-interactive` or
`DEVSESSION_NONINTERACTIVE=1`), devsession runs `sudo -n` and fails within
milliseconds with status 123 instead of waiting for a password. An unattended
caller therefore needs one of:

- an account whose sudo needs no password (the usual CI-runner or disposable-VM
  arrangement);
- a sudo credential refreshed beforehand (`sudo -v`) and still cached;
- to be started by root itself (a systemd unit, root's crontab) and name the
  session owner: `devsession --user alice exec build -- make`. Workloads still
  run as `alice` with no capabilities. `--user` is refused through sudo.

There is still no setuid helper and no restricted sudo rule: a sudoers entry
limited to `/usr/local/bin/devsession` is root-equivalent, not a restriction.

## Directory activation

Tie a directory tree to a session, direnv-style, so that working there uses
that session without naming it. A marker file `.devsession` holds one line of
data ([example](examples/dot-devsession)):

```sh
cd ~/projects/app
devsession create client-a --mount "$PWD:/workspace"
echo 'session = client-a' > .devsession
devsession allow            # shows what the binding grants, asks, records the approval
```

**Resolution (scripts and terminals alike).** A command given no session name,
or `.` in its place, uses the nearest marker at or above the current
directory:

```sh
devsession exec -- make test          # runs in client-a, in /workspace/<same subdirectory>
devsession status                     # also start, stop, inspect, shell
devsession env set . REGION eu-west-1 # "." works wherever a name is expected
devsession resolve                    # prints client-a; exit 0, 1 (no marker) or 119 (not approved)
```

`exec` and `shell` start in the same place as the session sees it: the host
directory mapped through the session's mounts (a project mounted at
`/workspace` maps `~/projects/app/api` to `/workspace/api`). If the directory
is not mounted in that session the command fails (120) rather than running
somewhere else; `--cwd` overrides. `exec` needs the `--` when the name is
omitted. `delete` and `exists` never take the session implicitly (use `.`).

**Trust.** A marker arrives with whatever repository you clone, so it is
untrusted input and does nothing until approved:

- `devsession allow [DIR]` prints the marker path and SHA-256, the session it
  names and what that session holds (network mode, mounts, tool trees,
  environment names, published ports), then asks. `--yes` skips the question
  for scripts. The session must already exist, so there is always something
  to show.
- The approval is an exact copy of the marker stored outside the tree, under
  `${XDG_STATE_HOME:-~/.local/state}/devsession/allow/<path>`. It covers that
  path and those bytes only: any edit, including retargeting it to another
  session, revokes it (status 119) until you approve again. `devsession deny`
  revokes explicitly. That store can never be mounted into a session.
- The nearest marker always decides. An unapproved marker in a subdirectory is
  an error there, not a fall-through to an approved one further up.
- A marker is declarative data with a single key, `session`. It is never
  sourced or executed; shell syntax, extra keys (it cannot declare mounts,
  tools, networking or how to create a session), symbolic links, control
  characters and anything over 4 KiB are rejected. It holds no secrets.
- Approval binds a name. What the session of that name holds is changed only
  by your own `devsession` commands, shown again at the next `allow`.

**Shell hook.** In `~/.bashrc`:

```sh
eval "$(devsession hook bash)"
```

In an interactive Bash, `cd` into an approved tree enters the session's shell
at the same (mapped) path. `exit` returns to the host shell, which then stays
on the host until you leave that tree. Changing directory out of the tree
*inside* the session also ends the session shell, and the host shell follows
to that directory: its host path if it lies under a mount, otherwise the same
absolute path if that exists on the host. A nearer marker in a subdirectory
hands over to its own session, and back again on the way out. An unapproved
or edited marker is reported once and never entered.

- The hook runs at every prompt using shell builtins only: no sudo and no
  process unless a session is actually entered (measured: about 85
  microseconds per prompt in an unmarked directory). Entering runs
  `devsession shell`, which needs sudo like any other entry.
- It installs itself only in interactive shells; scripts and non-interactive
  shells behave exactly as described under Scripting.
- `DEVSESSION_AUTO_ENTER=0` switches automatic entry off (per shell, or
  exported from `~/.bashrc`); name-less commands still resolve.
- Nothing is ever entered from inside a session: the hook does not install
  there, and name-less commands fail with 125.
- Only Bash is supplied. Sessions started before 0.3.0 need one restart for
  leave detection.

## Lifecycle, servers and cleanup

```sh
devsession create web --mount "$PWD:/workspace" --publish 8000:8000
devsession exec web -- python3 -m http.server 8000
# Host: http://127.0.0.1:8000 (explicit loopback TCP proxy)

devsession list
devsession inspect web
devsession stop web
devsession start web
devsession delete web
devsession cleanup
```

Shell exit leaves the session and background processes running. Stop kills
session processes and releases interfaces, namespaces, firewall tables and
published listeners. Home/configuration persist through stop/start. Delete
removes private state, not bind-mounted projects. Stale/interrupted starts
are recovered by the next start/stop or `cleanup`. Conflicting lifecycle
operations are rejected with status 124 unless `--wait SECONDS` is given;
multiple running execs are supported. Exec returns the command's status.

Private-state deletion is ordinary filesystem deletion, not guaranteed secure
erasure of SSD/snapshot/backup copies. Host administrators can inspect state.
Writable project files can carry secrets or malicious code between sessions.
This is a shared-kernel development boundary, not a VM-equivalent sandbox for
hostile workloads.

See [cleanup/uninstall](docs/CLEANUP.md) for significant system changes and
their reversal. Same-VM tests exercise real tunnels but do not establish a
distinct public VPN egress IP or public-internet VPN transport/MTU behavior
for WireGuard and OpenVPN. The Tailscale backend was additionally run once
over the public internet against a remote control server and exit node; see
[executed results](docs/RESULTS.md), which also list what is not established.
A single-node check against Tailscale's hosted service is recorded there too.
