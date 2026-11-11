# devsession

Persistent Linux development sessions with **your host's tools**, private
credentials/home/processes, explicitly shared projects, and isolated off,
direct, WireGuard or OpenVPN networking. No container image or per-session
tool installation.

## Install

Tested on Ubuntu 26.04, Linux 7.0, Python 3.14, Bubblewrap 0.11.1,
util-linux 2.41+, nftables, WireGuard tools and OpenVPN 2.7.

```sh
sudo apt-get install bubblewrap iproute2 nftables util-linux wireguard-tools openvpn
./install.sh
devsession doctor
```

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

Both backends require **IPv4 full tunnel**, with IPv6 explicitly blocked.
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
operations are rejected with a retry message; multiple running execs are
supported. Exec returns the command's status.

Private-state deletion is ordinary filesystem deletion, not guaranteed secure
erasure of SSD/snapshot/backup copies. Host administrators can inspect state.
Writable project files can carry secrets or malicious code between sessions.
This is a shared-kernel development boundary, not a VM-equivalent sandbox for
hostile workloads.

See [cleanup/uninstall](docs/CLEANUP.md) for significant system changes and
their reversal. Same-VM tests exercise real tunnels but do not establish a
distinct public VPN egress IP or public-internet VPN transport/MTU behavior.
