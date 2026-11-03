# Isolation and privileges

`devsession` is a Python standard-library wrapper, not a container runtime. It
uses Bubblewrap for the empty mount tree, PID init/reaping and PID/IPC/UTS
namespaces, iproute2 network namespaces, nftables and the system VPN tools.

```
workload PID/mount/net namespace (invoking UID, zero capabilities)
  eth0 10.203.0.2 -> gateway namespace lan 10.203.0.1
                      VPN interface vpn0 -> private services / full tunnel
                      wan -> task-owned host veth -> physical network
```

Each gateway is separate from the workload. Only its privileged VPN daemon or
kernel WireGuard socket can originate transport traffic. Workload traffic is
FORWARD, never gateway OUTPUT. The forward policy accepts only `lan -> vpn0` in
VPN mode; a forced ordinary default route does not change this policy. IPv6 is
disabled and explicitly dropped. DNS servers are written into the private
`/etc/resolv.conf`; their packets take the same tunnel as any other workload
traffic. There is no host resolver socket, fallback resolver, or host network
namespace exposed. Endpoint names resolve once in the host setup helper, then
the transport exception uses a fixed IPv4/port/protocol. Reconfigure to refresh
a changed endpoint address.

Policies are installed before workloads start. On shutdown, workload processes
die before policies are removed. On failure/reconnect, a surviving gateway
keeps the forward policy. If the gateway itself dies, the workload loses its
link rather than gaining a host route. Both VPNs use full-tunnel IPv4; IPv6 is
blocked, not tunneled. OpenVPN uses persistent TUN and native redirect-gateway
routes; no supplied hooks run.

## Root boundary

Creation/network setup/join/cleanup use sudo. This release requires an ordinary
sudo-authorized host user; **do not delegate it as a restricted sudo command**.
It is an administration tool, not a multi-tenant privileged service or a
setuid executable. The installed source is root-owned. Do not execute a
user-writable development checkout with sudo on a non-disposable host.

Workloads use the original UID/GID, no supplementary groups, no capabilities,
and `no_new_privs`. `/proc` describes only the session PID namespace. There are
no host device nodes other than Bubblewrap's minimal synthetic `/dev`, no host
`/run`, no sysfs, no host sudo policy, and no host/sibling homes. A private
`TMUX_TMPDIR` plus private `/tmp` prevents accidental host-server attachment.
No container/desktop/SSH-agent sockets are exposed. Passing an explicitly
shared socket or exporting a daemon address is a deliberate boundary extension.

All environment data crosses the privileged join stage in an anonymous fd and
is applied **after** privilege drop. It is not injected into root nsenter,
setpriv, Python or Bubblewrap, and secret values are not passed in their argv.

Bubblewrap is launched after dropping to the invoking UID, with a new user
namespace mapping that UID to itself. This avoids Ubuntu's `unpriv_bwrap`
AppArmor prohibition on child setuid without weakening that profile. Setup
pre-opens only selected mount sources; Bubblewrap receives those descriptors.
Joining uses pinned namespace/root descriptors (not a racy numeric PID alone),
and closes them before any workload executes. An unprivileged supervisor forks
into the PID namespace and forwards directed signals/status. Interactive
commands receive a fresh session-side PTY/controlling terminal with raw-byte
relay and window-size propagation; this makes Ctrl-C and shell job control
operate inside the session.

State lives under `/var/lib/devsession`, root-only metadata and VPN keys;
private mounted home/tmp/runtime directories are owned by the invoking UID.
State ancestors are root-owned 0711 (traversable, not listable), so Bubblewrap
can canonicalize mount sources; metadata/key files are 0600 and private
directories 0700. Only selected trees are mounted, never those ancestors.
The host administrator can inspect all of it. A session workload can change
its own private files, but cannot change the helper metadata or firewall.

## Host network additions

- A pair of named network namespaces and one host veth per active direct/VPN
  session. Off mode only has a workload namespace and loopback.
- An allocated transport /30 within 10.231.0.0/16 (conflicting existing host
  routes must be rejected). Inner gateway links can overlap between sessions.
- IPv4 forwarding enabled if needed; prior disabled state recorded. Explicit
  cleanup restores it only after all sessions are stopped.
- Per-session `inet ds_TAG` filter and `ip ds_TAG` NAT tables. No ruleset flush.
  Host input on the veth is blocked. Forwarding to connected/local/private/link-local/
  multicast ranges is blocked except explicitly allowed networks and the
  exact VPN endpoint transport. Host NAT matches only the allocated transport
  address. Existing administrator firewall policies can still deny traffic.
- Default routes and resolver configuration on the host are never replaced.
- Optional loopback TCP proxy listeners for explicitly published ports.

## Filesystem/tool policy

The root starts empty, **not** as a bind of `/`. Read-only `/usr` (including
`/usr/local`), merged-usr symlinks/libraries and a narrow list of `/etc`
tool-support files are shared. The exact `/etc` list is `ETC_SHARE` in the
source: certificates, loader/alternatives, locale/timezone, input/completion
and Python support. Passwd/group/hosts/nsswitch/resolver files are synthetic.
System Git/SSH/cloud auth configuration is not shared.

Approved executable installation trees may be shared read-only at their host
absolute paths. This preserves interpreters, loader paths, symlinks and data,
not merely binaries. These installation trees are assumed to contain software,
not credentials. `inspect` lists them. Never place credentials under `/usr` or
an approved tool tree. Do not approve all of `.local`, `.config`, `.cargo`,
`.ssh`, `.aws`, a host home, or a project containing credentials accidentally.

Version managers need selective installation trees, e.g. `.pyenv/versions`,
`.pyenv/shims` and the pyenv executable, `.nvm/versions/node`, rustup toolchains
and cargo executable links. State/cache and authentication directories remain
private. Symlink targets outside approved trees need a separate explicit tool
mount. Updating read-only tools from inside sessions is intentionally unsupported.
Install/update on the host, then restart sessions when changing mount topology.

Only selected project mounts are shared writable, with original numeric UID
ownership. Project-local virtualenvs should be mounted at their original path
when shebangs reference absolute paths; `/workspace` aliases alone cannot fix
those shebangs. Files changed on the host are immediately visible in sessions.

Shell startup is an explicit approved customization snapshot, not the host
`.bashrc`. The supplied Bash integration exports only named aliases/functions
from a running shell. Review for embedded secrets, sourced files, daemon/agent
access and host-only paths before import. Session-local .bashrc files are
private and may be edited normally. Unexported running-shell state cannot be
magically inherited. Other shells can be executed, but only Bash startup
integration is supplied.

## Limits

This is not a VM-equivalent hostile-workload boundary. The kernel is shared;
there are no CPU/memory/disk quotas or broad seccomp syscall restrictions.
Administrators can inspect sessions. Writable shared files can carry secrets
or malicious executable code back to the host/other sessions. Read-only tool
trees can still expose anything stored in those trees. TTY use assumes the
modern Linux default `dev.tty.legacy_tiocsti=0`; no host terminal injection
interface should be enabled. No silent host execution fallback is provided.

Docker/Podman clients requiring host sockets, GUI keyrings, desktop D-Bus,
systemd user services, hardware access, privileged debuggers and tools needing
system-wide writes require separate explicit design and are unsupported by
default. A successful version check is not universal compatibility evidence.
