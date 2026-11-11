# Implementation progress

Three follow-on features are tracked at the end of this file (scripting,
directory activation, Tailscale). Resume at the first unticked item there.

## Original build (done)

- [x] Inventory host and verify root/network/mount/PID namespace capabilities.
- [x] Research Bubblewrap, WireGuard namespace semantics and OpenVPN configuration controls.
- [x] Gate: prototype host tools + reviewed shell customization, private credentials, real WireGuard/DNS and fail-closed packet checks.
- [x] Build lifecycle, environment, filesystem and network CLI on proven prototype.
- [x] Add OpenVPN and disposable overlapping-network test infrastructure.
- [x] Execute acceptance checks; fix failures; record exact results and limitations.
- [x] Finish installation, usage, architecture and cleanup documentation.

Decision: Bubblewrap provides filesystem/PID/IPC/UTS isolation using host
installations, iproute2 provides persistent network namespaces, nftables provides
scoped forwarding policy, and existing WireGuard/OpenVPN provide tunnels. A
gateway namespace is separate from the workload namespace, so transport exceptions
are never available to workload-generated traffic. Root controls setup and
metadata; workloads use the invoking UID with no capabilities/no-new-privileges.

Prototype revision: Ubuntu's AppArmor child profile denies post-Bubblewrap
setuid. Drop UID before Bubblewrap and let its user namespace preserve the
original UID instead. The root-owned state ancestors are execute-only (0711),
files 0600 and private homes 0700. A narrow local WireGuard AppArmor read rule
permits task-owned config locations. No global AppArmor policy is disabled.
Gate passed with a real WireGuard handshake, private DNS/HTTP, gateway identity,
forced tunnel deletion plus restored raw default route, zero captured bypass
packets, nft forwarding-drop counters and unchanged host default route/resolver.

Rootless Podman/pasta/slirp are mature for ordinary container networking, but do
not solve host installation continuity or privileged VPN routing policy by
themselves. An OCI rootfs assembled from host paths adds unnecessary machinery.
Raw mount/pivot_root/PID-init implementation would duplicate Bubblewrap.

Sources consulted:
- https://github.com/containers/bubblewrap (README, isolation and limitations)
- https://www.wireguard.com/netns/
- https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html
- https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md

Podman's rootless tutorial confirms pasta's user-mode transport, explicit
keep-id support and installation/config/credential paths. Those are useful
mature mechanisms, but selecting them would still require building a host
installation rootfs and a separate protected VPN transport policy. No claim
is made that rootless Podman cannot run VPNs; this task chose the smaller
host-filesystem-oriented Bubblewrap layer and a privileged network setup.

## Follow-on features (2026-11-11 onward)

Strict order: scripting support, then directory activation, then Tailscale.
The governing prompt is `docs/AUTONOMOUS_SESSION_PROMPT.md` (untracked copy in
the checkout). Design rationales go to `docs/ARCHITECTURE.md`.

Baseline before any change (2026-11-11, commit 9268a42, this host): parser unit
tests 4 passed; `tests/acceptance.py` 14 check groups passed, 0 failed; host
left clean. Known pre-existing gap: the legacy `prototype` session
(`/var/lib/devsession/prototype`, written by `tests/prototype.py` before state
directories were UID-prefixed) is shown by `list` but `inspect prototype`
answers "No session". It is the migration check: read-only commands must load
it and must leave its files byte-identical.

### Feature 1: scripting support (done 2026-11-11, version 0.2.0)

- [x] Reserved exit codes 120-125 for devsession, command status passed through; `--status-file` attribution
- [x] Non-interactive privilege: `sudo -n` probe, exit 123, `--non-interactive`, direct-root `--user`
- [x] Bounded lock wait (`--wait`, exit 124); lock-free read-only queries
- [x] `--json` for list/create/doctor/status/lifecycle results and errors; `status`/`exists` by exit code
- [x] Idempotent forms: `create --ensure`, `stop|delete --if-exists`, no-op `net set`
- [x] `exec --cwd/--env/--env-file/-t/-T/--no-start`; SIGPIPE reset; 126/127 for unrunnable commands
- [x] Legacy state (`prototype`) loads in list/inspect/status and is never rewritten by read/recovery paths
- [x] `examples/scripting.sh`, `examples/scripting.py`, `examples/devsession_client.py`
- [x] Acceptance group `scripting` (S1-S8, `tests/accept_scripting.py`): 22 groups passed in total, 0 failed
- [x] Docs (README, ARCHITECTURE, TESTING, CLEANUP, RESULTS), installed copy matches source, pushed

Result: unit tests 9 passed; acceptance 22 groups passed, 0 failed; no
leftovers (namespaces, nft tables, throwaway user, sudoers file). Not
established: see "Not established (feature 1)" in `docs/RESULTS.md`.

### Feature 2: directory activation

- [ ] Not started

### Feature 3: Tailscale

- [ ] Not started
