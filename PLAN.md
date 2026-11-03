# Implementation progress

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
