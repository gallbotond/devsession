# Cleanup and uninstall

Stop/delete desired sessions as their owning host user. Delete removes private
credentials but preserves mounted project/data paths:

```sh
devsession list
devsession delete client-a
devsession delete client-b
devsession cleanup
sudo python3 -B tests/lab.py down
```

`cleanup` recovers stopped/stale tracked sessions. It does not stop healthy
sessions. When none remain active, it restores IPv4 forwarding if this tool
originally enabled it. Check whether another application now relies on that
setting before restoring it on a shared host. The saved prior state is
`/var/lib/devsession/forwarding-before`. Default routes and resolver settings
never require restoration.

Runtime resources are named `ds<TAG>c`, `ds<TAG>g`, `ds<TAG>h`, nft tables
`inet ds_<TAG>`/`ip ds_<TAG>`, and optional
`devsession-<TAG>-<PORT>.service` transient proxy units. `inspect NAME` provides
the exact names. The helper only deletes those resources; never flush the
host firewall. Test servers use `dslab-*` namespaces and `dslab10` through
`dslab13` host veths, removed by `tests/lab.py down`.

After deleting sessions and cleaning:

```sh
sudo rm -f /usr/local/bin/devsession
sudo rm -rf /usr/local/lib/devsession
# Only after confirming all desired session data has been deleted:
sudo rm -rf /var/lib/devsession

# Remove only this tool's AppArmor include/rules, preserving other local rules:
sudo sed -i '\|^include if exists <local/devsession-wg>$|d' /etc/apparmor.d/local/wg
sudo rm -f /etc/apparmor.d/local/devsession-wg
sudo apparmor_parser -r /etc/apparmor.d/wg
```

Skip the AppArmor commands on systems without that profile. Installed package
dependencies are not removed automatically because other host applications may
use them. `install.sh` itself installs any of bubblewrap, iproute2, nftables,
util-linux, wireguard-tools, openvpn and python3 that were missing; its output
names the ones it added on your system. This task installed Bubblewrap, WireGuard tools, OpenVPN, Easy-RSA,
dnsmasq-base, Ansible, Python venv support, socat and their package dependencies;
see `INVENTORY.md`. Package installation also enabled the distribution's
OpenVPN service and PC/SC socket dependency (no host VPN profile was started).
If no other application needs them, disable/remove those packages using apt;
do not remove existing tmux/curl/tcpdump/bash-completion installations.

Task-installed standalone tool cleanup, if no longer wanted:

```sh
sudo rm -f /usr/local/bin/terraform /usr/local/bin/oh-my-posh /usr/local/bin/az
sudo rm -rf /opt/devsession-tools/azure
# nvm was absent before this task; remove only if still task-owned:
rm -rf "$HOME/.nvm"
sudo rm -rf /tmp/opencode/devsession-lab
sudo rm -f /tmp/opencode/acc-*-transport.pcap /tmp/opencode/acc-*-tcpdump.log
```

Generated test PKI and packet captures are local evidence, not required at
runtime. Downloads under `/tmp/opencode` can be removed individually after
inspection. Keep the source repository and test reports if desired. No host
shell startup files, SSH keys, host default routes or host DNS configuration
were intentionally modified.

## Scripting checks

The `scripting` acceptance group creates and removes the sessions `scr-a`,
`scr-b`, `script-sh` and `script-py`, a throwaway host user and one sudoers
file. They are removed by the run itself; after an interrupted run:

```sh
for s in scr-a scr-b script-sh script-py; do devsession delete --if-exists "$s"; done
sudo pkill -KILL -u dvs-pwtest; sudo userdel -r dvs-pwtest
sudo rm -f /etc/sudoers.d/dvs-pwtest
```

## Directory activation

Approvals are per user, outside any project tree. To forget all of them, and
to remove the shell integration:

```sh
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/devsession"
# delete the line  eval "$(devsession hook bash)"  from ~/.bashrc
```

`.devsession` marker files belong to their projects and are left alone. The
`activation` acceptance group uses sessions `act-a`/`act-b` and a temporary
directory `/tmp/devsession-activation-*` that also holds its approval store;
after an interrupted run delete those sessions and that directory.

## Tailscale

A session's node state (`STATE/tailscale`), auth key (`STATE/vpn/authkey`)
and daemon are removed by `stop`/`delete` like any other session resource;
`delete` first logs the node out of its tailnet. If that was skipped or
failed, remove the node in the tailnet's admin interface (or let its key
expire). Nothing is installed into the host's tailscaled, `/etc` or
systemd-resolved, so there is nothing to restore there.

The `tailscale` acceptance group uses sessions `ts-a ts-n ts-x ts-o ts-p ts-w
ts-v`, namespaces `dslab-hs`/`dslab-ts`, host links `dslab20`/`dslab21` and
files under `/tmp/opencode/devsession-lab`; `sudo python3 -B tests/lab.py
down` removes the fixtures. The headscale binary under `/tmp/opencode/hs` and
captures `/tmp/opencode/ts-*-transport.pcap` are kept as evidence and can be
deleted. After an interrupted run:

```sh
for s in ts-a ts-n ts-x ts-o ts-p ts-w ts-v ts-vm; do devsession delete --if-exists --no-logout "$s"; done
sudo python3 -B tests/lab.py down; devsession cleanup
```

The real-internet run leaves nothing on the test host beyond that. On the
remote machine run `tests/remote_vm_cleanup.sh PUBLIC_IP` as root, then close
the firewall rules and release any address opened for it.

The legacy session `prototype` (`/var/lib/devsession/prototype`) predates
this work and is deliberately left in place as the state-migration check.
