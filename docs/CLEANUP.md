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
use them. This task installed Bubblewrap, WireGuard tools, OpenVPN, Easy-RSA,
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
