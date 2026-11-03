# Initial host inventory (2026-11-03)

Ubuntu 26.04.1, Linux 7.0.0-38-generic, amd64. User ubuntu, UID/GID 1000.
Passwordless sudo available. `sudo unshare --mount --net --pid --fork
--mount-proc` succeeded. Seccomp disabled in the outer VM. Rootless user/network
namespace creation also succeeded when tested via sudo.

No existing project repository or AGENTS.md under /home. New repository:
`/home/ubuntu/devsession`.

Initial PATH:
`/home/ubuntu/.opencode/bin:/home/ubuntu/.opencode/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin`

- tmux: `/usr/bin/tmux`, preinstalled.
- Python/system tools: `/usr/bin`, supporting `/usr/lib`, `/usr/share`, merged-usr libraries.
- OpenCode: `/home/ubuntu/.opencode/bin/opencode`, wrapper `opencode2`.
  Installation can be shared read-only; host OpenCode auth/config is deliberately absent.
- Terraform, Ansible, oh-my-posh, Azure CLI: absent initially; installed for this task.
- No ~/.local/bin, pyenv, nvm, asdf, mise, rustup or cargo installation initially.
- No project virtual environment initially. Acceptance tests add dedicated
  user-local, version-managed and project-venv fixtures, identified as fixtures.
- Bash `/bin/bash`; stock Ubuntu .bashrc with color prompt, ll/la/l and grep
  aliases, bash-completion, optional ~/.bash_aliases and OpenCode PATH addition.
  The original file is not automatically sourced: optional sourced files and
  exported values require review. A separate approved customization file is used.
- Host ~/.ssh and ~/.config exist and are private, not tooling mounts.

Host default route initially via 192.168.1.1 on ens18; resolver is systemd-resolved
stub through `/etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf`.
Initial nftables ruleset empty. Tests must compare routes and resolver bytes.

## Installed for this task

Ubuntu archive packages (apt signature verification):
Bubblewrap 0.11.1-1ubuntu0.3; wireguard-tools 1.0.20250521-1ubuntu1;
OpenVPN 2.7.0-1ubuntu1.4; Easy-RSA 3.2.5-1; dnsmasq-base 2.92-1ubuntu0.5;
Ansible 13.1.0 / ansible-core 2.20.1; python3-venv 3.14.3-0ubuntu2;
socat 1.8.1.1-1ubuntu0.1 and dependencies. Existing util-linux is 2.41.3,
nftables 1.1.6; existing tmux reports 3.6 (package 3.6a-2ubuntu0.2).
curl, jq, tcpdump and bash-completion were already installed.

The first apt command hit the harness timeout during the large Ansible unpack.
The surviving dpkg process completed; `dpkg --configure -a` and apt repair
finished installation. **No package lock was deleted.** Final `dpkg --audit`
was empty. A PC/SC dependency service initially failed to start; it is unrelated
to sessions. Package scripts enabled pcscd.socket and openvpn.service. No host
OpenVPN client configuration was installed. No reboot was performed despite
the distribution's pending-kernel message, preserving the management connection.

Standalone host installations:

| Tool | Version | Location and source |
|---|---|---|
| Terraform | 1.17.1 | `/usr/local/bin/terraform`, official releases.hashicorp.com Linux amd64 ZIP |
| oh-my-posh | 31.9.1 | `/usr/local/bin/oh-my-posh`, official JanDeDobbeleer GitHub release |
| Azure CLI | 2.92.0 | `/opt/devsession-tools/azure` Python venv, `/usr/local/bin/az` symlink; PyPI azure-cli |
| nvm | 0.40.3 | `~/.nvm`, official nvm-sh/nvm tag; no host startup file changed |
| Node / npm | 26.13.0 / 11.20.0 | `~/.nvm/versions/node/v26.13.0`, official nodejs.org download via nvm |

Terraform ZIP SHA256 (matched official SHA256SUMS over HTTPS):
`4638628058e71a55212b1c563712eac03b902128f40740f3dc8174df12135061`.
oh-my-posh binary SHA256 (matched release checksums.txt over HTTPS):
`574074a4e84797180e0bda0d133da5f01fbda89ecdb450134c7e566b9a389212`.
Release signatures were not separately validated. nvm checkout commit:
`977563e97ddc66facf3a8e31c6cff01d236f09bd`; nvm reported Node SHA256 matched.
Azure bootstrap used `https://bootstrap.pypa.io/get-pip.py` inside the dedicated
venv, then PyPI package resolution over HTTPS. The long install command timed
out after writing packages, before making the symlink; the symlink was added
separately. `pip check` reported no broken requirements and `az version` ran
inside a session. No per-session reinstall was done.

Additional policy/system changes:
- Installed root-owned CLI at `/usr/local/bin/devsession` and implementation at
  `/usr/local/lib/devsession/devsession.py`.
- Root-owned `/var/lib/devsession` metadata; mode 0711 ancestors, 0600 config/VPN
  files and 0700 user-owned private homes. Modes permit Bubblewrap's path
  canonicalization without exposing whole directories in session mounts.
- Narrow `/etc/apparmor.d/local/devsession-wg` include from `local/wg`, allowing
  WireGuard to read task-owned configuration files. The prototype's temporary
  duplicate inline rules were removed after installing the include.
- Temporary scoped namespaces/veths/nft tables, loopback proxy services and
  IPv4 forwarding, as described in ARCHITECTURE.md. Forwarding restoration is
  recorded by the CLI. No host default-route/resolver edits.
- `.local/bin` was created for a user-local fixture; fixture executable is
  removed after testing. Tests use a temporary project venv and remove it.
- Real nvm/Node installation remains available for host use; it is not a fake
  version-manager fixture. Other managers (pyenv/asdf/mise/rustup) were absent
  and their toolchains were not independently exercised.

Resolved-path/version comparison is in `../tests/tool-results.json`.
Representative tasks include Terraform local apply/output, Ansible localhost
ping, Node evaluation, project-venv script, private tmux command, and Bash
completion/function/prompt execution. This does not establish compatibility
for every command or plugin of those tools. OpenCode's installation tree is
available, but its host authentication is intentionally absent; authenticated
OpenCode use inside a session requires independent credentials and was not tested.

## Repository publication

At the user's request, installed Ubuntu's `gh` package (2.46.0-4) to publish
this source to a private GitHub repository using the host's existing GitHub
CLI login. Authentication files, real VPN profiles and generated VPN keys are
outside this repository and are not included. Remove the optional publishing
prerequisite with `sudo apt-get remove gh` if it is no longer needed.
