#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ "$(id -u)" != 0 ]; then exec sudo -- "$0" "$@"; fi
for cmd in python3 bwrap ip nft nsenter setpriv wg openvpn; do
    command -v "$cmd" >/dev/null || { echo "Missing $cmd. Install: apt install bubblewrap iproute2 nftables util-linux wireguard-tools openvpn" >&2; exit 1; }
done
bwrap --help | grep -q -- --bind-fd || { echo 'Bubblewrap >=0.11 required (--bind-fd)' >&2; exit 1; }
nsenter --help | grep -q -- --wdns || { echo 'Newer util-linux required (nsenter --wdns)' >&2; exit 1; }
install -d -m 755 /usr/local/lib/devsession
install -m 644 devsession.py /usr/local/lib/devsession/devsession.py
install -m 755 devsession /usr/local/bin/devsession
if [ -f /etc/apparmor.d/wg ]; then
    install -m 644 examples/apparmor-wg.rules /etc/apparmor.d/local/devsession-wg
    touch /etc/apparmor.d/local/wg
    grep -q 'include if exists <local/devsession-wg>' /etc/apparmor.d/local/wg || \
        echo 'include if exists <local/devsession-wg>' >> /etc/apparmor.d/local/wg
    apparmor_parser -r /etc/apparmor.d/wg
fi
echo 'Installed /usr/local/bin/devsession. Try devsession doctor.'
