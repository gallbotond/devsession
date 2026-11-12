#!/bin/sh
# Install devsession system-wide (root-owned copy under /usr/local).
# Missing prerequisites are installed with the system package manager
# (apt-get). Pass --no-install to only report what is missing.
set -eu
cd "$(dirname "$0")"
install_missing=1
for arg; do
    case $arg in
        --no-install) install_missing=0 ;;
        -h|--help) echo "Usage: ./install.sh [--no-install]"; exit 0 ;;
        *) echo "Unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done
if [ "$(id -u)" != 0 ]; then exec sudo -- "$0" "$@"; fi

# command:package, Debian/Ubuntu package names.
REQUIRED="python3:python3 bwrap:bubblewrap ip:iproute2 nft:nftables nsenter:util-linux setpriv:util-linux wg:wireguard-tools openvpn:openvpn"
missing() {
    pkgs=
    for pair in $REQUIRED; do
        command -v "${pair%%:*}" >/dev/null 2>&1 && continue
        case " $pkgs " in *" ${pair#*:} "*) ;; *) pkgs="$pkgs ${pair#*:}" ;; esac
    done
    echo $pkgs
}
need=$(missing)
if [ -n "$need" ]; then
    if [ "$install_missing" = 0 ]; then
        echo "Missing prerequisites. Install: $need" >&2; exit 1
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "Missing prerequisites and no apt-get on this system. Install the equivalents of: $need" >&2; exit 1
    fi
    echo "Installing missing prerequisites: $need"
    export DEBIAN_FRONTEND=noninteractive
    # shellcheck disable=SC2086  # a list of package names
    apt-get install -y --no-install-recommends $need ||
        { apt-get update && apt-get install -y --no-install-recommends $need; }
    need=$(missing)
    [ -z "$need" ] || { echo "Still missing after installation: $need" >&2; exit 1; }
fi
# Versions a package manager cannot fix on an older distribution release.
bwrap --help | grep -q -- --bind-fd || { echo 'Bubblewrap >=0.11 required (--bind-fd); this distribution release is too old' >&2; exit 1; }
nsenter --help | grep -q -- --wdns || { echo 'Newer util-linux required (nsenter --wdns); this distribution release is too old' >&2; exit 1; }
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
# Optional tools are reported, never installed for you.
optional=
command -v socat >/dev/null 2>&1 || optional="$optional socat (for create --publish)"
command -v tailscaled >/dev/null 2>&1 || optional="$optional; tailscale (for the Tailscale backend)"
[ -z "$optional" ] || echo "Optional, not installed:${optional#;}"
echo 'Installed /usr/local/bin/devsession. Try devsession doctor.'
