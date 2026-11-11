#!/bin/sh
# Undo tests/remote_vm_setup.sh on the VM (run as root, public IPv4 as argument)
# and report anything that is left.
EXT=$1
D=/tmp/dvs-ts
pkill -f "$D/" 2>/dev/null; sleep 1; pkill -KILL -f "$D/" 2>/dev/null
[ -x "$D/tailscaled" ] && "$D/tailscaled" --cleanup --tun=tsdvs0 --socket="$D/peer.sock" --statedir="$D/peer" >/dev/null 2>&1
ip link del tsdvs0 2>/dev/null
ip addr del "$EXT/32" dev lo 2>/dev/null
[ -f "$D/ip_forward.before" ] && sysctl -qw net.ipv4.ip_forward="$(cat "$D/ip_forward.before")"
rm -rf "$D"
echo "left: dir=$(ls -d $D 2>/dev/null | wc -l) processes=$(pgrep -fc "$D/" || true) link=$(ip -br link | grep -c tsdvs0) lo_addr=$(ip -br addr show lo | grep -c "$EXT") ip_forward=$(cat /proc/sys/net/ipv4/ip_forward) rules52=$(ip rule | grep -c 'lookup 52') ts_chains=$( (nft list ruleset 2>/dev/null; iptables-save 2>/dev/null) | grep -c 'ts-')"
