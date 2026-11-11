#!/bin/sh
# Throwaway tailnet on a remote VM for tests/remote_tailscale.py: headscale
# (control, embedded DERP relay, STUN) and one ordinary tailscaled peer that
# offers an exit node and serves a test file. Run as root ON THE VM with its
# public IPv4 as the only argument. Every key and certificate is generated
# here; nothing secret is copied to the VM. tests/remote_vm_cleanup.sh undoes it.
set -eu
EXT=$1
D=/tmp/dvs-ts
HS_SHA=e827fc9b12d958bc95b081c4401dd63f8e0471d025b45b508535a920532150a8
TS_SHA=82a85429f733e52fd1a95dedb2c8dd8cd46d6603504e566a56b1779c9a7a4809
command -v openssl >/dev/null || { apt-get -qq update && apt-get -qq install -y openssl; }
mkdir -p -m 700 "$D" "$D/www" "$D/peer"; cd "$D"
curl -fsSL -o headscale https://github.com/juanfont/headscale/releases/download/v0.29.7/headscale_0.29.7_linux_amd64
echo "$HS_SHA  headscale" | sha256sum -c - >/dev/null
curl -fsSL -o ts.tgz https://pkgs.tailscale.com/stable/tailscale_1.104.6_amd64.tgz
echo "$TS_SHA  ts.tgz" | sha256sum -c - >/dev/null
tar xzf ts.tgz --strip-components=1; chmod +x headscale
EC="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
openssl req -x509 $EC -keyout ca.key -out ca.crt -days 2 -subj "/CN=devsession remote test CA" \
    -addext basicConstraints=critical,CA:TRUE 2>/dev/null
openssl req $EC -keyout server.key -out server.csr -subj "/CN=$EXT" 2>/dev/null
printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$EXT" > san.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 -extfile san.cnf 2>/dev/null
cat /etc/ssl/certs/ca-certificates.crt ca.crt > bundle.crt
cat > config.yaml <<CONFIG
server_url: https://$EXT:8443
listen_addr: 0.0.0.0:8443
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
tls_cert_path: $D/server.crt
tls_key_path: $D/server.key
noise:
  private_key_path: $D/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: vm
    region_name: devsession remote test
    verify_clients: true
    stun_listen_addr: 0.0.0.0:3478
    private_key_path: $D/derp_private.key
    automatically_add_embedded_derp_region: true
    ipv4: $EXT
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: $D/db.sqlite
    write_ahead_log: true
log:
  level: info
policy:
  mode: file
  path: ""
dns:
  magic_dns: true
  base_domain: vm.devsession.test
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []
unix_socket: $D/headscale.sock
unix_socket_permission: "0700"
logtail:
  enabled: false
CONFIG
# The peer on this same machine reaches control and relay at the public
# address without leaving the machine.
ip addr add "$EXT/32" dev lo
cat /proc/sys/net/ipv4/ip_forward > ip_forward.before
sysctl -qw net.ipv4.ip_forward=1
setsid nohup "$D/headscale" serve -c "$D/config.yaml" > headscale.log 2>&1 < /dev/null &
i=0; until [ -S headscale.sock ] && ss -ltn | grep -q ':8443 '; do i=$((i+1)); [ $i -lt 100 ] || { tail headscale.log; exit 1; }; sleep 0.2; done
hs() { "$D/headscale" -c "$D/config.yaml" -o json "$@"; }
hs users create vm >/dev/null
key() { hs preauthkeys create --user 1 --expiration 2h "$@" | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])'; }
(umask 077; key > peer.key; key --reusable > client.key)
SSL_CERT_FILE=$D/bundle.crt setsid nohup "$D/tailscaled" --tun=tsdvs0 --port=41641 --socket="$D/peer.sock" \
    --statedir="$D/peer" --state="$D/peer/tailscaled.state" --no-logs-no-support > peer.log 2>&1 < /dev/null &
i=0; until [ -S peer.sock ]; do i=$((i+1)); [ $i -lt 100 ] || { tail peer.log; exit 1; }; sleep 0.2; done
ts() { "$D/tailscale" --socket="$D/peer.sock" "$@"; }
ts up --login-server="https://$EXT:8443" --auth-key="file:$D/peer.key" --hostname=vm-peer \
    --advertise-exit-node --accept-dns=false --timeout=60s
hs nodes approve-routes --identifier 1 --routes 0.0.0.0/0,::/0 >/dev/null
PEER=$(ts ip -4)
head -c 20971520 /dev/urandom > www/blob
setsid nohup python3 -m http.server 8080 --bind "$PEER" --directory "$D/www" > http.log 2>&1 < /dev/null &
echo "PEER_IP=$PEER"
echo "BLOB_SHA256=$(sha256sum www/blob | cut -d' ' -f1)"
echo "CLIENT_KEY=$(cat client.key)"
echo "-----CA-----"; cat ca.crt
