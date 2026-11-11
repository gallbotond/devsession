"""Disposable real VPN servers, separate from all client/gateway namespaces."""
import contextlib
import json
import os
from pathlib import Path
import subprocess as sp
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import devsession as ds

LAB = Path('/tmp/opencode/devsession-lab')
NAMES = ['dslab-a', 'dslab-b', 'dslab-o', 'dslab-direct', 'dslab-hs', 'dslab-ts']
# Test prerequisite (docs/TESTING.md): the headscale release binary, not part of the runtime.
HEADSCALE = Path(os.environ.get('HEADSCALE', '/tmp/opencode/hs/headscale'))
HS_URL = 'https://198.18.20.2:8443'


def r(*args, ns=None, input=None, check=True):
    return ds.run(args, ns=ns, input=input, check=check).stdout.strip()


def spawn(ns, args, label):
    with open(LAB / (label + '.log'), 'w') as log:
        return sp.Popen(['ip', 'netns', 'exec', ns] + args, stdin=sp.DEVNULL,
                        stdout=log, stderr=log, start_new_session=True)


def cleanup():
    for ns in NAMES:
        for pid in r('ip', 'netns', 'pids', ns, check=False).split():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pid), 9)
        r('ip', 'netns', 'del', ns, check=False)
    for i in [10, 11, 12, 13, 20, 21]:
        r('ip', 'link', 'del', f'dslab{i}', check=False)


def link(ns, i):
    r('ip', 'netns', 'add', ns)
    r('ip', 'link', 'add', f'dslab{i}', 'type', 'veth', 'peer', 'name', 'uplink', 'netns', ns)
    r('ip', 'addr', 'add', f'198.18.{i}.1/30', 'dev', f'dslab{i}')
    r('ip', 'link', 'set', f'dslab{i}', 'up')
    r('ip', '-n', ns, 'addr', 'add', f'198.18.{i}.2/30', 'dev', 'uplink')
    r('ip', '-n', ns, 'link', 'set', 'uplink', 'up')
    r('ip', '-n', ns, 'link', 'set', 'lo', 'up')
    r('ip', '-n', ns, 'route', 'add', 'default', 'via', f'198.18.{i}.1')
    r('sysctl', '-qw', 'net.ipv4.ip_forward=1', ns=ns)


HTTP = '''import http.server,json,sys
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  data=json.dumps({'server':sys.argv[2],'source':self.client_address[0]}).encode()
  self.send_response(200); self.end_headers(); self.wfile.write(data)
http.server.HTTPServer((sys.argv[1],8080),Handler).serve_forever()
'''


def services(ns, label):
    spawn(ns, ['python3', '-I', str(LAB / 'http.py'), '10.77.0.1', label], label + '-http')
    spawn(ns, ['dnsmasq', '--no-daemon', '--no-resolv', '--no-hosts', '--bind-interfaces',
               '--listen-address=10.77.0.1', '--address=/vpn.test/10.77.0.1',
               '--user=root', '--pid-file='], label + '-dns')


def wg(ns, i, label):
    link(ns, i)
    server = r('wg', 'genkey')
    client = r('wg', 'genkey')
    pubserver = r('wg', 'pubkey', input=server)
    pubclient = r('wg', 'pubkey', input=client)
    ds.write(LAB / (label + '-server.key'), server + '\n')
    r('ip', '-n', ns, 'link', 'add', 'wg0', 'type', 'wireguard')
    r('wg', 'set', 'wg0', 'private-key', LAB / (label + '-server.key'), 'listen-port', '51820',
      'peer', pubclient, 'allowed-ips', '10.77.0.2/32', ns=ns)
    r('ip', '-n', ns, 'addr', 'add', '10.77.0.1/24', 'dev', 'wg0')
    r('ip', '-n', ns, 'link', 'set', 'wg0', 'up')
    r('nft', '-f', '-', ns=ns, input='''table ip lab { chain post { type nat hook postrouting priority srcnat; policy accept; oifname "uplink" ip saddr 10.77.0.0/24 masquerade; }\n}\n''')
    services(ns, label)
    ds.write(LAB / (label + '.conf'), f'''[Interface]
PrivateKey = {client}
Address = 10.77.0.2/24
DNS = 10.77.0.1
MTU = 1380
[Peer]
PublicKey = {pubserver}
Endpoint = 198.18.{i}.2:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 1
''')
    return {'kind': 'wireguard', 'endpoint': f'198.18.{i}.2', 'port': 51820,
            'addresses': ['10.77.0.2/24'], 'dns': ['10.77.0.1'],
            'raw': f'[Interface]\nPrivateKey = {client}\n[Peer]\nPublicKey = {pubserver}\nEndpoint = 198.18.{i}.2:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 1\n'}


def up(openvpn=False, tailscale=False):
    cleanup()
    LAB.mkdir(mode=0o700, parents=True, exist_ok=True)
    ds.write(LAB / 'http.py', HTTP)
    info = {'a': wg('dslab-a', 10, 'a'), 'b': wg('dslab-b', 11, 'b')}
    link('dslab-direct', 12)
    spawn('dslab-direct', ['python3', '-I', str(LAB / 'http.py'), '198.18.12.2', 'direct'], 'direct')
    if openvpn:
        ovpn()
    if tailscale:
        info['tailnet'] = tailnet()
    ds.write(LAB / 'info.json', json.dumps(info))
    time.sleep(.3)
    return info


def ovpn():
    """TLS PKI, no static-key shortcut. Certificates generated locally."""
    ns = 'dslab-o'
    link(ns, 13)
    pki = LAB / 'pki'
    if pki.exists():
        import shutil
        shutil.rmtree(pki)
    env = {'PATH': ds.SYSTEM_PATH, 'EASYRSA_PKI': str(pki), 'EASYRSA_BATCH': '1',
           'EASYRSA_ALGO': 'ec', 'EASYRSA_CURVE': 'prime256v1', 'EASYRSA_REQ_CN': 'devsession-lab'}
    for args in [['init-pki'], ['build-ca', 'nopass'], ['build-server-full', 'server', 'nopass'],
                 ['build-client-full', 'client', 'nopass']]:
        ds.run(['/usr/share/easy-rsa/easyrsa'] + args, env=env)
    ds.write(LAB / 'server.ovpn', f'''dev tun
proto udp4
port 1194
server 10.77.0.0 255.255.255.0
topology subnet
ca {pki}/ca.crt
cert {pki}/issued/server.crt
key {pki}/private/server.key
dh none
keepalive 1 5
data-ciphers AES-256-GCM:AES-128-GCM
disable-dco
verb 3
''')
    spawn(ns, ['openvpn', '--config', str(LAB / 'server.ovpn')], 'openvpn-server')
    for _ in range(100):
        if '10.77.0.1' in r('ip', '-n', ns, 'addr'):
            break
        time.sleep(.1)
    else:
        raise RuntimeError('OpenVPN server failed: ' + (LAB / 'openvpn-server.log').read_text())
    r('nft', '-f', '-', ns=ns, input='''table ip lab { chain post { type nat hook postrouting priority srcnat; policy accept; oifname "uplink" ip saddr 10.77.0.0/24 masquerade; }\n}\n''')
    services(ns, 'openvpn')
    ds.write(LAB / 'client.ovpn', f'''client
dev tun
proto udp
remote 198.18.13.2 1194
nobind
ca {pki}/ca.crt
cert {pki}/issued/client.crt
key {pki}/private/client.key
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM
persist-key
persist-tun
verb 3
''')


def hs(*args):
    """headscale CLI against the lab server's own socket; JSON output."""
    return json.loads(r(HEADSCALE, '-c', LAB / 'hs' / 'config.yaml', '-o', 'json', *args) or 'null')


PEER = dict(state=str(LAB / 'peer'), netns='dslab-ts', tag='labpeer',
            vpn=dict(kind='tailscale', pin=None, port=41641))


def tailnet():
    """A private tailnet: headscale (control, embedded DERP relay and STUN, TLS
    from a lab CA) in dslab-hs and an ordinary tailscaled peer in dslab-ts.
    Every key and certificate is generated here; nothing touches the host's
    tailscaled or any hosted service."""
    import shutil
    if not HEADSCALE.is_file():
        raise RuntimeError(f'headscale binary not found at {HEADSCALE}; see docs/TESTING.md')
    link('dslab-hs', 20)
    link('dslab-ts', 21)
    # The peer reaches control/relay over a lab-internal link, so the fixture
    # does not depend on (or switch on) IPv4 forwarding in the host namespace.
    r('ip', '-n', 'dslab-hs', 'link', 'add', 'peer', 'type', 'veth', 'peer', 'name', 'control', 'netns', 'dslab-ts')
    r('ip', '-n', 'dslab-hs', 'addr', 'add', '198.18.22.1/30', 'dev', 'peer')
    r('ip', '-n', 'dslab-ts', 'addr', 'add', '198.18.22.2/30', 'dev', 'control')
    r('ip', '-n', 'dslab-hs', 'link', 'set', 'peer', 'up')
    r('ip', '-n', 'dslab-ts', 'link', 'set', 'control', 'up')
    r('ip', '-n', 'dslab-ts', 'route', 'add', '198.18.20.2/32', 'via', '198.18.22.1')
    r('sysctl', '-qw', 'net.ipv6.conf.all.forwarding=1', ns='dslab-ts')
    d = LAB / 'hs'
    shutil.rmtree(d, ignore_errors=True); shutil.rmtree(LAB / 'peer', ignore_errors=True)
    d.mkdir(mode=0o700)
    ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes']
    r('openssl', 'req', '-x509', *ec, '-keyout', d / 'ca.key', '-out', d / 'ca.crt', '-days', '3',
      '-subj', '/CN=devsession lab CA', '-addext', 'basicConstraints=critical,CA:TRUE')
    r('openssl', 'req', *ec, '-keyout', d / 'server.key', '-out', d / 'server.csr', '-subj', '/CN=198.18.20.2')
    ds.write(d / 'san.cnf', 'subjectAltName=IP:198.18.20.2\nextendedKeyUsage=serverAuth\n')
    r('openssl', 'x509', '-req', '-in', d / 'server.csr', '-CA', d / 'ca.crt', '-CAkey', d / 'ca.key',
      '-CAcreateserial', '-out', d / 'server.crt', '-days', '3', '-extfile', d / 'san.cnf')
    ds.write(d / 'config.yaml', f"""server_url: {HS_URL}
listen_addr: 198.18.20.2:8443
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
tls_cert_path: {d}/server.crt
tls_key_path: {d}/server.key
noise:
  private_key_path: {d}/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: lab
    region_name: devsession lab
    verify_clients: true
    stun_listen_addr: 198.18.20.2:3478
    private_key_path: {d}/derp_private.key
    automatically_add_embedded_derp_region: true
    ipv4: 198.18.20.2
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: {d}/db.sqlite
    write_ahead_log: true
log:
  level: info
policy:
  mode: file
  path: ""
dns:
  magic_dns: true
  base_domain: lab.devsession.test
  override_local_dns: false
  nameservers:
    global: []
    split:
      vpn.test:
        - 100.64.0.1
  search_domains: []
  extra_records: []
unix_socket: {d}/headscale.sock
unix_socket_permission: "0700"
logtail:
  enabled: false
""")
    server = spawn('dslab-hs', [str(HEADSCALE), 'serve', '-c', str(d / 'config.yaml')], 'headscale')
    for _ in range(150):
        if server.poll() is not None:
            raise RuntimeError('headscale exited: ' + (LAB / 'headscale.log').read_text()[-2000:])
        if (d / 'headscale.sock').exists() and b'https' in sp.run(
                ['ip', 'netns', 'exec', 'dslab-hs', 'ss', '-ltn'], capture_output=True).stdout.replace(b':8443', b'https'):
            break
        time.sleep(.2)
    else:
        raise RuntimeError('headscale did not start: ' + (LAB / 'headscale.log').read_text()[-2000:])
    hs('users', 'create', 'lab')
    user = str(hs('users', 'list')[0]['id'])
    ds.write(LAB / 'ts-ca.crt', (d / 'ca.crt').read_text(), 0o644)
    ds.write(LAB / 'ts-authkey', authkey(reusable=True) + '\n')
    # The peer: an ordinary node offering an exit node and one subnet route.
    (LAB / 'peer' / 'vpn').mkdir(parents=True)
    ds.write(LAB / 'peer' / 'vpn' / 'ca.pem', (d / 'ca.crt').read_text())
    ds.ts_prepare(PEER)
    r('ip', '-n', 'dslab-ts', 'link', 'add', 'svc0', 'type', 'dummy')
    r('ip', '-n', 'dslab-ts', 'addr', 'add', '10.78.0.1/24', 'dev', 'svc0')
    r('ip', '-n', 'dslab-ts', 'link', 'set', 'svc0', 'up')
    peer_daemon()
    ds.ts(PEER, 'up', f'--login-server={HS_URL}', f'--auth-key=file:{LAB}/ts-authkey', '--hostname=lab-peer',
          '--advertise-exit-node', '--advertise-routes=10.78.0.0/24', '--accept-dns=false', '--timeout=40s', timeout=60)
    node = next(n for n in hs('nodes', 'list') if n['given_name'] == 'lab-peer')
    hs('nodes', 'approve-routes', '--identifier', str(node['id']), '--routes', '0.0.0.0/0,::/0,10.78.0.0/24')
    address = ds.ts_status(PEER)['Self']['TailscaleIPs'][0]
    if address != '100.64.0.1':
        raise RuntimeError(f'lab peer got {address}; the split-DNS fixture expects 100.64.0.1')
    spawn('dslab-ts', ['python3', '-I', str(LAB / 'http.py'), '0.0.0.0', 'tailnet'], 'tailnet-http')
    spawn('dslab-ts', ['dnsmasq', '--no-daemon', '--no-resolv', '--no-hosts', '--bind-interfaces',
                       f'--listen-address={address},127.0.0.1', f'--address=/vpn.test/{address}',
                       '--user=root', '--pid-file='], 'tailnet-dns')
    return dict(login_server=HS_URL, ca=str(LAB / 'ts-ca.crt'), authkey=str(LAB / 'ts-authkey'),
                peer='lab-peer', peer_ip=address, user=user)


def peer_daemon():
    base, etc, var, sock = ds.ts_paths(PEER)
    with open(LAB / 'peer-tailscaled.log', 'a') as log:
        sp.Popen(ds.ts_box(PEER, [ds.ts_binary('tailscaled'), '--tun=ts0', '--port=41641', f'--socket={sock}',
                                  f'--statedir={var}', f'--state={var}/tailscaled.state', '--no-logs-no-support']),
                 stdin=sp.DEVNULL, stdout=log, stderr=log, start_new_session=True,
                 env={'PATH': ds.SYSTEM_PATH, 'LANG': 'C.UTF-8'})
    for _ in range(100):
        if ds.ts_status(PEER).get('BackendState') not in (None, 'NoState'):
            return
        time.sleep(.1)
    raise RuntimeError('lab peer tailscaled failed: ' + (LAB / 'peer-tailscaled.log').read_text()[-2000:])


def authkey(reusable=False, ephemeral=False, expiration='2h'):
    user = str(hs('users', 'list')[0]['id'])
    extra = (['--reusable'] if reusable else []) + (['--ephemeral'] if ephemeral else [])
    return hs('preauthkeys', 'create', '--user', user, '--expiration', expiration, *extra)['key']


if __name__ == '__main__':
    if sys.argv[1:] == ['down']:
        cleanup()
    elif sys.argv[1:2] == ['hs']:      # headscale CLI passthrough for tests: lab.py hs nodes list
        print(json.dumps(hs(*sys.argv[2:])))
    elif sys.argv[1:2] == ['authkey']:  # lab.py authkey [reusable] [ephemeral]
        print(authkey('reusable' in sys.argv, 'ephemeral' in sys.argv))
    elif sys.argv[1:2] == ['peer']:    # lab.py peer TAILSCALE-ARGS...: CLI of the lab peer
        p = ds.ts(PEER, *sys.argv[2:], check=False, timeout=60)
        sys.stdout.write(p.stdout); sys.stderr.write(p.stderr); sys.exit(p.returncode)
    elif sys.argv[1:] == ['peer-daemon']:
        peer_daemon()
    elif sys.argv[1:2] == ['session']:  # lab.py session UID NAME TAILSCALE-ARGS...: a session daemon's CLI
        c = ds.load(int(sys.argv[2]), sys.argv[3])
        p = ds.ts(c, *sys.argv[4:], check=False, timeout=60)
        sys.stdout.write(p.stdout); sys.stderr.write(p.stderr); sys.exit(p.returncode)
    else:
        up(openvpn=True, tailscale='tailscale' in sys.argv)   # lab.py up [tailscale]
        print(LAB)
