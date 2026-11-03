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
NAMES = ['dslab-a', 'dslab-b', 'dslab-o', 'dslab-direct']


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
    for i in [10, 11, 12, 13]:
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


def up(openvpn=False):
    cleanup()
    LAB.mkdir(mode=0o700, parents=True, exist_ok=True)
    ds.write(LAB / 'http.py', HTTP)
    info = {'a': wg('dslab-a', 10, 'a'), 'b': wg('dslab-b', 11, 'b')}
    link('dslab-direct', 12)
    spawn('dslab-direct', ['python3', '-I', str(LAB / 'http.py'), '198.18.12.2', 'direct'], 'direct')
    if openvpn:
        ovpn()
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


if __name__ == '__main__':
    if sys.argv[1:] == ['down']:
        cleanup()
    else:
        up(openvpn=True)
        print(LAB)
