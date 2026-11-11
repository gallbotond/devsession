#!/usr/bin/python3
"""Host-tool development sessions. Root setup; unprivileged workloads."""
import argparse
import base64
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import socket
import subprocess as sp
import sys
import time

ROOT = Path('/var/lib/devsession')
SYSTEM_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
BLOCKED = '0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 192.0.0.0/24, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4'


VERSION = '0.4.0'
# Exit statuses reserved for devsession itself. exec/shell pass the command's
# own status through unchanged; 126/127/128+N keep their shell meaning.
EXIT_ERROR, EXIT_USAGE, EXIT_NOSESSION, EXIT_PRIVILEGE, EXIT_BUSY, EXIT_CONFLICT = 120, 121, 122, 123, 124, 125
EXIT_UNAPPROVED = 119
KINDS = {EXIT_UNAPPROVED: 'unapproved', EXIT_ERROR: 'error', EXIT_USAGE: 'usage', EXIT_NOSESSION: 'no-such-session',
         EXIT_PRIVILEGE: 'privilege', EXIT_BUSY: 'busy', EXIT_CONFLICT: 'conflict'}
EXIT_CODES = {'0': 'success; exec/shell: the command exited 0',
              '1': 'exists: no such session; resolve: no marker; doctor: a required prerequisite is missing',
              '3': 'status: the session exists but is stopped',
              '119': 'the directory marker is not approved, or changed after approval',
              '120': 'devsession failed (operation error)',
              '121': 'usage error',
              '122': 'no such session',
              '123': 'root privilege unavailable without a prompt',
              '124': 'state lock busy for longer than --wait',
              '125': 'conflict with existing state (exists, running, differs)',
              '126': 'exec: command found but not executable',
              '127': 'exec: command not found',
              '128+N': 'exec/shell: command killed by signal N',
              'other': 'exec/shell: the command\'s own exit status'}
OUT = {'json': False, 'quiet': False, 'status_file': None, 'hook_file': None, 'owner': None}


class Error(Exception):
    code = EXIT_ERROR

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as e:
        raise Error(f'Expected IPv4 address: {value}') from e


def endpoint(host):
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    except OSError as e:
        raise Error(f'Cannot resolve VPN endpoint {host}: {e}') from e


def wireguard_import(source, dest, dns=None):
    sections = {'Interface': {}, 'Peer': {}}
    section = None
    seen = set()
    allowed = {'Interface': {'PrivateKey', 'Address', 'DNS', 'MTU'},
               'Peer': {'PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'}}
    for line in Path(source).read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            if section not in sections or section in seen:
                raise Error('WireGuard requires exactly one [Interface] and one [Peer]')
            seen.add(section)
            continue
        if section is None or '=' not in line:
            raise Error('Malformed WireGuard configuration')
        k, v = [x.strip() for x in line.split('=', 1)]
        if k not in allowed[section] or k in sections[section]:
            raise Error(f'Unsupported/duplicate WireGuard directive: {k}; hooks are never executed')
        sections[section][k] = v
    a, p = sections['Interface'], sections['Peer']
    if not {'PrivateKey', 'Address'} <= a.keys() or not {'PublicKey', 'Endpoint', 'AllowedIPs'} <= p.keys():
        raise Error('WireGuard needs PrivateKey, Address, PublicKey, Endpoint and AllowedIPs')
    if '0.0.0.0/0' not in [x.strip() for x in p['AllowedIPs'].split(',')]:
        raise Error('Only full-tunnel WireGuard AllowedIPs including 0.0.0.0/0 is supported')
    for key, value in [('PrivateKey', a['PrivateKey']), ('PublicKey', p['PublicKey'])] + (
            [('PresharedKey', p['PresharedKey'])] if 'PresharedKey' in p else []):
        try:
            valid = len(base64.b64decode(value, validate=True)) == 32
        except ValueError:
            valid = False
        if not valid:
            raise Error(f'Invalid WireGuard {key}: expected a base64-encoded 32-byte key (value redacted)')
    if 'PersistentKeepalive' in p:
        if not p['PersistentKeepalive'].isdigit() or not 0 <= int(p['PersistentKeepalive']) <= 65535:
            raise Error('Invalid WireGuard PersistentKeepalive')
    host, port = p['Endpoint'].rsplit(':', 1)
    ip, port = endpoint(host), int(port)
    if not 1 <= port <= 65535:
        raise Error('Invalid VPN port')
    addresses = [str(ipaddress.IPv4Interface(x.strip())) for x in a['Address'].split(',')]
    servers = [ipv4(x.strip()) for x in (dns or a.get('DNS', '').split(',')) if x.strip()]
    if not servers:
        raise Error('VPN requires explicit IPv4 DNS: DNS= in WireGuard or --dns ADDRESS')
    p['Endpoint'] = f'{ip}:{port}'
    p['AllowedIPs'] = '0.0.0.0/0'
    mtu = int(a.get('MTU', 1380))
    if not 576 <= mtu <= 9000:
        raise Error('Invalid MTU')
    write(dest / 'wg.conf', '[Interface]\nPrivateKey = ' + a['PrivateKey'] + '\n[Peer]\n' +
          ''.join(f'{k} = {v}\n' for k, v in p.items()))
    return dict(kind='wireguard', endpoint=ip, port=port, addresses=addresses, dns=servers, mtu=mtu)


OVPN_VALUES = {
    'remote-cert-tls': (1, 1), 'verify-x509-name': (1, 2), 'peer-fingerprint': (1, 1),
    'data-ciphers': (1, 1), 'data-ciphers-fallback': (1, 1), 'cipher': (1, 1), 'auth': (1, 1),
    'tls-version-min': (1, 1), 'tls-version-max': (1, 1), 'tls-cipher': (1, 1), 'tls-ciphersuites': (1, 1),
    'key-direction': (1, 1), 'reneg-sec': (1, 1), 'tun-mtu': (1, 1), 'mssfix': (1, 2),
    'ping': (1, 1), 'ping-restart': (1, 1), 'connect-retry': (1, 2), 'connect-timeout': (1, 1),
    'resolv-retry': (1, 1), 'verb': (1, 1), 'mute': (1, 1), 'explicit-exit-notify': (0, 1),
    'auth-nocache': (0, 0), 'persist-key': (0, 0), 'persist-tun': (0, 0), 'nobind': (0, 0),
    'client': (0, 0), 'dev': (1, 1), 'proto': (1, 1), 'remote': (1, 3),
}
OVPN_FILES = {'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'auth-user-pass', 'pkcs12', 'crl-verify'}


def openvpn_import(source, dest, dns):
    if not dns:
        raise Error('OpenVPN requires --dns IPv4; pushed DNS is deliberately ignored')
    source = Path(source)
    lines = source.read_text().splitlines()
    output, opts, inline = [], {}, set()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('<'):
            key = line[1:-1]
            if key not in OVPN_FILES - {'pkcs12', 'crl-verify'} or key in inline or key in opts:
                raise Error('Unsupported or duplicate OpenVPN inline block')
            block = [line]
            while i < len(lines) and lines[i].strip() != f'</{key}>':
                block.append(lines[i]); i += 1
            if i == len(lines):
                raise Error('Unterminated OpenVPN inline block')
            block.append(lines[i]); i += 1
            output.extend(block)
            inline.add(key)
            continue
        words = shlex.split(line, comments=True)
        if not words:
            continue
        key, values = words[0], words[1:]
        if key in opts or key in inline:
            raise Error(f'Duplicate OpenVPN directive: {key}')
        opts[key] = values
        if key in OVPN_FILES:
            if not values or len(values) > (2 if key == 'tls-auth' else 1):
                raise Error(f'{key} requires a file; interactive VPN prompts are unsupported')
            src = (source.parent / values[0]).resolve()
            if not src.is_file() or src.stat().st_size > 4 * 1024 * 1024:
                raise Error(f'Invalid referenced OpenVPN file: {src}')
            dst = dest / (key + '.data')
            dst.write_bytes(src.read_bytes())
            os.chmod(dst, 0o600)
            output.append(' '.join(shlex.quote(x) for x in [key, str(dst)] + values[1:]))
        elif key in OVPN_VALUES:
            lo, hi = OVPN_VALUES[key]
            if not lo <= len(values) <= hi:
                raise Error(f'Invalid arguments for OpenVPN {key}')
            if key not in {'client', 'dev', 'proto', 'remote', 'nobind', 'persist-key', 'persist-tun', 'resolv-retry', 'verb'}:
                output.append(' '.join(shlex.quote(x) for x in words))
        else:
            raise Error(f'Unsupported OpenVPN directive: {key}; executable hooks/plugins/config includes are forbidden')
    remote = opts.get('remote', [])
    if not remote:
        raise Error('OpenVPN requires one remote endpoint')
    proto = remote[2] if len(remote) > 2 else opts.get('proto', ['udp'])[0]
    if proto not in ['udp', 'udp4', 'tcp', 'tcp-client', 'tcp4-client']:
        raise Error('Only IPv4 UDP or TCP-client OpenVPN transports are supported')
    proto = 'udp' if proto.startswith('udp') else 'tcp'
    if opts.get('dev', ['tun'])[0] != 'tun':
        raise Error('Only OpenVPN dev tun is supported')
    ip, port = endpoint(remote[0]), int(remote[1] if len(remote) > 1 else 1194)
    if not 1 <= port <= 65535:
        raise Error('Invalid VPN port')
    if 'ca' not in opts.keys() | inline and 'peer-fingerprint' not in opts:
        raise Error('OpenVPN requires a CA or peer-fingerprint')
    output += ['client', 'dev vpn0', 'dev-type tun', 'proto ' + ('udp4' if proto == 'udp' else 'tcp4-client'),
               f'remote {ip} {port}', 'nobind', 'persist-key', 'persist-tun', 'route-nopull',
               'redirect-gateway def1', 'pull-filter ignore "dhcp-option"', 'pull-filter ignore "dns"',
               'script-security 1', 'disable-dco', 'verb 3', 'resolv-retry 0']
    if 'remote-cert-tls' not in opts:
        output.append('remote-cert-tls server')
    write(dest / 'client.ovpn', '\n'.join(output) + '\n')
    return dict(kind='openvpn', endpoint=ip, port=port, proto=proto, dns=[ipv4(x) for x in dns])


def run(args, *, ns=None, input=None, check=True, env=None):
    args = [str(x) for x in args]
    if ns:
        args = ['ip', 'netns', 'exec', ns] + args
    p = sp.run(args, input=input, text=True, stdout=sp.PIPE, stderr=sp.PIPE,
               env=env or {'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'})
    if check and p.returncode:
        # Never print argv: it can contain imported VPN material or environment values.
        if 'wg' in args and ('setconf' in args or 'set' in args):
            raise Error('WireGuard configuration failed; check keys/endpoint/permissions (tool output redacted)')
        raise Error(f'{args[0]} failed ({p.returncode}): {p.stderr.strip()}')
    return p


def write(path, text, mode=0o600):
    path = Path(path)
    tmp = path.with_name(path.name + '.new')
    with open(tmp, 'w') as f:
        os.fchmod(f.fileno(), mode)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def save(c):
    write(Path(c['state']) / 'config.json', json.dumps(c, indent=2) + '\n')


def names(c):
    tag = c['tag']
    return 'ds' + tag + 'c', 'ds' + tag + 'g', 'ds' + tag + 'h', 'ds_' + tag


def network(c, login_timeout=45):
    """Build default-deny policy before any workload exists."""
    client, gateway, hostif, table = names(c)
    run(['ip', 'netns', 'add', client])
    run(['ip', '-n', client, 'link', 'set', 'lo', 'up'])
    run(['sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1'], ns=client)
    if c['mode'] == 'off':
        return
    run(['ip', 'netns', 'add', gateway])
    run(['ip', '-n', gateway, 'link', 'set', 'lo', 'up'])
    run(['sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1', 'net.ipv4.ip_forward=1'], ns=gateway)
    # Two links: host<->gateway transport and gateway<->workload. Fixed inner
    # addresses are safe because every gateway/workload has its own network NS.
    a, b = c['transport']
    run(['ip', 'link', 'add', hostif, 'type', 'veth', 'peer', 'name', 'wan', 'netns', gateway])
    # Host may have IPv6 on: keep its neighbor-discovery/MLD off the transport link.
    run(['sysctl', '-qw', f'net.ipv6.conf.{hostif}.disable_ipv6=1'])
    run(['ip', 'addr', 'add', a + '/30', 'dev', hostif])
    run(['ip', '-n', gateway, 'addr', 'add', b + '/30', 'dev', 'wan'])
    run(['ip', '-n', gateway, 'link', 'add', 'lan', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', client])
    run(['ip', '-n', gateway, 'addr', 'add', '10.203.0.1/30', 'dev', 'lan'])
    run(['ip', '-n', client, 'addr', 'add', '10.203.0.2/30', 'dev', 'eth0'])
    vpn = c.get('vpn', {}) if c['mode'] == 'vpn' else {}
    tailscale = vpn.get('kind') == 'tailscale'
    transport = quad100 = ''
    if tailscale:
        # Tailscale has no single endpoint (control, DERP relays, STUN, direct
        # peer UDP). The rule instead: this namespace holds exactly one
        # process, the session's tailscaled, so OUTPUT on wan is that daemon's
        # transport and nothing else; workload packets are FORWARD and may
        # only enter vpn0. Cleartext DNS from the daemon is refused outright.
        # Nor may it address the host end of its own link (it probes its
        # default gateway for NAT-PMP/PCP/UPnP port mappings) or multicast.
        transport = (f'oifname "wan" ip daddr {{ {a}, 224.0.0.0/4, 255.255.255.255 }} counter drop\n'
                     '   oifname "wan" meta l4proto { tcp, udp } th dport 53 counter drop\n'
                     '   oifname "wan" meta l4proto { tcp, udp } accept')
        # The service address answers DNS only; its other ports stay closed to workloads.
        quad100 = (f'iifname "lan" oifname "vpn0" ip daddr {TS_QUAD100} meta l4proto {{ tcp, udp }} '
                   'th dport != 53 counter drop')
        run(['sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=2', 'net.ipv4.conf.default.rp_filter=2'], ns=gateway)
    elif vpn:
        proto = vpn.get('proto', 'udp')
        transport = f'ip daddr {vpn["endpoint"]} {proto} dport {vpn["port"]} accept'
    outif = 'vpn0' if vpn else 'wan'
    # Transport is OUTPUT only in a separate namespace. No UID matching tricks.
    run(['nft', '-f', '-'], ns=gateway, input=f'''
table inet guard {{
 chain input {{ type filter hook input priority 0; policy drop;
   iifname "lo" accept
   ct state established,related accept
 }}
 chain output {{ type filter hook output priority 0; policy drop;
   meta nfproto ipv6 counter drop
   oifname "lo" accept
   oifname "lan" ct state established,related accept
   oifname "{outif}" accept
   {transport}
   counter drop
 }}
 chain forward {{ type filter hook forward priority 0; policy drop;
   meta nfproto ipv6 counter drop
   {quad100}
   iifname "lan" oifname "{outif}" counter accept
   iifname "{outif}" oifname "lan" ct state established,related counter accept
   counter drop
 }}
}}
table ip nat {{ chain post {{ type nat hook postrouting priority srcnat; policy accept;
 oifname "{outif}" ip saddr 10.203.0.2 masquerade
}}
}}
''')
    exceptions = ''.join(f'iifname "{hostif}" ip daddr {n} accept\n' for n in c.get('allow_net', []))
    local_routes = json.loads(run(['ip', '-j', '-4', 'route', 'show', 'scope', 'link']).stdout)
    local_nets = [str(ipaddress.IPv4Network(r['dst'], strict=False)) for r in local_routes
                  if r.get('dst') and r['dst'] != 'default']
    blocked = ', '.join(str(n) for n in ipaddress.collapse_addresses(
        [ipaddress.IPv4Network(n) for n in BLOCKED.split(', ') + local_nets]))
    if tailscale:
        # Private ranges stay blocked for the daemon too (including the host's
        # own tailnet, 100.64.0.0/10) unless named: a self-hosted control or
        # relay server on a private address.
        exceptions += ''.join(f'iifname "{hostif}" ip daddr {n} accept\n' for n in vpn.get('transport_nets', []))
    elif vpn:
        exceptions += f'iifname "{hostif}" {transport}\n'
    # No host default route/resolver changes. All hooks match the owned link.
    run(['nft', '-f', '-'], input=f'''
table inet {table} {{
 chain input {{ type filter hook input priority -10; policy accept;
   iifname "{hostif}" counter drop
 }}
 chain forward {{ type filter hook forward priority -10; policy accept;
   iifname "{hostif}" meta nfproto ipv6 drop
   {exceptions}
    iifname "{hostif}" ip daddr {{ {blocked} }} counter drop
   iifname "{hostif}" counter accept
   oifname "{hostif}" ct state established,related accept
   oifname "{hostif}" drop
 }}
}}
table ip {table} {{ chain post {{ type nat hook postrouting priority srcnat; policy accept;
 ip saddr {b}/32 oifname != "{hostif}" masquerade
}}
}}
''')
    if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
        if not (ROOT / 'forwarding-before').exists():
            write(ROOT / 'forwarding-before', '0\n')
        run(['sysctl', '-qw', 'net.ipv4.ip_forward=1'])
    for ns, dev in [(None, hostif), (gateway, 'wan'), (gateway, 'lan'), (client, 'eth0')]:
        run(['ip'] + (['-n', ns] if ns else []) + ['link', 'set', dev, 'up'])
    run(['ip', '-n', gateway, 'route', 'add', 'default', 'via', a])
    run(['ip', '-n', client, 'route', 'add', 'default', 'via', '10.203.0.1'])
    if tailscale:
        start_tailscale(c, gateway, login_timeout)
    elif vpn:
        run(['ip', '-n', gateway, 'route', 'replace', vpn['endpoint'] + '/32', 'via', a])
        start_vpn(c, gateway)


def start_vpn(c, gateway):
    v = c['vpn']
    state = Path(c['state'])
    if v['kind'] == 'wireguard':
        run(['ip', '-n', gateway, 'link', 'add', 'vpn0', 'type', 'wireguard'])
        run(['wg', 'setconf', 'vpn0', state / 'vpn' / 'wg.conf'], ns=gateway)
        for addr in v['addresses']:
            run(['ip', '-n', gateway, 'addr', 'add', addr, 'dev', 'vpn0'])
        run(['ip', '-n', gateway, 'link', 'set', 'vpn0', 'mtu', str(v.get('mtu', 1380)), 'up'])
        run(['ip', '-n', gateway, 'route', 'replace', 'default', 'dev', 'vpn0'])
    else:
        log = open(state / 'openvpn.log', 'w')
        p = sp.Popen(['ip', 'netns', 'exec', gateway, 'openvpn', '--config',
                      str(state / 'vpn' / 'client.ovpn')], stdin=sp.DEVNULL,
                     stdout=log, stderr=log, start_new_session=True,
                     env={'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'}, close_fds=True)
        log.close()
        # Policy is active throughout TLS negotiation and reconnect. Timeout
        # fails startup instead of admitting a workload with a broken config.
        for _ in range(300):
            if p.poll() is not None:
                raise Error(f'OpenVPN exited; root can inspect {state}/openvpn.log')
            routes = run(['ip', '-n', gateway, '-j', 'addr', 'show', 'dev', 'vpn0'], check=False)
            if routes.returncode == 0 and any(x.get('addr_info') for x in json.loads(routes.stdout)):
                run(['ip', '-n', gateway, 'route', 'replace', '0.0.0.0/1', 'dev', 'vpn0'])
                run(['ip', '-n', gateway, 'route', 'replace', '128.0.0.0/1', 'dev', 'vpn0'])
                return
            time.sleep(.1)
        raise Error('OpenVPN did not configure its tunnel within 30s; inspect root-only openvpn.log')


# ---------------------------------------------------------------------------
# Tailscale backend. Each session runs its own tailscaled in its gateway
# network namespace, with its own socket, state directory, interface and
# port. The host's tailscaled and its tailnet are never contacted: every
# tailscale binary we start runs inside TS_BOX, a private mount namespace in
# which the host's /etc, /run (D-Bus, systemd-resolved, NetworkManager and
# the host daemon's socket) and /var/lib/tailscale do not exist.
TS_BOX = r'''import json,os,subprocess,sys
cfg=json.loads(sys.argv[1])
os.unshare(os.CLONE_NEWNS)
def mount(*a): subprocess.run(('/usr/bin/mount',)+a,check=True)
mount('--make-rprivate','/')
mount('-t','tmpfs','-o','mode=755,nosuid,nodev','tmpfs','/run')
for d in ('/var/lib/tailscale','/var/cache/tailscale'):
 if os.path.isdir(d): mount('-t','tmpfs','-o','mode=700','tmpfs',d)
mount('--bind',cfg['etc'],'/etc')
mount('--bind','/usr','/usr'); mount('-o','remount,bind,ro','/usr')
os.execve(cfg['argv'][0],cfg['argv'],cfg['env'])
'''
TS_QUAD100 = '100.100.100.100'


def ts_paths(c):
    base = Path(c['state']) / 'tailscale'
    return base, base / 'etc', base / 'var', base / 'tailscaled.sock'


def ts_binary(name):
    path = shutil.which(name, path=SYSTEM_PATH)
    if not path:
        raise Error(f'{name} is not installed; the tailscale backend needs the tailscale package')
    return path


def ts_box(c, argv):
    base, etc, var, sock = ts_paths(c)
    env = {'PATH': SYSTEM_PATH, 'HOME': str(var), 'LANG': 'C.UTF-8', 'TS_NO_LOGS_NO_SUPPORT': 'true',
           'TS_LOGS_DIR': str(var), 'TS_DISABLE_PORTMAPPER': 'true', 'TS_DISABLE_UPNP': 'true'}
    return ['ip', 'netns', 'exec', c.get('netns') or names(c)[1], '/usr/bin/python3', '-I', '-c', TS_BOX,
            json.dumps(dict(etc=str(etc), argv=[str(a) for a in argv], env=env))]


def ts(c, *args, check=True, timeout=30):
    """One tailscale CLI call against this session's daemon, never the host's."""
    sock = ts_paths(c)[3]
    try:
        p = sp.run(ts_box(c, [ts_binary('tailscale'), f'--socket={sock}'] + list(args)), stdin=sp.DEVNULL,
                   stdout=sp.PIPE, stderr=sp.PIPE, text=True, timeout=timeout,
                   env={'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'})
    except sp.TimeoutExpired:
        if check:
            raise Error(f'tailscale {args[0]} did not finish within {timeout}s')
        return None
    if check and p.returncode:
        raise Error(f'tailscale {args[0]} failed: {printable(p.stderr.strip() or p.stdout.strip())[:400]}')
    return p


def ts_status(c):
    p = ts(c, 'status', '--json', check=False, timeout=10)
    try:
        return json.loads(p.stdout) if p else {}
    except ValueError:
        return {}


def tailscale_import(args, dest, previous):
    """Validate `vpn configure --tailscale` input. Only these options exist:
    nothing that exposes the gateway (SSH, advertised routes or exit node,
    serve/funnel, a relay) can be requested, and start() verifies the result."""
    import urllib.parse
    v = dict(kind='tailscale', login_server=None, pin=None, exit_node=args.exit_node or None,
             accept_routes=bool(args.accept_routes), hostname=args.hostname or 'ds-' + args.name,
             magic_dns=not args.dns, dns=[ipv4(x) for x in (args.dns or [TS_QUAD100])],
             transport_nets=[str(ipaddress.IPv4Network(x, strict=False)) for x in args.transport_net],
             port=previous.get('port') if previous.get('kind') == 'tailscale' else None)
    if not re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', v['hostname']):
        raise Error('Tailscale --hostname must be a DNS label: [a-z0-9-], at most 63 characters')
    if v['exit_node'] and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', v['exit_node']):
        raise Error('Tailscale --exit-node must be a peer name, tailnet IPv4 address or node ID')
    if args.login_server:
        u = urllib.parse.urlsplit(args.login_server)
        if u.scheme not in ('https', 'http') or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise Error('Tailscale --login-server must be http(s)://HOST[:PORT][/PATH] without credentials or a query')
        try:
            ip = str(ipaddress.IPv4Address(u.hostname))
        except ValueError:
            # Like the other backends: resolved once, on the host, at configuration
            # time. The daemon gets the result as a hosts entry and no resolver.
            ip = endpoint(u.hostname)
            v['pin'] = [u.hostname.lower(), ip]
        v['login_server'] = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path.rstrip('/'), '', ''))
    if args.auth_key_stdin or args.auth_key_file:
        key = (sys.stdin.read() if args.auth_key_stdin else Path(args.auth_key_file).read_text()).strip()
        if not 8 <= len(key) <= 512 or not re.fullmatch(r'[\x21-\x7e]+', key):
            raise Error('Tailscale auth key must be one line of 8-512 printable characters (value not shown)')
        write(dest / 'authkey', key + '\n')
    elif previous.get('kind') == 'tailscale' and (Path(args.previous_dir) / 'authkey').is_file():
        shutil.copyfile(Path(args.previous_dir) / 'authkey', dest / 'authkey')
        os.chmod(dest / 'authkey', 0o600)
    if args.ca_file:
        pem = Path(args.ca_file).read_text()
        if len(pem) > 1 << 20 or 'PRIVATE KEY' in pem or '-----BEGIN CERTIFICATE-----' not in pem:
            raise Error('Tailscale --ca-file must hold PEM certificates only')
        write(dest / 'ca.pem', pem)
    elif previous.get('kind') == 'tailscale' and (Path(args.previous_dir) / 'ca.pem').is_file():
        shutil.copyfile(Path(args.previous_dir) / 'ca.pem', dest / 'ca.pem')
    v['ca'] = (dest / 'ca.pem').exists()
    return v


def ts_prepare(c):
    """Private /etc for the daemon: no resolver, pinned control host, CA bundle."""
    v = c['vpn']
    base, etc, var, sock = ts_paths(c)
    base.mkdir(mode=0o700, exist_ok=True)
    os.chmod(base, 0o700)
    for d in [etc, etc / 'ssl', etc / 'ssl' / 'certs', var]:
        d.mkdir(mode=0o700 if d == var else 0o755, exist_ok=True)
    # The daemon must never resolve through the host or send cleartext DNS
    # itself; the control host comes from the hosts file. Its "system
    # resolver" is this namespace's own loopback, where nothing listens:
    # tailscaled needs some base resolver before it applies tailnet DNS
    # routes, and names outside those routes then fail instead of leaving.
    write(etc / 'resolv.conf', '# devsession: no system resolver for the gateway daemon\nnameserver 127.0.0.1\n', 0o644)
    write(etc / 'hosts', '127.0.0.1 localhost\n' + (f'{v["pin"][1]} {v["pin"][0]}\n' if v.get('pin') else ''), 0o644)
    write(etc / 'nsswitch.conf', 'passwd: files\ngroup: files\nhosts: files dns\n', 0o644)
    write(etc / 'passwd', 'root:x:0:0:root:/root:/bin/false\n', 0o644)
    write(etc / 'group', 'root:x:0:\n', 0o644)
    bundle = ''
    for candidate in ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt']:
        if Path(candidate).is_file():
            bundle = Path(candidate).read_text()
            break
    extra = Path(c['state']) / 'vpn' / 'ca.pem'
    write(etc / 'ssl' / 'certs' / 'ca-certificates.crt', bundle + ('\n' + extra.read_text() if extra.is_file() else ''), 0o644)
    with contextlib.suppress(FileNotFoundError):
        sock.unlink()


def ts_port(c):
    """A UDP port of this session's own, distinct from the host daemon's 41641."""
    used = {x.get('vpn', {}).get('port') for x in configs() if x['state'] != c['state']}
    return next(p for p in range(41700, 42700) if p not in used)


def start_tailscale(c, gateway, login_timeout=45):
    v = c['vpn']
    base, etc, var, sock = ts_paths(c)
    ts_prepare(c)
    if not v.get('port'):
        v['port'] = ts_port(c)
        save(c)
    log = open(base / 'tailscaled.log', 'w')
    p = sp.Popen(ts_box(c, [ts_binary('tailscaled'), '--tun=vpn0', f'--port={v["port"]}', f'--socket={sock}',
                            f'--statedir={var}', f'--state={var}/tailscaled.state', '--no-logs-no-support',
                            '--verbose=0']),
                 stdin=sp.DEVNULL, stdout=log, stderr=log, start_new_session=True,
                 env={'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'}, close_fds=True)
    log.close()
    for _ in range(150):
        if p.poll() is not None:
            raise Error(f'tailscaled exited; root can inspect {base}/tailscaled.log')
        state = ts_status(c).get('BackendState')
        if state and state != 'NoState':
            break
        time.sleep(.1)
    else:
        raise Error('tailscaled did not answer on its socket within 15s')
    key = Path(c['state']) / 'vpn' / 'authkey'
    if state == 'NeedsLogin' and not key.is_file():
        raise Error('Tailscale node is not logged in and no auth key is configured: '
                    'vpn configure NAME --tailscale --auth-key-file FILE')
    # Every preference is stated on each start. --reset drops anything else a
    # previous run (or someone with root) left in the node state.
    # With an exit node (selected below) "LAN access" must be allowed: tailscaled otherwise
    # routes every connected subnet into the tunnel, which here means the
    # gateway's own lan/wan links, and replies could not return to the
    # workload. Nothing is opened by it: workload packets toward those links
    # are refused by the forward chain (lan -> vpn0 only), not by routing.
    up = ['up', '--reset', f'--timeout={login_timeout}s', '--shields-up=true', '--ssh=false',
          '--advertise-routes=', '--advertise-exit-node=false', '--advertise-connector=false',
          '--netfilter-mode=off',
          '--accept-routes=' + ('true' if v.get('accept_routes') else 'false'),
          '--accept-dns=' + ('true' if v.get('magic_dns') else 'false'),
          '--hostname=' + v['hostname'], '--exit-node=']
    if v.get('login_server'):
        up.append('--login-server=' + v['login_server'])
    if key.is_file():
        up.append(f'--auth-key=file:{key}')  # read by the client from the file: never in argv
    done = ts(c, *up, check=False, timeout=login_timeout + 15)
    if done is None or done.returncode:
        detail = printable((done.stderr.strip() or done.stdout.strip()) if done else 'timed out')[:300]
        raise Error('Tailscale login or configuration failed (check the auth key, login server and exit node): ' + detail)
    ts(c, 'set', '--auto-update=false', '--webclient=false', '--relay-server-port=', check=False)
    ts(c, 'serve', 'reset', check=False)
    ts(c, 'funnel', 'reset', check=False)
    try:
        prefs = json.loads(ts(c, 'debug', 'prefs').stdout)
    except ValueError:
        raise Error('Cannot read tailscale preferences to verify that the gateway is not exposed')
    exposed = [name for name, bad in [
        ('Tailscale SSH', prefs.get('RunSSH')), ('shields down', not prefs.get('ShieldsUp')),
        ('advertised routes or exit node', prefs.get('AdvertiseRoutes')),
        ('app connector', (prefs.get('AppConnector') or {}).get('Advertise')),
        ('web client', prefs.get('RunWebClient')), ('peer relay', prefs.get('RelayServerPort') is not None),
        ('daemon-managed netfilter', prefs.get('NetfilterMode') not in (0, None)),
        ('automatic updates', (prefs.get('AutoUpdate') or {}).get('Apply'))] if bad]
    if exposed:
        raise Error('Tailscale preferences would expose or alter the gateway: ' + ', '.join(exposed))
    for _ in range(100):
        status = ts_status(c)
        if status.get('BackendState') == 'Running' and (status.get('Self') or {}).get('TailscaleIPs'):
            break
        time.sleep(.1)
    else:
        raise Error('Tailscale did not reach the Running state with a tailnet address within 10s')
    if v.get('exit_node'):
        # Selected after login (a peer cannot be named before the first
        # netmap) and before any workload exists. Without it nothing but
        # tailnet addresses is reachable, so there is no window of direct access.
        for _ in range(60):
            done = ts(c, 'set', '--exit-node=' + v['exit_node'], '--exit-node-allow-lan-access=true', check=False)
            if done and done.returncode == 0 and ts_status(c).get('ExitNodeStatus'):
                return
            time.sleep(.25)
        raise Error('Tailscale exit node is not available in the tailnet: ' + v['exit_node'])


def tailscale_logout(c):
    """Best effort, bounded: deregister the node when its session is deleted."""
    v = c.get('vpn') or {}
    if v.get('kind') != 'tailscale' or not (ts_paths(c)[2] / 'tailscaled.state').exists():
        return None
    try:
        if not (alive(c) and c['mode'] == 'vpn'):
            stop(c)
            c['mode'] = 'vpn'
            network(c, login_timeout=15)
        done = ts(c, 'logout', check=False, timeout=15)
        return bool(done and done.returncode == 0)
    except (Error, OSError):
        return False


ETC_SHARE = ['ssl/certs', 'ssl/openssl.cnf', 'ld.so.cache', 'ld.so.conf', 'ld.so.conf.d',
             'alternatives', 'localtime', 'locale.alias', 'locale.gen', 'terminfo',
             'inputrc', 'bash_completion', 'bash_completion.d', 'python3', 'python3.14']


def filesystem(c):
    state, home = Path(c['state']), c['home']
    uid, gid = c['uid'], c['gid']
    for rel in ['home', 'home/.config', 'home/.local', 'home/.local/share', 'home/.local/state', 'home/.cache', 'home/.azure',
                'home/.ssh', 'home/.kube', 'home/.docker', 'home/.aws', 'run', 'tmp']:
        p = state / rel
        if p.is_symlink() or any(q.is_symlink() for q in p.parents if q != state and state in q.parents):
            raise Error(f'Private directory must not be a symlink: {rel}')
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(p, uid, gid)
    etc = state / 'etc'
    etc.mkdir(mode=0o711, exist_ok=True)
    os.chmod(etc, 0o711)
    write(etc / 'passwd', f'root:x:0:0:root:/root:/bin/false\n{c["user"]}:x:{uid}:{gid}::{home}:{c["shell"]}\n', 0o644)
    write(etc / 'group', f'root:x:0:\n{c["user"]}:x:{gid}:\n', 0o644)
    write(etc / 'hosts', '127.0.0.1 localhost\n', 0o644)
    write(etc / 'nsswitch.conf', 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n', 0o644)
    dns = c.get('vpn', {}).get('dns', []) if c['mode'] == 'vpn' else c.get('dns', ['1.1.1.1'])
    write(etc / 'devsession-activate.bashrc', ACTIVATE_RC, 0o644)
    write(etc / 'resolv.conf', ''.join('nameserver ' + x + '\n' for x in dns) + 'options timeout:1 attempts:2\n', 0o644)
    args = ['bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts', '--hostname', c['name'],
            '--new-session', '--cap-drop', 'ALL',
            '--ro-bind', '/usr', '/usr']
    for d in ['bin', 'sbin', 'lib', 'lib64']:
        p = Path('/') / d
        if p.is_symlink():
            args += ['--symlink', os.readlink(p), '/' + d]
        elif p.exists():
            args += ['--ro-bind', str(p), str(p)]
    args += ['--dir', '/etc']
    for f in ETC_SHARE:
        p = Path('/etc') / f
        if p.exists():
            args += ['--ro-bind', str(p), str(p)]
    for p in etc.iterdir():
        args += ['--ro-bind', str(p), '/etc/' + p.name]
    args += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/dev/shm',
             '--dir', '/run', '--bind', str(state / 'run'), f'/run/user/{uid}',
             '--bind', str(state / 'tmp'), '/tmp', '--symlink', '/tmp', '/var/tmp',
             '--bind', str(state / 'home'), home]
    for path in c.get('tools', []):
        args += ['--ro-bind', path, path]
    for m in c.get('mounts', []):
        args += ['--ro-bind' if m['ro'] else '--bind', m['source'], m['target']]
    if (state / 'shellrc').exists():
        args += ['--ro-bind', str(state / 'shellrc'), '/etc/devsession.bashrc']
    args += ['--chdir', '/', '--remount-ro', '/']
    return args


def environment(c, overrides=None):
    h, uid = c['home'], c['uid']
    env = {'PATH': c['path'], 'HOME': h, 'USER': c['user'], 'LOGNAME': c['user'],
           'SHELL': c['shell'], 'LANG': 'C.UTF-8', 'TERM': 'xterm-256color',
           'XDG_CONFIG_HOME': h + '/.config', 'XDG_DATA_HOME': h + '/.local/share',
           'XDG_CACHE_HOME': h + '/.cache', 'XDG_STATE_HOME': h + '/.local/state', 'XDG_RUNTIME_DIR': f'/run/user/{uid}',
           'TMPDIR': '/tmp', 'TMUX_TMPDIR': f'/run/user/{uid}',
           'AZURE_CONFIG_DIR': h + '/.azure', 'DEVSESSION': c['name']}
    env.update(c.get('env', {}))
    env.update(overrides or {})
    return env


def alive(c):
    pid = c.get('pid')
    if not pid:
        return False
    try:
        return (Path(f'/proc/{pid}/stat').read_text().split()[21] == c.get('birth')
                and os.readlink(f'/proc/{pid}/ns/net') == c.get('net_inode'))
    except (FileNotFoundError, ProcessLookupError):
        return False


def start(c):
    if alive(c):
        return
    if c['mode'] == 'vpn' and not c.get('vpn'):
        raise Error('VPN mode requires a validated VPN configuration')
    stop(c)
    c['phase'] = 'starting'
    save(c)
    try:
        # Bubblewrap canonicalizes bind-fd paths. Traversable (not listable)
        # root-owned ancestors permit this; actual secrets stay mode 600/700.
        os.chmod(ROOT, 0o711)
        os.chmod(c['state'], 0o711)
        network(c)
        args = filesystem(c)
        info = Path(c['state']) / 'bwrap.json'
        # Open mount roots while privileged, then hand only these handles to
        # unprivileged Bubblewrap. No root-owned parent directory is exposed.
        fds = []
        try:
            for i, arg in enumerate(args):
                if arg in ['--bind', '--ro-bind']:
                    fd = os.open(args[i + 1], os.O_PATH | os.O_CLOEXEC)
                    fds.append(fd)
                    args[i], args[i + 1] = arg + '-fd', str(fd)
            with open(info, 'w') as f, open(Path(c['state']) / 'runtime.log', 'w') as log:
                args += ['--info-fd', str(f.fileno()), '--', '/bin/sleep', 'infinity']
                prefix = ['ip', 'netns', 'exec', names(c)[0], 'setpriv', '--reuid', str(c['uid']),
                          '--regid', str(c['gid']), '--clear-groups']
                p = sp.Popen(prefix + args, stdin=sp.DEVNULL, stdout=log, stderr=log,
                             env={'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'},
                             pass_fds=tuple(fds + [f.fileno()]), start_new_session=True)
        finally:
            for fd in fds:
                os.close(fd)
        for _ in range(100):
            if p.poll() is not None:
                raise Error('Bubblewrap failed: ' + (Path(c['state']) / 'runtime.log').read_text())
            try:
                pid = json.loads(info.read_text())['child-pid']
                if Path(f'/proc/{pid}/root/etc/devsession-ready').exists():
                    break
                # Child-pid is PID namespace init; wait for pivot_root/proc mount.
                if Path(f'/proc/{pid}/root/etc/passwd').read_text() == (Path(c['state']) / 'etc/passwd').read_text():
                    break
            except (ValueError, KeyError, FileNotFoundError):
                pass
            time.sleep(.03)
        else:
            raise Error('Bubblewrap startup timed out')
        c.update(pid=pid, birth=Path(f'/proc/{pid}/stat').read_text().split()[21],
                 net_inode=os.readlink(f'/proc/{pid}/ns/net'), phase='running')
        save(c)
        for hostport, innerport in c.get('publish', []):
            run(['systemd-run', '--quiet', '--collect', '--service-type=exec',
                 '--unit=' + proxy_unit(c, hostport), '--property=KillMode=control-group',
                 '/usr/bin/socat', f'TCP-LISTEN:{hostport},bind=127.0.0.1,reuseaddr,fork',
                 f'EXEC:"/usr/sbin/ip netns exec {names(c)[0]} /usr/bin/socat STDIO TCP:127.0.0.1:{innerport}"'])
    except BaseException:
        stop(c)
        raise


def enter_args(c, command, fds):
    if not alive(c):
        raise Error('Session is stopped; run devsession start NAME first', EXIT_CONFLICT)
    pid = c['pid']
    args = ['nsenter', '--no-fork']
    # Pin namespace/root descriptors before releasing the lifecycle lock. A
    # recycled numeric PID must never cause a join into a different process.
    for option, path in [('mount', 'ns/mnt'), ('pid', 'ns/pid'), ('net', 'ns/net'),
                         ('ipc', 'ns/ipc'), ('uts', 'ns/uts'), ('root', 'root')]:
        fd = os.open(f'/proc/{pid}/{path}', (os.O_PATH if option == 'root' else os.O_RDONLY) | os.O_CLOEXEC)
        fds.append(fd)
        args += [f'--{option}=/proc/self/fd/{fd}']
    if not alive(c):
        raise Error('Session stopped while joining; retry after start')
    # Join at the session root; the unprivileged launcher selects the working
    # directory afterwards so a missing directory is reported, not a join failure.
    return args + ['--wdns=/', '--', '/usr/bin/setpriv',
            '--reuid', str(c['uid']), '--regid', str(c['gid']), '--clear-groups',
            '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
            '--'] + command


# Runs inside the session as the invoking UID (python3 -I -c). It applies the
# environment and working directory after the privilege drop, supervises the
# command, forwards signals and reports the outcome on a close-on-exec pipe
# that the command never inherits.
LAUNCHER = r'''import os,sys,json,signal,pty,termios,tty,fcntl,select,errno
f=os.fdopen(int(sys.argv[1])); cfg=json.load(f); f.close()
e=cfg['env']; sfd=cfg.get('status_fd',-1)
if sfd>=3:
 os.closerange(3,sfd); os.closerange(sfd+1,4096); os.set_inheritable(sfd,False)
else:
 os.closerange(3,4096)
def report(**k):
 if sfd>=3:
  try: os.write(sfd,(json.dumps(k)+'\n').encode())
  except OSError: pass
os.umask(0o077)
try: os.chdir(cfg['cwd'])
except OSError as err:
 report(error='cwd',errno=err.errno); sys.exit(120)
mode=cfg.get('tty','auto'); intty=os.isatty(0)
interactive=mode=='always' or (mode=='auto' and intty and os.isatty(1))
if interactive:
 master,slave=pty.openpty()
 def resize(*unused):
  try: fcntl.ioctl(master,termios.TIOCSWINSZ,fcntl.ioctl(0,termios.TIOCGWINSZ,b'\0'*8))
  except OSError: pass
 resize()
SIGS=(signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGQUIT,signal.SIGUSR1,signal.SIGUSR2)
r,w=os.pipe()
child=os.fork()
if child == 0:
 os.close(r)
 if interactive:
  os.close(master); os.setsid(); fcntl.ioctl(slave,termios.TIOCSCTTY,0)
  for fd in (0,1,2): os.dup2(slave,fd)
  if slave>2: os.close(slave)
 # Python ignores SIGPIPE/SIGXFSZ and exec would pass that on to the command.
 for sig in SIGS+(signal.SIGPIPE,signal.SIGXFSZ): signal.signal(sig,signal.SIG_DFL)
 try: os.execvpe(sys.argv[2],sys.argv[2:],e)
 except OSError as err:
  os.write(w,str(err.errno).encode()); os._exit(127 if err.errno==errno.ENOENT else 126)
os.close(w)
def forward(sig,frame):
 try:
  if interactive: os.killpg(os.tcgetpgrp(master),sig)
  else: os.kill(child,sig)
 except (ProcessLookupError,OSError): pass
for sig in SIGS: signal.signal(sig,forward)
failed=b''
while True:
 try: failed=os.read(r,32); break
 except InterruptedError: pass
os.close(r)
if interactive:
 os.close(slave)
 def sendall(fd,data):
  while data: data=data[os.write(fd,data):]
 previous=None
 if intty:
  signal.signal(signal.SIGWINCH,resize)
  previous=termios.tcgetattr(0)
 try:
  if intty: tty.setraw(0)
  readers=[0,master]
  while True:
   try: ready,_,_=select.select(readers,[],[])
   except InterruptedError: continue
   if master in ready:
    try: data=os.read(master,65536)
    except OSError as err:
     if err.errno==errno.EIO: break
     raise
    if not data: break
    sendall(1,data)
   if 0 in ready:
    try: data=os.read(0,65536)
    except OSError: data=b''
    if data: sendall(master,data)
    else:
     readers.remove(0)
     if not intty: sendall(master,b'\x04')
 finally:
  if previous is not None: termios.tcsetattr(0,termios.TCSADRAIN,previous)
  os.close(master)
while True:
 try: _,status=os.waitpid(child,0); break
 except InterruptedError: pass
rc=os.waitstatus_to_exitcode(status)
if failed: report(error='exec',errno=int(failed))
elif rc<0: report(signal=-rc)
else: report(exit=rc)
sys.exit(rc if rc>=0 else 128-rc)
'''
FORWARDED = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2)


def execute(c, command, *, capture=False, overrides=None, release=None, cwd=None, tty='auto'):
    """Run argv in the session. Returns (exit status, attribution record)."""
    # Never inject session LD_PRELOAD/PYTHONPATH/etc into privileged nsenter or
    # setpriv. Hand environment over only AFTER dropping all privileges.
    status_r, status_w = os.pipe()
    target = cwd or c.get('cwd', c['home'])
    fd = os.memfd_create('devsession-env', os.MFD_CLOEXEC)
    os.write(fd, json.dumps(dict(env=environment(c, overrides), cwd=target,
                                 tty=tty, status_fd=status_w)).encode())
    os.lseek(fd, 0, 0)
    # Close all namespace/root descriptors before workload exec, including the
    # root handle: no inherited setup handle should be reachable via /proc/fd.
    fds = [fd, status_w]
    # nsenter's default waiting parent does not forward directed signals. Its
    # --no-fork form sets the child PID namespace; the unprivileged supervisor
    # forks into it, forwards signals and returns the actual command status.
    try:
        args = enter_args(c, ['/usr/bin/python3', '-I', '-c', LAUNCHER, str(fd)] + command, fds)
    except BaseException:
        for handle in fds + [status_r]:
            os.close(handle)
        raise
    safe = {'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'}
    if capture:
        try:
            return sp.run(args, env=safe, text=True, capture_output=True, pass_fds=tuple(fds))
        finally:
            for handle in fds + [status_r]:
                os.close(handle)
    try:
        p = sp.Popen(args, env=safe, pass_fds=tuple(fds))
    except BaseException:
        os.close(status_r)
        raise
    finally:
        for handle in fds:
            os.close(handle)
    if release:
        release()
    old = {}
    for sig in FORWARDED:
        old[sig] = signal.signal(sig, lambda s, f: p.send_signal(s) if p.poll() is None else None)
    try:
        rc = p.wait()
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)
    rc = rc if rc >= 0 else 128 - rc
    # The record is written by the unprivileged supervisor: untrusted data,
    # bounded, and only ever interpreted as small integers.
    os.set_blocking(status_r, False)
    try:
        raw = os.read(status_r, 4096)
    except OSError:
        raw = b''
    os.close(status_r)
    try:
        report = json.loads(raw.decode('ascii', 'replace').splitlines()[0])
        report = report if isinstance(report, dict) else {}
    except (ValueError, IndexError):
        report = {}
    if isinstance(report.get('exit'), int) and 0 <= report['exit'] <= 255:
        return report['exit'], dict(source='command', exit_code=report['exit'], signal=None, error=None)
    if isinstance(report.get('signal'), int) and 1 <= report['signal'] <= 64:
        return 128 + report['signal'], dict(source='command', exit_code=128 + report['signal'],
                                           signal=report['signal'], error=None)
    # Failures the supervisor could only detect inside the session. They are
    # reported here, by devsession, in the caller's chosen format.
    reason = os.strerror(report['errno']) if isinstance(report.get('errno'), int) else 'failed'
    if report.get('error') == 'exec':
        code = 127 if report.get('errno') == 2 else 126
        kind, message = 'command-not-found' if code == 127 else 'not-executable', f'cannot execute {command[0]}: {reason}'
    elif report.get('error') == 'cwd':
        code, kind, message = EXIT_ERROR, 'working-directory', f'working directory {target}: {reason}'
    else:  # no report: the join failed, or the supervisor was killed (session stop)
        code, kind = rc if rc > 128 else EXIT_ERROR, 'interrupted'
        message = 'the session was stopped or the join failed before the command reported a status'
    complain(code, message, kind)
    return code, dict(source='devsession', exit_code=code, signal=None, error=kind)


def complain(code, message, kind=None):
    """One error on stderr: text, or a single-line JSON object with --json."""
    if OUT['json']:
        print(json.dumps(dict(error=dict(kind=kind or KINDS.get(code, 'error'), exit_code=code, message=message))), file=sys.stderr)
    else:
        print(f'devsession: {message}', file=sys.stderr)


def proxy_unit(c, port):
    return f'devsession-{c["tag"]}-{port}.service'


def stop(c):
    client, gateway, hostif, table = names(c)
    for port, _ in c.get('publish', []):
        run(['systemctl', 'stop', proxy_unit(c, port)], check=False)
    # Namespace membership rather than an untrusted PID file also recovers an
    # interrupted startup. Kill workloads before removing the kill switch.
    for ns in [client, gateway]:
        p = run(['ip', 'netns', 'pids', ns], check=False)
        for pid in p.stdout.split():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pid), signal.SIGKILL)
        run(['ip', 'netns', 'del', ns], check=False)
    run(['ip', 'link', 'del', hostif], check=False)
    for family in ['inet', 'ip']:
        run(['nft', 'delete', 'table', family, table], check=False)
    # Rewrite state only if this changed it: recovering an already stopped
    # session (cleanup, a repeated stop) leaves its files byte-identical.
    changed = c.get('phase') != 'stopped' or any(k in c for k in ('pid', 'birth', 'net_inode'))
    c.pop('pid', None)
    c.pop('birth', None)
    c.pop('net_inode', None)
    c['phase'] = 'stopped'
    if changed:
        save(c)


RESERVED_ENV = {'HOME', 'USER', 'LOGNAME', 'SHELL', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
                'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR', 'TMPDIR', 'TMUX_TMPDIR', 'TMUX',
                'AZURE_CONFIG_DIR', 'DEVSESSION', 'DEVSESSION_TREE', 'DEVSESSION_TREE_MARKER',
                'DEVSESSION_LEAVE_FILE'}
NAME_RE = re.compile(r'[a-z][a-z0-9-]{0,31}\Z')


def env_key(key):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key) or key in RESERVED_ENV:
        raise Error(f'Invalid or isolation-reserved variable: {key}')
    return key


def env_file(text):
    if '\0' in text:
        raise Error('NUL is forbidden in environment data')
    result = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if '=' not in line:
            raise Error(f'Env file line {n}: expected NAME=value (no shell syntax)')
        k, v = line.split('=', 1)
        result[env_key(k.strip())] = v
    return result


def state_path(uid, name):
    if not NAME_RE.fullmatch(name):
        raise Error('Name must match [a-z][a-z0-9-]{0,31}')
    return ROOT / f'{uid}-{name}'


def normalize(c):
    """Fill keys that older state files lack; nothing is written back here."""
    for key, default in [('env', {}), ('mounts', []), ('tools', []), ('publish', []),
                         ('allow_net', []), ('dns', ['1.1.1.1']), ('phase', 'stopped')]:
        c.setdefault(key, type(default)(default))
    c.setdefault('cwd', c['home'])
    return c


def configs(uid=None):
    for p in sorted(ROOT.glob('*/config.json')):
        try:
            c = normalize(json.loads(p.read_text()))
        except FileNotFoundError:
            continue  # deleted while listing; queries take no lock
        except (ValueError, KeyError):
            print(f'devsession: ignoring unreadable state {p.parent.name}', file=sys.stderr)
            continue
        if uid is None or c['uid'] == uid:
            yield c


def session_dir(uid, name):
    """State directory of an existing session, or None."""
    p = state_path(uid, name)
    if (p / 'config.json').exists():
        return p
    # The first prototype wrote ROOT/NAME without the UID prefix. Such state
    # still loads when its own recorded owner and name match.
    legacy = ROOT / name
    try:
        c = json.loads((legacy / 'config.json').read_text())
        if c.get('uid') == uid and c.get('name') == name:
            return legacy
    except (OSError, ValueError):
        pass
    return None


def load(uid, name, missing_ok=False):
    p = session_dir(uid, name)
    if p:
        with contextlib.suppress(FileNotFoundError):
            return normalize(json.loads((p / 'config.json').read_text()))
    if missing_ok:
        return None
    raise Error(f'No session {name!r}; use devsession list', EXIT_NOSESSION)


def stopped(c):
    if alive(c):
        raise Error('Stop the session before changing mounts, VPN or network mode', EXIT_CONFLICT)
    stop(c)  # recover any incomplete/stale setup before modifying it


def absolute(path):
    if not path.startswith('/') or '..' in Path(path).parts or '\n' in path or '\0' in path:
        raise Error(f'Expected an absolute path without ..: {path}')
    return str(Path(path))


def mount_spec(spec, home, stores=()):
    parts = spec.split(':')
    if len(parts) not in [2, 3] or (len(parts) == 3 and parts[2] not in ['ro', 'rw']):
        raise Error('Mount syntax: /host/path:/session/path[:ro|rw] (colons in paths unsupported)')
    source = Path(parts[0]).resolve(strict=True)
    target = absolute(parts[1])
    if not source.is_dir() and not source.is_file():
        raise Error('Only regular files/directories can be mounted, not devices or sockets')
    forbidden_source = ['/', '/home', home, '/root', '/etc', '/run', '/proc', '/sys', '/dev', '/var', str(ROOT)]
    if str(source) in forbidden_source or str(source).startswith(('/proc/', '/sys/', '/dev/', '/run/', str(ROOT) + '/')):
        raise Error('Broad host/private/runtime mounts are forbidden; select a project or a specific credential file')
    # A session that could write the approval records could approve any marker.
    for store in [home + '/.local/state/devsession'] + [x for x in stores if x]:
        if str(source) == store or store.startswith(str(source) + '/') or str(source).startswith(store + '/'):
            raise Error('The directory-approval store (or a directory containing it) cannot be mounted into a session')
    protected = ['/', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc', '/proc', '/sys', '/dev', '/run', '/tmp', '/var', '/home', home]
    if target in protected or any(target.startswith(x + '/') for x in ['/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc', '/proc', '/sys', '/dev', '/run', '/var']):
        raise Error('Mount target overlaps a protected system path')
    return dict(source=str(source), target=target, ro=len(parts) == 3 and parts[2] == 'ro')


def tool_path(value, home):
    p = Path(value).absolute()
    if not p.exists():
        raise Error(f'Tool path does not exist: {p}')
    # Broad home/config/credential trees cannot be smuggled in as tool installs.
    if str(p) in ['/', '/home', home, '/root', '/etc', '/run', '/var', '/opt', '/srv', '/mnt',
                  home + '/.local', home + '/.config', home + '/.cargo', home + '/.rustup']:
        raise Error('Choose a narrow executable/toolchain installation tree')
    if any(x in {'.ssh', '.aws', '.azure', '.kube', '.docker', '.config'} for x in p.parts):
        raise Error('Credential/config trees cannot be tool mounts; use an explicit credential import')
    if not p.is_dir() and not p.is_file():
        raise Error('Tool mounts must be regular files/directories')
    resolved = str(p.resolve())
    if resolved in ['/', home, '/home', '/root', '/etc', '/var', '/run', '/proc', '/sys', '/dev'] or any(
            resolved.startswith(x + '/') for x in ['/root', '/etc', '/run', '/proc', '/sys', '/dev', str(ROOT)]):
        raise Error('Tool path resolves to a protected host/private/runtime tree')
    if any(x in {'.ssh', '.aws', '.azure', '.kube', '.docker', '.config'} for x in Path(resolved).parts):
        raise Error('Resolved tool path contains credential/configuration storage')
    # Paths are kept, rather than resolving symlinks and changing discovery paths.
    return str(p)


def host_tools(path, home):
    """Tool trees for the host PATH entries outside /usr (the --host-tools opt-in)."""
    found = []
    for entry in dict.fromkeys(x for x in path.split(':') if x.startswith('/')):
        p = Path(entry)
        real = str(p.resolve())
        # /usr is always mounted; snaps need the host snapd and cannot run here.
        if not p.is_dir() or real == '/usr' or real.startswith(('/usr/', '/snap/', '/var/lib/snapd/')):
            continue
        # Mount the directory itself unless its commands live in the surrounding
        # installation (asdf shims, Homebrew symlinks into Cellar). Widening by
        # default would expose siblings such as a tool's auth.json.
        parent = str(p.parent.resolve()) + '/'
        widen = p.name == 'shims' or any(
            x.is_symlink() and str(x.resolve()).startswith(parent) and not str(x.resolve()).startswith(real + '/')
            for x in p.iterdir())
        for candidate in ([p.parent] if widen else []) + [p]:
            try:
                found.append(tool_path(str(candidate), home))
                break
            except Error:
                continue
        else:
            print(f'--host-tools: skipped {entry} (not allowed as a tool mount)', file=sys.stderr)
    return found


def allocate():
    used = {c['transport'][0] for c in configs() if 'transport' in c}
    routes = json.loads(run(['ip', '-j', 'route', 'show', 'table', 'all']).stdout)
    nets = [ipaddress.ip_network(r['dst'], strict=False) for r in routes
            if r.get('dst') not in [None, 'default'] and ':' not in r['dst']]
    for subnet in ipaddress.ip_network('10.231.0.0/16').subnets(new_prefix=30):
        a, b = str(subnet[1]), str(subnet[2])
        if a not in used and not any(subnet.overlaps(n) for n in nets):
            return [a, b]
    raise Error('No unused transport /30 in 10.231.0.0/16; host routes conflict with pool')


def build(args, user, context):
    """Validate create options into a session configuration (no state written)."""
    import secrets
    mounts = [mount_spec(m, user.pw_dir, [context.get('state_home')]) for m in args.mount]
    targets = [m['target'] for m in mounts]
    if any(a == b or a.startswith(b + '/') or b.startswith(a + '/')
           for i, a in enumerate(targets) for b in targets[i + 1:]):
        raise Error('Overlapping mount targets are unsupported')
    tools = []
    for p in [user.pw_dir + '/.local/bin', user.pw_dir + '/.opencode/bin', '/opt/devsession-tools/azure']:
        if Path(p).exists():
            tools.append(tool_path(p, user.pw_dir))
    explicit = [tool_path(p, user.pw_dir) for p in args.tool]
    if args.host_tools:
        explicit += host_tools(context.get('path', SYSTEM_PATH), user.pw_dir)
    publish = []
    for p in args.publish:
        a, b = map(int, p.split(':'))
        if not 1024 <= a <= 65535 or not 1 <= b <= 65535:
            raise Error('Publish needs HOSTPORT:SESSIONPORT; host port must be 1024..65535')
        publish.append([a, b])
    if len({x[0] for x in publish}) != len(publish):
        raise Error('Duplicate published host port')
    c = dict(name=args.name, tag=secrets.token_hex(5), state=str(state_path(user.pw_uid, args.name)),
             uid=user.pw_uid, gid=user.pw_gid,
             user=user.pw_name, home=user.pw_dir, shell='/bin/bash', path=context.get('path', SYSTEM_PATH),
             mode=args.net or 'off', dns=[ipv4(x) for x in (args.dns or ['1.1.1.1'])],
             allow_net=[str(ipaddress.IPv4Network(x, strict=False)) for x in args.allow_net],
             mounts=mounts, tools=list(dict.fromkeys(tools + explicit)), publish=publish,
             env={}, phase='stopped',
             cwd=absolute(args.cwd) if args.cwd else (mounts[0]['target'] if mounts and Path(mounts[0]['source']).is_dir() else user.pw_dir))
    # Do not import startup files implicitly. This file is an explicit policy.
    rc = "[ -f ~/.bashrc ] && source ~/.bashrc\nPS1='[${DEVSESSION}] \\u@\\h:\\w\\$ '\n"
    if args.shell_rc:
        rc = Path(args.shell_rc).read_text() + '\n[ -f ~/.bashrc ] && source ~/.bashrc\n'
    return c, rc, explicit


def create(args, user, context):
    """Returns True when a session was created, False for a satisfied --ensure."""
    existing = load(user.pw_uid, args.name, missing_ok=True)
    if existing and not args.ensure:
        raise Error('Session already exists; use start or delete it first (or create --ensure)', EXIT_CONFLICT)
    c, rc, explicit = build(args, user, context)
    if existing:
        # --ensure: the session must already agree with every option that was
        # given explicitly. Nothing is modified; a mismatch is a conflict.
        differs = [field for field, given, same in [
            ('mount', args.mount, existing['mounts'] == c['mounts']),
            ('tool', explicit, set(explicit) <= set(existing['tools'])),
            ('net', args.net, existing['mode'] == c['mode']),
            ('dns', args.dns, existing['dns'] == c['dns']),
            ('allow-net', args.allow_net, existing['allow_net'] == c['allow_net']),
            ('publish', args.publish, existing['publish'] == c['publish']),
            ('cwd', args.cwd, existing['cwd'] == c['cwd']),
            ('shell-rc', args.shell_rc, (Path(existing['state']) / 'shellrc').read_text() == rc),
        ] if given and not same]
        if differs:
            raise Error('Session exists with different --' + ', --'.join(differs) +
                        '; delete it first or omit those options', EXIT_CONFLICT)
        return False
    if (ROOT / args.name).exists():
        raise Error('A session directory of that name from an older layout exists', EXIT_CONFLICT)
    c['transport'] = allocate()
    path = Path(c['state'])
    # Build in a root-only staging directory then publish the complete state in
    # one rename. Interrupted creates cannot reserve a broken session name.
    staging = ROOT / ('.create-' + c['tag'])
    staging.mkdir(mode=0o711)
    try:
        write(staging / 'shellrc', rc, 0o644)
        write(staging / 'config.json', json.dumps(c, indent=2) + '\n')
        staging.rename(path)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return True


# ---------------------------------------------------------------------------
# Directory activation. A marker file binds a directory tree to a session by
# name. It is untrusted repository content: parsed as data, effective only
# after the user approved that exact path and content, with the approval kept
# outside the tree. All of this runs as the invoking user; the privileged
# side only ever receives a validated session name and directory strings.
MARKER = '.devsession'


def printable(text):
    """Paths reach a terminal: never pass control characters on."""
    return ''.join(ch if ch.isprintable() else '?' for ch in str(text))


def state_home():
    base = os.environ.get('XDG_STATE_HOME', '')
    if not base.startswith('/'):
        base = os.path.join(pwd.getpwuid(os.getuid()).pw_dir, '.local', 'state')
    return Path(base) / 'devsession'


def parse_marker(data):
    """Marker bytes -> session name. Declarative data; nothing is evaluated."""
    if len(data) > 4096:
        raise Error('Marker is larger than 4096 bytes')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise Error('Marker is not UTF-8 text')
    if any(not ch.isprintable() and ch not in '\n\t' for ch in text):
        raise Error('Marker contains control characters')
    found = {}
    for number, line in enumerate(text.split('\n'), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or key.strip() != 'session' or found:
            raise Error(f'Marker line {number}: expected a single "session = NAME" (the only supported key)')
        found['session'] = value.strip()
    if not NAME_RE.fullmatch(found.get('session', '')):
        raise Error('Marker must name one session: session = NAME, NAME matching [a-z][a-z0-9-]{0,31}')
    return found['session']


def resolve_marker(start):
    """Nearest marker at or above start: dict(marker, dir, session, state, sha256, data) or None."""
    import hashlib
    import stat
    here = Path(os.path.realpath(start))
    for directory in [here, *here.parents]:
        marker = directory / MARKER
        if not os.path.lexists(marker):
            continue
        try:
            fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            raise Error(f'{printable(marker)} must be a readable regular file, not a symbolic link')
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise Error(f'{printable(marker)} must be a regular file')
            data = os.read(fd, 4097)
        finally:
            os.close(fd)
        session = parse_marker(data)
        try:
            recorded = approval_file(marker).read_bytes()
        except OSError:
            recorded = None
        state = 'approved' if recorded == data else 'unapproved' if recorded is None else 'changed'
        return dict(marker=str(marker), dir=str(directory), session=session, state=state,
                    sha256=hashlib.sha256(data).hexdigest(), data=data)
    return None


def approval_file(marker):
    """The approved copy lives outside the tree, at the marker's own absolute path."""
    return state_home() / 'allow' / str(Path(marker).parent).lstrip('/') / MARKER


def directory_session():
    """Session for the current directory, or the reason there is none."""
    if os.environ.get('DEVSESSION'):
        raise Error(f'Already inside session {printable(os.environ["DEVSESSION"])}; a session is never entered from inside one',
                    EXIT_CONFLICT)
    found = resolve_marker(os.getcwd())
    if found is None:
        raise Error(f'No session name given and no {MARKER} marker in this directory or above it', EXIT_USAGE)
    if found['state'] != 'approved':
        raise Error(f'{printable(found["marker"])} ' + ('changed after it was approved' if found['state'] == 'changed'
                    else 'is not approved') + '; review it, then run: devsession allow', EXIT_UNAPPROVED)
    return found


def activation(args):
    """allow / deny / resolve / hook: the invoking user's own state, no privilege."""
    os.umask(0o077)
    if args.action == 'hook':
        state_home().mkdir(mode=0o700, parents=True, exist_ok=True)
        sys.stdout.write(HOOK_BASH.replace('@STATE@', shlex.quote(str(state_home()))))
        return 0
    found = resolve_marker(args.dir)
    public = {k: v for k, v in (found or {}).items() if k != 'data'}
    if args.action == 'resolve':
        if found is None:
            emit(dict(marker=None, session=None, state='none'))
            return 1
        emit(public, found['session'] if found['state'] == 'approved' else None)
        if found['state'] != 'approved':
            if not OUT['json']:
                complain(EXIT_UNAPPROVED, f'{printable(found["marker"])} names session {found["session"]} but ' +
                         ('changed after it was approved' if found['state'] == 'changed' else 'is not approved'))
            return EXIT_UNAPPROVED
        return 0
    if found is None:
        raise Error(f'No {MARKER} marker in {printable(os.path.realpath(args.dir))} or above it', EXIT_USAGE)
    record = approval_file(found['marker'])
    if args.action == 'deny':
        changed = record.exists()
        record.unlink(missing_ok=True)
        for parent in record.parents:  # prune the now-empty mirror of the path
            if parent == state_home() / 'allow':
                break
            with contextlib.suppress(OSError):
                parent.rmdir()
        emit(dict(public, action='deny', changed=changed, state='unapproved'), f'Revoked approval of {printable(found["marker"])}')
        return 0
    # allow: show precisely what is granted, taken from a normal inspect.
    cmd = ['/usr/bin/python3', '-I', str(Path(__file__).resolve()), '--json'] + (
        ['--non-interactive'] if args.non_interactive else [])
    p = sp.run(cmd + ['inspect', found['session']], stdout=sp.PIPE, stderr=sp.PIPE, text=True)
    if p.returncode == EXIT_NOSESSION:
        raise Error(f'{printable(found["marker"])} names session {found["session"]}, which does not exist. '
                    'Create it first: an approval always shows what the session holds', EXIT_NOSESSION)
    if p.returncode:
        try:
            error = json.loads(p.stderr.splitlines()[-1])['error']
            raise Error('Cannot show what would be granted: ' + error['message'], error['exit_code'])
        except (ValueError, KeyError, IndexError):
            raise Error('Cannot show what would be granted (inspect failed)')
    c = json.loads(p.stdout)
    network = c['mode'] + (f' ({c["vpn"]["kind"]})' if c['mode'] == 'vpn' and c.get('vpn') else '')
    lines = [f'Marker:  {printable(found["marker"])}',
             f'SHA-256: {found["sha256"]}',
             f'Content: session = {found["session"]}',
             f'Grants:  below {printable(found["dir"])}, a devsession command given no session name runs in',
             f'         session "{found["session"]}", and an interactive Bash with the hook enters it on cd.',
             '         Whatever is run there uses what that session holds:',
             f'           network      {network}',
             '           mounts       ' + (', '.join(f'{printable(m["source"])} -> {printable(m["target"])} ({"ro" if m["ro"] else "rw"})'
                                                     for m in c['mounts']) or 'none'),
             '           tool trees   ' + (', '.join(printable(t) for t in c['tools']) or 'none'),
             '           environment  ' + (', '.join(sorted(c['env'])) or 'none') + ' (names; values are never shown)',
             '           published    ' + (', '.join(f'127.0.0.1:{a} -> {b}' for a, b in c['publish']) or 'none'),
             '           private home, credentials and caches of that session',
             'Nothing more: a marker cannot add mounts, tools, network access, environment or commands.',
             'Editing the marker revokes this approval; the record is kept outside the tree.']
    if not OUT['json'] and not (OUT['quiet'] and args.yes):
        print('\n'.join(lines), file=sys.stdout if args.yes else sys.stderr)
    if not args.yes:
        if not (sys.stdin and sys.stdin.isatty()):
            raise Error('Approval needs a terminal to confirm, or --yes after reviewing the marker', EXIT_USAGE)
        sys.stderr.write('Approve? [y/N] '); sys.stderr.flush()
        if sys.stdin.readline().strip().lower() not in ('y', 'yes'):
            raise Error('Not approved', EXIT_UNAPPROVED)
    record.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = record.with_name(MARKER + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.write(fd, found['data']); os.fsync(fd); os.close(fd)
    os.replace(temporary, record)
    emit(dict(public, action='allow', changed=found['state'] != 'approved', state='approved'),
         f'Approved {printable(found["marker"])} for session {found["session"]}')
    return 0


def map_in(c, host):
    """Host directory -> the path it has inside the session, or None if not mounted."""
    best = None
    for m in c['mounts']:
        source = m['source'].rstrip('/')
        if (host == source or host.startswith(source + '/')) and (best is None or len(source) > len(best[0])):
            best = (source, m['target'].rstrip('/') + host[len(source):])
    return best[1] if best else None


def map_out(c, inner):
    """Session directory -> host directory through the mounts; the same path otherwise."""
    best = None
    for m in c['mounts']:
        target = m['target'].rstrip('/')
        if (inner == target or inner.startswith(target + '/')) and (best is None or len(target) > len(best[0])):
            best = (target, m['source'].rstrip('/') + inner[len(target):])
    return best[1] if best else inner


def tree_roots(c, tree):
    """Session paths that lie inside the marked host tree."""
    roots = []
    for m in c['mounts']:
        source, target = m['source'].rstrip('/'), m['target'].rstrip('/')
        if source == tree or source.startswith(tree + '/'):
            roots.append(target)
        elif tree.startswith(source + '/'):
            roots.append(target + tree[len(source):])
    return roots


def read_leave(path, uid):
    """Directory a hook-entered shell left to. Written by the session: untrusted."""
    import stat
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_size > 4096:
            return None
        text = os.read(fd, 4096).decode('utf-8', 'replace').split('\n')[0]
    finally:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(path)
    try:
        return absolute(text) if text.isprintable() else None
    except Error:
        return None


# Host side, printed by `devsession hook bash`. Per prompt it runs shell
# builtins only; see docs/ARCHITECTURE.md for the measured cost.
HOOK_BASH = r'''# devsession directory activation for interactive Bash: eval "$(devsession hook bash)"
# Each prompt runs shell builtins only. A process is started solely when a
# component of the directory is a symbolic link (pwd -P) or a session is entered.
# Switch automatic entry off with DEVSESSION_AUTO_ENTER=0.
if [[ $- == *i* && -z ${DEVSESSION-} ]]; then
_DEVSESSION_STATE=@STATE@
_devsession_hook() {
    local _ds_rc=$? _ds_dir _ds_part _ds_marker _ds_text _ds_ok _ds_target _ds_round=0
    [[ ${DEVSESSION_AUTO_ENTER-1} == 0 || -n ${DEVSESSION-} ]] && return $_ds_rc
    while :; do
        _ds_dir=$PWD _ds_part=$PWD
        while [[ -n $_ds_part && $_ds_part != / ]]; do
            if [[ -L $_ds_part ]]; then _ds_dir=$(builtin pwd -P); break; fi
            _ds_part=${_ds_part%/*}
        done
        _ds_marker= _ds_part=$_ds_dir
        while :; do
            if [[ -f ${_ds_part%/}/.devsession ]]; then _ds_marker=$_ds_part; break; fi
            [[ -z $_ds_part || $_ds_part == / ]] && break
            _ds_part=${_ds_part%/*}; [[ -z $_ds_part ]] && _ds_part=/
        done
        if [[ -z $_ds_marker ]]; then _DEVSESSION_SKIP= _DEVSESSION_NOTED=; return $_ds_rc; fi
        [[ $_DEVSESSION_SKIP == "$_ds_marker" ]] && return $_ds_rc
        _DEVSESSION_SKIP=
        _ds_text= _ds_ok=
        IFS= read -r -d '' _ds_text < "${_ds_marker%/}/.devsession"
        if [[ -f $_DEVSESSION_STATE/allow${_ds_marker%/}/.devsession ]]; then
            IFS= read -r -d '' _ds_ok < "$_DEVSESSION_STATE/allow${_ds_marker%/}/.devsession"
            if [[ $_ds_text != "$_ds_ok" ]]; then
                [[ $_DEVSESSION_NOTED == "$_ds_marker:$_ds_text" ]] ||
                    printf 'devsession: %q changed after it was approved; review it, then run: devsession allow\n' "${_ds_marker%/}/.devsession" >&2
                _DEVSESSION_NOTED=$_ds_marker:$_ds_text; return $_ds_rc
            fi
        else
            [[ $_DEVSESSION_NOTED == "$_ds_marker:$_ds_text" ]] ||
                printf 'devsession: %q is not approved; review it, then run: devsession allow\n' "${_ds_marker%/}/.devsession" >&2
            _DEVSESSION_NOTED=$_ds_marker:$_ds_text; return $_ds_rc
        fi
        _DEVSESSION_NOTED=
        [[ -t 0 && -t 1 ]] || return $_ds_rc
        _ds_target=
        command devsession shell --hook-file "$_DEVSESSION_STATE/leave.$$"
        if [[ -f $_DEVSESSION_STATE/leave.$$ ]]; then
            IFS= read -r _ds_target < "$_DEVSESSION_STATE/leave.$$"
            command rm -f -- "$_DEVSESSION_STATE/leave.$$"
        fi
        # The session shell was left by changing directory out of the tree:
        # follow to the same place on the host and look again from there.
        if [[ -n $_ds_target && -d $_ds_target && $_ds_target != "$_ds_dir" && $((++_ds_round)) -le 8 ]] &&
           builtin cd -- "$_ds_target" 2>/dev/null; then
            continue
        fi
        [[ -n $_ds_target && ! -d $_ds_target ]] &&
            printf 'devsession: left the session; %q does not exist on the host\n' "$_ds_target" >&2
        # Plain exit (or a failed entry): stay on the host until this tree is left.
        _DEVSESSION_SKIP=$_ds_marker
        return $_ds_rc
    done
}
if [[ ${PROMPT_COMMAND[*]-} != *_devsession_hook* ]]; then
    if [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == 'declare -a'* ]]; then
        PROMPT_COMMAND=(_devsession_hook "${PROMPT_COMMAND[@]}")
    else
        PROMPT_COMMAND="_devsession_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
    fi
fi
fi
'''

# Session side: the startup file of a hook-entered shell. It sources the
# session's ordinary customization, then leaves the shell as soon as the
# working directory is outside the marked tree or under a nearer marker.
ACTIVATE_RC = r'''# Generated by devsession: session side of directory activation.
[ -f /etc/devsession.bashrc ] && source /etc/devsession.bashrc
if [[ -n ${DEVSESSION_TREE-} && -n ${DEVSESSION_LEAVE_FILE-} ]]; then
_devsession_leave() {
    local _ds_rc=$? _ds_root _ds_dir _ds_in=
    while IFS= read -r _ds_root; do
        [[ -z $_ds_root ]] && continue
        if [[ $PWD == "$_ds_root" || $PWD == "${_ds_root%/}"/* ]]; then
            _ds_in=1 _ds_dir=$PWD
            while [[ -n $_ds_dir && $_ds_dir != "$_ds_root" ]]; do
                if [[ -f $_ds_dir/.devsession ]]; then _ds_in=; break; fi
                _ds_dir=${_ds_dir%/*}
            done
            [[ -n $_ds_in && $_ds_root != "${DEVSESSION_TREE_MARKER-}" && -f $_ds_root/.devsession ]] && _ds_in=
            break
        fi
    done <<< "$DEVSESSION_TREE"
    [[ -n $_ds_in ]] && return $_ds_rc
    printf '%s\n' "$PWD" > "$DEVSESSION_LEAVE_FILE" 2>/dev/null
    exit 0
}
PROMPT_COMMAND=(_devsession_leave "${PROMPT_COMMAND[@]}")
fi
'''


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Error(f'{message} (try: {self.prog} --help)', EXIT_USAGE)


def common(top):
    """Options accepted both before and after the subcommand."""
    absent = (lambda value: value) if top else (lambda value: argparse.SUPPRESS)
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group('scripting options')
    g.add_argument('--json', action='store_true', default=absent(False),
                   help='Machine-readable results on stdout and one JSON error object on stderr')
    g.add_argument('-q', '--quiet', action='store_true', default=absent(False), help='No informational text')
    g.add_argument('--wait', type=float, metavar='SECONDS', default=absent(None),
                   help='Longest wait for the state lock (0: fail at once, negative: no limit). '
                        'Default 0 for changes, no limit for exec/shell/credential; env DEVSESSION_WAIT')
    g.add_argument('--non-interactive', action='store_true', default=absent(False),
                   help='Never prompt: fail with status 123 if sudo would need a password; env DEVSESSION_NONINTERACTIVE=1')
    g.add_argument('--user', metavar='NAME', default=absent(None),
                   help='Session owner; only when devsession itself is started by root (service, root cron)')
    return p


def action_of(argv):
    """The subcommand word of an argument vector (before argparse sees it)."""
    skip = False
    for word in argv:
        if skip:
            skip = False
        elif word in ('--wait', '--user'):
            skip = True
        elif not word.startswith('-'):
            return word
    return None


def parse(argv):
    # `exec -- COMMAND` (no session name: the directory decides) cannot be
    # expressed with argparse's REMAINDER, so the vector is split at the
    # first `--` and only the part before it is parsed for exec.
    if action_of(argv) == 'exec' and '--' in argv:
        cut = argv.index('--')
        args = parser(True).parse_args(argv[:cut])
        args.command = args.command + (['--'] if args.command else []) + argv[cut + 1:]
        return args
    return parser().parse_args(argv)


def parser(split=False):
    opts = common(False)
    p = Parser(prog='devsession', parents=[common(True)],
               description='Isolated Linux development sessions using host tools. Setup needs sudo; workloads never run as root.',
               epilog='Exit status: ' + '; '.join(f'{k} {v}' for k, v in EXIT_CODES.items()))
    p.add_argument('--version', action='version', version=VERSION)
    sub = p.add_subparsers(dest='action', required=True, parser_class=Parser)
    def add(parent, name, **kw):
        return parent.add_parser(name, parents=[opts], **kw)
    c = add(sub, 'create', help='Create persistent private state (default network: off)')
    c.add_argument('name'); c.add_argument('--mount', action='append', default=[], metavar='SOURCE:TARGET[:ro|rw]')
    c.add_argument('--tool', action='append', default=[], metavar='PATH', help='Explicit read-only host installation tree at the same absolute path')
    c.add_argument('--host-tools', action='store_true', help='Also mount, read-only, the installation tree of every host PATH entry outside /usr; inspect NAME lists them')
    c.add_argument('--shell-rc', help='Reviewed reusable Bash customization file (explicit trust/import)')
    c.add_argument('--cwd'); c.add_argument('--net', choices=['off', 'direct'])
    c.add_argument('--dns', action='append', metavar='IPv4'); c.add_argument('--allow-net', action='append', default=[], metavar='CIDR')
    c.add_argument('--publish', action='append', default=[], metavar='HOSTPORT:SESSIONPORT', help='Explicit loopback TCP proxy; requires systemd and socat')
    c.add_argument('--ensure', action='store_true', help='Succeed if the session already exists and agrees with the options given; never modifies it')
    for op in ['start', 'stop', 'delete', 'inspect', 'shell', 'status', 'exists']:
        q = add(sub, op, help={'status': 'Exit 0 running, 3 stopped, 122 absent',
                               'exists': 'Exit 0 if the session exists, 1 if not'}.get(op))
        if op in ['delete', 'exists']:
            q.add_argument('name', help='Session name, or "." for the session this directory is bound to')
        else:
            q.add_argument('name', nargs='?', help='Session name; omitted or ".": the session this directory is bound to')
        if op in ['stop', 'delete']:
            q.add_argument('--if-exists', action='store_true', help='Succeed when there is no such session')
        if op == 'delete':
            q.add_argument('--no-logout', action='store_true', help='Do not try to log a Tailscale node out of its tailnet first')
        if op == 'shell':
            q.add_argument('--forward', action='append', default=[], metavar='VARIABLE')
            q.add_argument('--cwd', metavar='DIR', help='Working directory inside the session')
            q.add_argument('--hook-file', help=argparse.SUPPRESS)  # used by the shell hook only
    q = add(sub, 'exec', help='Run argv without shell interpolation, auto-starting if necessary')
    q.add_argument('--forward', action='append', default=[], metavar='VARIABLE')
    q.add_argument('--cwd', metavar='DIR', help='Working directory inside the session for this call')
    q.add_argument('--env', action='append', default=[], metavar='NAME=VALUE',
                   help='Variable for this call only (visible in host process listings; use --env-file for secrets)')
    q.add_argument('--env-file', action='append', default=[], metavar='FILE', help='Literal NAME=value lines for this call only')
    g = q.add_mutually_exclusive_group()
    g.add_argument('-t', '--tty', dest='tty', action='store_const', const='always', default='auto',
                   help='Always give the command a pseudo-terminal')
    g.add_argument('-T', '--no-tty', dest='tty', action='store_const', const='never',
                   help='Never allocate a pseudo-terminal (binary-clean stdio even on a terminal)')
    q.add_argument('--no-start', action='store_true', help='Fail with status 125 instead of starting a stopped session')
    q.add_argument('--status-file', metavar='FILE',
                   help='Write a JSON record saying whether the exit status is the command\'s or devsession\'s')
    if split:
        q.add_argument('name', nargs='?'); q.add_argument('command', nargs='*')
    else:
        q.add_argument('name', help='Session name; with "exec -- COMMAND" the directory decides')
        q.add_argument('command', nargs=argparse.REMAINDER)
    q = add(sub, 'allow', help='Approve the nearest .devsession marker after showing exactly what it grants')
    q.add_argument('dir', nargs='?', default='.'); q.add_argument('-y', '--yes', action='store_true', help='Do not ask (the grant is still printed)')
    q = add(sub, 'deny', help='Revoke the approval of the nearest .devsession marker'); q.add_argument('dir', nargs='?', default='.')
    q = add(sub, 'resolve', help='Print the session a directory is bound to: exit 0 approved, 1 no marker, 119 not approved')
    q.add_argument('dir', nargs='?', default='.')
    q = add(sub, 'hook', help='Print shell integration; use: eval "$(devsession hook bash)"'); q.add_argument('shell', choices=['bash'])
    add(sub, 'list'); add(sub, 'doctor', help='Report prerequisites and host tool paths; exit 1 if a required one is missing')
    add(sub, 'version', help='Print the version (and the exit-status table with --json)')
    add(sub, 'cleanup', help='Clean stale owned resources; restore forwarding if all sessions stopped')
    e = add(sub, 'env', help='Session environment; files are literal NAME=value data').add_subparsers(dest='env_action', required=True, parser_class=Parser)
    q = add(e, 'set'); q.add_argument('name'); q.add_argument('key'); q.add_argument('value', nargs='?')
    g = q.add_mutually_exclusive_group(); g.add_argument('--stdin', action='store_true'); g.add_argument('--file')
    q = add(e, 'import'); q.add_argument('name'); q.add_argument('file', help='File or - for stdin')
    q = add(e, 'unset'); q.add_argument('name'); q.add_argument('key')
    n = add(sub, 'net').add_subparsers(dest='net_action', required=True, parser_class=Parser)
    q = add(n, 'set'); q.add_argument('name'); q.add_argument('mode', choices=['off', 'direct', 'vpn'])
    v = add(sub, 'vpn').add_subparsers(dest='vpn_action', required=True, parser_class=Parser)
    q = add(v, 'configure'); q.add_argument('name')
    g = q.add_mutually_exclusive_group(required=True); g.add_argument('--wireguard'); g.add_argument('--openvpn')
    g.add_argument('--tailscale', action='store_true', help='Join a tailnet as this session\'s own node')
    q.add_argument('--dns', action='append', metavar='IPv4')
    t = q.add_argument_group('tailscale options')
    k = t.add_mutually_exclusive_group()
    k.add_argument('--auth-key-file', metavar='FILE', help='Auth key for unattended login (never on the command line)')
    k.add_argument('--auth-key-stdin', action='store_true', help='Read the auth key from stdin')
    t.add_argument('--login-server', metavar='URL', help='Self-hosted control server; default is Tailscale\'s')
    t.add_argument('--ca-file', metavar='FILE', help='Extra PEM CA certificate(s) for a self-hosted control or relay server')
    t.add_argument('--exit-node', metavar='PEER', help='Send all IPv4 through this peer; without it only tailnet addresses and accepted routes are reachable')
    t.add_argument('--accept-routes', action='store_true', help='Accept subnet routes advertised in the tailnet')
    t.add_argument('--hostname', metavar='NAME', help='Node name in the tailnet (default ds-SESSION)')
    t.add_argument('--transport-net', action='append', default=[], metavar='CIDR',
                   help='Private range the gateway daemon (never a workload) may reach, e.g. a control server on a private address')
    q = add(sub, 'credential', help='Import stdin/file into private HOME, never argv; auto-starts session')
    q.add_argument('name'); q.add_argument('destination', help='Relative path in private HOME, e.g. .ssh/id_ed25519')
    q.add_argument('--file', help='Default is stdin')
    return p


REQUIRED = ['bwrap', 'ip', 'nft', 'nsenter', 'setpriv', 'python3']


def doctor(context):
    cmds = ['bwrap', 'ip', 'nft', 'nsenter', 'setpriv', 'wg', 'openvpn', 'tailscale', 'tailscaled', 'socat',
            'terraform', 'ansible', 'tmux', 'oh-my-posh', 'az', 'python3', 'node', 'rustc', 'mise', 'pyenv']
    found = {cmd: shutil.which(cmd, path=context.get('path', SYSTEM_PATH)) for cmd in cmds}
    missing = [cmd for cmd in REQUIRED if not found[cmd]]
    if OUT['json']:
        print(json.dumps(dict(version=VERSION, ok=not missing, missing_required=missing, commands={
            cmd: dict(path=path, resolved=str(Path(path).resolve()) if path else None, required=cmd in REQUIRED)
            for cmd, path in found.items()}), indent=2))
        return 1 if missing else 0
    for cmd, path in found.items():
        print(f'{cmd}: {path or "MISSING"}' + (f' -> {Path(path).resolve()}' if path else ''))
    print('Requires Bubblewrap >=0.11 (--bind-fd), util-linux nsenter --wdns, nftables, user/network/mount/PID namespaces.')
    print('Default installation mounts: /usr + merged-usr libraries; ~/.local/bin, ~/.opencode/bin, /opt/devsession-tools/azure when present.')
    print('Additional runtimes/toolchains: create --tool PATH; inspect NAME shows all approved mounts.')
    return 1 if missing else 0


def invocation(args):
    """Explicit per-call data from the invoking environment; literal values only."""
    forwards = {env_key(k): os.environ[k] for k in getattr(args, 'forward', []) if k in os.environ}
    extra = {}
    for name in getattr(args, 'env_file', []):
        extra.update(env_file(Path(name).read_text()))
    for item in getattr(args, 'env', []):
        if '=' not in item:
            raise Error('--env needs NAME=VALUE', EXIT_USAGE)
        k, v = item.split('=', 1)
        if '\0' in v:
            raise Error('NUL is forbidden in environment data', EXIT_USAGE)
        extra[env_key(k)] = v
    wait = args.wait
    if wait is None and os.environ.get('DEVSESSION_WAIT'):
        try:
            wait = float(os.environ['DEVSESSION_WAIT'])
        except ValueError:
            raise Error('DEVSESSION_WAIT must be a number of seconds', EXIT_USAGE)
    return dict(path=os.environ.get('PATH', SYSTEM_PATH), forward=forwards, env=extra, wait=wait,
                status_file=os.path.abspath(args.status_file) if getattr(args, 'status_file', None) else None,
                terminal={k: os.environ[k] for k in ['TERM', 'COLORTERM', 'LANG'] if k in os.environ})


def can_prompt(args):
    if args.non_interactive or os.environ.get('DEVSESSION_NONINTERACTIVE', '0') not in ('', '0'):
        return False
    try:
        os.close(os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY))
        return True
    except OSError:
        return False


def lock_state(wait):
    """Exclusive state lock with a bounded wait (None or negative: no limit)."""
    lock = open(ROOT / '.lock', 'a')
    if wait is None or wait < 0:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return lock
    deadline = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock
        except BlockingIOError:
            if time.monotonic() >= deadline:
                lock.close()
                raise Error('Another lifecycle operation is in progress; retry shortly or pass --wait SECONDS', EXIT_BUSY)
            time.sleep(.05)


def write_status(record):
    """Attribution record for exec --status-file."""
    write_owner(OUT.get('status_file'), (json.dumps(record) + '\n').encode() if record else b'')


def write_owner(path, data):
    """Write a caller-named file with the caller's own rights, never as root."""
    if not path:
        return
    def store():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.write(fd, data); os.close(fd)
    owner = OUT.get('owner')
    if os.geteuid() != 0 or owner is None:
        with contextlib.suppress(OSError):
            store()
        return
    pid = os.fork()
    if pid == 0:
        try:
            os.initgroups(owner.pw_name, owner.pw_gid); os.setgid(owner.pw_gid); os.setuid(owner.pw_uid)
            store()
        except BaseException:
            os._exit(1)
        os._exit(0)
    os.waitpid(pid, 0)


def emit(result, text=None):
    if OUT['json']:
        print(json.dumps(result, indent=2))
    elif text and not OUT['quiet']:
        print(text)


def state_of(c):
    return 'running' if alive(c) else 'stopped'


def summary(c):
    return dict(name=c['name'], state=state_of(c), running=alive(c), mode=c['mode'], phase=c.get('phase', 'stopped'))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    # A caller may have closed stdin/stdout/stderr. Occupy the slots so that
    # no internal descriptor (lock, status pipe) is ever handed on as stdio.
    for fd in (0, 1, 2):
        try:
            os.fstat(fd)
        except OSError:
            os.set_inheritable(os.open(os.devnull, os.O_RDWR), True)
    OUT['json'] = '--json' in (argv[:argv.index('--')] if '--' in argv else argv)
    args = parse(argv)
    OUT.update(json=args.json, quiet=args.quiet)
    if args.action == 'version':
        emit(dict(version=VERSION, exit_codes=EXIT_CODES), VERSION)
        return 0
    if args.action in ['allow', 'deny', 'resolve', 'hook']:
        if os.geteuid() == 0:
            raise Error('Directory approvals belong to a user; run this as that user, not as root', EXIT_USAGE)
        return activation(args)
    by_dir = args.action != 'create' and hasattr(args, 'name') and args.name in (None, '.')
    direct_root = os.geteuid() == 0 and 'SUDO_UID' not in os.environ
    if args.user and not direct_root:
        raise Error('--user is only for invocations started by root itself, not through sudo', EXIT_USAGE)
    if os.geteuid() != 0:
        context = invocation(args)
        OUT['status_file'] = context['status_file']
        write_status(None)  # a stale record must never be mistaken for this call's
        context['state_home'] = str(state_home())
        if getattr(args, 'hook_file', None):
            context['hook_file'] = os.path.abspath(args.hook_file)
            write_owner(context['hook_file'], b'')
        if by_dir:
            # The marker is read, parsed and checked against the approval here,
            # as the user. Root receives the resulting name and two paths.
            found = directory_session()
            context.update(session=found['session'], tree=found['dir'], hostcwd=os.path.realpath(os.getcwd()))
        if args.action == 'doctor':
            return doctor(context)
        # No arbitrary host environment, agent socket or token is inherited by
        # the privileged interpreter. -I ignores Python discovery variables.
        clean = {'PATH': SYSTEM_PATH, 'TERM': os.environ.get('TERM', 'xterm')}
        sudo = ['sudo']
        if not can_prompt(args):
            # Unattended: never let sudo prompt. A separate probe gives this
            # failure its own status instead of sudo's generic 1.
            if sp.run(['/usr/bin/sudo', '-n', 'true'], stdin=sp.DEVNULL, stdout=sp.DEVNULL,
                      stderr=sp.DEVNULL, env=clean).returncode:
                raise Error('Root privilege is required, sudo needs a password and no prompt is possible '
                            '(no terminal, or --non-interactive). Use an account with passwordless sudo, '
                            'refresh the credential first (sudo -v), or run as root with --user NAME',
                            EXIT_PRIVILEGE)
            sudo.append('-n')
        os.execve('/usr/bin/sudo', sudo + ['--preserve-env=DEVSESSION_CONTEXT', '--',
                  '/usr/bin/python3', '-I', str(Path(__file__).resolve())] + argv,
                  dict(clean, DEVSESSION_CONTEXT=json.dumps(context)))
    if 'DEVSESSION_CONTEXT' in os.environ:
        context = json.loads(os.environ.pop('DEVSESSION_CONTEXT'))
    else:
        context = invocation(args)  # started by root itself: this is the invoking environment
    try:
        user = pwd.getpwnam(args.user) if args.user else pwd.getpwuid(int(os.environ.get('SUDO_UID', os.getuid())))
    except KeyError:
        raise Error(f'Unknown user: {args.user}', EXIT_USAGE)
    OUT.update(status_file=context.get('status_file'), owner=user if user.pw_uid else None)
    if by_dir:
        if not context.get('session'):
            raise Error('A session name is required here: directory resolution needs the invoking '
                        'user\'s own approval records', EXIT_USAGE)
        args.name = context['session']
    if user.pw_uid == 0 and args.action not in ['doctor', 'cleanup', 'list']:
        raise Error('Invoke as a normal host user (or via sudo from that user, or as root with --user NAME); '
                    'root workloads are forbidden', EXIT_USAGE)
    os.environ.clear(); os.environ.update(PATH=SYSTEM_PATH, LANG='C.UTF-8')
    os.umask(0o077)
    ROOT.mkdir(mode=0o711, exist_ok=True)
    if args.action == 'doctor':
        return doctor(context)
    # Read-only queries take no lock: state files are replaced atomically, so
    # a query never blocks behind (or delays) a long-running start.
    if args.action == 'list':
        sessions = list(configs(user.pw_uid if user.pw_uid else None))
        if OUT['json']:
            print(json.dumps(dict(sessions=[summary(c) for c in sessions]), indent=2))
        else:
            for c in sessions:
                print(f'{c["name"]}\t{state_of(c)}\t{c["mode"]}')
        return 0
    if args.action in ['exists', 'status']:
        c = load(user.pw_uid, args.name, missing_ok=True)
        if args.action == 'exists':
            emit(dict(name=args.name, exists=bool(c)))
            return 0 if c else 1
        if not c:
            emit(dict(name=args.name, exists=False, state='absent', running=False), 'absent')
            return EXIT_NOSESSION
        emit(dict(summary(c), exists=True), state_of(c))
        return 0 if alive(c) else 3
    if args.action == 'inspect':
        c = load(user.pw_uid, args.name)
        public = dict(c)
        public['env'] = {k: '<redacted>' for k in c['env']}
        public['running'] = alive(c)
        public['namespaces'] = dict(zip(['workload', 'gateway', 'host_veth', 'nft_table'], names(c)))
        print(json.dumps(public, indent=2))
        return 0
    wait = context.get('wait')
    if wait is None and args.action not in ['exec', 'shell', 'credential']:
        wait = 0
    lock = lock_state(wait)
    def release():
        if not lock.closed:
            lock.close()
    try:
        result = dict(action=args.action, changed=True)
        if args.action == 'create':
            result.update(name=args.name, changed=create(args, user, context))
            emit(result, f'Created {args.name}; run devsession shell {args.name}' if result['changed']
                 else f'Session {args.name} already exists')
            return 0
        if args.action == 'cleanup':
            for p in ROOT.glob('.create-*'):
                shutil.rmtree(p)
            for c in list(configs()):
                if not alive(c):
                    stop(c)
            if not any(alive(c) for c in configs()) and (ROOT / 'forwarding-before').exists():
                run(['sysctl', '-qw', 'net.ipv4.ip_forward=' + (ROOT / 'forwarding-before').read_text().strip()])
                (ROOT / 'forwarding-before').unlink()
            emit(result)
            return 0
        c = load(user.pw_uid, args.name, missing_ok=getattr(args, 'if_exists', False))
        result['name'] = args.name
        if c is None:  # stop/delete --if-exists
            emit(dict(result, changed=False, state='absent'))
            return 0
        if args.action == 'start':
            result['changed'] = not alive(c)
            start(c)
        elif args.action in ['stop', 'delete']:
            result['changed'] = args.action == 'delete' or alive(c) or c.get('phase') != 'stopped'
            if args.action == 'delete' and not args.no_logout:
                logged_out = tailscale_logout(c)
                if logged_out is not None:
                    result['tailscale_logout'] = logged_out
                    if not logged_out and not OUT['quiet']:
                        print('devsession: could not log the Tailscale node out; it stays registered until '
                              'its key expires or it is removed in the tailnet', file=sys.stderr)
            stop(c)
            if args.action == 'delete':
                shutil.rmtree(c['state'])
                emit(dict(result, state='absent'))
                return 0
        elif args.action == 'env':
            if args.env_action == 'set':
                k = env_key(args.key)
                if args.value is not None and (args.stdin or args.file):
                    raise Error('Use a value OR --stdin/--file', EXIT_USAGE)
                value = sys.stdin.read().removesuffix('\n') if args.stdin else Path(args.file).read_text().removesuffix('\n') if args.file else args.value
                if value is None or '\0' in value:
                    raise Error('Supply a value, --stdin or --file (NUL is forbidden)', EXIT_USAGE)
                c['env'][k] = value
            elif args.env_action == 'import':
                c['env'].update(env_file(sys.stdin.read() if args.file == '-' else Path(args.file).read_text()))
            else:
                result['changed'] = c['env'].pop(env_key(args.key), None) is not None
            save(c)
        elif args.action == 'net':
            if c['mode'] == args.mode:
                result['changed'] = False  # already so: no stop is required
            else:
                stopped(c)
                if args.mode == 'vpn' and not c.get('vpn'):
                    raise Error('Configure WireGuard, OpenVPN or Tailscale before selecting VPN mode', EXIT_CONFLICT)
                c['mode'] = args.mode; save(c)
        elif args.action == 'vpn':
            stopped(c)
            folder = Path(c['state']) / 'vpn'
            # Import is stopped-only. On invalid input retain the previous config.
            staging = Path(c['state']) / 'vpn-import'
            shutil.rmtree(staging, ignore_errors=True); staging.mkdir(mode=0o700)
            try:
                if args.tailscale:
                    args.previous_dir = str(folder)
                    v = tailscale_import(args, staging, c.get('vpn') or {})
                    old = c.get('vpn') or {}
                    if old.get('kind') == 'tailscale' and old.get('login_server') != v['login_server']:
                        # A node identity belongs to one control server.
                        shutil.rmtree(ts_paths(c)[2], ignore_errors=True)
                elif any([args.auth_key_file, args.auth_key_stdin, args.login_server, args.ca_file, args.exit_node,
                          args.accept_routes, args.hostname, args.transport_net]):
                    raise Error('Those options belong to --tailscale', EXIT_USAGE)
                else:
                    v = wireguard_import(args.wireguard, staging, args.dns) if args.wireguard else openvpn_import(args.openvpn, staging, args.dns)
                if v['kind'] == 'openvpn':
                    data = (staging / 'client.ovpn').read_text().replace(str(staging) + '/', str(folder) + '/')
                    write(staging / 'client.ovpn', data)
                shutil.rmtree(folder, ignore_errors=True)
                staging.rename(folder); c['vpn'] = v; save(c)
            finally:
                shutil.rmtree(staging, ignore_errors=True)
        elif args.action in ['exec', 'shell', 'credential']:
            if getattr(args, 'no_start', False) and not alive(c):
                raise Error('Session is stopped and exec --no-start was given', EXIT_CONFLICT)
            start(c)
            extra = dict(context.get('terminal', {}))
            extra.update({env_key(k): v for k, v in context.get('forward', {}).items()})
            extra.update({env_key(k): v for k, v in context.get('env', {}).items()})
            cwd = absolute(args.cwd) if getattr(args, 'cwd', None) else None
            leave = None
            if by_dir and cwd is None and args.action != 'credential':
                # Same place, as the session sees it: the host directory mapped through the mounts.
                cwd = map_in(c, absolute(context['hostcwd']))
                if cwd is None:
                    raise Error(f'{printable(context["hostcwd"])} is not inside a mount of session {c["name"]}; '
                                'mount the project there or pass --cwd')
            if args.action == 'shell':
                command = ['/bin/bash', '--noprofile', '--rcfile', '/etc/devsession.bashrc', '-i']
                if by_dir and context.get('hook_file'):
                    if Path(f'/proc/{c["pid"]}/root/etc/devsession-activate.bashrc').exists():
                        import secrets
                        leave = 'devsession-leave-' + secrets.token_hex(8)
                        tree = absolute(context['tree'])
                        extra.update(DEVSESSION_TREE='\n'.join(tree_roots(c, tree)),
                                     DEVSESSION_TREE_MARKER=map_in(c, tree) or '',
                                     DEVSESSION_LEAVE_FILE=f'/run/user/{c["uid"]}/{leave}')
                        command[3] = '/etc/devsession-activate.bashrc'
                    else:
                        print('devsession: this session was started by an older version; restart it '
                              'to be returned to the host on leaving the tree', file=sys.stderr)
            elif args.action == 'credential':
                dest = Path(args.destination)
                if dest.is_absolute() or '..' in dest.parts or not dest.parts:
                    raise Error('Credential destination must be a relative path inside private HOME', EXIT_USAGE)
                # Copy inside the isolated filesystem, as the unprivileged user;
                # symlinks cannot make the helper write to host private paths.
                command = ['/usr/bin/python3', '-I', '-c',
                           'import os,pathlib,sys; p=pathlib.Path(os.environ["HOME"])/sys.argv[1]; p.parent.mkdir(mode=0o700,parents=True,exist_ok=True); f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600); os.write(f,sys.stdin.buffer.read()); os.close(f)', str(dest)]
                if args.file:
                    f = open(args.file, 'rb'); os.dup2(f.fileno(), 0); f.close()
            else:
                command = args.command
                if command[:1] == ['--']:
                    command = command[1:]
                if not command:
                    raise Error('exec needs a command after NAME --', EXIT_USAGE)
            code, record = execute(c, command, overrides=extra, release=release, cwd=cwd,
                                   tty=getattr(args, 'tty', 'auto'))
            write_status(record)
            OUT['status_file'] = None
            if leave:
                target = read_leave(Path(c['state']) / 'run' / leave, c['uid'])
                if target:
                    write_owner(context['hook_file'], (map_out(c, target) + '\n').encode())
            return code
        emit(dict(result, state=state_of(c)))
        return 0
    finally:
        release()


def fail(code, message):
    complain(code, message)
    write_status(dict(source='devsession', exit_code=code, signal=None, error=KINDS.get(code, 'error')))
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Error as e:
        sys.exit(fail(e.code, str(e)))
    except BrokenPipeError:
        # The reader of our own output went away; behave like a SIGPIPE death.
        os.dup2(os.open(os.devnull, os.O_WRONLY), 1)
        sys.exit(141)
    except (ValueError, OSError) as e:
        sys.exit(fail(EXIT_ERROR, str(e)))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:  # never a bare traceback with an unreserved status
        sys.exit(fail(EXIT_ERROR, f'internal error: {type(e).__name__}: {e}'))
