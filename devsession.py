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


class Error(Exception):
    pass


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


def network(c):
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
    run(['ip', 'addr', 'add', a + '/30', 'dev', hostif])
    run(['ip', '-n', gateway, 'addr', 'add', b + '/30', 'dev', 'wan'])
    run(['ip', '-n', gateway, 'link', 'add', 'lan', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', client])
    run(['ip', '-n', gateway, 'addr', 'add', '10.203.0.1/30', 'dev', 'lan'])
    run(['ip', '-n', client, 'addr', 'add', '10.203.0.2/30', 'dev', 'eth0'])
    vpn = c.get('vpn', {}) if c['mode'] == 'vpn' else {}
    transport = ''
    if vpn:
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
    if vpn:
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
    if vpn:
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
        raise Error('Session is stopped; run devsession start NAME first')
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
    return args + [f'--wdns={c.get("cwd", c["home"])}', '--', '/usr/bin/setpriv',
            '--reuid', str(c['uid']), '--regid', str(c['gid']), '--clear-groups',
            '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
            '--'] + command


def execute(c, command, *, capture=False, overrides=None, release=None):
    # Never inject session LD_PRELOAD/PYTHONPATH/etc into privileged nsenter or
    # setpriv. Hand environment over only AFTER dropping all privileges.
    fd = os.memfd_create('devsession-env', os.MFD_CLOEXEC)
    os.write(fd, json.dumps(environment(c, overrides)).encode())
    os.lseek(fd, 0, 0)
    # Close all namespace/root descriptors before workload exec, including the
    # root handle: no inherited setup handle should be reachable via /proc/fd.
    fds = [fd]
    # nsenter's default waiting parent does not forward directed signals. Its
    # --no-fork form sets the child PID namespace; this unprivileged supervisor
    # forks into it, forwards signals and returns the actual command status.
    launcher = '''import os,sys,json,signal,pty,termios,tty,fcntl,select,errno
f=os.fdopen(int(sys.argv[1])); e=json.load(f); f.close()
os.closerange(3,4096); os.umask(0o077)
interactive=os.isatty(0) and os.isatty(1)
if interactive:
 master,slave=pty.openpty()
 def resize(*unused):
  try: fcntl.ioctl(master,termios.TIOCSWINSZ,fcntl.ioctl(0,termios.TIOCGWINSZ,b'\\0'*8))
  except OSError: pass
 resize()
child=os.fork()
if child == 0:
 if interactive:
  os.close(master); os.setsid(); fcntl.ioctl(slave,termios.TIOCSCTTY,0)
  for fd in (0,1,2): os.dup2(slave,fd)
  if slave>2: os.close(slave)
 for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,signal.SIG_DFL)
 os.execvpe(sys.argv[2],sys.argv[2:],e)
def forward(sig,frame):
 try:
  if interactive: os.killpg(os.tcgetpgrp(master),sig)
  else: os.kill(child,sig)
 except (ProcessLookupError,OSError): pass
for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,forward)
if interactive:
 os.close(slave)
 signal.signal(signal.SIGWINCH,resize)
 previous=termios.tcgetattr(0)
 def sendall(fd,data):
  while data: data=data[os.write(fd,data):]
 try:
  tty.setraw(0)
  readers=[0,master]
  while True:
   ready,_,_=select.select(readers,[],[])
   if master in ready:
    try: data=os.read(master,65536)
    except OSError as err:
     if err.errno==errno.EIO: break
     raise
    if not data: break
    sendall(1,data)
   if 0 in ready:
    data=os.read(0,65536)
    if data: sendall(master,data)
    else: readers.remove(0)
 finally:
  termios.tcsetattr(0,termios.TCSADRAIN,previous); os.close(master)
_,status=os.waitpid(child,0)
rc=os.waitstatus_to_exitcode(status)
sys.exit(rc if rc>=0 else 128-rc)
'''
    try:
        args = enter_args(c, ['/usr/bin/python3', '-I', '-c', launcher, str(fd)] + command, fds)
    except BaseException:
        for handle in fds:
            os.close(handle)
        raise
    safe = {'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'}
    if capture:
        try:
            return sp.run(args, env=safe, text=True, capture_output=True, pass_fds=tuple(fds))
        finally:
            for handle in fds:
                os.close(handle)
    try:
        p = sp.Popen(args, env=safe, pass_fds=tuple(fds))
    finally:
        for handle in fds:
            os.close(handle)
    if release:
        release()
    old = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        old[sig] = signal.signal(sig, lambda s, f: p.send_signal(s) if p.poll() is None else None)
    try:
        rc = p.wait()
        return rc if rc >= 0 else 128 - rc
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


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
    c.pop('pid', None)
    c.pop('birth', None)
    c.pop('net_inode', None)
    c['phase'] = 'stopped'
    save(c)


RESERVED_ENV = {'HOME', 'USER', 'LOGNAME', 'SHELL', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
                'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR', 'TMPDIR', 'TMUX_TMPDIR', 'TMUX',
                'AZURE_CONFIG_DIR', 'DEVSESSION'}
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


def configs(uid=None):
    for p in sorted(ROOT.glob('*/config.json')):
        c = json.loads(p.read_text())
        if uid is None or c['uid'] == uid:
            yield c


def load(uid, name):
    p = state_path(uid, name) / 'config.json'
    if not p.exists():
        raise Error(f'No session {name!r}; use devsession list')
    return json.loads(p.read_text())


def stopped(c):
    if alive(c):
        raise Error('Stop the session before changing mounts, VPN or network mode')
    stop(c)  # recover any incomplete/stale setup before modifying it


def absolute(path):
    if not path.startswith('/') or '..' in Path(path).parts or '\n' in path or '\0' in path:
        raise Error(f'Expected an absolute path without ..: {path}')
    return str(Path(path))


def mount_spec(spec, home):
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


def create(args, user, context):
    import secrets
    path = state_path(user.pw_uid, args.name)
    if path.exists():
        raise Error('Session already exists; use start or delete it first')
    mounts = [mount_spec(m, user.pw_dir) for m in args.mount]
    targets = [m['target'] for m in mounts]
    if any(a == b or a.startswith(b + '/') or b.startswith(a + '/')
           for i, a in enumerate(targets) for b in targets[i + 1:]):
        raise Error('Overlapping mount targets are unsupported')
    tools = []
    for p in [user.pw_dir + '/.local/bin', user.pw_dir + '/.opencode/bin', '/opt/devsession-tools/azure']:
        if Path(p).exists():
            tools.append(tool_path(p, user.pw_dir))
    tools += [tool_path(p, user.pw_dir) for p in args.tool]
    if args.host_tools:
        tools += host_tools(context.get('path', SYSTEM_PATH), user.pw_dir)
    publish = []
    for p in args.publish:
        a, b = map(int, p.split(':'))
        if not 1024 <= a <= 65535 or not 1 <= b <= 65535:
            raise Error('Publish needs HOSTPORT:SESSIONPORT; host port must be 1024..65535')
        publish.append([a, b])
    if len({x[0] for x in publish}) != len(publish):
        raise Error('Duplicate published host port')
    c = dict(name=args.name, tag=secrets.token_hex(5), state=str(path), uid=user.pw_uid, gid=user.pw_gid,
             user=user.pw_name, home=user.pw_dir, shell='/bin/bash', path=context.get('path', SYSTEM_PATH),
             mode=args.net, dns=[ipv4(x) for x in (args.dns or ['1.1.1.1'])],
             allow_net=[str(ipaddress.IPv4Network(x, strict=False)) for x in args.allow_net],
             mounts=mounts, tools=list(dict.fromkeys(tools)), publish=publish,
             transport=allocate(), env={}, phase='stopped',
             cwd=absolute(args.cwd) if args.cwd else (mounts[0]['target'] if mounts and Path(mounts[0]['source']).is_dir() else user.pw_dir))
    # Do not import startup files implicitly. This file is an explicit policy.
    rc = "[ -f ~/.bashrc ] && source ~/.bashrc\nPS1='[${DEVSESSION}] \\u@\\h:\\w\\$ '\n"
    if args.shell_rc:
        rc = Path(args.shell_rc).read_text() + '\n[ -f ~/.bashrc ] && source ~/.bashrc\n'
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
    print(f'Created {args.name}; run devsession shell {args.name}')


def parser():
    p = argparse.ArgumentParser(prog='devsession', description='Isolated Linux development sessions using host tools. Setup needs sudo; workloads never run as root.')
    sub = p.add_subparsers(dest='action', required=True)
    c = sub.add_parser('create', help='Create persistent private state (default network: off)')
    c.add_argument('name'); c.add_argument('--mount', action='append', default=[], metavar='SOURCE:TARGET[:ro|rw]')
    c.add_argument('--tool', action='append', default=[], metavar='PATH', help='Explicit read-only host installation tree at the same absolute path')
    c.add_argument('--host-tools', action='store_true', help='Also mount, read-only, the installation tree of every host PATH entry outside /usr; inspect NAME lists them')
    c.add_argument('--shell-rc', help='Reviewed reusable Bash customization file (explicit trust/import)')
    c.add_argument('--cwd'); c.add_argument('--net', choices=['off', 'direct'], default='off')
    c.add_argument('--dns', action='append', metavar='IPv4'); c.add_argument('--allow-net', action='append', default=[], metavar='CIDR')
    c.add_argument('--publish', action='append', default=[], metavar='HOSTPORT:SESSIONPORT', help='Explicit loopback TCP proxy; requires systemd and socat')
    for op in ['start', 'stop', 'delete', 'inspect', 'shell']:
        q = sub.add_parser(op); q.add_argument('name')
        if op == 'shell':
            q.add_argument('--forward', action='append', default=[], metavar='VARIABLE')
    q = sub.add_parser('exec', help='Run argv without shell interpolation, auto-starting if necessary')
    q.add_argument('--forward', action='append', default=[], metavar='VARIABLE')
    q.add_argument('name'); q.add_argument('command', nargs=argparse.REMAINDER)
    sub.add_parser('list'); sub.add_parser('doctor', help='Report prerequisites and host tool paths')
    sub.add_parser('cleanup', help='Clean stale owned resources; restore forwarding if all sessions stopped')
    e = sub.add_parser('env', help='Session environment; files are literal NAME=value data').add_subparsers(dest='env_action', required=True)
    q = e.add_parser('set'); q.add_argument('name'); q.add_argument('key'); q.add_argument('value', nargs='?')
    g = q.add_mutually_exclusive_group(); g.add_argument('--stdin', action='store_true'); g.add_argument('--file')
    q = e.add_parser('import'); q.add_argument('name'); q.add_argument('file', help='File or - for stdin')
    q = e.add_parser('unset'); q.add_argument('name'); q.add_argument('key')
    n = sub.add_parser('net').add_subparsers(dest='net_action', required=True)
    q = n.add_parser('set'); q.add_argument('name'); q.add_argument('mode', choices=['off', 'direct', 'vpn'])
    v = sub.add_parser('vpn').add_subparsers(dest='vpn_action', required=True)
    q = v.add_parser('configure'); q.add_argument('name')
    g = q.add_mutually_exclusive_group(required=True); g.add_argument('--wireguard'); g.add_argument('--openvpn')
    q.add_argument('--dns', action='append', metavar='IPv4')
    q = sub.add_parser('credential', help='Import stdin/file into private HOME, never argv; auto-starts session')
    q.add_argument('name'); q.add_argument('destination', help='Relative path in private HOME, e.g. .ssh/id_ed25519')
    q.add_argument('--file', help='Default is stdin')
    return p


def doctor(context):
    cmds = ['bwrap', 'ip', 'nft', 'nsenter', 'setpriv', 'wg', 'openvpn', 'socat',
            'terraform', 'ansible', 'tmux', 'oh-my-posh', 'az', 'python3', 'node', 'rustc', 'mise', 'pyenv']
    for cmd in cmds:
        found = shutil.which(cmd, path=context.get('path', SYSTEM_PATH))
        print(f'{cmd}: {found or "MISSING"}' + (f' -> {Path(found).resolve()}' if found else ''))
    print('Requires Bubblewrap >=0.11 (--bind-fd), util-linux nsenter --wdns, nftables, user/network/mount/PID namespaces.')
    print('Default installation mounts: /usr + merged-usr libraries; ~/.local/bin, ~/.opencode/bin, /opt/devsession-tools/azure when present.')
    print('Additional runtimes/toolchains: create --tool PATH; inspect NAME shows all approved mounts.')


def main():
    args = parser().parse_args()
    if os.geteuid() != 0:
        forwards = {env_key(k): os.environ[k] for k in getattr(args, 'forward', []) if k in os.environ}
        context = dict(path=os.environ.get('PATH', SYSTEM_PATH), forward=forwards,
                       terminal={k: os.environ[k] for k in ['TERM', 'COLORTERM', 'LANG'] if k in os.environ})
        if args.action == 'doctor':
            doctor(context)
            return 0
        # No arbitrary host environment, agent socket or token is inherited by
        # the privileged interpreter. -I ignores Python discovery variables.
        os.execve('/usr/bin/sudo', ['sudo', '--preserve-env=DEVSESSION_CONTEXT', '--',
                  '/usr/bin/python3', '-I', str(Path(__file__).resolve())] + sys.argv[1:],
                  {'PATH': SYSTEM_PATH, 'TERM': os.environ.get('TERM', 'xterm'),
                   'DEVSESSION_CONTEXT': json.dumps(context)})
    context = json.loads(os.environ.pop('DEVSESSION_CONTEXT', '{}'))
    user = pwd.getpwuid(int(os.environ.get('SUDO_UID', os.getuid())))
    if user.pw_uid == 0 and args.action not in ['doctor', 'cleanup', 'list']:
        raise Error('Invoke as a normal host user (or via sudo from that user); root workloads are forbidden')
    os.environ.clear(); os.environ.update(PATH=SYSTEM_PATH, LANG='C.UTF-8')
    os.umask(0o077)
    ROOT.mkdir(mode=0o711, exist_ok=True)
    lock = open(ROOT / '.lock', 'a')
    try:
        flags = fcntl.LOCK_EX
        if args.action not in ['exec', 'shell', 'credential', 'inspect', 'list']:
            flags |= fcntl.LOCK_NB
        fcntl.flock(lock, flags)
    except BlockingIOError:
        raise Error('Another lifecycle operation is in progress; retry shortly')
    def release():
        if not lock.closed:
            lock.close()
    try:
        if args.action == 'create':
            create(args, user, context); return 0
        if args.action == 'doctor':
            doctor(context); return 0
        if args.action == 'list':
            for c in configs(user.pw_uid if user.pw_uid else None):
                print(f'{c["name"]}\t{"running" if alive(c) else "stopped"}\t{c["mode"]}')
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
            return 0
        c = load(user.pw_uid, args.name)
        if args.action == 'start':
            start(c)
        elif args.action in ['stop', 'delete']:
            stop(c)
            if args.action == 'delete':
                shutil.rmtree(c['state'])
        elif args.action == 'inspect':
            public = dict(c)
            public['env'] = {k: '<redacted>' for k in c['env']}
            public['running'] = alive(c)
            public['namespaces'] = dict(zip(['workload', 'gateway', 'host_veth', 'nft_table'], names(c)))
            print(json.dumps(public, indent=2))
        elif args.action == 'env':
            if args.env_action == 'set':
                k = env_key(args.key)
                if args.value is not None and (args.stdin or args.file):
                    raise Error('Use a value OR --stdin/--file')
                value = sys.stdin.read().removesuffix('\n') if args.stdin else Path(args.file).read_text().removesuffix('\n') if args.file else args.value
                if value is None or '\0' in value:
                    raise Error('Supply a value, --stdin or --file (NUL is forbidden)')
                c['env'][k] = value
            elif args.env_action == 'import':
                c['env'].update(env_file(sys.stdin.read() if args.file == '-' else Path(args.file).read_text()))
            else:
                c['env'].pop(env_key(args.key), None)
            save(c)
        elif args.action == 'net':
            stopped(c)
            if args.mode == 'vpn' and not c.get('vpn'):
                raise Error('Configure WireGuard or OpenVPN before selecting VPN mode')
            c['mode'] = args.mode; save(c)
        elif args.action == 'vpn':
            stopped(c)
            folder = Path(c['state']) / 'vpn'
            # Import is stopped-only. On invalid input retain the previous config.
            staging = Path(c['state']) / 'vpn-import'
            shutil.rmtree(staging, ignore_errors=True); staging.mkdir(mode=0o700)
            try:
                v = wireguard_import(args.wireguard, staging, args.dns) if args.wireguard else openvpn_import(args.openvpn, staging, args.dns)
                if v['kind'] == 'openvpn':
                    data = (staging / 'client.ovpn').read_text().replace(str(staging) + '/', str(folder) + '/')
                    write(staging / 'client.ovpn', data)
                shutil.rmtree(folder, ignore_errors=True)
                staging.rename(folder); c['vpn'] = v; save(c)
            finally:
                shutil.rmtree(staging, ignore_errors=True)
        elif args.action in ['exec', 'shell', 'credential']:
            start(c)
            extra = dict(context.get('terminal', {}))
            extra.update({env_key(k): v for k, v in context.get('forward', {}).items()})
            if args.action == 'shell':
                command = ['/bin/bash', '--noprofile', '--rcfile', '/etc/devsession.bashrc', '-i']
            elif args.action == 'credential':
                dest = Path(args.destination)
                if dest.is_absolute() or '..' in dest.parts or not dest.parts:
                    raise Error('Credential destination must be a relative path inside private HOME')
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
                    raise Error('exec needs a command after NAME --')
            return execute(c, command, overrides=extra, release=release)
        return 0
    finally:
        release()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Error, ValueError, OSError) as e:
        print(f'devsession: {e}', file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
