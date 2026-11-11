#!/usr/bin/python3
"""One real-internet run of the Tailscale backend against a remote tailnet.

The control server (headscale with embedded DERP/STUN) and a peer offering an
exit node run on a remote VM (tests/remote_vm_setup.sh). This script runs on
the development host as the normal user and is given only public facts and
the client auth key generated on that VM:

    python3 -B tests/remote_tailscale.py --server https://IP:8443 --ca ca.crt \
        --auth-key-file key --peer-ip 100.64.0.1 --vm-ip IP --peer-private-ip 10.x.y.z --blob-sha256 HEX

It is not part of acceptance.py: it needs a second machine. Results are
written to tests/remote-results.json.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess as sp
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import accept_tailscale as at

NAME = 'ts-vm'
RESULTS = []


def check(name, function):
    try:
        detail = function()
        RESULTS.append(dict(check=name, status='passed', detail=detail or ''))
        print('PASS', name, detail or '', flush=True)
        return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        RESULTS.append(dict(check=name, status='failed', detail=str(e)))
        print('FAIL', name, e, flush=True)
        return False


def main():
    ap = argparse.ArgumentParser()
    for flag in ['--server', '--ca', '--auth-key-file', '--peer-ip', '--vm-ip', '--peer-private-ip', '--blob-sha256']:
        ap.add_argument(flag, required=True)
    a = ap.parse_args()
    local_ip = at.cmd(['curl', '-s', '-4', '--max-time', '10', 'https://checkip.amazonaws.com']).stdout.strip()
    assert local_ip and local_ip != a.vm_ip
    at.cli('delete', '--if-exists', '--no-logout', NAME, check=False)
    host = at.host_snapshot()
    record = None
    try:
        at.cli('create', NAME)
        # A public control server: no --transport-net, the default host policy applies.
        at.cli('vpn', 'configure', NAME, '--tailscale', '--auth-key-stdin', '--login-server', a.server, '--ca-file', a.ca,
               '--exit-node', 'vm-peer', input=Path(a.auth_key_file).read_text())
        at.cli('net', 'set', NAME, 'vpn')
        record = at.capture_begin(NAME)
        # Second capture point: the host's uplink. Probes to a peer's private
        # candidate address must be dropped by the host and never appear here.
        uplink = json.loads(at.cmd(['ip', '-j', 'route', 'show', 'default']).stdout)[0]['dev']
        uplink_pcap = '/tmp/opencode/ts-vm-uplink.pcap'
        uplink_log = open('/tmp/opencode/ts-vm-uplink.log', 'w')
        uplink_capture = sp.Popen(['sudo', '-n', 'tcpdump', '-Z', 'root', '-U', '-n', '-i', uplink, '-w', uplink_pcap,
                                   'ip', 'and', 'udp', 'and', 'dst', 'host', a.peer_private_ip, 'and', 'dst', 'port', '41641',
                                   'and', 'not', 'src', 'port', '41641'],   # 41641 as source is the host's own daemon
                                  stdout=uplink_log, stderr=uplink_log)

        def join():
            t = time.monotonic(); at.cli('start', NAME, timeout=180)
            address, _ = at.node(NAME)
            listing = at.ex(NAME, 'curl', '-fsS', '--max-time', '15', f'http://{a.peer_ip}:8080/').stdout
            assert 'blob' in listing
            return f'joined the remote tailnet in {time.monotonic() - t:.1f}s as {address}; HTTP to the peer at {a.peer_ip}'
        if not check('R1 join a tailnet whose control server and relay are on the public internet', join):
            return 1

        def egress():
            seen = at.eventually(lambda: at.ex(NAME, 'curl', '-fsS', '-4', '--max-time', '15', 'https://checkip.amazonaws.com').stdout.strip(), 40)
            at.eq(seen, a.vm_ip)
            # The host's own address is compared, not recorded: results files get committed.
            return f'public egress address through the exit node is {seen}; this host\'s own public address differs'
        check('R2 distinct public egress IP: all IPv4 leaves at the remote exit node (HTTPS, name resolved through it)', egress)

        def path():
            status = json.loads(at.session_ts(NAME, 'status', '--json').stdout)
            peer = next(p for p in status['Peer'].values() if p['HostName'] == 'vm-peer')
            at.session_ts(NAME, 'ping', '--c', '5', '--timeout', '3s', a.peer_ip, check=False)
            peer = next(p for p in json.loads(at.session_ts(NAME, 'status', '--json').stdout)['Peer'].values() if p['HostName'] == 'vm-peer')
            return f'peer path: direct to {peer["CurAddr"]}' if peer.get('CurAddr') else f'peer path: relayed through DERP region {peer.get("Relay")}'
        check('R3 transport path to the remote peer (direct UDP or DERP relay)', path)

        def mtu():
            # Workloads have no raw sockets, so path MTU is probed with UDP and the
            # don't-fragment option: the tunnel MTU is 1280 (1252 bytes of UDP payload).
            probe = """import socket,sys,time,errno
peer=sys.argv[1]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP,10,2)            # IP_MTU_DISCOVER = IP_PMTUDISC_DO
s.sendto(b'x'*1252,(peer,9)); print('1252 sent with DF')
refused=False
for i in range(20):
    try: s.sendto(b'x'*1253,(peer,9))
    except OSError as e:
        refused = e.errno==errno.EMSGSIZE; break
    time.sleep(.1)
c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); c.connect((peer,9))
print('1253 refused' if refused else '1253 NOT refused'); print('path mtu',c.getsockopt(socket.IPPROTO_IP,14))
"""
            out = at.ex(NAME, 'python3', '-c', probe, a.peer_ip).stdout.split('\n')
            at.eq(out[:3], ['1252 sent with DF', '1253 refused', 'path mtu 1280'])
            t = time.monotonic()
            got = at.ex(NAME, 'sh', '-c', f'curl -fsS --max-time 240 http://{a.peer_ip}:8080/blob | sha256sum', timeout=300).stdout.split()[0]
            seconds = time.monotonic() - t
            at.eq(got, a.blob_sha256)
            return (f'UDP with DF: 1252-byte payload passes, 1253 is refused after the gateway reports the tunnel MTU '
                    f'(path MTU 1280); 20 MiB over TCP through the WAN tunnel in {seconds:.1f}s with matching SHA-256')
        check('R4 WAN path MTU discovery through the tunnel; bulk transfer integrity', mtu)

        def killed():
            at.root('kill', '-KILL', str(at.daemon(NAME)))
            at.ex(NAME, 'python3', '-c', at.LEAK_PROBE)
            at.fails(NAME, 'curl', '--max-time', '4', 'https://checkip.amazonaws.com')
            at.fails(NAME, 'curl', '--max-time', '4', f'http://{a.peer_ip}:8080/')
            at.fails(NAME, 'getent', 'hosts', 'example.com')
            drops = at.counters(NAME, 'forward')
            assert drops > 0
            at.cli('stop', NAME); at.cli('start', NAME, timeout=180)
            at.eventually(lambda: at.eq(at.ex(NAME, 'curl', '-fsS', '-4', '--max-time', '15', 'https://checkip.amazonaws.com').stdout.strip(), a.vm_ip), 40)
            return f'daemon killed: no direct egress, {drops} forwarded packets dropped; restart resumed with the persisted node'
        check('R5 kill switch on the real path', killed)

        def transport():
            evidence = at.capture_end(record)
            c = at.inspect(NAME)
            # Control, relay, STUN and the peer all live on the VM. The only other
            # destinations a daemon may try are the peer's private candidate
            # endpoints (its LAN address), as encrypted probes from its own UDP
            # port; the host's private-range rule drops those before they leave.
            private = '(dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16 or dst net 100.64.0.0/10 or dst net 169.254.0.0/16)'
            read = lambda expr: at.root('tcpdump', '-nr', evidence['capture'], expr).stdout.strip()
            others = read(f'ip and not dst host {a.vm_ip} and not {private}')
            assert not others, others[:600]
            candidates = read(f'ip and {private}').splitlines()
            stray = read(f'ip and {private} and not (udp and src port {c["vpn"]["port"]})')
            assert not stray, stray[:600]
            rules = at.root('nft', 'list', 'chain', 'inet', c['namespaces']['nft_table'], 'forward').stdout
            dropped = next(int(line.split('counter packets')[1].split()[0]) for line in rules.splitlines()
                           if 'ip daddr {' in line and 'drop' in line)
            assert candidates and dropped > 0, (len(candidates), dropped)
            at.root('pkill', '-INT', '-P', str(uplink_capture.pid), check=False); uplink_capture.wait(timeout=10)
            escaped = at.root('tcpdump', '-nr', uplink_pcap).stdout.strip()
            assert not escaped, escaped[:600]
            return dict(evidence, destinations=f'every packet toward the internet went to {a.vm_ip}',
                        private_candidates=f'{len(candidates)} encrypted probes to the peer\'s private address reached '
                                           f'the session link; none appeared on the uplink {uplink} '
                                           f'(host private-range rule, {dropped} drops since the last start)')
        check('R6 transport capture: only encrypted traffic to the control/relay/peer address, no DNS, no cleartext', transport)
        record = None
    finally:
        if record:
            at.root('pkill', '-INT', '-P', str(record[0].pid), check=False)
        with contextlib.suppress(Exception):
            at.root('pkill', '-INT', '-P', str(uplink_capture.pid), check=False); uplink_log.close()
        logout = at.cli('--json', 'delete', '--if-exists', NAME, check=False)
        at.cli('cleanup', check=False)
        def unchanged():
            at.eq(at.host_changes(host, at.host_snapshot()), [])
            return 'host tailscale node/peers/prefs/process, rules, routes, table 52, nft ruleset and resolver byte-identical; ' + \
                   f'node logged out on delete: {json.loads(logout.stdout or "{}").get("tailscale_logout")}'
        check('R7 host unchanged after the real-internet run; node logged out', unchanged)
        (HERE / 'remote-results.json').write_text(json.dumps(RESULTS, indent=2) + '\n')
    return 1 if any(r['status'] == 'failed' for r in RESULTS) else 0


if __name__ == '__main__':
    sys.exit(main())
