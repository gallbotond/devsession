#!/usr/bin/python3
"""Interoperability check against Tailscale's hosted control plane.

Needs an auth key for a THROWAWAY tailnet in the environment and runs on the
development host only (the key is a real credential: never copy it anywhere):

    TS_AUTHKEY=tskey-auth-... python3 -B tests/hosted_tailscale.py

Without TS_AUTHKEY it exits 77 ("skipped"). It creates session `ts-hosted`,
logs in, checks the node is Running with a tailnet address and that MagicDNS
answers through the tunnel, verifies the host is unchanged, and deletes the
session, which logs the node out. It refuses a key for the tailnet that the
host's own tailscaled belongs to, unless the owner of that tailnet says so
explicitly with TS_ALLOW_HOST_TAILNET=1. In that mode the host necessarily
sees one more peer (the test node), so the "host unchanged" comparison leaves
that peer and its routes out; nothing else in that tailnet is contacted.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import accept_tailscale as at

NAME = 'ts-hosted'
STATUS = 'tailscale status (node, peers, tailnet)'
TEXT = 'tailscale status text (address, name, owner, os)'


def without_test_node(snapshot, addresses):
    """Host snapshot minus the test node as a peer of the host (same-tailnet mode only)."""
    out = dict(snapshot)
    status = json.loads(out[STATUS])
    status['Peer'] = [p for p in status['Peer'] if not (p.get('HostName') or '').startswith('ds-' + NAME)]
    out[STATUS] = json.dumps(status, sort_keys=True)
    out[TEXT] = '\n'.join(line for line in out[TEXT].splitlines() if 'ds-' + NAME not in line)
    for table in ['ip route table all', 'ip route table 52', 'ip -6 route table all']:
        out[table] = '\n'.join(line for line in out[table].splitlines()
                               if not any(line.startswith(a + ' ') for a in addresses))
    return out


def main():
    key = os.environ.get('TS_AUTHKEY')
    if not key:
        print('SKIP hosted Tailscale interoperability: TS_AUTHKEY is not set')
        return 77
    at.cli('delete', '--if-exists', '--no-logout', NAME, check=False)
    host = at.host_snapshot()
    shared, addresses = False, []
    try:
        at.cli('create', NAME)
        at.cli('vpn', 'configure', NAME, '--tailscale', '--auth-key-stdin', input=key + '\n')
        at.cli('net', 'set', NAME, 'vpn')
        at.cli('start', NAME, timeout=180)
        status = json.loads(at.session_ts(NAME, 'status', '--json').stdout)
        # The key must be for a throwaway tailnet, never the one this host's own
        # tailscaled belongs to. Checked first; the finally block logs the node out.
        mine = json.loads(at.cmd(['tailscale', 'status', '--json'], check=False).stdout or '{}')
        same = lambda k: status.get(k) and status.get(k) == mine.get(k)
        if same('MagicDNSSuffix') or same('CurrentTailnet'):
            if os.environ.get('TS_ALLOW_HOST_TAILNET') != '1':
                raise AssertionError('TS_AUTHKEY belongs to the tailnet of this host\'s own tailscaled; use a throwaway '
                                     'tailnet, or set TS_ALLOW_HOST_TAILNET=1 if that tailnet is yours to test in')
            shared = True
        addresses = status['Self']['TailscaleIPs']
        address = addresses[0]
        assert status['BackendState'] == 'Running' and address.startswith('100.'), status['BackendState']
        name = status['Self']['DNSName'].rstrip('.')
        assert at.ex(NAME, 'getent', 'hosts', name).stdout.split()[0] == address      # MagicDNS through the tunnel
        relay = status['Self'].get('Relay') or 'none'
        assert relay != 'none', 'no home DERP region: the hosted relay network was not reached'
        at.fails(NAME, 'curl', '--max-time', '3', 'http://1.1.1.1')                   # no exit node: nothing direct
        at.fails(NAME, 'getent', 'hosts', 'example.com')
        prefs = json.loads(at.session_ts(NAME, 'debug', 'prefs').stdout)
        assert prefs['ShieldsUp'] and not prefs['RunSSH'] and not prefs.get('AdvertiseRoutes')
        scrub = (lambda snap: without_test_node(snap, addresses)) if shared else (lambda snap: snap)
        assert at.host_changes(scrub(host), scrub(at.host_snapshot()), ours=['ds']) == []
        # Fail closed here too: with the daemon gone nothing is reachable.
        at.root('kill', '-KILL', str(at.daemon(NAME)))
        at.fails(NAME, 'getent', 'hosts', name)
        at.fails(NAME, 'curl', '--max-time', '3', 'http://1.1.1.1')
        assert at.counters(NAME, 'forward') > 0
        at.cli('stop', NAME); at.cli('start', NAME, timeout=180)                      # persisted node, no second login
        assert at.ex(NAME, 'getent', 'hosts', name).stdout.split()[0] == address
        print(f'PASS hosted control plane: node {name.split(".")[0]} Running with a tailnet address, home relay region '
              f'"{relay}"; MagicDNS answers its own name through the tunnel; outside names and direct egress fail; '
              f'shields up; host {"unchanged apart from seeing the test node as a peer" if shared else "unchanged"} '
              'while it ran; daemon killed: nothing reachable, forward drops counted')
    finally:
        done = at.cli('--json', 'delete', '--if-exists', NAME, check=False)
        at.cli('cleanup', check=False)
        print('node logged out on delete:', json.loads(done.stdout or '{}').get('tailscale_logout'))
    scrub = (lambda snap: without_test_node(snap, addresses)) if shared else (lambda snap: snap)
    assert at.host_changes(scrub(host), scrub(at.host_snapshot())) == []
    print('PASS host unchanged afterwards' + (' (the logged-out test node, as a peer of the host, left out)' if shared else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
