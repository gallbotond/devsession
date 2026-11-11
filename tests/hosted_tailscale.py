#!/usr/bin/python3
"""Interoperability check against Tailscale's hosted control plane.

Needs an auth key for a THROWAWAY tailnet in the environment and runs on the
development host only (the key is a real credential: never copy it anywhere):

    TS_AUTHKEY=tskey-auth-... python3 -B tests/hosted_tailscale.py

Without TS_AUTHKEY it exits 77 ("skipped"). It creates session `ts-hosted`,
logs in, checks the node is Running with a tailnet address and that MagicDNS
answers through the tunnel, verifies the host is unchanged, and deletes the
session, which logs the node out. NOTE: as of 2026-11-11 this script has never
been executed, because no key was available; see docs/RESULTS.md.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import accept_tailscale as at

NAME = 'ts-hosted'


def main():
    key = os.environ.get('TS_AUTHKEY')
    if not key:
        print('SKIP hosted Tailscale interoperability: TS_AUTHKEY is not set')
        return 77
    at.cli('delete', '--if-exists', '--no-logout', NAME, check=False)
    host = at.host_snapshot()
    try:
        at.cli('create', NAME)
        at.cli('vpn', 'configure', NAME, '--tailscale', '--auth-key-stdin', input=key + '\n')
        at.cli('net', 'set', NAME, 'vpn')
        at.cli('start', NAME, timeout=180)
        status = json.loads(at.session_ts(NAME, 'status', '--json').stdout)
        address = status['Self']['TailscaleIPs'][0]
        assert status['BackendState'] == 'Running' and address.startswith('100.'), status['BackendState']
        name = status['Self']['DNSName'].rstrip('.')
        assert at.ex(NAME, 'getent', 'hosts', name).stdout.split()[0] == address      # MagicDNS through the tunnel
        at.fails(NAME, 'curl', '--max-time', '3', 'http://1.1.1.1')                   # no exit node: nothing direct
        assert at.host_changes(host, at.host_snapshot(), ours=['ds']) == []
        print(f'PASS hosted control plane: node {name} Running at {address}; MagicDNS answers; no direct egress')
    finally:
        done = at.cli('--json', 'delete', '--if-exists', NAME, check=False)
        at.cli('cleanup', check=False)
        print('node logged out on delete:', json.loads(done.stdout or '{}').get('tailscale_logout'))
    assert at.host_changes(host, at.host_snapshot()) == []
    print('PASS host unchanged')
    return 0


if __name__ == '__main__':
    sys.exit(main())
