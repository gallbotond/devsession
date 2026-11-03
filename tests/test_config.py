"""Parser tests complement (never substitute for) real namespace integration."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import devsession as ds


class ConfigTests(unittest.TestCase):
    def test_wireguard_hooks_and_split_tunnel_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            src = p / 'input'
            base = '[Interface]\nPrivateKey = key\nAddress = 10.1.0.2/24\nDNS = 10.1.0.1\n[Peer]\nPublicKey = key\nEndpoint = 192.0.2.1:51820\nAllowedIPs = '
            src.write_text(base + '10.1.0.0/24\n')
            with self.assertRaises(ds.Error):
                ds.wireguard_import(src, p)
            src.write_text(base + '0.0.0.0/0\nPostUp = touch /tmp/unsafe\n')
            with self.assertRaises(ds.Error):
                ds.wireguard_import(src, p)

    def test_openvpn_executable_directives_rejected(self):
        for line in ['up /bin/true', 'plugin /lib/a.so', 'config another', 'iproute /tmp/hook',
                     'script-security 3', 'management /tmp/socket unix', 'log /tmp/anything',
                     'providers /tmp/code.so', 'setenv LD_PRELOAD /tmp/code.so', 'remote a\nremote b']:
            with self.subTest(line=line), tempfile.TemporaryDirectory() as t:
                p = Path(t)
                src = p / 'input'
                src.write_text('client\n' + line + '\n')
                with self.assertRaises(ds.Error):
                    ds.openvpn_import(src, p, ['10.77.0.1'])

    def test_openvpn_copy_and_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            (p / 'ca.crt').write_text('CERTIFICATE DATA')
            (p / 'auth.txt').write_text('username\npassword\n')
            src = p / 'input'
            src.write_text('client\ndev tun\nremote 192.0.2.1 1194\nca ca.crt\nauth-user-pass auth.txt\n')
            out = p / 'out'; out.mkdir()
            v = ds.openvpn_import(src, out, ['10.77.0.1'])
            self.assertEqual(v['proto'], 'udp')
            self.assertEqual((out / 'auth-user-pass.data').read_text(), 'username\npassword\n')
            self.assertEqual(os.stat(out / 'auth-user-pass.data').st_mode & 0o777, 0o600)
            self.assertIn('redirect-gateway def1', (out / 'client.ovpn').read_text())


if __name__ == '__main__':
    unittest.main()
