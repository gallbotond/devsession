#!/usr/bin/python3
"""Architecture gate: run BEFORE building the full CLI."""
import json
import os
from pathlib import Path
import subprocess as sp
import sys
import time
import lab
ds = lab.ds


def main():
    assert os.geteuid() == 0
    ds.ROOT.mkdir(mode=0o700, exist_ok=True)
    routes = ds.run(['ip', '-j', 'route', 'show', 'default']).stdout
    resolver = Path('/etc/resolv.conf').read_bytes()
    state = ds.ROOT / 'prototype'
    state.mkdir(mode=0o700, exist_ok=True)
    c = dict(name='prototype', tag='prototype', uid=1000, gid=1000, user='user',
             home='/home/user', shell='/bin/bash', path=ds.SYSTEM_PATH,
             state=str(state), mode='vpn', transport=['10.231.255.1', '10.231.255.2'])
    ds.save(c)
    sentinel = sp.Popen(['sleep', '600'], env={'HOST_SENTINEL': 'NEVER_IN_SESSION'})
    try:
        v = lab.up()['a']
        (state / 'vpn').mkdir(mode=0o700, exist_ok=True)
        ds.write(state / 'vpn/wg.conf', v.pop('raw'))
        c['vpn'] = v
        ds.write(state / 'shellrc', "alias ll='ls -alF'\nfunction familiar { echo familiar-shell; }\nsource /usr/share/bash-completion/bash_completion\neval \"$(oh-my-posh init bash)\"\n", 0o644)
        ds.start(c)
        def check(cmd, expected=None):
            p = ds.execute(c, cmd, capture=True)
            if p.returncode or (expected and expected not in p.stdout):
                raise AssertionError((cmd, p.returncode, p.stdout, p.stderr))
            print('PASS', ' '.join(cmd), p.stdout[:600].strip(), flush=True)
            return p.stdout
        check(['terraform', 'version'], 'Terraform')
        check(['ansible', '--version'], 'ansible')
        check(['tmux', '-V'], 'tmux')
        check(['oh-my-posh', 'version'])
        check(['bash', '--noprofile', '--rcfile', '/etc/devsession.bashrc', '-ic',
               'alias ll; familiar; type _init_completion; declare -p PROMPT_COMMAND'], 'familiar-shell')
        check(['sh', '-c', f'test ! -e /proc/{sentinel.pid}/environ; test ! -e "$HOME/.ssh/authorized_keys"; test -z "$HOST_SENTINEL$SSH_AUTH_SOCK"; grep NoNewPrivs /proc/self/status'], '1')
        check(['curl', '-fsS', '--max-time', '5', 'http://vpn.test:8080'], '"server": "a"')
        check(['curl', '-fsS', '--max-time', '5', 'http://198.18.12.2:8080'], '198.18.10.2')
        assert int(ds.run(['wg', 'show', 'vpn0', 'transfer'], ns=ds.names(c)[1]).stdout.split()[1]) > 0
        # Capture raw cleartext attempts while tunnel is absent. Both a counter
        # and packet capture are checked; HTTP failure alone is insufficient.
        capture = lab.LAB / 'prototype-leaks.pcap'
        log = open(lab.LAB / 'capture.log', 'w')
        tcp = sp.Popen(['tcpdump', '-U', '-n', '-i', ds.names(c)[2], '-w', str(capture),
                        'port 53 or tcp port 8080 or ip6'], stdout=log, stderr=log)
        time.sleep(.3)
        ds.run(['ip', '-n', ds.names(c)[1], 'link', 'del', 'vpn0'])
        ds.run(['ip', '-n', ds.names(c)[1], 'route', 'replace', 'default', 'via', c['transport'][0]])
        p = ds.execute(c, ['python3', '-c', '''import socket
for addr in [('198.18.12.2',8080),('1.1.1.1',53)]:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'LEAK',addr)
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
try: s.sendto(b'LEAK',('2606:4700:4700::1111',53))
except OSError: pass
'''], capture=True)
        assert p.returncode == 0, p.stderr
        p = ds.execute(c, ['curl', '--max-time', '1', 'http://198.18.12.2:8080'], capture=True)
        assert p.returncode != 0
        time.sleep(.3)
        tcp.send_signal(2)
        tcp.wait(timeout=5)
        log.close()
        assert ds.run(['tcpdump', '-nr', capture]).stdout.strip() == ''
        rules = ds.run(['nft', 'list', 'chain', 'inet', 'guard', 'forward'], ns=ds.names(c)[1]).stdout
        print(rules)
        assert 'counter packets 0 bytes 0 drop' not in rules.splitlines()[-2], rules
        assert routes == ds.run(['ip', '-j', 'route', 'show', 'default']).stdout
        assert resolver == Path('/etc/resolv.conf').read_bytes()
        print('PASS forced-down: zero leaked packets; forwarding drops; unchanged host route/resolver')
    finally:
        ds.stop(c)
        lab.cleanup()
        sentinel.terminate()
        sentinel.wait()


if __name__ == '__main__':
    main()
