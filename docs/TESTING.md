# Reproduce the checks

Run on a disposable Linux VM as its normal sudo-authorized development user.
The tests allocate local network namespaces, veths and VPN servers. They never
need Azure accounts, a VPN provider or cloud spending.

Prerequisites beyond the runtime:

```sh
sudo apt-get install easy-rsa dnsmasq-base tcpdump socat python3-venv \
  ansible tmux bash-completion curl
```

Install Terraform, oh-my-posh and Azure CLI once on the host, as described in
`INVENTORY.md`. The acceptance test also expects nvm 0.40.3 and a Node runtime:

```sh
git clone --depth 1 --branch v0.40.3 https://github.com/nvm-sh/nvm.git ~/.nvm
bash --noprofile --norc -c 'export NVM_DIR="$HOME/.nvm"; source "$NVM_DIR/nvm.sh"; nvm install --lts'
```

Do not overwrite an existing nvm installation; use it and adjust the explicit
version assertion if needed. The suite creates/removes a temporary
`~/.local/bin/ds-user-tool`, a project virtualenv, a sentinel file under `.ssh`,
a host Unix socket and a host tmux session named `ds-host-sentinel`.

```sh
./install.sh
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
sudo python3 -B tests/prototype.py
python3 -B tests/acceptance.py | tee tests/acceptance.log
```

`prototype.py` is the initial architecture gate, retained as an executable
demonstration. It exercises the actual host Terraform, Ansible, tmux and
oh-my-posh installations and reviewed Bash customization, private process/home
state, real WireGuard/DNS/private HTTP, gateway identity and forced tunnel
failure with capture/counter evidence. It was run successfully **before** the
full CLI was implemented. The original run used this VM's UID/GID 1000 and
`/home/ubuntu`; adjust those fixture values on another VM.

`acceptance.py` uses the **installed CLI** for user workflows and separate root
commands only for test servers/fault injection/packet evidence. It writes
`tests/results.json` and `tests/tool-results.json`. Assertions distinguish
synthetic Azure selected-account state from actual Azure authentication.
The tests use real commands and real kernel networking; parser unit tests are
additional checks, not replacements for networking tests.

## Topology

- `dslab-a`: WireGuard UDP/51820 at 198.18.10.2, private 10.77.0.1.
- `dslab-b`: another WireGuard server at 198.18.11.2, same private addresses.
- `dslab-o`: OpenVPN TLS server UDP/1194 at 198.18.13.2, same private addresses.
- `dslab-direct`: independent HTTP detector at 198.18.12.2:8080.
- Each server has its own network namespace, distinct from every workload and
  gateway namespace. Easy-RSA generates a local ephemeral CA/server/client PKI.
- Private HTTP and dnsmasq bind to 10.77.0.1. `vpn.test` resolves there in all
  VPNs but returns the identity of the corresponding separate server.
- The host has no route to 10.77.0.0/24. Off/direct requests cannot reach the
  private service. Each VPN gateway NATs tunnel traffic to its own transport
  address, observed at the independent detector. Direct access has a different
  controlled source address.

Captures at the host transport links cover running, forced failure, reconnect,
stop and restart. The probes attempt ordinary direct HTTP/DNS/IPv6 and misuse
of the exact VPN UDP exception. Captures must contain actual encrypted
transport, no cleartext probe marker, and no raw DNS/HTTP/IPv6; nft counters must
record forwarding drops after tunnel removal. A deliberately restored direct
default route tests that fail-closed behavior does not rely on a missing route.

Tests also kill a real OpenVPN startup helper during a deliberately
nonresponsive handshake, check concurrent lifecycle rejection, then recover
recorded resources with repeated cleanup. Interactive checks use a real PTY.

## Manual lab

```sh
sudo python3 -B tests/lab.py up
devsession create lab-demo
devsession vpn configure lab-demo --wireguard /tmp/opencode/devsession-lab/a.conf
devsession net set lab-demo vpn
devsession exec lab-demo -- curl http://vpn.test:8080
devsession delete lab-demo
sudo python3 -B tests/lab.py down
devsession cleanup
```

The generated VPN configs/keys are root-only. The CLI's root importer reads
them. Do not run `lab.py up` concurrently with another acceptance run: these
fixtures intentionally have deterministic, task-owned names.

## Scope of evidence

This is real same-VM VPN transport, including WireGuard kernel crypto and
OpenVPN TLS/data channels. Controlled source addresses establish which local
gateway carried traffic. They do **not** prove distinct public egress IPs,
public-internet VPN transport, external-provider interoperability or practical
WAN MTU/fragmentation behavior. Those external integration checks remain
unverified; no external disposable VM was supplied.
