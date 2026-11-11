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
python3 -B tests/acceptance.py scripting      # one group only: core, scripting
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

## Scripting checks (group `scripting`, `tests/accept_scripting.py`)

Every call runs under `setsid` (no controlling terminal) with stdin closed or
`/dev/null` unless the check itself feeds data. Sessions `scr-a`/`scr-b` use
network mode off, so this group needs no lab servers.

- S1: each documented failure status (1, 3, 120-127, 128+N) with its JSON
  error object; a state lock held from outside gives 124 at once, 124 after
  `--wait 1`, success with a sufficient `--wait`, and no delay for queries.
- S2: a throwaway user `dvs-pwtest` with a random password and a
  password-required rule in `/etc/sudoers.d/dvs-pwtest`. Without a terminal
  devsession must exit 123 within 5 s; on a real PTY `--non-interactive` and
  `DEVSESSION_NONINTERACTIVE=1` must refuse without prompting, and the plain
  call must show sudo's password prompt. A root systemd service then runs
  `devsession --user USER exec`. The user, its home and the sudoers file are
  removed and their absence asserted.
- S3: 64 MiB of random data host to session, session to host and round trip,
  compared by SHA-256; all 256 byte values; closed stdin; SIGPIPE on an early
  reader.
- S4: 16 exit statuses (including 120-125) attributed to the command by
  `--status-file`; HUP/INT/QUIT/USR1/TERM forwarded to a handler; death by
  SIGTERM reported as 143 with `signal: 15`; no leftover process.
- S5: 16 concurrent execs racing one auto-start; 8 concurrent
  `create --ensure`; 16 mixed lifecycle calls with `--wait`.
- S6: `changed` flags of the idempotent forms; stdout carries only command
  output; `--cwd`/`--env`/`--env-file`/`--forward` precedence; an `--env-file`
  secret absent from the host process listing; `-t`/`-T`.
- S7: `examples/scripting.sh` and `examples/scripting.py` run to completion.
- S8: the legacy `prototype` session is listed, inspected and reported
  stopped, and its files are byte-identical afterwards.

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
