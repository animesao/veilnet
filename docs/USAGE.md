# Usage

## Daemon

Start/stop via systemd:

```bash
sudo systemctl enable --now veilnet
sudo systemctl status veilnet
sudo journalctl -u veilnet -f
```

## CLI

```
veilctl strategies                 # list built-in strategy presets
veilctl strategy <id>              # show one strategy's parameters
veilctl gen <id> [--cidr CIDR]     # generate a TOML rule snippet
veilctl import <path> [--out DIR]  # import zapret .bat strategies
veilctl status                     # daemon status (IPC)
veilctl reload                     # reload config + re-sync BPF maps
veilctl attach <iface>             # attach to interface (e.g. eth0, auto)
veilctl detach <iface>             # detach from interface
veilctl info                       # maps/programs/stats
veilctl stats                      # packet counters (packets/matched/passed/dropped)
veilctl iface                      # show resolved interface
veilctl version
```

## Configuration

Edit `/etc/veilnet/veilnet.toml`:

```toml
[interface]
name = "eth0"   # or "auto"

[[rule]]
match = { ip = ["203.0.113.0/24"] }
strategy = "fake-multidisorder"
params = { split_pos = 1, repeats = 11, tcp_fooling = "badseq", udp = true }
```

Rule parameters:

| param | meaning |
|---|---|
| `split_pos` | byte position where the payload is split |
| `seqovl` | sequence overlap size (0 = off) |
| `repeats` | fake packet repeat count |
| `tcp_fooling` | none / badseq / badsum / ts / md5 |
| `udp` | also apply to UDP (QUIC) |

After editing, apply: `veilctl reload` (or restart the service).

## Zapret import

```bash
# import all strategies from a zapret-discord-youtube checkout
veilctl import ~/zapret-discord-youtube

# or a single file
veilctl import "general (ALT).bat"
```

Imported TOML files land in `/etc/veilnet/imported/`. They are **reference translations**: they document the original winws filter blocks and arguments in comments. Review and map them to native veilnet rules before enabling.

## Stats & inspection

```bash
bpftool prog show
bpftool map show
bpftool map dump name stats_map
tc qdisc show dev eth0
tc filter show dev eth0 egress
```
