<div align="center">

# veilnet

**TC + eBPF based DPI bypass for Linux**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20%E2%89%A55.8-green.svg)](#requirements)
[![Language: Rust + C](https://img.shields.io/badge/Rust%20%2B%20C-eBPF-orange.svg)](#tech-stack)

A kernel-level traffic interception tool with flexible per-IP/subnet/domain rules,
built as a native Linux alternative to WinDivert-based DPI bypass tools.

</div>

---

## Why veilnet?

| | veilnet | NFQUEUE-based tools | WinDivert (Windows) |
|---|---|---|---|
| Interception point | TC (clsact) in kernel | Netfilter queue | Kernel driver |
| Userspace copies | Minimal | Per-packet copy | Per-packet copy |
| Always active | Yes, while service runs | Yes | Yes |
| Platform | Linux | Linux | Windows |

- **Kernel-level interception** — eBPF programs attached to TC `clsact` on your interface
- **Rule-based targeting** — apply strategies only to specific IPs, subnets or domains
- **10 built-in strategies** — ported concepts from zapret: `multisplit`, `fake`, `multidisorder`, `seqovl` and more
- **Zapret import** — parse existing zapret-discord-youtube `.bat` strategies and translate them to veilnet configs
- **System service** — install once, manage with `systemctl` and `veilctl`

## Requirements

- Linux kernel **>= 5.8** with BTF (`/sys/kernel/btf/vmlinux`)
- `clang`, `llvm`, `bpftool`, `libbpf`
- Rust toolchain (stable)
- `iproute2`, `systemd`
- Arch Linux recommended; any modern distro works

## Install

```bash
git clone https://github.com/animesao/veilnet.git
cd veilnet

# generate kernel headers for eBPF
just gen-vmlinux

# build eBPF object + daemon + CLI
just build-all

# install to system
sudo ./scripts/install.sh
```

Full instructions: [docs/INSTALL.md](docs/INSTALL.md)

## Usage

```bash
# list built-in strategies
veilctl strategies

# generate a rule for a subnet
veilctl gen fake-multidisorder --cidr 203.0.113.0/24

# import zapret .bat strategies
veilctl import /path/to/zapret-discord-youtube --out /etc/veilnet/imported

# manage the service
sudo systemctl enable --now veilnet
veilctl status
sudo systemctl status veilnet
```

## Configuration

`/etc/veilnet/veilnet.toml`:

```toml
[interface]
name = "eth0"   # or "auto"

[[rule]]
match = { ip = ["203.0.113.0/24"] }
strategy = "fake-multidisorder"
params = { split_pos = 1, repeats = 11, tcp_fooling = "badseq", udp = true }
```

More examples: [config/veilnet.toml.example](config/veilnet.toml.example)

## Built-in strategies

| id | description |
|---|---|
| `none` | pass-through, no desync |
| `multisplit` | split TLS ClientHello at position 1 |
| `multisplit-seqovl` | split + sequence overlap 681 |
| `fake` | fake packets, wrong sequence, 6 repeats |
| `fake-aggressive` | fake with 11 repeats |
| `fake-fakedsplit` | fake + split, ts fooling |
| `fake-multidisorder` | fake + disorder, badseq fooling |
| `multidisorder` | out-of-order segments, midsld |
| `disorder` | minimal reordering |
| `split2` | two-segment split at position 2 |

## Zapret import

veilnet can read [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) `.bat` strategy files:

```bash
veilctl import ~/zapret-discord-youtube
```

Each `.bat` is parsed into a reference TOML translation (filter blocks, desync modes, ports) under `/etc/veilnet/imported/`. Imported files document the original winws arguments so you can map them to veilnet rules.

## Tech stack

- **eBPF (kernel)**: TC `clsact` classifier programs in C (`clang -target bpf`)
- **Userspace**: Rust daemon `veilnetd` (libbpf-rs, tokio, clap)
- **CLI**: `veilctl`
- **Maps**: `BPF_MAP_TYPE_LPM_TRIE` for CIDR rules, `ARRAY` for stats, `RINGBUF` for events

## Repository structure

```
veilnet/
├── bpf/          # eBPF programs (C): tc hooks, maps, parser, desync
├── cli/          # veilctl: control CLI + strategy presets + zapret import
├── config/       # example configuration
├── docs/         # install, usage, architecture, development docs
├── scripts/      # build/install/test scripts
├── src/          # veilnetd daemon (Rust)
└── systemd/      # systemd unit
```

## Development

All eBPF/TC/kernel work is developed and tested in a **VM only** — see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
Plan and progress: [PLAN_DETAILED.mmd](PLAN_DETAILED.mmd), [STATUS.md](STATUS.md)

## License

[MIT](LICENSE)

## Credits

- Desync strategy concepts are informed by [bol-van/zapret](https://github.com/bol-van/zapret) (research only, no code copied)
- Built with libbpf, libbpf-rs
