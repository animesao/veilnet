# Installation

## Requirements
- Linux kernel >= 5.8 with BTF
- clang, llvm, bpftool, libbpf
- Rust toolchain
- iproute2, systemd

## Build (VM for eBPF)
```bash
just gen-vmlinux
just build-bpf
just build
```

## Install
```bash
sudo cp target/release/veilnetd /usr/local/bin/
sudo cp target/release/veilctl /usr/local/bin/
sudo mkdir -p /etc/veilnet
sudo cp config/veilnet.toml.example /etc/veilnet/veilnet.toml
sudo cp systemd/veilnet.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now veilnet
```

## Notes
All eBPF/TC development and testing must be done in a test VM.
```