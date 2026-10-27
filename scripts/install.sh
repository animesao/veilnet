#!/usr/bin/env bash
set -euo pipefail

echo "[veilnet] Installing binaries..."
install -Dm755 target/release/veilnetd /usr/local/bin/veilnetd
install -Dm755 target/release/veilctl /usr/local/bin/veilctl

echo "[veilnet] Installing eBPF object..."
install -Dm644 bpf/veilnet.bpf.o /usr/local/lib/veilnet/veilnet.bpf.o

echo "[veilnet] Installing config..."
install -Dm644 config/veilnet.toml.example /etc/veilnet/veilnet.toml.example
[ -f /etc/veilnet/veilnet.toml ] || install -Dm644 config/veilnet.toml.example /etc/veilnet/veilnet.toml

echo "[veilnet] Installing systemd unit..."
install -Dm644 systemd/veilnet.service /etc/systemd/system/veilnet.service
systemctl daemon-reload

echo "[veilnet] Done. Edit /etc/veilnet/veilnet.toml and run: systemctl enable --now veilnet"
