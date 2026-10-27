#!/usr/bin/env bash
set -euo pipefail

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "Error: /sys/kernel/btf/vmlinux not found. Kernel BTF is required."
    exit 1
fi

echo "Generating vmlinux.h from kernel BTF..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
echo "vmlinux.h generated: bpf/vmlinux.h"
