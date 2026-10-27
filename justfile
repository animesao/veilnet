# veilnet justfile

default:
    @just --list

# Generate vmlinux.h from kernel BTF
gen-vmlinux:
    @echo "Generating vmlinux.h..."
    @if [ ! -f /sys/kernel/btf/vmlinux ]; then echo "Error: /sys/kernel/btf/vmlinux not found"; exit 1; fi
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
    @echo "Done: bpf/vmlinux.h"

# Build eBPF objects
build-bpf:
    @echo "Building eBPF..."
    @if [ ! -f bpf/vmlinux.h ]; then echo "Missing bpf/vmlinux.h. Run 'just gen-vmlinux' first."; exit 1; fi
    clang -O2 -target bpf -g -Wall -Werror -I./bpf -c bpf/main.c -o bpf/veilnet.bpf.o
    @echo "Built: bpf/veilnet.bpf.o"

# Build Rust daemon + CLI
build:
    cargo build --release

# Build all
build-all: gen-vmlinux build-bpf build
    @echo "Build complete"

# Run daemon
run:
    cargo run --release

# Install systemd unit
install-systemd:
    sudo cp systemd/veilnet.service /etc/systemd/system/
    sudo systemctl daemon-reload

# Clean
clean:
    cargo clean
    rm -f bpf/*.o bpf/*.skel.h bpf/vmlinux.h
