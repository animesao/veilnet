# PHASE_1 Checklist - Environment & Tooling

## Goal
Prepare build toolchain for eBPF development in the test VM.

## Required packages (Arch Linux)
- [ ] `base-devel`
- [ ] `clang`
- [ ] `llvm`
- [ ] `bpftool`
- [ ] `rustup`
- [ ] `libbpf`
- [ ] `linux-headers`
- [ ] `iproute2`

## Toolchain
- [ ] `rustup default stable`
- [ ] `clang --version` verified
- [ ] `bpftool version` verified
- [ ] `rustc --version` / `cargo --version` verified
- [ ] Kernel BTF available: `/sys/kernel/btf/vmlinux` exists

## vmlinux.h
- [ ] `scripts/gen-vmlinux.sh` executable and working
- [ ] `just gen-vmlinux` runs in VM
- [ ] `bpf/vmlinux.h` generated successfully

## eBPF compile test
- [ ] `clang -O2 -target bpf -Wall -Werror -I./bpf -c bpf/main.c -o /tmp/veilnet_test.bpf.o` succeeds (skeleton)
- [ ] No missing headers

## Acceptance
- [ ] bpftool can dump BTF
- [ ] vmlinux.h present
- [ ] Toolchain versions logged
- [ ] Skeleton BPF object compiles

**Status:** IN_PROGRESS (execute in VM)
```