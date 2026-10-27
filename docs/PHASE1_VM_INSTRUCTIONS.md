# PHASE 1 VM Instructions (Arch Linux)

Do all of these steps inside the test VM. Do **not** run eBPF load/attach on the main host.

## 1) Copy project
Copy the `veilnet/` directory to the VM (e.g. `~/veilnet/`).

```bash
cd ~/veilnet
```

## 2) Install dependencies
```bash
sudo pacman -S --needed base-devel clang llvm bpftool rustup libbpf linux-headers iproute2 git just
```

## 3) Setup Rust toolchain
```bash
rustup default stable
rustc --version
cargo --version
```

## 4) Verify kernel BTF
```bash
ls -la /sys/kernel/btf/vmlinux
uname -r
bpftool version
clang --version
```

BTF must exist. If missing, use a kernel with CONFIG_DEBUG_INFO_BTF=y (modern Arch kernels have it).

## 5) Generate vmlinux.h
```bash
chmod +x scripts/gen-vmlinux.sh
./scripts/gen-vmlinux.sh
# or
just gen-vmlinux
```

Expected: `bpf/vmlinux.h` created.

## 6) Build eBPF skeleton
```bash
just build-bpf
# or
clang -O2 -target bpf -g -Wall -Werror -I./bpf -c bpf/main.c -o bpf/veilnet.bpf.o
```

Expected: `bpf/veilnet.bpf.o` without errors.

## Acceptance for PHASE 1
- [ ] All packages installed
- [ ] `/sys/kernel/btf/vmlinux` exists
- [ ] `bpf/vmlinux.h` generated
- [ ] `bpf/veilnet.bpf.o` compiled successfully with `clang -target bpf`
- [ ] Toolchain versions noted

Once all checked, update `STATUS.md` to mark PHASE 1 as DONE and move to PHASE 2.
