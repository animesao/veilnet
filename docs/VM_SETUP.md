# VM Setup for veilnet (Arch Linux)

Тестовая VM обязательна для всей ядровой части.

## Recommended
- Distro: Arch Linux (minimal)
- Kernel: >= 5.8 (современный Arch подойдёт)
- Hypervisor: virt-manager/QEMU, VirtualBox, UTM
- Networking: bridge/veth для изолированных тестов

## Packages (Arch)
```bash
sudo pacman -S --needed base-devel clang llvm bpftool rustup libbpf linux-headers \
  iproute2 nftables tcpdump ethtool git
```

## Rust
```bash
rustup default stable
rustc --version && cargo --version
```

## BPF tooling check
```bash
bpftool version
clang --version
ls /sys/kernel/btf/vmlinux && echo "BTF available"
uname -r
```

## vmlinux.h
```bash
cd /path/to/veilnet
./scripts/gen-vmlinux.sh  # or just gen-vmlinux
```

## Test iface (optional but useful)
```bash
ip link add veth0 type veth peer name veth1
ip netns add testns
ip link set veth1 netns testns
```

## Notes
- Не тестировать загрузку eBPF на основном хосте
- Для TC clsact нужны CAP_NET_ADMIN
- Следить за `dmesg`, `journalctl -k`
```