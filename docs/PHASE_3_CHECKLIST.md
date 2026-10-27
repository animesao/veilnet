# PHASE 3 Checklist - Userspace Loader (libbpf-rs)

## Goal
Load eBPF object and attach to TC clsact on a target interface.

## Tasks
- [x] src/loader/mod.rs skeleton with load/attach/detach
- [x] Drop-based cleanup
- [x] Tracing + anyhow error handling
- [ ] Real libbpf-rs object open/load (VM)
- [ ] TcHook: ensure clsact qdisc (VM)
- [ ] Attach ingress/egress filters (VM)
- [ ] Detach/cleanup verification (VM)

## Acceptance
- [ ] veilnetd can load object in VM
- [ ] Attached to test iface (tc filter show)
- [ ] Clean detach works

## Test
In VM: `scripts/vm_test_netns.sh`, then attach/detach on veth0

**Status:** host skeleton DONE, VM verification pending
