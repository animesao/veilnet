# PHASE 2 Checklist - eBPF Core Skeleton

## Goal
Create a clean, verifier-friendly TC eBPF skeleton with maps and structure for future parsing/desync.

## Tasks
- [x] Add bpf/veilnet.h with strategy defines
- [x] Refine bpf/main.c with TC ingress/egress
- [x] Keep bpf/maps.h with BPF_MAP_TYPE_LPM_TRIE rules_map
- [x] Keep bpf/parser.h with basic Ethernet parser
- [x] Ensure includes are correct
- [ ] Compile with clang -target bpf in VM

## Acceptance
- [ ] bpf/veilnet.bpf.o compiles with no errors/warnings treated as errors
- [ ] No obvious unbounded pointer access
- [ ] Maps defined correctly
- [ ] TC sections present (tc/ingress, tc/egress)

## Test
In VM: `just build-bpf` or `clang -O2 -target bpf -g -Wall -Werror -I./bpf -c bpf/main.c -o bpf/veilnet.bpf.o`

**Status:** IN_PROGRESS
```