# PHASE 4 Checklist - Config & Rules Sync

## Goal
Sync veilnet.toml rules to BPF LPM_TRIE (rules_map) via libbpf-rs.

## Tasks
- [x] Expand src/config/mod.rs with Config/Rule/Match
- [x] Implement src/rules/mod.rs with LPM key building and strategy mapping
- [x] Support IPv4 and IPv6 CIDR
- [ ] Update BPF maps via libbpf-rs (VM)
- [ ] Integrate with veilctl reload path (scaffold)
- [ ] Validate config on load

## Acceptance
- [ ] Adding rule updates rules_map
- [ ] Removing/clearing works
- [ ] Invalid CIDR rejected with clear error
- [ ] bpftool map dump shows entries in VM

## Test
In VM: load config, call reload, verify with `bpftool map show/list/dump`

**Status:** IN_PROGRESS
```