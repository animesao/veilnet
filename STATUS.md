# veilnet Status

- **Project:** veilnet (TC + eBPF DPI bypass)
- **Current Phase:** PHASE 10 - Hardening & Iteration (host work complete)
- **Status:** IN_PROGRESS — all host-side code done; kernel debugging deferred to CI/community
- **Mode:** VM-only for kernel/eBPF work; debugging & E2E deferred to GitHub CI + community

## Completed (host)
- Project structure, docs, plan, checklists, README with badges, CONTRIBUTING
- eBPF code (full, ready to compile in VM/CI):
  - bpf/main.c — parse → LPM lookup → strategy dispatch → events/stats
  - bpf/parser.h — ETH/IP/TCP + TLS SNI + HTTP Host extraction (verifier-safe bounds)
  - bpf/desync.h — multisplit/seqovl/fake/disorder strategies via bpf_l4_csum_replace (correct checksum updates)
  - bpf/maps.h — LPM_TRIE, 20-byte keys / 16-byte values (shared wire format with userspace)
  - bpf/stats.h, bpf/ringbuf.h (match/strat/drop events), bpf/veilnet.h (strategy ids 1..10, 0 = invalid; synced with strategy_to_u8)
- Rust daemon (veilnetd):
  - config (+validation: unknown strategy, empty match — with tests)
  - rules (LPM keys, strategy params, prefix validation — with tests)
  - loader: real libbpf-rs under cfg(linux): open/load, rules_map full re-sync, TcHook attach/detach, background ringbuf thread, stats reading; non-Linux stub
  - maps: byte-layout helpers with roundtrip tests (userspace <-> eBPF wire format)
  - ringbuf: event decode + real libbpf-rs RingBuffer consumer (cfg(linux))
  - stats: counters from stats_map (cfg(linux)) + IPC exposure
  - nft: exclusion ruleset render/apply/cleanup (optional) + tests
  - iface: default-route detection with metric selection + tests
  - IPC: real unix-socket server (tokio: status/reload/attach/detach/info/stats/iface/ping) + client, cfg-gated
- CLI veilctl: status/reload/attach/detach/info/stats/strategies/strategy/gen/import/iface/ping/version
- **10 built-in strategy presets** (cli/src/strategies.rs)
- **Zapret .bat importer** (cli/src/zapret_import.rs), tested on 22 real files: 22/22, 9 filter blocks each
- Found & fixed real bugs during host work:
  - TOML `[[rule]]` vs `rules` field mismatch silently dropped all rules (alias added)
  - strategy id mismatch: bpf NONE=0 vs userspace none→1 (ids renumbered 1..10, 0 = invalid)
  - bat parser: unclosed quote after winws.exe merged all tokens into one
  - prefix length >32/128 accepted in cidr_to_lpm
- CI: Rust build+test+smoke for both crates, plus a dedicated eBPF compile job (vmlinux.h generation + clang build)

## Verified on host
- `cargo check -p veilnetd -p veilctl` — clean, no errors
- `cargo test` — **21/21 passed** (veilctl 5 + veilnetd 16)
- `veilctl strategies` / `strategy` / `gen` output correct
- `veilctl import` on 22 real zapret bat files: 22/22 imported

## Pending (VM / CI / community)
- Compile bpf/veilnet.bpf.o (CI job exists; verifier errors to be fixed there)
- libbpf-rs loader: first real load/attach in CI/VM (code is written, cfg(linux))
- E2E tests in netns/VM
- Strategy tuning against real DPI behavior

## Rules
- Follow `PLAN_DETAILED.mmd` strictly
- Test after each phase by ACCEPTANCE/TEST
- Never load/test eBPF on main host
- Keep changes minimal and justified
