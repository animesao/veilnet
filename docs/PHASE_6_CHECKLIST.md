# PHASE 6 Checklist - Desync Engine

## Goal
Implement core desync tricks: fake, multisplit, seqovl with checksum correction.

## Tasks
- [x] Add bpf/desync.h scaffold
- [ ] Strategy dispatch by rule
- [ ] multisplit
- [ ] seqovl with pattern
- [ ] fake segment approach
- [ ] bpf_csum_diff for TCP/IP
- [ ] Verifier-safe skb edits

## Acceptance
- [ ] Strategy applied on match
- [ ] Flow not corrupted
- [ ] No verifier errors

## Test
In VM: controlled traffic test

**Status:** IN_PROGRESS
```