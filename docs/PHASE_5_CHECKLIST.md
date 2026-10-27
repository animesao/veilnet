# PHASE 5 Checklist - Packet Parsing

## Goal
Parse Ethernet/IP/TCP and extract TLS SNI / HTTP Host with strict bounds checks.

## Tasks
- [x] ETH/IP/TCP parsing helpers
- [ ] TLS ClientHello SNI extraction (bounded)
- [ ] HTTP Host header extraction (bounded)
- [ ] Verifier-safe pointer arithmetic
- [ ] Early return on OOB

## Acceptance
- [ ] Detect target SNI/Host in VM test traffic
- [ ] No verifier errors
- [ ] No unbounded access

## Test
In VM: netns/veth + curl/openssl test, tcpdump verification

**Status:** IN_PROGRESS
```