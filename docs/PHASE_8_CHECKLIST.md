# PHASE 8 Checklist - VM E2E Testing

## Goal
End-to-end testing in isolated VM environment.

## Tasks
- [ ] Isolated test net (veth + netns)
- [ ] Attach veilnet to test iface
- [ ] Apply minimal rules
- [ ] Traffic tests
- [ ] Cleanup + rollback
- [ ] Check dmesg/logs for errors/warnings

## Acceptance
- [ ] Stable for attach/detach
- [ ] No kernel panic/oops
- [ ] No verifier rejects at load
- [ ] No TC/qdisc errors

## Test
Full cycle in VM only

**Status:** IN_PROGRESS
```