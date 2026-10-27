# PHASE 7 Checklist - veilctl + systemd

## Goal
Make veilnet usable as a system service.

## Tasks
- [x] veilctl: status/reload/attach/detach/version
- [ ] Socket/IPC to veilnetd (future)
- [x] systemd/veilnet.service with CAP_NET_ADMIN/CAP_NET_RAW
- [x] Paths: /etc/veilnet/, /usr/local/bin/
- [x] Install layout documented

## Acceptance
- [ ] systemctl start/stop veilnet works in VM
- [ ] veilctl controls daemon (scaffold)
- [ ] Service runs with minimal caps

## Test
In VM: systemctl enable/start/status, journalctl -u veilnet

**Status:** IN_PROGRESS
```