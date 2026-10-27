#!/usr/bin/env bash
IFACE=${1:-eth0}
echo "Attaching veilnet to $IFACE (clsact)..."
tc qdisc add dev $IFACE clsact 2>/dev/null || true
# tc filter add dev $IFACE egress  bpf da obj bpf/veilnet.bpf.o sec tc action ok
# tc filter add dev $IFACE ingress bpf da obj bpf/veilnet.bpf.o sec tc action ok
echo "Edit this script to attach filters after building"

