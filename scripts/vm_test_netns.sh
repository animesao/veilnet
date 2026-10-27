#!/usr/bin/env bash
set -euo pipefail

NS=testns
VETH0=veth0
VETH1=veth1

ip netns add "$NS" 2>/dev/null || true
ip link add "$VETH0" type veth peer name "$VETH1" 2>/dev/null || true
ip link set "$VETH1" netns "$NS" 2>/dev/null || true
ip addr add 10.200.200.1/24 dev "$VETH0" 2>/dev/null || true
ip netns exec "$NS" ip addr add 10.200.200.2/24 dev "$VETH1" 2>/dev/null || true
ip link set "$VETH0" up
ip netns exec "$NS" ip link set "$VETH1" up
ip netns exec "$NS" ip link set lo up

echo "Test net: $VETH0 <-> $NS:$VETH1 (10.200.200.0/24)"
echo "Use only in VM for veilnet attach/detach tests"
