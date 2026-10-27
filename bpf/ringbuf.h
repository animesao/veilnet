#ifndef __VEILNET_RINGBUF_H
#define __VEILNET_RINGBUF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Event types emitted to userspace via events_rb */
#define VEILNET_EVT_PKTS   0  /* periodic packet counters */
#define VEILNET_EVT_MATCH  1  /* a packet matched a rule */
#define VEILNET_EVT_STRAT  2  /* strategy application detail (per action) */
#define VEILNET_EVT_DROP   3  /* a packet was dropped */
#define VEILNET_EVT_MAX    4

struct veilnet_event {
    __u64 ts_ns;
    __u32 ifindex;
    __u8 type;
    __u8 action;
    __u8 strategy;
    __u8 proto;      /* 0 = unset, 4 = IPv4, 6 = IPv6 */
    __u32 src_v4;    /* network byte order, 0 for IPv6 */
    __u32 dst_v4;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

static __always_inline void veilnet_evt(struct __sk_buff *skb, __u8 type, __u8 action, __u8 strategy, struct pkt_ctx *ctx)
{
    struct veilnet_event *evt;

    evt = bpf_ringbuf_reserve(&events_rb, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->ts_ns = bpf_ktime_get_ns();
    evt->ifindex = skb->ifindex;
    evt->type = type;
    evt->action = action;
    evt->strategy = strategy;

    if (ctx && ctx->tcp) {
        evt->proto = ctx->ip4 ? 4 : 6;
        if (ctx->ip4) {
            evt->src_v4 = ctx->ip4->saddr;
            evt->dst_v4 = ctx->ip4->daddr;
        }
        evt->sport = ctx->tcp->source;
        evt->dport = ctx->tcp->dest;
    } else {
        evt->proto = 0;
        evt->src_v4 = 0;
        evt->dst_v4 = 0;
    }

    bpf_ringbuf_submit(evt, 0);
}

#endif /* __VEILNET_RINGBUF_H */
