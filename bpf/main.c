#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "uapi_defs.h"
#include "veilnet.h"
#include "parser.h"
#include "maps.h"
#include "desync.h"
#include "stats.h"
#include "ringbuf.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Build an LPM trie key from a packet IPv4 address.
 * LPM expects the key as (prefixlen, data) with data in big-endian.
 */
static __always_inline void key_from_ip4(__be32 ip, struct rule_key *key)
{
    __u32 i;

    key->prefixlen = 32;
    __builtin_memset(key->addr, 0, sizeof(key->addr));
    __builtin_memcpy(key->addr, &ip, 4);
    (void)i;
}

static __always_inline void key_from_ip6(struct in6_addr *ip, struct rule_key *key)
{
    key->prefixlen = 128;
    __builtin_memcpy(key->addr, ip, 16);
}

/*
 * Look up the strategy rule for the packet destination (egress)
 * or source (ingress) address.
 */
static __always_inline int veilnet_lookup_rule(struct pkt_ctx *ctx, int egress, struct veilnet_rule_val **out)
{
    struct rule_key key;
    struct veilnet_rule_val *val;

    __builtin_memset(&key, 0, sizeof(key));

    if (ctx->ip4) {
        __be32 ip = egress ? ctx->ip4->daddr : ctx->ip4->saddr;
        key_from_ip4(ip, &key);
    } else if (ctx->ip6) {
        struct in6_addr *ip = egress ? &ctx->ip6->daddr : &ctx->ip6->saddr;
        key_from_ip6(ip, &key);
    } else {
        return -1;
    }

    val = bpf_map_lookup_elem(&rules_map, &key);
    if (!val)
        return -1;

    *out = val;
    return 0;
}

static __always_inline int veilnet_process(struct __sk_buff *skb, int egress)
{
    struct pkt_ctx ctx = {};
    struct veilnet_rule_val *rv = NULL;

    veilnet_stat_inc(VEILNET_STAT_PKTS);

    /* Only TCP over IPv4/IPv6 with payload is interesting */
    if (veilnet_parse_tcp(skb, &ctx) < 0)
        return TC_ACT_OK;
    if (ctx.payload_len == 0)
        return TC_ACT_OK;

    /* Rule lookup by IP (LPM trie) */
    if (veilnet_lookup_rule(&ctx, egress, &rv) < 0)
        return TC_ACT_OK;

    if (!rv || !rv->enabled)
        return TC_ACT_OK;

    veilnet_stat_inc(VEILNET_STAT_MATCHED);
    veilnet_evt(skb, VEILNET_EVT_MATCH, TC_ACT_OK, rv->strategy, &ctx);

    /* Apply desync strategy */
    int act = veilnet_desync_apply(skb, &ctx, rv);
    if (act == TC_ACT_OK) {
        veilnet_stat_inc(VEILNET_STAT_PASSED);
        veilnet_evt(skb, VEILNET_EVT_STRAT, act, rv->strategy, &ctx);
    } else {
        veilnet_stat_inc(VEILNET_STAT_DROPPED);
        veilnet_evt(skb, VEILNET_EVT_DROP, act, rv->strategy, &ctx);
    }

    return act;
}

SEC("tc")
int veilnet_ingress(struct __sk_buff *skb)
{
    return veilnet_process(skb, 0);
}

SEC("tc")
int veilnet_egress(struct __sk_buff *skb)
{
    return veilnet_process(skb, 1);
}
