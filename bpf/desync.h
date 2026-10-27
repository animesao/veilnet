#ifndef __VEILNET_DESYNC_H
#define __VEILNET_DESYNC_H

#include "uapi_defs.h"
#include "parser.h"

#include "veilnet.h"

/* rule_val layout shared with userspace (src/rules/mod.rs + src/maps/mod.rs) */
#define VEILNET_FOOL_NONE   0
#define VEILNET_FOOL_BADSEQ 1
#define VEILNET_FOOL_BADSUM 2
#define VEILNET_FOOL_TS     3
#define VEILNET_FOOL_MD5    4

struct veilnet_rule_val {
    __u8 strategy;
    __u16 split_pos;
    __u16 seqovl;
    __u8 repeats;
    __u8 tcp_fooling;
    __u8 udp;
    __u8 enabled;
    __u8 pad[7];
};

/*
 * Rewrite the TCP sequence number and fix the checksum.
 * Uses bpf_l4_csum_replace with the pseudo-header flag so the kernel folds
 * the 4-byte seq diff correctly into the TCP checksum.
 */
static __always_inline void veilnet_tcp_set_seq(struct pkt_ctx *ctx, struct __sk_buff *skb, __u32 new_seq)
{
    __u32 old_seq = ctx->tcp->seq;
    __u64 off_check, off_seq;

    if (old_seq == new_seq)
        return;

    off_check = (__u8 *)&ctx->tcp->check - (__u8 *)ctx->data;
    off_seq = (__u8 *)&ctx->tcp->seq - (__u8 *)ctx->data;
    (void)off_seq;

    bpf_l4_csum_replace(skb, off_check, bpf_ntohl(old_seq), bpf_ntohl(new_seq), BPF_F_PSEUDO_HDR | 4);
    ctx->tcp->seq = new_seq;
}

/*
 * Strategy: multisplit / split2 / seqovl family.
 *
 * TC cannot split a packet in place, so veilnet's kernel-side split is a
 * sequence shift: the payload of this packet is presented to the DPI as
 * starting at a different stream offset (seqovl window). The endpoint
 * retransmission logic and end-host reassembly restore the true stream,
 * but the DPI's reassembly state diverges. split_pos controls the shift
 * magnitude, seqovl (if non-zero) overrides it.
 */
static __always_inline int veilnet_do_multisplit(struct __sk_buff *skb, struct pkt_ctx *ctx, struct veilnet_rule_val *rv)
{
    __u16 shift;

    if (!ctx->tcp || ctx->payload_len == 0)
        return TC_ACT_OK;

    if (rv->seqovl > 0)
        shift = rv->seqovl;
    else if (rv->split_pos > 0)
        shift = rv->split_pos;
    else
        return TC_ACT_OK;

    if ((__u64)shift >= ctx->payload_len)
        return TC_ACT_OK;

    veilnet_tcp_set_seq(ctx, skb, ctx->tcp->seq + bpf_htonl(shift));
    return TC_ACT_OK;
}

/*
 * Strategy: fake / fake-aggressive family (badseq-style fooling).
 *
 * Shift the sequence far outside the receiver window: the DPI tracks the
 * bogus stream state while the real endpoint discards the packet and
 * retransmits with the correct sequence. dpi-desync-repeats controls how
 * aggressively the shift is randomized (higher = further from window).
 */
static __always_inline int veilnet_do_fake(struct __sk_buff *skb, struct pkt_ctx *ctx, struct veilnet_rule_val *rv)
{
    __u32 seq;

    if (!ctx->tcp || ctx->payload_len == 0)
        return TC_ACT_OK;

    if (rv->repeats == 0)
        return TC_ACT_OK;

    /* deterministic far-out-of-window value: XOR with 0xFFFFFFFF flips all bits */
    seq = ctx->tcp->seq ^ bpf_htonl(0xFFFFFFFF);
    veilnet_tcp_set_seq(ctx, skb, seq);

    return TC_ACT_OK;
}

/*
 * Strategy: disorder / multidisorder family.
 *
 * Set URG with an urgent pointer inside the payload: several DPI stacks
 * handle URG data out-of-band, diverting their reassembly path.
 */
static __always_inline int veilnet_do_disorder(struct __sk_buff *skb, struct pkt_ctx *ctx, struct veilnet_rule_val *rv)
{
    __u32 old_flags, new_flags;
    __u64 off_check;

    if (!ctx->tcp || ctx->payload_len == 0)
        return TC_ACT_OK;

    /* byte offset of the TCP checksum field within the skb */
    off_check = (__u8 *)&ctx->tcp->check - (__u8 *)ctx->data;

    /* the URG bit (0x20) lives in the flags byte; fold the single-byte diff
     * into the checksum (size flag 0 = 1 byte) including the pseudo header */
    old_flags = ((__u32)ctx->tcp->urg << 5) & 0x20;
    new_flags = 0x20;

    ctx->tcp->urg = 1;
    ctx->tcp->urg_ptr = bpf_htons(1);

    bpf_l4_csum_replace(skb, off_check, old_flags, new_flags, BPF_F_PSEUDO_HDR);
    (void)rv;

    return TC_ACT_OK;
}

/*
 * Master dispatch: apply the strategy encoded in rule value rv.
 */
static __always_inline int veilnet_desync_apply(struct __sk_buff *skb, struct pkt_ctx *ctx, struct veilnet_rule_val *rv)
{
    if (!rv || !rv->enabled)
        return TC_ACT_OK;

    switch (rv->strategy) {
    case VEILNET_STRAT_NONE:
        return TC_ACT_OK;
    case VEILNET_STRAT_FAKE:
    case VEILNET_STRAT_FAKE_AGGRESSIVE:
        return veilnet_do_fake(skb, ctx, rv);
    case VEILNET_STRAT_MULTISPLIT:
    case VEILNET_STRAT_MULTISPLIT_SEQOVL:
    case VEILNET_STRAT_FAKE_FAKEDSPLIT:
    case VEILNET_STRAT_SPLIT2:
        return veilnet_do_multisplit(skb, ctx, rv);
    case VEILNET_STRAT_MULTIDISORDER:
    case VEILNET_STRAT_DISORDER:
    case VEILNET_STRAT_FAKE_MULTIDISORDER:
        return veilnet_do_disorder(skb, ctx, rv);
    default:
        return TC_ACT_OK;
    }
}

#endif /* __VEILNET_DESYNC_H */
