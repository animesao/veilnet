#ifndef __VEILNET_PARSER_H
#define __VEILNET_PARSER_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VEILNET_SNI_MAX 64
#define VEILNET_HTTP_SCAN_MAX 96

/* Parsed packet context shared across helpers */
struct pkt_ctx {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip4;
    struct ipv6hdr *ip6;
    struct tcphdr *tcp;
    __u8 *payload;      /* start of TCP payload */
    __u64 payload_len;  /* TCP payload length */
};

static __always_inline int veilnet_parse_eth(struct __sk_buff *skb, struct pkt_ctx *ctx)
{
    ctx->data = (void *)(long)skb->data;
    ctx->data_end = (void *)(long)skb->data_end;

    ctx->eth = ctx->data;
    if ((void *)(ctx->eth + 1) > ctx->data_end)
        return -1;

    return 0;
}

static __always_inline int veilnet_parse_ip(struct __sk_buff *skb, struct pkt_ctx *ctx)
{
    int ihl;

    if (veilnet_parse_eth(skb, ctx) < 0)
        return -1;

    if (ctx->eth->h_proto == bpf_htons(ETH_P_IP)) {
        ctx->ip4 = (struct iphdr *)(ctx->eth + 1);
        if ((void *)(ctx->ip4 + 1) > ctx->data_end)
            return -1;

        ihl = ctx->ip4->ihl * 4;
        if (ihl < 20)
            return -1;

        if ((void *)ctx->ip4 + ihl > ctx->data_end)
            return -1;

        if (ctx->ip4->protocol != IPPROTO_TCP)
            return -1;

        ctx->tcp = (struct tcphdr *)((void *)ctx->ip4 + ihl);
        ctx->ip6 = NULL;
    } else if (ctx->eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ctx->ip6 = (struct ipv6hdr *)(ctx->eth + 1);
        if ((void *)(ctx->ip6 + 1) > ctx->data_end)
            return -1;

        /* no extension headers support for now: plain TCP only */
        if (ctx->ip6->nexthdr != IPPROTO_TCP)
            return -1;

        ctx->tcp = (struct tcphdr *)(ctx->ip6 + 1);
        ctx->ip4 = NULL;
    } else {
        return -1;
    }

    if ((void *)(ctx->tcp + 1) > ctx->data_end)
        return -1;

    return 0;
}

static __always_inline int veilnet_parse_tcp(struct __sk_buff *skb, struct pkt_ctx *ctx)
{
    __u16 doff;
    void *tcp_end;

    if (veilnet_parse_ip(skb, ctx) < 0)
        return -1;

    doff = ctx->tcp->doff * 4;
    if (doff < 20)
        return -1;

    tcp_end = (void *)ctx->tcp + doff;
    if (tcp_end > ctx->data_end)
        return -1;

    ctx->payload = (__u8 *)tcp_end;
    ctx->payload_len = (__u64)(ctx->data_end - tcp_end);

    return 0;
}

/*
 * Extract SNI from a TLS ClientHello.
 *
 * Layout:
 *   payload[0]    handshake type (0x01 = ClientHello)
 *   payload[1..3] handshake length (3 bytes)
 *   payload[4..5] client version
 *   payload[6..37] random (32 bytes)
 *   payload[38]   session id length
 *   ...           session id
 *   ...           cipher suites length (2 bytes)
 *   ...           cipher suites
 *   ...           compression methods length (1 byte)
 *   ...           compression methods
 *   ...           extensions length (2 bytes)
 *   ...           extensions
 *
 * Each extension: type (2) + length (2) + data.
 * SNI extension (0x0000): list length (2) + [type (1, 0x00) + name length (2) + name]
 *
 * Returns SNI length (>0) and fills name, or 0 if not found,
 * or -1 on malformed/out-of-bounds input.
 */
static __always_inline int veilnet_extract_sni(struct pkt_ctx *ctx, __u8 *name, __u32 name_max)
{
    __u8 *p = ctx->payload;
    __u64 plen = ctx->payload_len;
    __u8 sid_len, comp_len;
    __u16 ext_total, ext_type, ext_len, sni_len;
    __u64 off;

    /* minimum: type(1) + len(3) + version(2) + random(32) + sid_len(1) = 39 */
    if (plen < 39 || p[0] != 0x01)
        return 0;

    off = 4;  /* skip type + 3-byte length */

    /* session id: version(2) + random(32) then sid_len at offset 38 */
    if (off + 34 > plen)
        return -1;
    sid_len = p[off + 33];  /* version(2) + random(32) then sid_len at +1 */
    off += 2 + 32 + 1 + sid_len;

    /* cipher suites: 2-byte length field + that many bytes */
    if (off + 2 > plen)
        return -1;
    off += 2 + ((__u16)p[off] << 8 | p[off + 1]);

    /* compression methods: 1-byte length + that many bytes */
    if (off + 1 > plen)
        return -1;
    comp_len = p[off];
    off += 1 + comp_len;

    /* extensions total length */
    if (off + 2 > plen)
        return -1;
    ext_total = ((__u16)p[off] << 8) | p[off + 1];
    off += 2;

    /* walk extensions; bound both by plen and ext_total */
    __u64 ext_end = off + ext_total;
    if (ext_end > plen)
        ext_end = plen;

    while (off + 4 <= ext_end) {
        ext_type = ((__u16)p[off] << 8) | p[off + 1];
        ext_len = ((__u16)p[off + 2] << 8) | p[off + 3];
        off += 4;

        if (off + ext_len > ext_end)
            break;

        if (ext_type == 0x0000 && ext_len >= 5) {
            /* server_name_list: list_len(2) + name_type(1) + name_len(2) + name */
            sni_len = ((__u16)p[off + 4] << 8) | p[off + 5];
            if (sni_len == 0 || sni_len > name_max)
                return 0;
            if (off + 6 + sni_len > ext_end)
                return 0;
            __builtin_memcpy(name, p + off + 6, sni_len);
            return sni_len;
        }

        off += ext_len;
    }

    return 0;
}

/*
 * Extract HTTP Host header from a plain HTTP request.
 * Scans only the first VEILNET_HTTP_SCAN_MAX bytes of payload.
 * Returns host length (>0) and fills host, 0 if not found.
 */
static __always_inline int veilnet_extract_http_host(struct pkt_ctx *ctx, __u8 *host, __u32 host_max)
{
    __u8 *p = ctx->payload;
    __u64 plen = ctx->payload_len;
    __u64 scan_len;
    __u64 i;

    if (plen < 16)
        return 0;

    /* must look like an HTTP request */
    if (p[0] != 'G' && p[0] != 'P' && p[0] != 'H' && p[0] != 'D' && p[0] != 'C' &&
        p[0] != 'O' && p[0] != 'T' && p[0] != 'L')
        return 0;

    scan_len = plen < VEILNET_HTTP_SCAN_MAX ? plen : VEILNET_HTTP_SCAN_MAX;

    for (i = 0; i + 6 <= scan_len; i++) {
        /* "Host: " */
        if (p[i] == 'H' && p[i + 1] == 'o' && p[i + 2] == 's' &&
            p[i + 3] == 't' && p[i + 4] == ':' && p[i + 5] == ' ') {
            __u64 j = i + 6;
            __u64 hlen = 0;
            while (j < scan_len && p[j] != '\r' && p[j] != '\n' && hlen < host_max) {
                host[hlen++] = p[j++];
            }
            if (hlen > 0)
                return hlen;
            return 0;
        }
    }

    return 0;
}

#endif /* __VEILNET_PARSER_H */
