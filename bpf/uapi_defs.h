#ifndef __VEILNET_UAPI_DEFS_H
#define __VEILNET_UAPI_DEFS_H

/*
 * UAPI constants used by veilnet's BPF programs.
 *
 * vmlinux.h (generated from kernel BTF) contains type and enum definitions
 * only -- it never carries #define macros. These constants normally come
 * from linux/pkt_cls.h, linux/if_ether.h, linux/in.h and linux/bpf.h, which
 * must not be mixed into a BPF program that includes vmlinux.h, so they are
 * re-declared here.
 */

/* linux/pkt_cls.h */
#ifndef TC_ACT_OK
#define TC_ACT_OK		0
#endif
#ifndef TC_ACT_RECLASSIFY
#define TC_ACT_RECLASSIFY	1
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT		2
#endif
#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE		3
#endif
#ifndef TC_ACT_STOLEN
#define TC_ACT_STOLEN		4
#endif
#ifndef TC_ACT_QUEUED
#define TC_ACT_QUEUED		5
#endif
#ifndef TC_ACT_REPEAT
#define TC_ACT_REPEAT		6
#endif
#ifndef TC_ACT_REDIRECT
#define TC_ACT_REDIRECT		7
#endif
#ifndef TC_ACT_JUMP
#define TC_ACT_JUMP		8
#endif

/* linux/if_ether.h */
#ifndef ETH_P_IP
#define ETH_P_IP	0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6	0x86DD
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP	0x0806
#endif

/* linux/in.h */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP	6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP	17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP	1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6	58
#endif

/* linux/bpf.h: csum replace and map flags */
#ifndef BPF_F_RECOMPUTE_CSUM
#define BPF_F_RECOMPUTE_CSUM		(1ULL << 0)
#endif
#ifndef BPF_F_INVALIDATE_HASH
#define BPF_F_INVALIDATE_HASH		(1ULL << 1)
#endif
#ifndef BPF_F_PSEUDO_HDR
#define BPF_F_PSEUDO_HDR		(1ULL << 4)
#endif
#ifndef BPF_F_MARK_MANGLED_0
#define BPF_F_MARK_MANGLED_0		(1ULL << 5)
#endif
#ifndef BPF_F_MARK_ENFORCE
#define BPF_F_MARK_ENFORCE		(1ULL << 6)
#endif
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC		(1U << 0)
#endif

#endif /* __VEILNET_UAPI_DEFS_H */
