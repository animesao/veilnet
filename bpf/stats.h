#ifndef __VEILNET_STATS_H
#define __VEILNET_STATS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum veilnet_stat {
    VEILNET_STAT_PKTS = 0,
    VEILNET_STAT_MATCHED,
    VEILNET_STAT_PASSED,
    VEILNET_STAT_DROPPED,
    VEILNET_STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, VEILNET_STAT_MAX);
} stats_map SEC(".maps");

static __always_inline void veilnet_stat_inc(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

#endif /* __VEILNET_STATS_H */
