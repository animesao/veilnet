#ifndef __VEILNET_MAPS_H
#define __VEILNET_MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "desync.h"

/* LPM trie key: prefixlen must be the first field for BPF_MAP_TYPE_LPM_TRIE.
 * IPv4 addresses are stored in the first 4 bytes of addr (rest zero),
 * matching userspace maps::RawRuleKey (20 bytes total). */
struct rule_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct rule_key);
    __type(value, struct veilnet_rule_val);
    __uint(max_entries, VEILNET_MAX_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rules_map SEC(".maps");

#endif /* __VEILNET_MAPS_H */
