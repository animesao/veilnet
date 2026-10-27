//! Byte-layout helpers for BPF maps.
//!
//! These encode the exact wire format shared between userspace and
//! `bpf/maps.h` / `bpf/desync.h`:
//!
//! - `rule_key`: `u32 prefixlen (be) + u8 addr[16]` = 20 bytes
//! - `rule_val`: `u8 strategy, u16 split_pos, u16 seqovl, u8 repeats,
//!    u8 tcp_fooling, u8 udp, u8 enabled, u8 pad[7]` = 16 bytes

use crate::rules::{LpmKey, RuleVal};

pub const RULE_KEY_SIZE: usize = 20;
pub const RULE_VAL_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRuleKey(pub [u8; RULE_KEY_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRuleVal(pub [u8; RULE_VAL_SIZE]);

impl From<&LpmKey> for RawRuleKey {
    fn from(key: &LpmKey) -> Self {
        let mut out = [0u8; RULE_KEY_SIZE];
        out[0..4].copy_from_slice(&key.prefixlen.to_be_bytes());
        out[4..20].copy_from_slice(&key.addr);
        RawRuleKey(out)
    }
}

impl From<&RuleVal> for RawRuleVal {
    fn from(val: &RuleVal) -> Self {
        let mut out = [0u8; RULE_VAL_SIZE];
        out[0] = val.strategy;
        out[1..3].copy_from_slice(&val.split_pos.to_le_bytes());
        out[3..5].copy_from_slice(&val.seqovl.to_le_bytes());
        out[5] = val.repeats;
        out[6] = val.tcp_fooling;
        out[7] = if val.udp { 1 } else { 0 };
        out[8] = val.enabled;
        RawRuleVal(out)
    }
}

impl RawRuleVal {
    /// Decode back into a RuleVal (inverse of From impl).
    pub fn to_rule_val(&self) -> RuleVal {
        RuleVal {
            strategy: self.0[0],
            split_pos: u16::from_le_bytes([self.0[1], self.0[2]]),
            seqovl: u16::from_le_bytes([self.0[3], self.0[4]]),
            repeats: self.0[5],
            tcp_fooling: self.0[6],
            udp: self.0[7] != 0,
            enabled: self.0[8],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip_prefix_and_addr() {
        let key = LpmKey {
            prefixlen: 24,
            family: 2,
            addr: {
                let mut a = [0u8; 16];
                a[0..4].copy_from_slice(&[192, 0, 2, 0]);
                a
            },
        };
        let raw = RawRuleKey::from(&key);
        // prefixlen is big-endian on the wire
        assert_eq!(&raw.0[0..4], &[0, 0, 0, 24]);
        assert_eq!(&raw.0[4..8], &[192, 0, 2, 0]);
    }

    #[test]
    fn val_roundtrip_all_fields() {
        let val = RuleVal {
            strategy: 3,
            split_pos: 681,
            seqovl: 65535,
            repeats: 11,
            tcp_fooling: 2,
            udp: true,
            enabled: 1,
        };
        let raw = RawRuleVal::from(&val);
        assert_eq!(raw.0[0], 3);
        assert_eq!(u16::from_le_bytes([raw.0[1], raw.0[2]]), 681);
        let back = raw.to_rule_val();
        assert_eq!(back.strategy, 3);
        assert_eq!(back.split_pos, 681);
        assert_eq!(back.seqovl, 65535);
        assert_eq!(back.repeats, 11);
        assert_eq!(back.tcp_fooling, 2);
        assert!(back.udp);
        assert_eq!(back.enabled, 1);
    }
}
