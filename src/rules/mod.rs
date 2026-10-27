use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::Config;

/// LPM trie key. NOTE: `prefixlen` must be the first field of the on-wire
/// struct (see maps::RawRuleKey); `family` is metadata for userspace only.
#[derive(Debug, Clone)]
pub struct LpmKey {
    pub prefixlen: u32,
    pub family: u32,
    pub addr: [u8; 16],
}

#[derive(Debug, Clone, Default)]
pub struct RuleVal {
    pub strategy: u8,
    pub split_pos: u16,
    pub seqovl: u16,
    pub repeats: u8,
    pub tcp_fooling: u8,
    pub udp: bool,
    pub enabled: u8,
}

pub const FOOLING_NONE: u8 = 0;
pub const FOOLING_BADSEQ: u8 = 1;
pub const FOOLING_BADSUM: u8 = 2;
pub const FOOLING_TS: u8 = 3;
pub const FOOLING_MD5: u8 = 4;

/// Strategy ids shared with veilctl's built-in presets.
pub const STRATEGY_IDS: &[&str] = &[
    "none",
    "multisplit",
    "multisplit-seqovl",
    "fake",
    "fake-aggressive",
    "fake-fakedsplit",
    "fake-multidisorder",
    "multidisorder",
    "disorder",
    "split2",
];

pub fn strategy_to_u8(s: &str) -> u8 {
    // 0 = none, otherwise index+1 in STRATEGY_IDS
    STRATEGY_IDS
        .iter()
        .position(|id| *id == s)
        .map(|p| (p + 1) as u8)
        .unwrap_or(0)
}

pub fn fooling_to_u8(s: &str) -> u8 {
    match s {
        "badseq" => FOOLING_BADSEQ,
        "badsum" => FOOLING_BADSUM,
        "ts" => FOOLING_TS,
        "md5" => FOOLING_MD5,
        _ => FOOLING_NONE,
    }
}

pub fn cidr_to_lpm(cidr: &str) -> Result<LpmKey> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .context("Invalid CIDR, expected ip/prefix")?;
    let prefixlen: u32 = prefix_str.parse().context("Invalid prefix length")?;

    if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
        if prefixlen > 32 {
            anyhow::bail!("Prefix length {prefixlen} invalid for IPv4");
        }
        let mut addr = [0u8; 16];
        addr[0..4].copy_from_slice(&v4.octets());
        Ok(LpmKey { prefixlen, family: 2, addr })
    } else if let Ok(v6) = ip_str.parse::<Ipv6Addr>() {
        if prefixlen > 128 {
            anyhow::bail!("Prefix length {prefixlen} invalid for IPv6");
        }
        Ok(LpmKey { prefixlen, family: 10, addr: v6.octets() })
    } else {
        anyhow::bail!("Invalid IP address in CIDR: {}", cidr)
    }
}

pub fn build_from_config(cfg: &Config) -> Vec<(LpmKey, RuleVal)> {
    let mut out = Vec::new();
    for rule in &cfg.rules {
        for ip in &rule.r#match.ip {
            if let Ok(key) = cidr_to_lpm(ip) {
                out.push((key, rule_val_from(rule)));
            }
        }
    }
    out
}

fn rule_val_from(rule: &crate::config::Rule) -> RuleVal {
    let p = &rule.params;
    let get_u16 = |k: &str| -> u16 {
        p.get(k)
            .and_then(|v| v.as_integer())
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(0)
    };
    let get_u8 = |k: &str| -> u8 {
        p.get(k)
            .and_then(|v| v.as_integer())
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(0)
    };
    let get_str = |k: &str, d: &str| -> String {
        p.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or(d)
            .to_string()
    };

    RuleVal {
        strategy: strategy_to_u8(&rule.strategy),
        split_pos: get_u16("split_pos"),
        seqovl: get_u16("seqovl"),
        repeats: get_u8("repeats"),
        tcp_fooling: fooling_to_u8(&get_str("tcp_fooling", "none")),
        udp: p.get("udp").and_then(|v| v.as_bool()).unwrap_or(false),
        enabled: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_ids_match_bpf() {
        // bpf/veilnet.h strategy constants are 0..=9 in this exact order
        for (i, id) in STRATEGY_IDS.iter().enumerate() {
            assert_eq!(strategy_to_u8(id), (i as u8) + 1, "id {id} must map to {}", i + 1);
        }
        assert_eq!(strategy_to_u8("none"), 1);
        assert_eq!(strategy_to_u8("bogus"), 0);
    }

    #[test]
    fn cidr_to_lpm_v4() {
        let key = cidr_to_lpm("192.0.2.0/24").unwrap();
        assert_eq!(key.prefixlen, 24);
        assert_eq!(&key.addr[0..4], &[192, 0, 2, 0]);
        assert_eq!(key.family, 2);
    }

    #[test]
    fn cidr_to_lpm_v6() {
        let key = cidr_to_lpm("2001:db8::/32").unwrap();
        assert_eq!(key.prefixlen, 32);
        assert_eq!(&key.addr[0..4], &[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(key.family, 10);
    }

    #[test]
    fn cidr_invalid_rejected() {
        assert!(cidr_to_lpm("192.0.2.0").is_err());
        assert!(cidr_to_lpm("999.0.2.0/24").is_err());
        assert!(cidr_to_lpm("192.0.2.0/99").is_err());
    }

    #[test]
    fn build_from_config_rules() {
        let cfg_src = r#"
[interface]
name = "eth0"

[[rule]]
match = { ip = ["8.8.8.8/32", "203.0.113.0/24"] }
strategy = "fake"
params = { repeats = 6, udp = true }
"#;
        let cfg: Config = toml::from_str(cfg_src).unwrap();
        let rules = build_from_config(&cfg);
        assert_eq!(rules.len(), 2);
        let val = &rules[0].1;
        assert_eq!(val.strategy, 4); /* fake = id 3 in bpf, +1 */
        assert_eq!(val.repeats, 6);
        assert!(val.udp);
        assert_eq!(val.enabled, 1);
    }

    #[test]
    fn fooling_mapping() {
        assert_eq!(fooling_to_u8("badseq"), FOOLING_BADSEQ);
        assert_eq!(fooling_to_u8("badsum"), FOOLING_BADSUM);
        assert_eq!(fooling_to_u8("ts"), FOOLING_TS);
        assert_eq!(fooling_to_u8("md5"), FOOLING_MD5);
        assert_eq!(fooling_to_u8("none"), FOOLING_NONE);
        assert_eq!(fooling_to_u8("junk"), FOOLING_NONE);
    }
}
