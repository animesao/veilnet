use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub interface: Interface,
    /// `[[rule]]` array-of-tables; `rules = []` is also accepted.
    #[serde(default, alias = "rule")]
    pub rules: Vec<Rule>,
    /// IPs/CIDRs excluded from interception (optional, applied via nftables).
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Interface {
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    #[serde(alias = "match")]
    pub r#match: Match,
    pub strategy: String,
    #[serde(default = "default_params")]
    pub params: toml::Value,
}

fn default_params() -> toml::Value {
    toml::Value::Table(Default::default())
}

#[derive(Debug, Deserialize, Clone)]
pub struct Match {
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let cfg: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", path.display()))?;

        cfg.validate()?;
        Ok(cfg)
    }

    /// Structural validation: every rule must have a match and a known strategy id.
    pub fn validate(&self) -> Result<()> {
        use crate::rules::STRATEGY_IDS;

        for (i, rule) in self.rules.iter().enumerate() {
            if rule.r#match.ip.is_empty() && rule.r#match.domain.is_empty() {
                anyhow::bail!("rule[{i}]: 'match' must specify at least one ip or domain");
            }
            if !STRATEGY_IDS.contains(&rule.strategy.as_str()) {
                anyhow::bail!(
                    "rule[{i}]: unknown strategy '{}' (known: {})",
                    rule.strategy,
                    STRATEGY_IDS.join(", ")
                );
            }
        }
        Ok(())
    }

    pub fn default_path() -> &'static str {
        "/etc/veilnet/veilnet.toml"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[interface]
name = "eth0"

[[rule]]
match = { ip = ["8.8.8.8/32"] }
strategy = "multisplit"
params = { split_pos = 1 }
"#;

    #[test]
    fn parse_and_validate_ok() {
        let cfg: Config = toml::from_str(SAMPLE).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].strategy, "multisplit");
    }

    #[test]
    fn reject_unknown_strategy() {
        let bad = SAMPLE.replace("multisplit", "bogus");
        let cfg: Config = toml::from_str(&bad).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_empty_match() {
        let bad = r#"
[interface]
name = "eth0"

[[rule]]
match = { ip = [] }
strategy = "multisplit"
"#;
        let cfg: Config = toml::from_str(bad).unwrap();
        assert!(cfg.validate().is_err());
    }
}
