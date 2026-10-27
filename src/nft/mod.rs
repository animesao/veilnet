//! Optional nftables integration.
//!
//! veilnet does not require nftables: TC + eBPF works standalone. This module
//! provides a helper for deployments that want to exclude the daemon's own
//! traffic or specific hosts from interception (e.g. loopback protection),
//! mirroring `--ipset-exclude` semantics from zapret configs.

use anyhow::{Context, Result};
use std::process::Command;

pub const NFT_TABLE: &str = "veilnet";

/// An nftables exclusion entry: traffic to/from these IPs skips veilnet.
#[derive(Debug, Clone)]
pub struct NftExclusions {
    pub ips: Vec<String>,
}

impl NftExclusions {
    pub fn from_config_ips(ips: &[String]) -> Self {
        Self {
            ips: ips.to_vec(),
        }
    }

    /// Render an nftables ruleset creating table `veilnet` with an exclusion set.
    pub fn render_ruleset(&self) -> String {
        let mut set_elements = String::new();
        for (i, ip) in self.ips.iter().enumerate() {
            if i > 0 {
                set_elements.push_str(", ");
            }
            set_elements.push_str(ip);
        }

        format!(
            "table inet {table} {{\n\
             \x20\x20\x20\x20set exclude {{\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20type ipv4_addr\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20flags interval\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20elements = {{ {elements} }}\n\
             \x20\x20\x20\x20}}\n\
             }}\n",
            table = NFT_TABLE,
            elements = set_elements
        )
    }

    /// Apply the ruleset via `nft -f -`.
    pub fn apply(&self) -> Result<()> {
        if self.ips.is_empty() {
            return Ok(());
        }

        let ruleset = self.render_ruleset();
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn nft (is nftables installed?)")?;

        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(ruleset.as_bytes())
                .context("Failed to write ruleset to nft")?;
        }
        // drop stdin to signal EOF
        drop(child.stdin.take());

        let out = child
            .wait_with_output()
            .context("Failed to wait for nft")?;
        if !out.status.success() {
            anyhow::bail!(
                "nft failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }

        Ok(())
    }
}

/// Remove the `veilnet` nftables table if it exists.
pub fn cleanup() -> Result<()> {
    let status = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .status()
        .context("Failed to spawn nft")?;
    let _ = status;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_ruleset_empty() {
        let excl = NftExclusions::from_config_ips(&[]);
        let rs = excl.render_ruleset();
        // table renders fine but contains no elements
        assert!(rs.contains("table inet veilnet"));
        assert!(!rs.contains("10."));
        // and apply() is a no-op for empty lists
        assert!(excl.apply().is_ok());
    }

    #[test]
    fn render_ruleset_elements() {
        let excl = NftExclusions::from_config_ips(&["10.0.0.0/8".into(), "192.168.1.1".into()]);
        let rs = excl.render_ruleset();
        assert!(rs.contains("table inet veilnet"));
        assert!(rs.contains("10.0.0.0/8, 192.168.1.1"));
    }
}
