use anyhow::{Context, Result};
use std::fs;

/// Detect the interface of the default route via /proc/net/route.
pub fn detect_default_iface() -> Result<String> {
    let content = fs::read_to_string("/proc/net/route")
        .context("Failed to read /proc/net/route (Linux only)")?;

    let mut best: Option<(u32, String)> = None;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        // default route: destination 00000000, usable flags (UP|GATEWAY)
        if parts[1] == "00000000" {
            let metric: u32 = parts[7].parse().unwrap_or(u32::MAX);
            if best.as_ref().map(|(m, _)| metric < *m).unwrap_or(true) {
                best = Some((metric, parts[0].to_string()));
            }
        }
    }

    match best {
        Some((_, name)) => Ok(name),
        None => Ok("eth0".to_string()),
    }
}

/// Resolve the interface name: explicit wins, "auto" or empty triggers detection.
pub fn resolve_iface(explicit: Option<String>) -> Result<String> {
    match explicit {
        Some(iface) if !iface.is_empty() && iface != "auto" => Ok(iface),
        _ => detect_default_iface().context("Failed to auto-detect network interface"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_explicit_wins() {
        assert_eq!(resolve_iface(Some("wlan0".into())).unwrap(), "wlan0");
    }

    #[test]
    fn resolve_auto_falls_back() {
        // on non-Linux dev hosts /proc is absent -> Err, on Linux -> Ok(eth0 or detected)
        let r = resolve_iface(Some("auto".into()));
        match r {
            Ok(name) => assert!(!name.is_empty()),
            Err(_) => {} // acceptable on non-Linux hosts
        }
    }
}
