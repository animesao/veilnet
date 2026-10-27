#[derive(Debug, Default, Clone)]
pub struct VeilnetStats {
    pub packets: u64,
    pub matched: u64,
    pub passed: u64,
    pub dropped: u64,
}

impl VeilnetStats {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::VeilnetStats;
    use anyhow::{Context, Result};
    use libbpf_rs::MapCore;
    use libbpf_rs::Object;
    use tracing::debug;

    pub fn read_stats(obj: &mut Object) -> Result<VeilnetStats> {
        let map = obj
            .maps_mut()
            .find(|m| m.name() == "stats_map")
            .context("stats_map not found in BPF object")?;

        let get = |key: u32| -> Result<u64> {
            let k = key.to_ne_bytes();
            match map.lookup(&k, libbpf_rs::MapFlags::ANY) {
                Ok(Some(bytes)) => {
                    let mut arr = [0u8; 8];
                    let n = bytes.len().min(8);
                    arr[..n].copy_from_slice(&bytes[..n]);
                    Ok(u64::from_le_bytes(arr))
                }
                Ok(None) => Ok(0),
                Err(e) => Err(e).context("Failed to lookup stats_map"),
            }
        };

        let stats = VeilnetStats {
            packets: get(0)?,
            matched: get(1)?,
            passed: get(2)?,
            dropped: get(3)?,
        };

        debug!(?stats, "read stats from stats_map");
        Ok(stats)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::VeilnetStats;
    use anyhow::Result;
    use tracing::debug;

    pub fn read_stats() -> Result<VeilnetStats> {
        debug!("stats reading is a no-op on non-Linux hosts");
        Ok(VeilnetStats::default())
    }
}

#[allow(unused_imports)]
pub use imp::read_stats;
