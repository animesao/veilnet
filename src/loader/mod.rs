use crate::config::Config;
use anyhow::Result;

#[cfg(target_os = "linux")]
mod imp {
    use crate::config::Config;
    use crate::maps::{RawRuleKey, RawRuleVal};
    use crate::paths::BPF_OBJ_PATH;
    use crate::rules::{build_from_config, LpmKey, RuleVal};
    use anyhow::{bail, Context, Result};
    use libbpf_rs::{MapCore, Object, ObjectBuilder, TcHook, TC_EGRESS, TC_INGRESS};
    use tracing::info;

    pub struct Loader {
        obj: Option<Object>,
        hooks: Vec<TcHook>,
        ifaces: Vec<String>,
    }

    impl Loader {
        pub fn new() -> Loader {
            Loader {
                obj: None,
                hooks: Vec::new(),
                ifaces: Vec::new(),
            }
        }

        pub fn load(&mut self) -> Result<()> {
            let obj_data = std::fs::read(BPF_OBJ_PATH)
                .with_context(|| format!("Failed to read BPF object {BPF_OBJ_PATH}"))?;
            let mut obj = ObjectBuilder::new()
                .open_memory("veilnet", &obj_data)
                .context("Failed to open BPF object")?
                .load()
                .context("Failed to load BPF object")?;

            for prog in obj.progs_mut() {
                info!(prog = prog.name(), "loaded eBPF program");
            }

            self.obj = Some(obj);
            Ok(())
        }

        pub fn sync_rules(&mut self, cfg: &Config) -> Result<()> {
            let obj = self
                .obj
                .as_mut()
                .context("BPF object not loaded; call load() first")?;
            let map = obj
                .map_mut("rules_map")
                .context("rules_map not found in BPF object")?;

            let rules = build_from_config(cfg);

            // full re-sync: clear existing entries then insert fresh
            for key in map.keys().collect::<Vec<_>>() {
                let _ = map.delete(&key);
            }

            for (key, val) in &rules {
                let k = RawRuleKey::from(key).0;
                let v = RawRuleVal::from(val).0;
                map.update(&k, &v, libbpf_rs::MapFlags::NO_EXIST)
                    .context("Failed to insert rule into rules_map")?;
            }

            info!(rules = rules.len(), "synced rules to rules_map");
            Ok(())
        }

        pub fn attach(&mut self, iface: &str) -> Result<()> {
            let obj = self
                .obj
                .as_mut()
                .context("BPF object not loaded; call load() first")?;

            let ifindex = if_nametoindex(iface)? as i32;

            let ingress_prog = obj
                .prog_mut("veilnet_ingress")
                .context("veilnet_ingress program not found")?;
            let egress_prog = obj
                .prog_mut("veilnet_egress")
                .context("veilnet_egress program not found")?;

            // create() also installs the clsact qdisc if missing
            let mut ingress_hook = TcHook::new(ingress_prog.fd());
            ingress_hook
                .ifindex(ifindex)
                .attach_point(TC_INGRESS)
                .replace(true);
            ingress_hook
                .create()
                .context("Failed to create TC ingress hook")?;
            ingress_hook
                .attach()
                .context("Failed to attach TC ingress filter")?;

            let mut egress_hook = TcHook::new(egress_prog.fd());
            egress_hook
                .ifindex(ifindex)
                .attach_point(TC_EGRESS)
                .replace(true);
            egress_hook
                .create()
                .context("Failed to create TC egress hook")?;
            egress_hook
                .attach()
                .context("Failed to attach TC egress filter")?;

            info!(iface = %iface, "attached TC ingress+egress hooks");
            self.ifaces.push(iface.to_string());
            self.hooks.push(ingress_hook);
            self.hooks.push(egress_hook);
            Ok(())
        }

        pub fn detach(&mut self) -> Result<()> {
            let mut last_err = None;
            while let Some(mut hook) = self.hooks.pop() {
                if let Err(e) = hook.detach() {
                    tracing::warn!(error = %e, "TC hook detach failed");
                    last_err = Some(e);
                }
            }
            self.ifaces.clear();
            match last_err {
                Some(e) => bail!("detach failed: {e:#}"),
                None => Ok(()),
            }
        }

        /// Spawn a background thread that consumes ringbuf events and logs them.
        pub fn start_event_task(&mut self) {
            use crate::ringbuf::EventReader;

            if let Some(obj) = self.obj.as_mut() {
                match EventReader::new(obj) {
                    Ok(mut reader) => {
                        std::thread::spawn(move || {
                            if let Err(e) = reader.run() {
                                tracing::warn!("ringbuf reader thread stopped: {e:#}");
                            }
                        });
                    }
                    Err(e) => tracing::warn!("Failed to start ringbuf reader: {e:#}"),
                }
            }
        }

        /// Read current counters from stats_map.
        pub fn stats(&mut self) -> crate::stats::VeilnetStats {
            use crate::stats::read_stats;
            match self.obj.as_mut() {
                Some(obj) => read_stats(obj).unwrap_or_default(),
                None => crate::stats::VeilnetStats::default(),
            }
        }
    }

    impl Drop for Loader {
        fn drop(&mut self) {
            let _ = self.detach();
        }
    }

    fn if_nametoindex(iface: &str) -> Result<u32> {
        let c = std::ffi::CString::new(iface)
            .with_context(|| format!("Invalid interface name {iface}"))?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx == 0 {
            bail!("Interface {iface} not found");
        }
        Ok(idx)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use crate::config::Config;
    use anyhow::Result;
    use tracing::{info, warn};

    pub struct Loader;

    impl Loader {
        pub fn new() -> Loader {
            Loader
        }

        pub fn load(&mut self) -> Result<()> {
            warn!("eBPF loading is only supported on Linux");
            Ok(())
        }

        pub fn sync_rules(&mut self, cfg: &Config) -> Result<()> {
            info!(rules = cfg.rules.len(), "rule sync is a no-op on non-Linux hosts");
            Ok(())
        }

        pub fn attach(&mut self, iface: &str) -> Result<()> {
            warn!(iface = %iface, "TC attach is only supported on Linux");
            Ok(())
        }

        pub fn detach(&mut self) -> Result<()> {
            Ok(())
        }

        /// Spawn a background thread that consumes ringbuf events and logs them.
        pub fn start_event_task(&mut self) {
            tracing::debug!("ringbuf events are unavailable on non-Linux hosts");
        }

        /// Read current counters from stats_map.
        pub fn stats(&mut self) -> crate::stats::VeilnetStats {
            crate::stats::VeilnetStats::default()
        }
    }
}

pub use imp::Loader;

pub struct BpfLoader {
    iface: Option<String>,
    inner: Loader,
}

impl Default for BpfLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfLoader {
    pub fn new() -> Self {
        Self {
            iface: None,
            inner: Loader::new(),
        }
    }

    pub fn with_iface(mut self, iface: impl Into<String>) -> Self {
        self.iface = Some(iface.into());
        self
    }

    pub fn load(&mut self) -> Result<()> {
        self.inner.load()
    }

    pub fn load_from_config(&mut self, cfg: &Config) -> Result<()> {
        self.inner.sync_rules(cfg)
    }

    pub fn attach(&mut self, iface: &str) -> Result<()> {
        self.inner.attach(iface)?;
        self.iface = Some(iface.to_string());
        Ok(())
    }

    pub fn detach(&mut self) -> Result<()> {
        self.inner.detach()?;
        self.iface = None;
        Ok(())
    }

    pub fn is_attached(&self) -> bool {
        self.iface.is_some()
    }

    /// Spawn a background thread that consumes ringbuf events and logs them.
    pub fn start_event_task(&mut self) {
        self.inner.start_event_task();
    }

    /// Read current counters from stats_map.
    pub fn stats(&mut self) -> crate::stats::VeilnetStats {
        self.inner.stats()
    }
}

impl Drop for BpfLoader {
    fn drop(&mut self) {
        let _ = self.inner.detach();
    }
}
