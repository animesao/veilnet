use anyhow::Result;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::{
    config::Config,
    iface::resolve_iface,
    loader::BpfLoader,
    paths::{DEFAULT_CFG_PATH, EXAMPLE_CFG_PATH},
    rules::build_from_config,
};

pub struct App {
    cfg: Config,
    iface: String,
}

impl App {
    pub fn new() -> Result<Self> {
        let cfg = match Config::load(DEFAULT_CFG_PATH) {
            Ok(c) => c,
            Err(e) => {
                warn!("Config at {DEFAULT_CFG_PATH} failed: {e:#}; falling back to example");
                Config::load(EXAMPLE_CFG_PATH)?
            }
        };

        let iface = resolve_iface(Some(cfg.interface.name.clone()))?;
        Ok(Self { cfg, iface })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            iface = %self.iface,
            rules = self.cfg.rules.len(),
            "veilnet app initialized"
        );

        let reload = Arc::new(Notify::new());

        let mut loader = BpfLoader::new().with_iface(&self.iface);
        loader.load()?;
        loader.load_from_config(&self.cfg)?;
        loader.attach(&self.iface)?;
        loader.start_event_task();

        let state = Arc::new(Mutex::new(DaemonState {
            iface: self.iface.clone(),
            rules: self.cfg.rules.len(),
            attached: true,
            stats: loader.stats(),
        }));

        self.serve_ipc(state, reload).await
    }
}

pub struct DaemonState {
    iface: String,
    rules: usize,
    attached: bool,
    stats: crate::stats::VeilnetStats,
}

#[cfg(unix)]
impl App {
    async fn serve_ipc(
        self,
        state: Arc<Mutex<DaemonState>>,
        reload: Arc<Notify>,
    ) -> Result<()> {
        use crate::ipc::server::Server;
        use crate::paths::SOCK_PATH;

        let handler = move |cmd: &str| -> String { handle_command(cmd, &state, &reload) };
        let server = Server::new(SOCK_PATH);
        server.run(handler).await?;
        Ok(())
    }
}

#[cfg(not(unix))]
impl App {
    async fn serve_ipc(
        self,
        _state: Arc<Mutex<DaemonState>>,
        _reload: Arc<Notify>,
    ) -> Result<()> {
        warn!("IPC server is unavailable on this platform (unix sockets required)");
        Ok(())
    }
}

fn handle_command(cmd: &str, state: &Arc<Mutex<DaemonState>>, reload: &Arc<Notify>) -> String {
    let mut parts = cmd.split_whitespace();
    let verb = parts.next().unwrap_or("");
    let arg = parts.next().unwrap_or("");

    match verb {
        "ping" => "pong".to_string(),
        "status" => {
            let s = state.lock().unwrap();
            format!(
                "iface={} rules={} attached={} status=ok",
                s.iface, s.rules, s.attached
            )
        }
        "stats" => {
            let s = state.lock().unwrap();
            format!(
                "packets={} matched={} passed={} dropped={}",
                s.stats.packets, s.stats.matched, s.stats.passed, s.stats.dropped
            )
        }
        "iface" => {
            let s = state.lock().unwrap();
            s.iface.clone()
        }
        "reload" => {
            match Config::load(DEFAULT_CFG_PATH).or_else(|_| Config::load(EXAMPLE_CFG_PATH)) {
                Ok(cfg) => {
                    let rules = build_from_config(&cfg).len();
                    let mut s = state.lock().unwrap();
                    s.rules = rules;
                    reload.notify_one();
                    format!("reloaded rules={rules}")
                }
                Err(e) => format!("error reload: {e:#}"),
            }
        }
        "attach" => {
            let iface = if arg.is_empty() || arg == "auto" {
                None
            } else {
                Some(arg.to_string())
            };
            match resolve_iface(iface) {
                Ok(name) => {
                    let mut s = state.lock().unwrap();
                    s.iface = name.clone();
                    s.attached = true;
                    format!("attached {name}")
                }
                Err(e) => format!("error attach: {e:#}"),
            }
        }
        "detach" => {
            let mut s = state.lock().unwrap();
            s.attached = false;
            "detached".to_string()
        }
        "info" => {
            let s = state.lock().unwrap();
            format!(
                "iface={} rules={} attached={} packets={} matched={} passed={} dropped={}",
                s.iface,
                s.rules,
                s.attached,
                s.stats.packets,
                s.stats.matched,
                s.stats.passed,
                s.stats.dropped
            )
        }
        _ => format!("unknown command: {cmd}"),
    }
}
