mod app;
mod config;
mod iface;
#[cfg(unix)]
mod ipc;
mod loader;
mod maps;
mod nft;
mod paths;
mod ringbuf;
mod rules;
mod stats;
mod util;

use anyhow::Result;
use app::App;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("veilnetd starting (TC + eBPF)");
    warn!("Running in skeleton mode - eBPF load/attach not yet active");

    if !util::is_root() {
        warn!("Not running as root. CAP_NET_ADMIN/CAP_NET_RAW may be required for TC/eBPF");
    }

    let app = App::new()?;
    app.run().await?;

    Ok(())
}
