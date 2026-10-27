use anyhow::{Context, Result};
use std::os::unix::net::UnixListener;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener as TokioListener;
use tracing::{debug, error, info};

/// Commands accepted on the IPC socket (one per line, response one line).
pub const CMD_STATUS: &str = "status";
pub const CMD_RELOAD: &str = "reload";
pub const CMD_ATTACH: &str = "attach";
pub const CMD_DETACH: &str = "detach";
pub const CMD_INFO: &str = "info";
pub const CMD_IFACE: &str = "iface";
pub const CMD_PING: &str = "ping";

#[derive(Debug)]
pub struct Server {
    socket_path: String,
}

impl Server {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_string_lossy().into_owned(),
        }
    }

    /// Bind the unix socket and serve commands forever.
    /// `handler` processes each command line and returns a response line.
    pub async fn run<F>(&self, handler: F) -> Result<()>
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        // remove stale socket
        let _ = std::fs::remove_file(&self.socket_path);

        if let Some(parent) = Path::new(&self.socket_path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }

        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("Failed to bind {}", self.socket_path))?;
        let listener = TokioListener::from_std(listener)
            .context("Failed to convert to tokio listener")?;

        info!(path = %self.socket_path, "IPC server listening");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let handler = &handler;
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    match reader.read_line(&mut line).await {
                        Ok(0) => continue, // closed
                        Ok(_) => {
                            let cmd = line.trim();
                            debug!(cmd = %cmd, "IPC command");
                            let resp = handler(cmd);
                            let mut stream = reader.into_inner();
                            if let Err(e) = stream.write_all(resp.as_bytes()).await {
                                error!("IPC write failed: {e}");
                            }
                            let _ = stream.shutdown().await;
                        }
                        Err(e) => error!("IPC read failed: {e}"),
                    }
                }
                Err(e) => error!("IPC accept failed: {e}"),
            }
        }
    }
}
