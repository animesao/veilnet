use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
pub struct Client {
    socket_path: String,
}

impl Client {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_string_lossy().into_owned(),
        }
    }

    /// Send one command, read one response line.
    pub fn request(&self, cmd: &str) -> Result<String> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "Failed to connect to veilnetd at {} (is the daemon running?)",
                self.socket_path
            )
        })?;

        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        stream.write_all(format!("{cmd}\n").as_bytes())?;
        stream.write_all(&[])?; // no flush needed for small writes, but be explicit
        stream.flush()?;

        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;

        Ok(resp.trim().to_string())
    }

    /// True when the daemon answers a ping.
    pub fn ping(&self) -> bool {
        self.request("ping").map(|r| r.contains("pong")).unwrap_or(false)
    }
}
