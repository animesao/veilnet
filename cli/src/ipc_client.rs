use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod imp {
    use super::*;
    use anyhow::Context;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    pub fn request(socket_path: &str, cmd: &str) -> Result<String> {
        let mut stream = UnixStream::connect(socket_path).with_context(|| {
            format!(
                "Failed to connect to veilnetd at {socket_path} (is the daemon running?)"
            )
        })?;

        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        stream.write_all(format!("{cmd}\n").as_bytes())?;
        stream.flush()?;

        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;

        Ok(resp.trim().to_string())
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    pub fn request(_socket_path: &str, _cmd: &str) -> Result<String> {
        anyhow::bail!("IPC is only supported on Unix systems")
    }
}

#[derive(Debug)]
pub struct Client {
    socket_path: PathBuf,
}

impl Client {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Send one command, read the response.
    pub fn request(&self, cmd: &str) -> Result<String> {
        imp::request(&self.socket_path.to_string_lossy(), cmd)
    }

    /// True when the daemon answers a ping.
    pub fn ping(&self) -> bool {
        self.request("ping").map(|r| r.contains("pong")).unwrap_or(false)
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new("/run/veilnet/veilnet.sock")
    }
}
