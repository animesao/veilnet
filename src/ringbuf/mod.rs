use std::net::Ipv4Addr;

/// One event read from the eBPF ring buffer.
/// Layout must match `struct veilnet_event` in bpf/ringbuf.h.
#[derive(Debug, Clone, Default)]
pub struct VeilnetEvent {
    pub ts_ns: u64,
    pub ifindex: u32,
    pub evt_type: u8,
    pub action: u8,
    pub strategy: u8,
    pub proto: u8,
    pub src_v4: u32,
    pub dst_v4: u32,
    pub sport: u16,
    pub dport: u16,
}

impl VeilnetEvent {
    const SIZE: usize = 32; /* 8+4+1+1+1+1+pad+4+4+2+2 = 32 bytes with padding */

    /// Decode a raw ring buffer record into an event.
    /// Returns None if the record is malformed or a different version.
    pub fn from_bytes(buf: &[u8]) -> Option<VeilnetEvent> {
        if buf.len() != Self::SIZE {
            return None;
        }

        let evt = VeilnetEvent {
            ts_ns: u64::from_le_bytes(buf[0..8].try_into().ok()?),
            ifindex: u32::from_le_bytes(buf[8..12].try_into().ok()?),
            evt_type: buf[12],
            action: buf[13],
            strategy: buf[14],
            proto: buf[15],
            src_v4: u32::from_le_bytes(buf[16..20].try_into().ok()?),
            dst_v4: u32::from_le_bytes(buf[20..24].try_into().ok()?),
            sport: u16::from_le_bytes(buf[24..26].try_into().ok()?),
            dport: u16::from_le_bytes(buf[26..28].try_into().ok()?),
        };
        Some(evt)
    }

    pub fn event_name(&self) -> &'static str {
        match self.evt_type {
            0 => "pkts",
            1 => "match",
            2 => "strat",
            3 => "drop",
            _ => "unknown",
        }
    }

    /// IPv4 source as dotted-quad string, "n/a" for IPv6 or unset.
    pub fn src_str(&self) -> String {
        if self.proto != 4 {
            return "n/a".to_string();
        }
        Ipv4Addr::from(self.src_v4).to_string()
    }

    /// IPv4 destination as dotted-quad string, "n/a" for IPv6 or unset.
    pub fn dst_str(&self) -> String {
        if self.proto != 4 {
            return "n/a".to_string();
        }
    Ipv4Addr::from(self.dst_v4).to_string()
    }
}

#[cfg(target_os = "linux")]
mod reader {
    use super::VeilnetEvent;
    use anyhow::{Context, Result};
    use libbpf_rs::{MapCore, Object, RingBuffer, RingBufferBuilder};
    use std::time::Duration;
    use tracing::{info, warn};

    /// eBPF ringbuf consumer. Logs every event via tracing.
    pub struct EventReader {
        rb: RingBuffer<'static>,
    }

    impl EventReader {
        /// Attach a ring buffer consumer to the `events_rb` map of a loaded object.
        pub fn new(obj: &mut Object) -> Result<Self> {
            let mut builder = RingBufferBuilder::new();

            let cb = move |data: &[u8]| -> i32 {
                match VeilnetEvent::from_bytes(data) {
                    Some(evt) => {
                        info!(
                            evt = evt.event_name(),
                            ifindex = evt.ifindex,
                            src = %evt.src_str(),
                            dst = %evt.dst_str(),
                            dport = evt.dport,
                            strategy = evt.strategy,
                            "veilnet event"
                        );
                        0
                    }
                    None => {
                        warn!(len = data.len(), "malformed ringbuf record skipped");
                        0
    }
                }
            };

            let map = obj
                .maps_mut()
                .find(|m| m.name() == "events_rb")
                .context("events_rb map not found in BPF object")?;

            builder
                .add(&*map, cb)
                .context("Failed to add ringbuf callback")?;
            let rb = builder.build().context("Failed to build ring buffer")?;

            Ok(Self { rb })
        }

        /// Poll once with a 50ms timeout, consume available events.
        pub fn poll(&mut self) -> Result<()> {
            self.rb.poll(Duration::from_millis(50))?;
            Ok(())
        }

        /// Poll until the daemon shuts down.
        pub fn run(&mut self) -> Result<()> {
            loop {
                self.poll()?;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod reader {
    use anyhow::Result;
    use tracing::debug;

    pub struct EventReader;

    impl EventReader {
        pub fn new() -> Result<Self> {
            debug!("ringbuf reader is a no-op on non-Linux hosts");
            Ok(Self)
        }

        pub fn poll(&mut self) -> Result<()> {
            Ok(())
        }

        pub fn run(&mut self) -> Result<()> {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
    }
}

#[allow(unused_imports)]
pub use reader::EventReader;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_event_roundtrip() {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&123456789u64.to_le_bytes());
        buf[8..12].copy_from_slice(&7u32.to_le_bytes());
        buf[12] = 1; /* match */
        buf[13] = 0;
        buf[14] = 3; /* fake */
        buf[15] = 4; /* IPv4 */
        buf[16..20].copy_from_slice(&0x08080808u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0xC0000211u32.to_le_bytes());
        buf[24..26].copy_from_slice(&12345u16.to_le_bytes());
        buf[26..28].copy_from_slice(&443u16.to_le_bytes());

        let evt = VeilnetEvent::from_bytes(&buf).unwrap();
        assert_eq!(evt.ts_ns, 123456789);
        assert_eq!(evt.ifindex, 7);
        assert_eq!(evt.evt_type, 1);
        assert_eq!(evt.src_str(), "8.8.8.8");
        assert_eq!(evt.dst_str(), "192.0.2.17");
        assert_eq!(evt.dport, 443);
    }
}
