pub mod client;
pub mod server;

// These are used by the IPC protocol; kept for documentation/future use
#[allow(dead_code)]
pub use server::{CMD_ATTACH, CMD_DETACH, CMD_IFACE, CMD_INFO, CMD_PING, CMD_RELOAD, CMD_STATUS};
