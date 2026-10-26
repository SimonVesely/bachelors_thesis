use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::Protocol;

mod decrypt;
mod dissect;
mod keys;
mod layers;
#[cfg(feature = "capture")]
mod live;
mod ssh;
mod tftp;
mod tls;

pub use decrypt::Plain;
pub use dissect::{
    ACK, App, Dissector, FIN, Headers, Ipv4, LinkLayer, Packet, SYN, Tcp, TcpOption, Transport,
    Udp, flag_names, parse_headers,
};
pub use keys::{keylog, record_secret};
pub use layers::{Field, Layer, decrypted_layers, layers};
#[cfg(feature = "capture")]
pub use live::{Capture, start};
pub use ssh::SshHalf;
pub use tls::TlsHalf;

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub server_ip: IpAddr,
    pub protocol: Protocol,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct RawFrame {
    pub timestamp: SystemTime,
    pub linktype: i32,
    pub data: Vec<u8>,
    pub wire_len: u32,
    pub interface: Arc<str>,
}
