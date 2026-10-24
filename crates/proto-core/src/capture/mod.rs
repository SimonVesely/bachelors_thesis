use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::Protocol;

mod dissect;
mod layers;
#[cfg(feature = "capture")]
mod live;
mod tftp;
mod tls;

pub use dissect::{
    ACK, App, Dissector, FIN, Headers, Ipv4, LinkLayer, Packet, SYN, Tcp, TcpOption, Transport,
    Udp, flag_names, parse_headers,
};
pub use layers::{Field, Layer, layers};
#[cfg(feature = "capture")]
pub use live::{Capture, start};
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
