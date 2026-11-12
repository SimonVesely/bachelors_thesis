//! # Packet capture and Wireshark-like dissection
//! ## About:
//! - Pipeline: `live::start` (pcap) -> `RawFrame` -> `Dissector::dissect` -> `Packet` -> `layers()`
//! - Only traffic of the running server is kept (`CaptureConfig`: server IP, protocol, ports;
//!   `ports[0]` = control port, rest = data ports)
//! - TLS records are decrypted inline with secrets the FTPS server logged into `keys`
//! - `live` needs libpcap/Npcap and is behind the `capture` feature, the rest is pure parsing
//! ## Structure:
//! - live.rs - pcap device selection, BPF filter, reader threads
//! - dissect.rs - header parsing, TCP stream tracking, app protocol detection, Info column
//! - layers.rs - detail tree (layers + fields with byte ranges) for the GUI
//! - tls.rs, ssh.rs, tftp.rs - protocol parsers shared by dissect.rs and layers.rs
//! - decrypt.rs - TLS 1.2 / 1.3 key derivation and AEAD record decryption
//! - keys.rs - process-wide TLS key log

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
