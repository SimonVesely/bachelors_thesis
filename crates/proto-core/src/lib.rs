use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Ftp,
    Ftps,
    Tftp,
    Sftp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Message,
    Data,
    TcpOpen,
    TcpClose,
    Tls,
}

#[derive(Debug, Clone)]
pub struct MessageEvent {
    pub protocol: Protocol,
    pub kind: EventKind,
    pub direction: Direction,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub timestamp: SystemTime,
    pub raw: Vec<u8>,
    pub length: usize,
    pub parsed: Option<String>,
    pub encrypted: bool,
}

impl MessageEvent {
    pub fn new(
        protocol: Protocol,
        kind: EventKind,
        direction: Direction,
        peer: SocketAddr,
        local: SocketAddr,
        raw: Vec<u8>,
        parsed: impl Into<String>,
    ) -> Self {
        let length = raw.len();
        MessageEvent {
            protocol,
            kind,
            direction,
            peer,
            local,
            timestamp: SystemTime::now(),
            raw,
            length,
            parsed: Some(parsed.into()),
            encrypted: false,
        }
    }

    pub fn with_encrypted(mut self, encrypted: bool) -> Self {
        self.encrypted = encrypted;
        self
    }

    pub fn with_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }
}

pub type EventSender = tokio::sync::mpsc::UnboundedSender<MessageEvent>;
pub type EventReceiver = tokio::sync::mpsc::UnboundedReceiver<MessageEvent>;

pub fn event_channel() -> (EventSender, EventReceiver) {
    tokio::sync::mpsc::unbounded_channel()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInterface {
    pub name: String,
    pub ip: IpAddr,
}

pub fn list_interfaces() -> Vec<NetInterface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| {
            let ip = iface.ip();
            NetInterface {
                name: iface.name,
                ip,
            }
        })
        .collect()
}
