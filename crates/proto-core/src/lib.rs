use std::net::IpAddr;
use std::net::SocketAddr;
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

#[derive(Debug, Clone)]
pub struct MessageEvent {
    pub protocol: Protocol,
    pub direction: Direction,
    pub peer: SocketAddr,
    pub timestamp: SystemTime,
    pub raw: Vec<u8>,
    pub parsed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInterface {
    pub name: String,
    pub ip: IpAddr,
}

pub type EventSender = tokio::sync::mpsc::UnboundedSender<MessageEvent>;
pub type EventReceiver = tokio::sync::mpsc::UnboundedReceiver<MessageEvent>;

pub fn event_channel() -> (EventSender, EventReceiver) {
    tokio::sync::mpsc::unbounded_channel()
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
