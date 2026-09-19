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

pub type EventSender = tokio::sync::mpsc::UnboundedSender<MessageEvent>;
pub type EventReceiver = tokio::sync::mpsc::UnboundedReceiver<MessageEvent>;

pub fn event_channel() -> (EventSender, EventReceiver) {
    tokio::sync::mpsc::unbounded_channel()
}
