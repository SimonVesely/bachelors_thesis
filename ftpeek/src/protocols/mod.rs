mod ftp;
mod ftps;
mod sftp;
mod tftp;

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use proto_core::{Direction, EventKind, EventSender, MessageEvent, Protocol, UserDb};
use tokio::sync::broadcast;

use crate::components::ClientInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    Ftp,
    Ftps,
    Tftp,
    Sftp,
}

impl Proto {
    pub const ALL: [Proto; 4] = [Proto::Ftp, Proto::Ftps, Proto::Tftp, Proto::Sftp];

    pub fn spec(self) -> &'static dyn Spec {
        match self {
            Proto::Ftp => &ftp::Ftp,
            Proto::Ftps => &ftps::Ftps,
            Proto::Tftp => &tftp::Tftp,
            Proto::Sftp => &sftp::Sftp,
        }
    }

    pub fn of(protocol: Protocol) -> Proto {
        Proto::ALL
            .into_iter()
            .find(|p| p.spec().core() == protocol)
            .unwrap_or(Proto::Ftp)
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.spec().id())
    }
}

impl FromStr for Proto {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Proto::ALL
            .into_iter()
            .find(|p| p.spec().id() == s)
            .ok_or_else(|| format!("unknown protocol \"{s}\""))
    }
}

pub type ServeFuture = Pin<Box<dyn Future<Output = io::Result<()>>>>;

pub struct ServeCtx {
    pub bind: IpAddr,
    pub root: PathBuf,
    pub users: Option<Arc<UserDb>>,
    pub opts: Options,
    pub events: EventSender,
    pub shutdown: broadcast::Receiver<()>,
}

#[derive(Debug, PartialEq)]
pub enum Opt {
    Port {
        key: &'static str,
        label: &'static str,
        default: u16,
    },
    Choice {
        key: &'static str,
        label: &'static str,
        choices: &'static [(&'static str, &'static str)],
        default: &'static str,
    },
}

impl Opt {
    pub fn key(&self) -> &'static str {
        match self {
            Opt::Port { key, .. } | Opt::Choice { key, .. } => key,
        }
    }

    fn default_value(&self) -> String {
        match self {
            Opt::Port { default, .. } => default.to_string(),
            Opt::Choice { default, .. } => default.to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Options(HashMap<&'static str, String>);

impl Options {
    pub fn defaults(spec: &dyn Spec) -> Self {
        Options(
            spec.options()
                .iter()
                .map(|o| (o.key(), o.default_value()))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> &str {
        self.0.get(key).map_or("", String::as_str)
    }

    pub fn set(&mut self, key: &'static str, value: String) {
        self.0.insert(key, value);
    }

    pub fn port(&self, key: &str) -> u16 {
        self.get(key).parse().unwrap_or(0)
    }

    pub fn is(&self, key: &str, value: &str) -> bool {
        self.get(key) == value
    }
}

pub type Rows = Vec<(&'static str, String)>;
pub type Cells = [(String, String); 3];

pub struct Channel {
    pub name: &'static str,
    pub title: &'static str,
    pub record: (&'static str, &'static str),
}

pub const TLS: Channel = Channel {
    name: "TLS",
    title: "Transport Layer Security",
    record: ("Record layer", "Application Data (encrypted)"),
};

pub const SSH: Channel = Channel {
    name: "SSH",
    title: "Secure Shell",
    record: ("Binary packet", "SSH-2.0 channel data (encrypted)"),
};

pub fn track_common(client: &mut ClientInfo, e: &MessageEvent) {
    match e.kind {
        EventKind::Data => client.data_bytes += e.length as u64,
        EventKind::TcpClose if e.peer == client.addr => client.connected = false,
        _ => {}
    }
}

pub trait Spec: Sync {
    fn id(&self) -> &'static str;
    fn label(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn core(&self) -> Protocol;
    fn options(&self) -> &'static [Opt];
    fn capture_ports(&self, opts: &Options) -> Vec<u16>;
    fn serve(&self, ctx: ServeCtx) -> ServeFuture;

    fn title(&self, _opts: &Options) -> String {
        self.label().to_string()
    }

    fn login(&self) -> bool {
        true
    }

    fn can_decrypt(&self) -> bool {
        false
    }

    fn hints(&self) -> &'static [&'static str] {
        &[]
    }

    fn on_change(&self, _key: &str, _opts: &mut Options) {}

    fn channel(&self) -> Channel {
        TLS
    }

    fn transport_title(&self) -> &'static str {
        "Transmission Control Protocol"
    }

    fn app_title(&self, _e: &MessageEvent) -> String {
        format!("Application ({:?})", self.core())
    }

    fn detail_rows(&self, _e: &MessageEvent) -> Rows {
        Vec::new()
    }

    fn diagram_cells(&self, _e: &MessageEvent) -> Option<Cells> {
        None
    }

    fn proto_column(&self, e: &MessageEvent) -> String {
        let base = match e.kind {
            EventKind::TcpOpen | EventKind::TcpClose => return "TCP".into(),
            EventKind::Tls => return "TLS".into(),
            EventKind::Data => format!("{}-DATA", self.label()),
            EventKind::Message => self.label().to_string(),
        };
        match e.encrypted {
            true => format!("{base}+{}", self.channel().name),
            false => base,
        }
    }

    fn info(&self, e: &MessageEvent) -> String {
        let text = e.parsed.clone().unwrap_or_default();
        match (e.kind, e.direction) {
            (EventKind::Message, Direction::ClientToServer) => format!("Request: {text}"),
            (EventKind::Message, Direction::ServerToClient) => format!("Response: {text}"),
            _ => text,
        }
    }

    fn starts_group(&self, e: &MessageEvent) -> bool {
        e.kind == EventKind::TcpOpen
            || (e.kind == EventKind::Message && e.direction == Direction::ClientToServer)
    }

    fn track(&self, client: &mut ClientInfo, e: &MessageEvent) {
        track_common(client, e);
    }
}
