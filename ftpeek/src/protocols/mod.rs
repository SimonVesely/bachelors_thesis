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

use proto_core::{EventSender, Protocol, UserDb};
use tokio::sync::broadcast;

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
}
