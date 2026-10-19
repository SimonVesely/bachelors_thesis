use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use tokio::net::TcpListener;

use proto_core::Protocol;

use crate::tls::TlsUpgrader;

pub enum DataChannel {
    None,
    Passive(TcpListener),
    Active(SocketAddr),
}

pub struct Session {
    pub id: u64,
    pub root: PathBuf,
    pub cwd: PathBuf,
    pub protocol: Protocol,
    pub username: Option<String>,
    pub authenticated: bool,
    pub host: Option<String>,
    pub data_channel: DataChannel,
    pub binary: bool,
    pub rename_from: Option<PathBuf>,
    pub rest_offset: u64,
    pub tls: Option<TlsUpgrader>,
    pub tls_active: bool,
    pub pbsz_done: bool,
    pub prot_private: bool,
}

impl Session {
    pub fn new(id: u64, root: PathBuf, protocol: Protocol, tls: Option<TlsUpgrader>) -> Self {
        Session {
            id,
            root,
            cwd: PathBuf::from("/"),
            protocol,
            username: None,
            authenticated: false,
            host: None,
            data_channel: DataChannel::None,
            binary: true,
            rename_from: None,
            rest_offset: 0,
            tls,
            tls_active: false,
            pbsz_done: false,
            prot_private: false,
        }
    }

    pub fn resolve(&self, arg: &str) -> PathBuf {
        let mut target = if arg.starts_with('/') {
            self.root.clone()
        } else {
            self.root
                .join(self.cwd.strip_prefix("/").unwrap_or(&self.cwd))
        };

        for comp in Path::new(arg).components() {
            match comp {
                Component::Normal(part) => target.push(part),
                Component::ParentDir => {
                    if target != self.root {
                        target.pop();
                    }
                }
                Component::RootDir => target = self.root.clone(),
                _ => {}
            }
        }

        if !target.starts_with(&self.root) {
            target = self.root.clone();
        }
        target
    }

    pub fn reset_after_auth(&mut self) {
        self.username = None;
        self.authenticated = false;
        self.cwd = PathBuf::from("/");
        self.data_channel = DataChannel::None;
        self.binary = true;
        self.rename_from = None;
        self.rest_offset = 0;
        self.pbsz_done = false;
        self.prot_private = false;
    }

    pub fn virtual_cwd(&self) -> String {
        self.cwd.to_string_lossy().replace('\\', "/")
    }
}
