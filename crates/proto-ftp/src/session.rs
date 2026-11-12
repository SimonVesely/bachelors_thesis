//! # Per-client FTP session state
//! ## About:
//! - Login state, virtual cwd, transfer type, REST offset, RNFR source, pending data channel
//!   (`DataChannel::Passive` listener / `Active` address) and TLS state (PBSZ, PROT)
//! - `resolve` maps a client path to a real path under root: `..` can't go above `/`, and the
//!   result is checked with `proto_core::within_root` so symlinks can't escape (falls back to root)
//! - `virtual_path` / `virtual_cwd` - paths as the client sees them (root = `/`)
//! - `reset_after_auth` - RFC 4217: AUTH TLS resets the session to the logged-out state

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use tokio::net::TcpListener;

use crate::tls::TlsUpgrader;

pub enum DataChannel {
    None,
    Passive(TcpListener),
    Active(SocketAddr),
}

pub struct Session {
    pub root: PathBuf,
    pub cwd: PathBuf,
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
    pub active_port: u16,
}

impl Session {
    pub fn new(root: PathBuf, tls: Option<TlsUpgrader>) -> Self {
        Session {
            root,
            cwd: PathBuf::from("/"),
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
            active_port: 0,
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

        if !target.starts_with(&self.root) || !proto_core::within_root(&self.root, &target) {
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

    pub fn virtual_path(&self, target: &Path) -> String {
        let inside = target.strip_prefix(&self.root).unwrap_or(Path::new(""));
        format!("/{}", inside.to_string_lossy().replace('\\', "/"))
    }
}
