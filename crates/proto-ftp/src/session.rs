use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use tokio::net::TcpListener;

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
}

impl Session {
    pub fn new(root: PathBuf) -> Self {
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

    pub fn virtual_cwd(&self) -> String {
        self.cwd.to_string_lossy().replace('\\', "/")
    }
}
