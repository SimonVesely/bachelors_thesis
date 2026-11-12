//! # FTP server listener
//! ## About:
//! - `serve` - plain FTP; `serve_with` - shared entry point used by proto-ftps with a
//!   `TlsUpgrader` and explicit/implicit mode
//! - One tokio task per client (`handle_client`), at most `MAX_CLIENTS` (200) at once,
//!   over the limit the client gets 421 (nothing is sent in implicit TLS mode)
//! - Accept errors (e.g. out of file descriptors) are logged and retried after 100 ms
//! - Shutdown broadcast stops accepting and is forwarded to every running session

use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast};

use proto_core::{EventSender, Protocol, UserDb};

use crate::connection::{DataPorts, handle_client};
use crate::tls::TlsUpgrader;

pub const MAX_CLIENTS: usize = 200;

pub struct FtpServerConfig {
    pub bind_addr: IpAddr,
    pub control_port: u16,
    pub pasv_port_start: u16,
    pub pasv_port_end: u16,
    pub active_port: u16,
    pub root_dir: PathBuf,
    pub users: Option<Arc<UserDb>>,
}

pub async fn serve(
    cfg: FtpServerConfig,
    events: EventSender,
    shutdown: broadcast::Receiver<()>,
) -> io::Result<()> {
    serve_with(cfg, events, shutdown, Protocol::Ftp, None, false).await
}

pub async fn serve_with(
    cfg: FtpServerConfig,
    events: EventSender,
    mut shutdown: broadcast::Receiver<()>,
    protocol: Protocol,
    tls: Option<TlsUpgrader>,
    implicit_tls: bool,
) -> io::Result<()> {
    let listener = TcpListener::bind((cfg.bind_addr, cfg.control_port)).await?;
    tracing::info!(addr = %cfg.bind_addr, port = cfg.control_port, ?protocol, "server listening");
    let slots = Arc::new(Semaphore::new(MAX_CLIENTS));

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, peer, local) = match accepted.and_then(|(s, p)| Ok((s.local_addr()?, s, p))) {
                    Ok((local, stream, peer)) => (stream, peer, local),
                    Err(err) => {
                        tracing::warn!(%err, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    if !implicit_tls {
                        let _ = stream.write_all(b"421 Too many connections, try again later.\r\n").await;
                    }
                    continue;
                };
                let events = events.clone();
                let root = cfg.root_dir.clone();
                let users = cfg.users.clone();
                let ports = DataPorts {
                    passive_start: cfg.pasv_port_start,
                    passive_end: cfg.pasv_port_end,
                    active: cfg.active_port,
                };
                let client_shutdown = shutdown.resubscribe();
                let tls = tls.clone();

                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(err) = handle_client(
                        stream, peer, local, users, root, ports,
                        events, client_shutdown, protocol, tls, implicit_tls,
                    ).await {
                        tracing::warn!(%peer, %err, "session ended with an error");
                    }
                });
            }
            _ = shutdown.recv() => {
                tracing::info!("server shutting down - no new connections accepted");
                break;
            }
        }
    }

    Ok(())
}
