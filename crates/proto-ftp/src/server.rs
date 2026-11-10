use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::broadcast;

use proto_core::{EventSender, Protocol, UserDb};

use crate::connection::{DataPorts, handle_client};
use crate::tls::TlsUpgrader;

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

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let local = stream.local_addr()?;
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
