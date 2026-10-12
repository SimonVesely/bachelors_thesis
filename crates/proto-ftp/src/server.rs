use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use tokio::net::TcpListener;
use tokio::sync::broadcast;

use proto_core::{EventSender, Protocol};

use crate::connection::{PassiveRange, handle_client};
use crate::tls::TlsUpgrader;

pub struct FtpServerConfig {
    pub bind_addr: IpAddr,
    pub control_port: u16,
    pub pasv_port_start: u16,
    pub pasv_port_end: u16,
    pub root_dir: PathBuf,
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
                let bind_addr = cfg.bind_addr;
                let pasv_range = PassiveRange { start: cfg.pasv_port_start, end: cfg.pasv_port_end };
                let client_shutdown = shutdown.resubscribe();
                let tls = tls.clone();

                tokio::spawn(async move {
                    if let Err(err) = handle_client(
                        stream, peer, local, bind_addr, root, pasv_range,
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
