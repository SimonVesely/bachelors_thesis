use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use tokio::net::TcpListener;

use proto_core::EventSender;

use crate::connection::{PassiveRange, handle_client};

pub struct FtpServerConfig {
    pub bind_addr: IpAddr,
    pub control_port: u16,
    pub pasv_port_start: u16,
    pub pasv_port_end: u16,
    pub root_dir: PathBuf,
}

pub async fn serve(cfg: FtpServerConfig, events: EventSender) -> io::Result<()> {
    let listener = TcpListener::bind((cfg.bind_addr, cfg.control_port)).await?;
    tracing::info!(addr = %cfg.bind_addr, port = cfg.control_port, "FTP server listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let events = events.clone();
        let root = cfg.root_dir.clone();
        let bind_addr = cfg.bind_addr;
        let pasv_range = PassiveRange {
            start: cfg.pasv_port_start,
            end: cfg.pasv_port_end,
        };

        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, peer, bind_addr, root, pasv_range, events).await
            {
                tracing::warn!(%peer, %err, "FTP session ended with an error");
            }
        });
    }
}
