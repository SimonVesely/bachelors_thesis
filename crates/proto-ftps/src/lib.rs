//! # FTPS Protocol implementation using RFCs 4217(FTP over TLS) and 2228(FTP security extensions)
//! ## About:
//! - FTPS server made in pure Rust on top of proto-ftp crate, all FTP logic (commands, sessions,
//! passive data connections) is reused from proto-ftp, this crate only adds the TLS layer
//! - Supports both modes:
//!   - Explicit - client connects in plain FTP and upgrades with AUTH TLS (usually port 21)
//!   - Implicit - TLS from the first byte of the connection (usually port 990)
//! - TLS via rustls with ring crypto provider, TLS 1.2 and TLS 1.3
//! - Self-signed certificate (rcgen) is generated on every start for localhost and bind address
//! - Data connections resume the TLS session of the control connection (session cache + tickets),
//! which many clients like FileZilla require
//! - Session secrets are recorded through rustls KeyLog into proto_core::capture, so captured
//! traffic can be decrypted in FTPeek for lab purpose
//! ## Structure:
//! - lib.rs - Public API (FtpsServerConfig, FtpsMode, serve), building of TLS acceptors for
//! control and data connections, certificate generation and key logger
//! ## Public API usage example:
//! ```
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::path::PathBuf;
//! use std::thread::sleep;
//! use std::time::Duration;
//! use tokio::sync::broadcast;
//!
//! use proto_core::event_channel;
//! use proto_ftp::FtpServerConfig;
//! use proto_ftps::{FtpsMode, FtpsServerConfig, serve};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = FtpsServerConfig {
//!         ftp: FtpServerConfig {
//!             bind_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
//!             control_port: 2121,
//!             pasv_port_start: 30000,
//!             pasv_port_end: 30100,
//!             active_port: 2020,
//!             root_dir: PathBuf::from("./ftp_root"),
//!             users: None,
//!         },
//!         mode: FtpsMode::Explicit,
//!     };
//!
//!     // Initialize the event channel provided by proto_core
//!     let (events_tx, mut _events_rx) = event_channel();
//!
//!     // Initialize the broadcast channel for graceful shutdown
//!     let (shutdown_tx, shutdown_rx) = broadcast::channel(16);
//!
//!     let server_handle = tokio::spawn(async move {
//!         if let Err(err) = serve(config, events_tx, shutdown_rx).await {
//!             eprintln!("FTPS server error: {err}");
//!         }
//!     });
//!
//!     println!("FTPS server is running on 127.0.0.1:2121. Press Ctrl+C to stop.");
//!     sleep(Duration::from_millis(50));
//!
//!     println!("Shutdown signal received, stopping server...");
//!     let _ = shutdown_tx.send(());
//!
//!     server_handle.await?;
//!     println!("FTPS server successfully shut down.");
//!
//!     Ok(())
//! }
//! ```

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use proto_core::{EventSender, Protocol};
use proto_ftp::{BoxedStream, FtpServerConfig, TlsRole, TlsUpgrader, serve_with};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ServerSessionMemoryCache;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpsMode {
    Explicit,
    Implicit,
}

pub struct FtpsServerConfig {
    pub ftp: FtpServerConfig,
    pub mode: FtpsMode,
}

pub async fn serve(
    cfg: FtpsServerConfig,
    events: EventSender,
    shutdown: broadcast::Receiver<()>,
) -> io::Result<()> {
    let acceptors = build_acceptors(cfg.ftp.bind_addr)?;

    let upgrader = TlsUpgrader::new(move |stream: BoxedStream, role: TlsRole| {
        let acceptor = match role {
            TlsRole::Control => acceptors.control.clone(),
            TlsRole::Data => acceptors.data.clone(),
        };
        async move {
            let tls = acceptor.accept(stream).await?;
            let (_, conn) = tls.get_ref();
            let version = conn
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "unknown version".into());
            let suite = conn
                .negotiated_cipher_suite()
                .map(|s| format!("{:?}", s.suite()))
                .unwrap_or_else(|| "unknown cipher".into());
            let resumed = match (role, conn.handshake_kind()) {
                (TlsRole::Data, Some(rustls::HandshakeKind::Resumed)) => ", session resumed",
                (TlsRole::Data, _) => ", new session (not resumed)",
                (TlsRole::Control, _) => "",
            };
            Ok((
                Box::new(tls) as BoxedStream,
                format!("{version}, {suite}{resumed}"),
            ))
        }
    });

    serve_with(
        cfg.ftp,
        events,
        shutdown,
        Protocol::Ftps,
        Some(upgrader),
        cfg.mode == FtpsMode::Implicit,
    )
    .await
}

#[derive(Clone)]
struct Acceptors {
    control: TlsAcceptor,
    data: TlsAcceptor,
}

fn build_acceptors(bind_addr: IpAddr) -> io::Result<Acceptors> {
    let mut names = vec!["localhost".to_string()];
    if !bind_addr.is_unspecified() {
        names.push(bind_addr.to_string());
    }

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names).map_err(io::Error::other)?;
    let cert_der = cert.der().clone();
    let key_der = signing_key.serialize_der();

    let ticketer = rustls::crypto::ring::Ticketer::new().map_err(io::Error::other)?;
    let session_cache = ServerSessionMemoryCache::new(256);

    let config = |tickets: usize| -> io::Result<ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone()));
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::clone(&cert_der)], key)
            .map_err(io::Error::other)?;
        config.ticketer = ticketer.clone();
        config.session_storage = session_cache.clone();
        config.send_tls13_tickets = tickets;
        config.key_log = Arc::new(KeyLogger);
        Ok(config)
    };

    Ok(Acceptors {
        control: TlsAcceptor::from(Arc::new(config(1)?)),
        data: TlsAcceptor::from(Arc::new(config(0)?)),
    })
}

#[derive(Debug)]
struct KeyLogger;

impl rustls::KeyLog for KeyLogger {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        proto_core::capture::record_secret(label, client_random, secret);
    }
}
