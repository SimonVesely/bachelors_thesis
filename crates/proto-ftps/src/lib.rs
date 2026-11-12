//! # FTPS Protocol implementation using RFCs 4217(FTP over TLS) and 2228(FTP security extensions)
//! ## About:
//! - FTPS server made in pure Rust on top of proto-ftp crate, all FTP logic (commands, sessions,
//!   passive data connections) is reused from proto-ftp, this crate only adds the TLS layer
//! - Supports both modes:
//!   - Explicit - client connects in plain FTP and upgrades with AUTH TLS (usually port 21)
//!   - Implicit - TLS from the first byte of the connection (usually port 990)
//! - TLS via rustls with ring crypto provider, TLS 1.2 and TLS 1.3
//! - Self-signed certificate (rcgen) is generated on every start for localhost and bind address
//! - Data connections resume the TLS session of the control connection (session cache + tickets),
//!   which many clients like FileZilla require
//! - Session secrets are recorded through rustls KeyLog into proto_core::capture, so captured
//!   traffic can be decrypted in FTPeek for lab purpose
//! ## Structure:
//! - lib.rs - Public API (FtpsServerConfig, FtpsMode, serve), building of TLS acceptors for
//!   control and data connections, certificate generation and key logger
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
//!
//! ## Encryption process:
//! Real explicit FTPS session, client `curl --ssl-reqd` (OpenSSL 3) -> FTPeek on 127.0.0.1:2121.
//! C = client, S = server, `[TLS]` = sent inside the encrypted control connection.
//! ```text
//! Server start (build_acceptors)
//!   rcgen self-signed X.509 v3 certificate, new on every start
//!     key:        ECDSA P-256 (secp256r1)
//!     signature:  ecdsa-with-SHA256, issuer = subject = "CN=rcgen self signed cert"
//!     SAN:        DNS:localhost, IP:<bind address>
//!     valid:      1975-01-01 .. 4096-01-01
//!   rustls (ring) offers: TLS 1.3  AES_256_GCM_SHA384, AES_128_GCM_SHA256, CHACHA20_POLY1305_SHA256
//!                         TLS 1.2  ECDHE_ECDSA_WITH_AES_256/128_GCM, ..._CHACHA20_POLY1305
//!                         groups   x25519, secp256r1, secp384r1
//!
//! Control connection (port 2121)
//!   C -> S  TCP SYN / S -> C SYN-ACK / C -> S ACK
//!   S -> C  220 FTPeek FTPS server ready.                                     (plaintext)
//!   C -> S  AUTH TLS
//!   S -> C  234 AUTH TLS successful - starting TLS handshake.
//!   C -> S  ClientHello
//!             versions: TLS 1.3, 1.2; 31 cipher suites, AES_256_GCM_SHA384 first
//!             key_share x25519 (32 B public key), signature_algorithms ecdsa_secp256r1_sha256, ...
//!             client_random (32 B) -> key log index
//!   S -> C  ServerHello
//!             TLS 1.3, cipher TLS_AES_256_GCM_SHA384, key_share x25519 (32 B public key)
//!             -> both sides: ECDHE(x25519) shared secret -> HKDF-SHA384 -> handshake keys
//!           ---- everything below is AES-256-GCM encrypted ----
//!           EncryptedExtensions
//!           Certificate        (the ECDSA P-256 certificate above, 360 B)
//!           CertificateVerify  ecdsa_secp256r1_sha256 over the transcript hash (72 B)
//!           Finished           HMAC-SHA384 over the transcript
//!   C -> S  Finished           -> both sides switch to application traffic keys
//!   S -> C  [TLS] NewSessionTicket (1 ticket, used later to resume on data connections)
//!   C -> S  [TLS] USER anonymous / PASS x        (login only after AUTH, RFC 4217)
//!   S -> C  [TLS] 331 / 230
//!   C -> S  [TLS] PBSZ 0     S -> C [TLS] 200 PBSZ=0
//!   C -> S  [TLS] PROT P     S -> C [TLS] 200 PROT now Private.   (data connections must use TLS)
//!   C -> S  [TLS] PASV       S -> C [TLS] 227 Entering Passive Mode (127,0,0,1,8,74) = port 2122
//!   C -> S  [TLS] RETR a.txt S -> C [TLS] 150 Opening data connection
//!
//! Data connection (port 2122, TlsRole::Data)
//!   C -> S  TCP handshake
//!   C -> S  ClientHello  + pre_shared_key (ticket from the control session),
//!                         psk_key_exchange_modes psk_dhe_ke, key_share x25519
//!   S -> C  ServerHello  TLS_AES_256_GCM_SHA384, pre_shared_key selected identity 0, x25519
//!           EncryptedExtensions, Finished    (no Certificate - session resumed, PSK + ECDHE)
//!   C -> S  Finished
//!   S -> C  [TLS] file content (AES-256-GCM)
//!   S -> C  [TLS] Alert close_notify, TCP FIN   C -> S [TLS] Alert close_notify
//!   S -> C  [TLS] 226 Transfer complete.         (on the control connection)
//!
//! Key log (KeyLogger -> proto_core::capture::record_secret), per connection:
//!   CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET,
//!   CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0, EXPORTER_SECRET
//!   -> FTPeek derives key + IV (HKDF-Expand-Label) and decrypts the captured records
//! ```
//! - Implicit mode: same TLS handshake, but right after the TCP handshake on port 990,
//!   before the `220` banner, no AUTH TLS
//! - TLS 1.2 client: ECDHE_ECDSA_* suite, keys from the master secret (`CLIENT_RANDOM` in key log),
//!   resumption through the session cache (256 entries) or ticket shared by control and data acceptors
//! - Errors: data TLS handshake failure -> `522`, TLS error during transfer -> `535`,
//!   `CCC` -> `534`, pipelined bytes after AUTH -> `421`

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
