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
        Ok(config)
    };

    Ok(Acceptors {
        control: TlsAcceptor::from(Arc::new(config(1)?)),
        data: TlsAcceptor::from(Arc::new(config(0)?)),
    })
}
