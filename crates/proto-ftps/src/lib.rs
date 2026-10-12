use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use proto_core::{EventSender, Protocol};
use proto_ftp::{BoxedStream, FtpServerConfig, TlsUpgrader, serve_with};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
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
    let acceptor = build_acceptor(cfg.ftp.bind_addr)?;

    let upgrader = TlsUpgrader::new(move |stream: BoxedStream| {
        let acceptor = acceptor.clone();
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
            Ok((Box::new(tls) as BoxedStream, format!("{version}, {suite}")))
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

fn build_acceptor(bind_addr: IpAddr) -> io::Result<TlsAcceptor> {
    let mut names = vec!["localhost".to_string()];
    if !bind_addr.is_unspecified() {
        names.push(bind_addr.to_string());
    }

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names).map_err(io::Error::other)?;
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(io::Error::other)?;

    config.send_tls13_tickets = 0;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
