mod fs;
mod log;

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use proto_core::{Direction, EventKind, EventSender, UserDb, next_session_id};
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::log::{Log, Tee};

#[derive(Clone)]
pub struct SftpServerConfig {
    pub bind_addr: IpAddr,
    pub port: u16,
    pub root_dir: PathBuf,
    pub users: Option<Arc<UserDb>>,
}

impl Default for SftpServerConfig {
    fn default() -> Self {
        SftpServerConfig {
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 22,
            root_dir: PathBuf::from("shared"),
            users: None,
        }
    }
}

pub async fn serve(
    cfg: SftpServerConfig,
    events: EventSender,
    mut shutdown: broadcast::Receiver<()>,
) -> io::Result<()> {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).map_err(io::Error::other)?;
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    let config = Arc::new(russh::server::Config {
        methods: MethodSet::from(&[MethodKind::Password][..]),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        ..Default::default()
    });
    let listener = TcpListener::bind((cfg.bind_addr, cfg.port)).await?;

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = shutdown.recv() => return Ok(()),
        };
        let log = Log {
            events: events.clone(),
            session: next_session_id(),
            peer,
            local: stream.local_addr()?,
        };
        let text = format!("TCP connection opened, SSH host key ED25519 {fingerprint}");
        log.emit(
            Direction::ClientToServer,
            EventKind::TcpOpen,
            Vec::new(),
            text,
        );
        let handler = SshSession {
            cfg: cfg.clone(),
            log: log.clone(),
            channel: None,
        };
        let config = config.clone();
        let mut shutdown = shutdown.resubscribe();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                let handle = session.handle();
                tokio::select! {
                    _ = session => {}
                    _ = shutdown.recv() => {
                        let reason = "Server shutting down".to_string();
                        let _ = handle.disconnect(Disconnect::ByApplication, reason, "en".into()).await;
                    }
                }
            }
            log.emit(
                Direction::ClientToServer,
                EventKind::TcpClose,
                Vec::new(),
                "TCP connection closed".into(),
            );
        });
    }
}

struct SshSession {
    cfg: SftpServerConfig,
    log: Log,
    channel: Option<Channel<Msg>>,
}

impl SshSession {
    fn request(&self, text: String) {
        self.log.emit(
            Direction::ClientToServer,
            EventKind::Message,
            Vec::new(),
            text,
        );
    }

    fn reply(&self, text: &str) {
        self.log.emit(
            Direction::ServerToClient,
            EventKind::Message,
            Vec::new(),
            text.into(),
        );
    }
}

impl russh::server::Handler for SshSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.request(format!(
            "SSH_MSG_USERAUTH_REQUEST user={user}, method=password ({} characters)",
            password.chars().count()
        ));
        let accepted = match &self.cfg.users {
            None => true,
            Some(db) => {
                let (db, user, password) = (db.clone(), user.to_string(), password.to_string());
                tokio::task::spawn_blocking(move || db.verify(&user, &password))
                    .await
                    .unwrap_or(false)
            }
        };
        if accepted {
            self.reply("SSH_MSG_USERAUTH_SUCCESS");
            Ok(Auth::Accept)
        } else {
            self.reply("SSH_MSG_USERAUTH_FAILURE (wrong user name or password)");
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.request(format!(
            "SSH_MSG_CHANNEL_OPEN session, channel {}",
            channel.id()
        ));
        self.channel = Some(channel);
        reply.accept().await;
        self.reply("SSH_MSG_CHANNEL_OPEN_CONFIRMATION");
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.request(format!("SSH_MSG_CHANNEL_REQUEST subsystem \"{name}\""));
        let channel = self.channel.take().filter(|c| c.id() == channel_id);
        match (name, channel) {
            ("sftp", Some(channel)) => {
                session.channel_success(channel_id)?;
                self.reply("SSH_MSG_CHANNEL_SUCCESS, SFTP started");
                let stream = Tee::new(channel.into_stream(), self.log.clone());
                let fs = fs::Fs::new(self.cfg.root_dir.clone());
                russh_sftp::server::run(stream, fs).await;
            }
            _ => {
                session.channel_failure(channel_id)?;
                self.reply("SSH_MSG_CHANNEL_FAILURE, only the sftp subsystem is available");
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.request("SSH_MSG_CHANNEL_EOF".into());
        session.close(channel)?;
        Ok(())
    }
}
