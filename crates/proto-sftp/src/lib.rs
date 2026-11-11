//! # SFTP Protocol implementation using SSH File Transfer Protocol version 3 (draft-ietf-secsh-filexfer-02) over SSH-2 (RFCs 4251-4254)
//! ## About:
//! - SFTP server made in pure Rust, SSH-2 layer (key exchange, encryption, authentication,
//!   channels) is provided by russh crate, SFTP packet parsing by russh-sftp crate, this crate
//!   implements the file operations and logging
//! - New ED25519 host key is generated on every start, clients will warn that the key changed
//! - Authentication only by password:
//!   - users: None - anonymous, any user name and password is accepted
//!   - users: Some(UserDb) - checked against proto-core user database (redb + argon2)
//! - All paths are confined to the root directory, ".." can't leave it, ':' and '\' are rejected
//! - Every SSH step (auth, channel, subsystem) and every SFTP packet is sent as MessageEvent,
//!   password itself is never logged, only its length
//! - Supported operations: realpath, stat, lstat, fstat, opendir, readdir, open, read, write,
//!   close, remove, mkdir, rmdir, rename, setstat/fsetstat (size, permissions, times),
//!   symlinks are not supported
//! - Shell, exec and pty requests are refused with CHANNEL_FAILURE (no shell, no legacy scp),
//!   exit status 0 is sent when the client closes the sftp channel
//! - SSH traffic can't be decrypted in FTPeek capture view (russh doesn't expose session keys),
//!   decrypted content is visible in the event log
//! ## Structure:
//! - lib.rs - Public API (SftpServerConfig, serve), SSH server, password authentication,
//!   session channel and sftp subsystem handling
//! - fs.rs - Contains SFTP file operations over the root directory and handle table
//! - log.rs - Contains event logging, Tee wrapper splitting SSH channel stream into SFTP
//!   packets and their human readable description
//! ## Public API usage example:
//! ```
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::path::PathBuf;
//! use std::thread::sleep;
//! use std::time::Duration;
//! use tokio::sync::broadcast;
//!
//! use proto_core::event_channel;
//! use proto_sftp::{SftpServerConfig, serve};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = SftpServerConfig {
//!         bind_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
//!         port: 2222,
//!         root_dir: PathBuf::from("./sftp_root"),
//!         users: None,
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
//!             eprintln!("SFTP server error: {err}");
//!         }
//!     });
//!
//!     println!("SFTP server is running on 127.0.0.1:2222. Press Ctrl+C to stop.");
//!     sleep(Duration::from_millis(50));
//!
//!     println!("Shutdown signal received, stopping server...");
//!     let _ = shutdown_tx.send(());
//!
//!     server_handle.await?;
//!     println!("SFTP server successfully shut down.");
//!
//!     Ok(())
//! }
//! ```

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
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet, Pty};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast};

use crate::log::{Log, Tee};

pub const MAX_CLIENTS: usize = 200;

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
        inactivity_timeout: Some(Duration::from_secs(300)),
        ..Default::default()
    });
    let listener = TcpListener::bind((cfg.bind_addr, cfg.port)).await?;
    let slots = Arc::new(Semaphore::new(MAX_CLIENTS));

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.recv() => return Ok(()),
        };
        let (stream, peer, local) = match accepted.and_then(|(s, p)| Ok((s.local_addr()?, s, p))) {
            Ok((local, stream, peer)) => (stream, peer, local),
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let log = Log {
            events: events.clone(),
            session: next_session_id(),
            peer,
            local,
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
            let _slot = slot;
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

    fn refuse(&mut self, channel_id: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        if self.channel.as_ref().is_some_and(|c| c.id() == channel_id) {
            self.channel = None;
        }
        session.channel_failure(channel_id)?;
        self.reply("SSH_MSG_CHANNEL_FAILURE, only the sftp subsystem is available");
        Ok(())
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
            _ => self.refuse(channel_id, session)?,
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        self.request(format!("SSH_MSG_CHANNEL_REQUEST exec \"{command}\""));
        self.refuse(channel_id, session)
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.request("SSH_MSG_CHANNEL_REQUEST shell".into());
        self.refuse(channel_id, session)
    }

    async fn pty_request(
        &mut self,
        channel_id: ChannelId,
        term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.request(format!("SSH_MSG_CHANNEL_REQUEST pty-req \"{term}\""));
        self.refuse(channel_id, session)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.request("SSH_MSG_CHANNEL_EOF".into());
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        self.reply(
            "SSH_MSG_CHANNEL_REQUEST exit-status 0, SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_CLOSE",
        );
        Ok(())
    }
}
