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
//!
//! ## Encryption process:
//! Real session, client OpenSSH 9.6 `sftp user@127.0.0.1 -P 2222`, `get b.txt` -> FTPeek (russh 0.63).
//! C = client, S = server, `[SSH]` = sent inside the encrypted transport.
//! ```text
//! Server start
//!   new ED25519 host key on every start (PrivateKey::random) - clients warn "host key changed"
//!   russh offers: kex     mlkem768x25519-sha256, curve25519-sha256, diffie-hellman-group14..18
//!                 hostkey ssh-ed25519
//!                 cipher  chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes256/192/128-ctr
//!                 mac     hmac-sha2-512/256(-etm)  (only for -ctr ciphers)
//!                 + ext-info-s, kex-strict-s-v00@openssh.com (Terrapin mitigation)
//!
//! Transport (RFC 4253), port 2222
//!   C -> S  TCP SYN / S -> C SYN-ACK / C -> S ACK
//!   C -> S  SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20                       (plaintext)
//!   S -> C  SSH-2.0-russh_0.63.3
//!   C -> S  KEXINIT  (1536 B) 16-byte cookie + algorithm lists, client preference first:
//!             kex sntrup761x25519-sha512, curve25519-sha256, ecdh-sha2-nistp256, ...
//!             cipher chacha20-poly1305@openssh.com, aes128-ctr, ..., aes256-gcm@openssh.com
//!   S -> C  KEXINIT  (776 B)  server lists above
//!           -> both pick the first client algorithm the server also supports:
//!              kex curve25519-sha256, hostkey ssh-ed25519,
//!              cipher chacha20-poly1305@openssh.com both directions (MAC implicit, Poly1305),
//!              compression none
//!   C -> S  KEX_ECDH_INIT   Q_C = client ephemeral X25519 public key (32 B)
//!   S -> C  KEX_ECDH_REPLY  K_S = ED25519 host key,
//!                           Q_S = server ephemeral X25519 public key (32 B),
//!                           signature ssh-ed25519 over exchange hash H
//!           NEWKEYS
//!             K = X25519(shared secret), H = SHA-256(versions, KEXINITs, K_S, Q_C, Q_S, K)
//!             keys = SHA-256(K || H || "A".."F" || session_id), "C"/"D" = 64 B chacha key per direction
//!           client checks the host key fingerprint (SHA256:...) and the signature
//!   C -> S  NEWKEYS
//!           ---- everything below is chacha20-poly1305 encrypted ----
//!   C <-> S [SSH] EXT_INFO  server-sig-algs=ssh-ed25519,ecdsa-sha2-*,rsa-sha2-512/256
//!   C -> S  [SSH] SERVICE_REQUEST ssh-userauth      S -> C [SSH] SERVICE_ACCEPT
//!
//! Authentication (RFC 4252)
//!   C -> S  [SSH] USERAUTH_REQUEST user, method none
//!   S -> C  [SSH] USERAUTH_FAILURE, can continue: password
//!   C -> S  [SSH] USERAUTH_REQUEST user, method password, "x"   (logged only as its length)
//!   S -> C  [SSH] USERAUTH_SUCCESS     (UserDb / anonymous; failure is delayed 1 s)
//!
//! Channel + SFTP subsystem (RFC 4254, draft-ietf-secsh-filexfer-02)
//!   C -> S  [SSH] CHANNEL_OPEN session          S -> C [SSH] CHANNEL_OPEN_CONFIRMATION
//!                                               (window 2 MiB, max packet 32 KiB)
//!   C -> S  [SSH] CHANNEL_REQUEST subsystem "sftp"   S -> C [SSH] CHANNEL_SUCCESS
//!   C -> S  [SSH] SSH_FXP_INIT v3          S -> C [SSH] SSH_FXP_VERSION 3
//!   C -> S  [SSH] SSH_FXP_REALPATH "."     S -> C [SSH] SSH_FXP_NAME "/"
//!   C -> S  [SSH] SSH_FXP_STAT "/b.txt"    S -> C [SSH] SSH_FXP_ATTRS size, mode 100644, times
//!   C -> S  [SSH] SSH_FXP_OPEN "/b.txt" READ   S -> C [SSH] SSH_FXP_HANDLE
//!   C -> S  [SSH] SSH_FXP_READ offset 0    S -> C [SSH] SSH_FXP_DATA (10 B file content)
//!   C -> S  [SSH] SSH_FXP_READ offset 10   S -> C [SSH] SSH_FXP_STATUS EOF
//!   C -> S  [SSH] SSH_FXP_CLOSE            S -> C [SSH] SSH_FXP_STATUS OK
//!   C -> S  [SSH] CHANNEL_EOF              S -> C [SSH] exit-status 0, CHANNEL_EOF, CHANNEL_CLOSE
//!   C -> S  [SSH] CHANNEL_CLOSE, DISCONNECT, TCP FIN
//! ```
//! - On the wire every packet after NEWKEYS is `uint32 length` (encrypted with its own
//!   ChaCha20 key) + ChaCha20 ciphertext + 16 B Poly1305 tag; 4-255 B random padding
//! - Session keys stay inside russh, FTPeek can't decrypt the capture; the `Tee` in log.rs
//!   reads the SFTP stream after russh decrypted it, so the event log shows the plaintext
//! - With a client preferring AES: `aes256-gcm@openssh.com` (16 B tag) or `aes*-ctr` +
//!   `hmac-sha2-*-etm@openssh.com` (encrypt-then-MAC)

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
