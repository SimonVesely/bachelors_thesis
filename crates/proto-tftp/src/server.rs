use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::time::{Instant, timeout_at};

use proto_core::{Direction, EventKind, EventSender, MessageEvent, Protocol, next_session_id};

use crate::packet::{ACCESS_VIOLATION, FILE_NOT_FOUND, ILLEGAL_OPERATION, NOT_DEFINED};
use crate::packet::{Packet, Request};

const TIMEOUT: Duration = Duration::from_secs(2);
const RETRIES: u32 = 5;
pub const MAX_BLKSIZE: usize = 1468;

#[derive(Debug, Clone)]
pub struct TftpServerConfig {
    pub bind_addr: IpAddr,
    pub port: u16,
    pub root_dir: PathBuf,
    pub allow_write: bool,
}

impl Default for TftpServerConfig {
    fn default() -> Self {
        TftpServerConfig {
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 69,
            root_dir: PathBuf::from("shared"),
            allow_write: true,
        }
    }
}

pub async fn serve(
    cfg: TftpServerConfig,
    events: EventSender,
    mut shutdown: broadcast::Receiver<()>,
) -> io::Result<()> {
    let socket = UdpSocket::bind((cfg.bind_addr, cfg.port)).await?;
    let local = socket.local_addr()?;
    let cfg = Arc::new(cfg);
    let mut buf = vec![0; 65536];

    loop {
        let (len, peer) = tokio::select! {
            received = socket.recv_from(&mut buf) => match received {
                Ok(received) => received,
                Err(err) if err.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(err) => return Err(err),
            },
            _ = shutdown.recv() => return Ok(()),
        };
        let session = next_session_id();
        let log = Log {
            events: events.clone(),
            session,
            local,
            peer,
        };
        let packet = Packet::parse(&buf[..len]);
        log.incoming(&buf[..len], packet.as_ref());

        let (request, upload) = match packet {
            Some(Packet::Rrq(request)) => (request, false),
            Some(Packet::Wrq(request)) => (request, true),
            Some(Packet::Error { .. }) => continue,
            _ => {
                let message = "Only RRQ or WRQ may be sent to this port".into();
                let error = Packet::Error {
                    code: ILLEGAL_OPERATION,
                    message,
                };
                if socket.send_to(&error.encode(), peer).await.is_ok() {
                    log.outgoing(&error, "");
                }
                continue;
            }
        };

        let socket = UdpSocket::bind((cfg.bind_addr, 0)).await?;
        let log = Log {
            local: socket.local_addr()?,
            ..log
        };
        let shutdown = shutdown.resubscribe();
        let transfer = Transfer {
            socket,
            log,
            shutdown,
            buf: vec![0; 65536],
        };
        if upload {
            tokio::spawn(transfer.receive_file(cfg.clone(), request));
        } else {
            tokio::spawn(transfer.send_file(cfg.clone(), request));
        }
    }
}

enum Fail {
    Error(u16, String),
    Quiet,
}

impl From<io::Error> for Fail {
    fn from(err: io::Error) -> Self {
        Fail::Error(NOT_DEFINED, err.to_string())
    }
}

enum Next {
    Done,
    Resend,
    Wait,
}

struct Transfer {
    socket: UdpSocket,
    log: Log,
    shutdown: broadcast::Receiver<()>,
    buf: Vec<u8>,
}

impl Transfer {
    async fn send_file(mut self, cfg: Arc<TftpServerConfig>, req: Request) {
        let result = self.send_blocks(&cfg, &req).await;
        self.finish(result).await;
    }

    async fn receive_file(mut self, cfg: Arc<TftpServerConfig>, req: Request) {
        if !cfg.allow_write {
            let message = "Uploads are disabled".into();
            return self
                .finish(Err(Fail::Error(ACCESS_VIOLATION, message)))
                .await;
        }
        let path = match resolve(&cfg.root_dir, &req.filename) {
            Ok(path) => path,
            Err(fail) => return self.finish(Err(fail)).await,
        };
        let result = self.receive_blocks(&path, &req).await;
        if result.is_err() {
            let _ = fs::remove_file(&path).await;
        }
        self.finish(result).await;
    }

    async fn send_blocks(&mut self, cfg: &TftpServerConfig, req: &Request) -> Result<(), Fail> {
        let not_found = || Fail::Error(FILE_NOT_FOUND, "File not found".into());
        let path = resolve(&cfg.root_dir, &req.filename)?;
        let mut file = File::open(path).await.map_err(|_| not_found())?;
        let meta = file.metadata().await?;
        if !meta.is_file() {
            return Err(not_found());
        }

        let (blksize, oack) = negotiate(&req.options, Some(meta.len()));
        if !oack.is_empty() {
            let oack = Packet::Oack { options: oack };
            self.exchange(&oack, "", |p| match p {
                Packet::Ack { block: 0 } => Next::Done,
                _ => Next::Wait,
            })
            .await?;
        }

        let mut block: u16 = 1;
        loop {
            let data = read_block(&mut file, blksize).await?;
            let last = data.len() < blksize;
            let note = if last { " (last)" } else { "" };
            self.exchange(&Packet::Data { block, data }, note, |p| match p {
                Packet::Ack { block: acked } if *acked == block => Next::Done,
                _ => Next::Wait,
            })
            .await?;
            if last {
                return Ok(());
            }
            block = block.wrapping_add(1);
        }
    }

    async fn receive_blocks(&mut self, path: &Path, req: &Request) -> Result<(), Fail> {
        let created = File::create(path).await;
        let mut file = created.map_err(|err| Fail::Error(ACCESS_VIOLATION, err.to_string()))?;
        let (blksize, oack) = negotiate(&req.options, None);
        let mut reply = match oack.is_empty() {
            true => Packet::Ack { block: 0 },
            false => Packet::Oack { options: oack },
        };

        let mut block: u16 = 1;
        loop {
            let previous = block.wrapping_sub(1);
            let packet = self.exchange(&reply, "", |p| match p {
                Packet::Data { block: got, .. } if *got == block => Next::Done,
                Packet::Data { block: got, .. } if *got == previous => Next::Resend,
                _ => Next::Wait,
            });
            let Packet::Data { data, .. } = packet.await? else {
                unreachable!("exchange only accepts DATA here");
            };

            file.write_all(&data).await?;
            reply = Packet::Ack { block };
            if data.len() < blksize {
                file.flush().await?;
                self.send(&reply, " (last)").await?;
                return Ok(());
            }
            block = block.wrapping_add(1);
        }
    }

    async fn finish(&self, result: Result<(), Fail>) {
        if let Err(Fail::Error(code, message)) = result {
            let _ = self.send(&Packet::Error { code, message }, "").await;
        }
    }

    async fn send(&self, packet: &Packet, note: &str) -> io::Result<()> {
        self.socket.send_to(&packet.encode(), self.log.peer).await?;
        self.log.outgoing(packet, note);
        Ok(())
    }

    async fn exchange(
        &mut self,
        packet: &Packet,
        note: &str,
        next: impl Fn(&Packet) -> Next,
    ) -> Result<Packet, Fail> {
        self.send(packet, note).await?;
        let mut retries = 0;
        let mut deadline = Instant::now() + TIMEOUT;
        loop {
            let resend = match self.recv(deadline).await? {
                None => true,
                Some(Packet::Error { .. }) => return Err(Fail::Quiet),
                Some(reply) => match next(&reply) {
                    Next::Done => return Ok(reply),
                    Next::Resend => true,
                    Next::Wait => false,
                },
            };
            if resend {
                retries += 1;
                if retries > RETRIES {
                    return Err(Fail::Quiet);
                }
                self.send(packet, &format!("{note} [retransmission]"))
                    .await?;
                deadline = Instant::now() + TIMEOUT;
            }
        }
    }

    async fn recv(&mut self, deadline: Instant) -> Result<Option<Packet>, Fail> {
        loop {
            let received = timeout_at(deadline, self.socket.recv_from(&mut self.buf));
            let (len, from) = tokio::select! {
                received = received => match received {
                    Err(_elapsed) => return Ok(None),
                    Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionReset => continue,
                    Ok(received) => received?,
                },
                _ = self.shutdown.recv() => {
                    return Err(Fail::Error(NOT_DEFINED, "Server shutting down".into()));
                }
            };
            if from != self.log.peer {
                continue;
            }
            let packet = Packet::parse(&self.buf[..len]);
            self.log.incoming(&self.buf[..len], packet.as_ref());
            if packet.is_some() {
                return Ok(packet);
            }
        }
    }
}

fn negotiate(
    options: &[(String, String)],
    file_size: Option<u64>,
) -> (usize, Vec<(String, String)>) {
    let mut blksize = 512;
    let mut oack = Vec::new();
    for (name, value) in options {
        match name.to_ascii_lowercase().as_str() {
            "blksize" => {
                if let Ok(requested) = value.parse::<usize>()
                    && requested >= 8
                {
                    blksize = requested.min(MAX_BLKSIZE);
                    oack.push(("blksize".into(), blksize.to_string()));
                }
            }
            "tsize" => {
                if let Ok(announced) = value.parse::<u64>() {
                    oack.push(("tsize".into(), file_size.unwrap_or(announced).to_string()));
                }
            }
            _ => {}
        }
    }
    (blksize, oack)
}

fn resolve(root: &Path, name: &str) -> Result<PathBuf, Fail> {
    let mut path = root.to_path_buf();
    for part in name
        .split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != ".")
    {
        if part == ".." || part.contains(':') {
            let message = "Path outside the server root".into();
            return Err(Fail::Error(ACCESS_VIOLATION, message));
        }
        path.push(part);
    }
    Ok(path)
}

async fn read_block(file: &mut File, size: usize) -> io::Result<Vec<u8>> {
    let mut block = vec![0; size];
    let mut filled = 0;
    while filled < size {
        let n = file.read(&mut block[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    block.truncate(filled);
    Ok(block)
}

struct Log {
    events: EventSender,
    session: u64,
    local: SocketAddr,
    peer: SocketAddr,
}

impl Log {
    fn incoming(&self, raw: &[u8], packet: Option<&Packet>) {
        let text = packet.map_or("Malformed packet".into(), Packet::summary);
        self.emit(Direction::ClientToServer, raw.to_vec(), packet, text);
    }

    fn outgoing(&self, packet: &Packet, note: &str) {
        let text = packet.summary() + note;
        self.emit(
            Direction::ServerToClient,
            packet.encode(),
            Some(packet),
            text,
        );
    }

    fn emit(&self, dir: Direction, raw: Vec<u8>, packet: Option<&Packet>, text: String) {
        let kind = match packet {
            Some(Packet::Data { .. }) => EventKind::Data,
            _ => EventKind::Message,
        };
        let (proto, peer, local) = (Protocol::Tftp, self.peer, self.local);
        let event = MessageEvent::new(proto, kind, dir, peer, local, raw, text);
        let _ = self.events.send(event.with_session(self.session));
    }
}
