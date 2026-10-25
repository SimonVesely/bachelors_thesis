use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use proto_core::{Direction, EventKind, EventSender, MessageEvent, Protocol};
use russh_sftp::protocol::{FileAttributes, OpenFlags, Packet, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone)]
pub struct Log {
    pub events: EventSender,
    pub session: u64,
    pub peer: SocketAddr,
    pub local: SocketAddr,
}

impl Log {
    pub fn emit(&self, dir: Direction, kind: EventKind, raw: Vec<u8>, text: String) {
        let encrypted = !matches!(kind, EventKind::TcpOpen | EventKind::TcpClose);
        let event = MessageEvent::new(Protocol::Sftp, kind, dir, self.peer, self.local, raw, text)
            .with_session(self.session)
            .with_encrypted(encrypted);
        let _ = self.events.send(event);
    }

    fn packet(&self, dir: Direction, frame: Vec<u8>) {
        let mut body = Bytes::copy_from_slice(&frame[4..]);
        let (kind, text) = match Packet::try_from(&mut body) {
            Ok(packet) => describe(&packet),
            Err(_) => (
                EventKind::Message,
                format!("SFTP packet type {} (not decoded)", frame[4]),
            ),
        };
        self.emit(dir, kind, frame, text);
    }
}

pub struct Tee<S> {
    inner: S,
    log: Log,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
}

impl<S> Tee<S> {
    pub fn new(inner: S, log: Log) -> Self {
        Tee {
            inner,
            log,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }
    }
}

fn frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while buf.len() >= 5 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            break;
        }
        out.push(buf.drain(..4 + len).collect());
    }
    out
}

impl<S: AsyncRead + Unpin> AsyncRead for Tee<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            this.incoming.extend_from_slice(&buf.filled()[before..]);
            for frame in frames(&mut this.incoming) {
                this.log.packet(Direction::ClientToServer, frame);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tee<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            this.outgoing.extend_from_slice(&buf[..n]);
            for frame in frames(&mut this.outgoing) {
                this.log.packet(Direction::ServerToClient, frame);
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn flags(f: &OpenFlags) -> String {
    let names = [
        (OpenFlags::READ, "READ"),
        (OpenFlags::WRITE, "WRITE"),
        (OpenFlags::APPEND, "APPEND"),
        (OpenFlags::CREATE, "CREATE"),
        (OpenFlags::TRUNCATE, "TRUNCATE"),
        (OpenFlags::EXCLUDE, "EXCL"),
    ];
    let set: Vec<&str> = names
        .iter()
        .filter(|(flag, _)| f.contains(*flag))
        .map(|(_, name)| *name)
        .collect();
    set.join("|")
}

fn attrs(a: &FileAttributes) -> String {
    let mut parts = Vec::new();
    if let Some(size) = a.size {
        parts.push(format!("size={size}"));
    }
    if let Some(perms) = a.permissions {
        parts.push(format!("perms={:o}", perms & 0o7777));
    }
    match parts.is_empty() {
        true => "no attributes".into(),
        false => parts.join(", "),
    }
}

fn status(code: StatusCode) -> &'static str {
    match code {
        StatusCode::Ok => "OK",
        StatusCode::Eof => "EOF",
        StatusCode::NoSuchFile => "No such file",
        StatusCode::PermissionDenied => "Permission denied",
        StatusCode::Failure => "Failure",
        StatusCode::BadMessage => "Bad message",
        StatusCode::NoConnection => "No connection",
        StatusCode::ConnectionLost => "Connection lost",
        StatusCode::OpUnsupported => "Operation unsupported",
    }
}

fn describe(packet: &Packet) -> (EventKind, String) {
    use EventKind::{Data, Message};
    match packet {
        Packet::Init(p) => (Message, format!("SSH_FXP_INIT version={}", p.version)),
        Packet::Version(p) => {
            let mut ext: Vec<&str> = p.extensions.keys().map(String::as_str).collect();
            ext.sort();
            (
                Message,
                format!(
                    "SSH_FXP_VERSION version={}, extensions: {}",
                    p.version,
                    ext.join(", ")
                ),
            )
        }
        Packet::Open(p) => (
            Message,
            format!(
                "SSH_FXP_OPEN id={} {} [{}]",
                p.id,
                p.filename,
                flags(&p.pflags)
            ),
        ),
        Packet::Close(p) => (
            Message,
            format!("SSH_FXP_CLOSE id={} handle={}", p.id, p.handle),
        ),
        Packet::Read(p) => (
            Message,
            format!(
                "SSH_FXP_READ id={} handle={} offset={} len={}",
                p.id, p.handle, p.offset, p.len
            ),
        ),
        Packet::Write(p) => (
            Data,
            format!(
                "SSH_FXP_WRITE id={} handle={} offset={} ({} bytes)",
                p.id,
                p.handle,
                p.offset,
                p.data.len()
            ),
        ),
        Packet::Lstat(p) => (Message, format!("SSH_FXP_LSTAT id={} {}", p.id, p.path)),
        Packet::Fstat(p) => (
            Message,
            format!("SSH_FXP_FSTAT id={} handle={}", p.id, p.handle),
        ),
        Packet::SetStat(p) => (
            Message,
            format!("SSH_FXP_SETSTAT id={} {} {}", p.id, p.path, attrs(&p.attrs)),
        ),
        Packet::FSetStat(p) => (
            Message,
            format!(
                "SSH_FXP_FSETSTAT id={} handle={} {}",
                p.id,
                p.handle,
                attrs(&p.attrs)
            ),
        ),
        Packet::OpenDir(p) => (Message, format!("SSH_FXP_OPENDIR id={} {}", p.id, p.path)),
        Packet::ReadDir(p) => (
            Message,
            format!("SSH_FXP_READDIR id={} handle={}", p.id, p.handle),
        ),
        Packet::Remove(p) => (
            Message,
            format!("SSH_FXP_REMOVE id={} {}", p.id, p.filename),
        ),
        Packet::MkDir(p) => (Message, format!("SSH_FXP_MKDIR id={} {}", p.id, p.path)),
        Packet::RmDir(p) => (Message, format!("SSH_FXP_RMDIR id={} {}", p.id, p.path)),
        Packet::RealPath(p) => (Message, format!("SSH_FXP_REALPATH id={} {}", p.id, p.path)),
        Packet::Stat(p) => (Message, format!("SSH_FXP_STAT id={} {}", p.id, p.path)),
        Packet::Rename(p) => (
            Message,
            format!("SSH_FXP_RENAME id={} {} -> {}", p.id, p.oldpath, p.newpath),
        ),
        Packet::ReadLink(p) => (Message, format!("SSH_FXP_READLINK id={} {}", p.id, p.path)),
        Packet::Symlink(p) => (
            Message,
            format!(
                "SSH_FXP_SYMLINK id={} {} -> {}",
                p.id, p.linkpath, p.targetpath
            ),
        ),
        Packet::Status(p) => {
            let mut text = format!(
                "SSH_FXP_STATUS id={} {} ({})",
                p.id,
                status(p.status_code),
                p.status_code as u32
            );
            if !p.error_message.is_empty() && p.error_message != status(p.status_code) {
                text += &format!(": {}", p.error_message);
            }
            (Message, text)
        }
        Packet::Handle(p) => (
            Message,
            format!("SSH_FXP_HANDLE id={} handle={}", p.id, p.handle),
        ),
        Packet::Data(p) => (
            Data,
            format!("SSH_FXP_DATA id={} ({} bytes)", p.id, p.data.len()),
        ),
        Packet::Name(p) => {
            let names: Vec<&str> = p
                .files
                .iter()
                .take(5)
                .map(|f| f.filename.as_str())
                .collect();
            let more = p.files.len().saturating_sub(names.len());
            let mut text = format!("SSH_FXP_NAME id={} {}", p.id, names.join(", "));
            if more > 0 {
                text += &format!(" (+{more} more)");
            }
            (Message, text)
        }
        Packet::Attrs(p) => (
            Message,
            format!("SSH_FXP_ATTRS id={} {}", p.id, attrs(&p.attrs)),
        ),
        Packet::Extended(p) => (
            Message,
            format!("SSH_FXP_EXTENDED id={} {}", p.id, p.request),
        ),
        Packet::ExtendedReply(p) => (Message, format!("SSH_FXP_EXTENDED_REPLY id={}", p.id)),
    }
}
