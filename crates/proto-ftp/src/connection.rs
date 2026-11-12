//! # FTP / FTPS control connection
//! ## About:
//! - `handle_client` runs one client session: banner, command loop, replies, data transfers
//! - Implicit FTPS does the TLS handshake before the banner, explicit upgrades on `AUTH TLS`
//! - FTPS refuses USER/PASS before AUTH TLS; everything except login, FEAT, SYST, NOOP, OPTS,
//!   HOST and the TLS commands requires a logged-in session (530)
//! - Control line limit 4096 B (longer -> 500, session continues), idle timeout 300 s,
//!   shutdown broadcast closes the session with 421
//! - Data connections:
//!   - PASV - listener on the first free port of the configured range
//!   - PORT - server connects from `active_port` (20 by default) to the client
//!   - only the control peer's IP may connect to a passive port, others are logged as intruders
//!   - 30 s timeout, PROT P wraps the data stream in TLS (`TlsRole::Data`)
//! - Transfers: LIST/NLST/MLSD listing, RETR with REST offset, STOR/APPE; errors mapped to
//!   425/426/451/522/535
//! - Every command, reply, TCP open/close, TLS step and data transfer is emitted as `MessageEvent`;
//!   PASS is masked in the log
//! - Non-UTF-8 command bytes are decoded lossily, Telnet IAC sequences are dropped

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{Instant, timeout, timeout_at};

use proto_core::{Direction, EventKind, EventSender, MessageEvent, Protocol, UserDb};

use crate::command::Command;
use crate::listing::{format_list_line, format_mdtm, format_mlsx_facts};
use crate::session::{DataChannel, Session};
use crate::tls::{AsyncStream, BoxedStream, TlsRole, TlsUpgrader};

const FEATURES: &[&str] = &[
    "MDTM",
    "REST STREAM",
    "SIZE",
    "UTF8",
    "MLST type*;size*;modify*;",
    "MLSD",
    "HOST",
];

const DATA_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_LINE: u64 = 4096;

pub struct DataPorts {
    pub passive_start: u16,
    pub passive_end: u16,
    pub active: u16,
}

#[derive(Clone, Copy)]
struct Endpoints {
    peer: SocketAddr,
    local: SocketAddr,
    protocol: Protocol,
    encrypted: bool,
    session: u64,
}

enum TransferError {
    Connect,
    TlsNegotiation,
    Protection,
    Aborted,
    LocalFile,
}

impl TransferError {
    fn reply(&self) -> &'static str {
        match self {
            TransferError::Connect => "425 Can't open data connection.\r\n",
            TransferError::TlsNegotiation => {
                "522 TLS negotiation on the data connection failed.\r\n"
            }
            TransferError::Protection => "535 Data protection failed during the transfer.\r\n",
            TransferError::Aborted => "426 Connection closed; transfer aborted.\r\n",
            TransferError::LocalFile => {
                "451 Requested action aborted: local error in processing.\r\n"
            }
        }
    }
}

fn classify(err: io::Error, encrypted: bool) -> TransferError {
    if encrypted && err.kind() == io::ErrorKind::InvalidData {
        TransferError::Protection
    } else {
        TransferError::Aborted
    }
}

#[derive(Clone, Copy)]
enum ListFormat {
    Long,
    Names,
    Facts,
}

enum Transfer {
    Listing(String),
    Download(fs::File),
    Upload {
        path: PathBuf,
        append: bool,
        offset: u64,
    },
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_client<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    users: Option<Arc<UserDb>>,
    root: PathBuf,
    ports: DataPorts,
    events: EventSender,
    mut shutdown: broadcast::Receiver<()>,
    protocol: Protocol,
    tls: Option<TlsUpgrader>,
    implicit_tls: bool,
) -> io::Result<()>
where
    S: AsyncStream + 'static,
{
    let session_id = proto_core::next_session_id();
    let mut ep = Endpoints {
        peer,
        local,
        protocol,
        encrypted: false,
        session: session_id,
    };
    let mut session = Session::new(root, tls.clone());
    session.active_port = ports.active;
    let mut stream: BoxedStream = Box::new(stream);

    emit(
        &events,
        ep,
        EventKind::TcpOpen,
        Direction::ClientToServer,
        Vec::new(),
        "TCP handshake complete (SYN, SYN-ACK, ACK) - control connection established",
    );

    if implicit_tls {
        let upgrader = tls.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "implicit FTPS needs a TLS upgrader",
            )
        })?;
        let (secured, info) = upgrader.upgrade(stream, TlsRole::Control).await?;
        stream = secured;
        session.tls_active = true;
        emit(
            &events,
            ep,
            EventKind::Tls,
            Direction::ServerToClient,
            Vec::new(),
            format!(
                "TLS handshake complete ({info}) - implicit FTPS, control connection encrypted"
            ),
        );
        ep.encrypted = true;
    }

    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    let banner = match protocol {
        Protocol::Ftps => "220 FTPeek FTPS server ready.\r\n",
        _ => "220 FTPeek FTP server ready.\r\n",
    };
    send(&mut writer, ep, &events, banner).await?;

    let mut raw = Vec::new();
    loop {
        raw.clear();
        let read = {
            let mut limited = (&mut reader).take(MAX_LINE);
            tokio::select! {
                result = timeout(IDLE_TIMEOUT, limited.read_until(b'\n', &mut raw)) => Some(result),
                _ = shutdown.recv() => None,
            }
        };
        let closing = match read {
            Some(Ok(result)) => match result? {
                0 => break,
                _ => None,
            },
            Some(Err(_)) => Some("421 Idle timeout, closing control connection.\r\n"),
            None => Some("421 Service not available, closing control connection.\r\n"),
        };
        if let Some(reply) = closing {
            let _ = send(&mut writer, ep, &events, reply).await;
            break;
        }
        if raw.len() as u64 >= MAX_LINE && !raw.ends_with(b"\n") {
            let mut rest = Vec::new();
            loop {
                rest.clear();
                let skipped = timeout(
                    IDLE_TIMEOUT,
                    (&mut reader).take(MAX_LINE).read_until(b'\n', &mut rest),
                )
                .await;
                match skipped {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(_)) if rest.ends_with(b"\n") => break,
                    Ok(Ok(_)) => {}
                }
            }
            send(&mut writer, ep, &events, "500 Command line too long.\r\n").await?;
            continue;
        }
        let line = decode_line(&raw);
        log_incoming(ep, &events, &line);

        let cmd = Command::parse(&line);

        if tls.is_some()
            && !session.tls_active
            && matches!(cmd, Command::User(_) | Command::Pass(_))
        {
            send(
                &mut writer,
                ep,
                &events,
                "530 Login requires a protected connection - issue AUTH TLS first.\r\n",
            )
            .await?;
            continue;
        }

        let requires_auth = !matches!(
            cmd,
            Command::User(_)
                | Command::Pass(_)
                | Command::Quit
                | Command::Noop
                | Command::Syst
                | Command::Feat
                | Command::Opts(_)
                | Command::Host(_)
                | Command::Auth(_)
                | Command::Pbsz(_)
                | Command::Prot(_)
                | Command::Ccc
                | Command::Help
        );
        if requires_auth && !session.authenticated {
            send(&mut writer, ep, &events, "530 Not logged in.\r\n").await?;
            continue;
        }

        match cmd {
            Command::User(name) => {
                session.authenticated = false;
                session.username = Some(name.clone());
                send(
                    &mut writer,
                    ep,
                    &events,
                    &format!("331 Password required for {name}.\r\n"),
                )
                .await?;
            }
            Command::Pass(password) => {
                if session.authenticated {
                    send(&mut writer, ep, &events, "503 Already logged in.\r\n").await?;
                    continue;
                }
                let Some(name) = session.username.clone() else {
                    send(&mut writer, ep, &events, "503 Login with USER first.\r\n").await?;
                    continue;
                };
                let accepted = match &users {
                    None => true,
                    Some(db) => {
                        let db = Arc::clone(db);
                        tokio::task::spawn_blocking(move || db.verify(&name, &password))
                            .await
                            .unwrap_or(false)
                    }
                };
                if accepted {
                    session.authenticated = true;
                    send(&mut writer, ep, &events, "230 User logged in.\r\n").await?;
                } else {
                    session.username = None;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    send(&mut writer, ep, &events, "530 Login incorrect.\r\n").await?;
                }
            }
            Command::Host(name) => {
                if session.authenticated {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "503 HOST not allowed after login.\r\n",
                    )
                    .await?;
                } else {
                    session.host = Some(name);
                    send(&mut writer, ep, &events, "220 Host accepted.\r\n").await?;
                }
            }
            Command::Quit => {
                send(&mut writer, ep, &events, "221 Goodbye.\r\n").await?;
                break;
            }
            Command::Pwd => {
                let cwd = session.virtual_cwd();
                send(
                    &mut writer,
                    ep,
                    &events,
                    &format!("257 \"{cwd}\" is the current directory.\r\n"),
                )
                .await?;
            }
            Command::Cwd(arg) => {
                let target = session.resolve(&arg);
                if target.is_dir() {
                    session.cwd = PathBuf::from(session.virtual_path(&target));
                    send(&mut writer, ep, &events, "250 Directory changed.\r\n").await?;
                } else {
                    send(&mut writer, ep, &events, "550 No such directory.\r\n").await?;
                }
            }
            Command::Cdup => {
                let target = session.resolve("..");
                session.cwd = PathBuf::from(session.virtual_path(&target));
                send(&mut writer, ep, &events, "250 Directory changed.\r\n").await?;
            }
            Command::Type(t) => {
                let parts: Vec<String> =
                    t.split_whitespace().map(str::to_ascii_uppercase).collect();
                let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
                let reply = match parts.as_slice() {
                    ["I"] | ["L", "8"] => {
                        session.binary = true;
                        "200 Type set to I.\r\n"
                    }
                    ["A"] | ["A", "N"] => {
                        session.binary = false;
                        "200 Type set to A.\r\n"
                    }
                    _ => "504 Type not supported.\r\n",
                };
                send(&mut writer, ep, &events, reply).await?;
            }
            Command::Pasv => {
                session.data_channel = DataChannel::None;
                match open_passive(local.ip(), &ports).await {
                    Ok((listener, port)) => {
                        session.data_channel = DataChannel::Passive(listener);
                        let ip = match local.ip() {
                            IpAddr::V4(v4) => v4.octets(),
                            IpAddr::V6(_) => [127, 0, 0, 1],
                        };
                        let reply = format!(
                            "227 Entering Passive Mode ({},{},{},{},{},{}).\r\n",
                            ip[0],
                            ip[1],
                            ip[2],
                            ip[3],
                            port >> 8,
                            port & 0xFF
                        );
                        send(&mut writer, ep, &events, &reply).await?;
                    }
                    Err(_) => {
                        send(
                            &mut writer,
                            ep,
                            &events,
                            "425 Can't open passive connection.\r\n",
                        )
                        .await?;
                    }
                }
            }
            Command::Port(arg) => {
                let reply = match parse_port_arg(&arg) {
                    None => "501 Malformed PORT argument.\r\n",
                    Some(addr) if addr.ip() != peer.ip() || addr.port() < 1024 => {
                        "500 Illegal PORT command - use your own address and a port from 1024.\r\n"
                    }
                    Some(addr) => {
                        session.data_channel = DataChannel::Active(addr);
                        "200 PORT command successful.\r\n"
                    }
                };
                send(&mut writer, ep, &events, reply).await?;
            }
            Command::List(ref arg) | Command::Nlst(ref arg) | Command::Mlsd(ref arg) => {
                let format = match cmd {
                    Command::Nlst(_) => ListFormat::Names,
                    Command::Mlsd(_) => ListFormat::Facts,
                    _ => ListFormat::Long,
                };
                let target = session.resolve(list_path(arg.as_deref()));
                match build_listing(&target, format).await {
                    Ok(body) => {
                        run_transfer(
                            &mut session,
                            &events,
                            &mut writer,
                            ep,
                            "150 Opening data connection for directory listing.\r\n",
                            Transfer::Listing(body),
                        )
                        .await?
                    }
                    Err(reply) => send(&mut writer, ep, &events, reply).await?,
                }
            }
            Command::Mlst(path) => {
                let target = session.resolve(path.as_deref().unwrap_or("."));
                match fs::metadata(&target).await {
                    Ok(meta) => {
                        let name = target
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let facts = format_mlsx_facts(&meta);
                        send(&mut writer, ep, &events, "250-Listing:\r\n").await?;
                        send(&mut writer, ep, &events, &format!(" {facts} {name}\r\n")).await?;
                        send(&mut writer, ep, &events, "250 End.\r\n").await?;
                    }
                    Err(_) => {
                        send(
                            &mut writer,
                            ep,
                            &events,
                            "550 No such file or directory.\r\n",
                        )
                        .await?
                    }
                }
            }
            Command::Retr(path) => {
                let target = session.resolve(&path);
                let offset = std::mem::take(&mut session.rest_offset);
                match open_download(&target, offset).await {
                    Ok(file) => {
                        run_transfer(
                            &mut session,
                            &events,
                            &mut writer,
                            ep,
                            "150 Opening data connection for RETR.\r\n",
                            Transfer::Download(file),
                        )
                        .await?
                    }
                    Err(_) => send(&mut writer, ep, &events, "550 File not found.\r\n").await?,
                }
            }
            Command::Stor(ref path) | Command::Appe(ref path) => {
                let target = session.resolve(path);
                let append = matches!(cmd, Command::Appe(_));
                let offset = std::mem::take(&mut session.rest_offset);
                let parent_ok = target.parent().is_some_and(Path::is_dir);
                if target == session.root || target.is_dir() || !parent_ok {
                    send(&mut writer, ep, &events, "553 File name not allowed.\r\n").await?;
                } else {
                    let upload = Transfer::Upload {
                        path: target,
                        append,
                        offset,
                    };
                    run_transfer(
                        &mut session,
                        &events,
                        &mut writer,
                        ep,
                        "150 Opening data connection for upload.\r\n",
                        upload,
                    )
                    .await?;
                }
            }
            Command::Dele(path) => {
                let target = session.resolve(&path);
                match fs::remove_file(&target).await {
                    Ok(_) => send(&mut writer, ep, &events, "250 File deleted.\r\n").await?,
                    Err(_) => send(&mut writer, ep, &events, "550 Delete failed.\r\n").await?,
                }
            }
            Command::Mkd(path) => {
                let target = session.resolve(&path);
                match fs::create_dir(&target).await {
                    Ok(_) => {
                        let created = session.virtual_path(&target).replace('"', "\"\"");
                        send(
                            &mut writer,
                            ep,
                            &events,
                            &format!("257 \"{created}\" created.\r\n"),
                        )
                        .await?
                    }
                    Err(_) => {
                        send(&mut writer, ep, &events, "550 Create directory failed.\r\n").await?
                    }
                }
            }
            Command::Rmd(path) => {
                let target = session.resolve(&path);
                let removed = match target == session.root {
                    true => false,
                    false => fs::remove_dir(&target).await.is_ok(),
                };
                let reply = match removed {
                    true => "250 Directory removed.\r\n",
                    false => "550 Remove directory failed.\r\n",
                };
                send(&mut writer, ep, &events, reply).await?;
            }
            Command::Rnfr(path) => {
                let target = session.resolve(&path);
                if target != session.root && fs::metadata(&target).await.is_ok() {
                    session.rename_from = Some(target);
                    send(&mut writer, ep, &events, "350 Ready for RNTO.\r\n").await?;
                } else {
                    session.rename_from = None;
                    send(&mut writer, ep, &events, "550 File not found.\r\n").await?;
                }
            }
            Command::Rnto(path) => {
                if let Some(from) = session.rename_from.take() {
                    let to = session.resolve(&path);
                    match fs::rename(&from, &to).await {
                        Ok(_) => {
                            send(&mut writer, ep, &events, "250 Rename successful.\r\n").await?
                        }
                        Err(_) => send(&mut writer, ep, &events, "550 Rename failed.\r\n").await?,
                    }
                } else {
                    send(&mut writer, ep, &events, "503 RNFR required first.\r\n").await?;
                }
            }
            Command::Size(path) => {
                let target = session.resolve(&path);
                match fs::metadata(&target).await {
                    Ok(meta) => {
                        send(&mut writer, ep, &events, &format!("213 {}\r\n", meta.len())).await?
                    }
                    Err(_) => send(&mut writer, ep, &events, "550 No such file.\r\n").await?,
                }
            }
            Command::Mdtm(path) => {
                let target = session.resolve(&path);
                match fs::metadata(&target).await {
                    Ok(meta) => {
                        send(
                            &mut writer,
                            ep,
                            &events,
                            &format!("213 {}\r\n", format_mdtm(&meta)),
                        )
                        .await?
                    }
                    Err(_) => send(&mut writer, ep, &events, "550 No such file.\r\n").await?,
                }
            }
            Command::Rest(offset) => {
                session.rest_offset = offset;
                send(
                    &mut writer,
                    ep,
                    &events,
                    &format!("350 Restarting at {offset}.\r\n"),
                )
                .await?;
            }
            Command::Feat => {
                send(&mut writer, ep, &events, "211-Features:\r\n").await?;
                for feature in FEATURES {
                    send(&mut writer, ep, &events, &format!(" {feature}\r\n")).await?;
                }
                if tls.is_some() {
                    for feature in ["AUTH TLS", "PBSZ", "PROT"] {
                        send(&mut writer, ep, &events, &format!(" {feature}\r\n")).await?;
                    }
                }
                send(&mut writer, ep, &events, "211 End.\r\n").await?;
            }
            Command::Opts(arg) => {
                if arg.eq_ignore_ascii_case("UTF8 ON") {
                    send(&mut writer, ep, &events, "200 UTF8 mode enabled.\r\n").await?;
                } else {
                    send(&mut writer, ep, &events, "501 Option not recognized.\r\n").await?;
                }
            }
            Command::Syst => send(&mut writer, ep, &events, "215 UNIX Type: L8\r\n").await?,
            Command::Noop => send(&mut writer, ep, &events, "200 NOOP ok.\r\n").await?,
            Command::Help => {
                send(
                    &mut writer,
                    ep,
                    &events,
                    "214 Commands: see RFC 959, RFC 3659, RFC 4217.\r\n",
                )
                .await?
            }
            Command::Abor => send(&mut writer, ep, &events, "226 Abort successful.\r\n").await?,

            Command::Auth(_) | Command::Pbsz(_) | Command::Prot(_) | Command::Ccc
                if tls.is_none() =>
            {
                send(
                    &mut writer,
                    ep,
                    &events,
                    "502 Security extensions are not available on this listener.\r\n",
                )
                .await?;
            }
            Command::Auth(mechanism) => {
                let mechanism = mechanism.to_ascii_uppercase();
                if mechanism.is_empty() {
                    send(&mut writer, ep, &events, "501 AUTH needs a mechanism.\r\n").await?;
                } else if session.tls_active {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "534 Request denied for policy reasons - TLS is already active.\r\n",
                    )
                    .await?;
                } else if mechanism != "TLS" && mechanism != "TLS-C" {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "504 Only AUTH TLS is supported.\r\n",
                    )
                    .await?;
                } else if !reader.buffer().is_empty() {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "421 Unexpected data after AUTH, closing control connection.\r\n",
                    )
                    .await?;
                    break;
                } else if let Some(upgrader) = tls.as_ref() {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "234 AUTH TLS successful - starting TLS handshake.\r\n",
                    )
                    .await?;
                    let plain = reader.into_inner().unsplit(writer);
                    let (secured, info) = upgrader.upgrade(plain, TlsRole::Control).await?;
                    let (read_half, write_half) = tokio::io::split(secured);
                    reader = BufReader::new(read_half);
                    writer = write_half;
                    session.reset_after_auth();
                    session.tls_active = true;
                    emit(
                        &events,
                        ep,
                        EventKind::Tls,
                        Direction::ServerToClient,
                        Vec::new(),
                        format!("TLS handshake complete ({info}) - control connection encrypted"),
                    );
                    ep.encrypted = true;
                }
            }
            Command::Pbsz(arg) => {
                if !session.tls_active {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "503 PBSZ requires AUTH TLS first.\r\n",
                    )
                    .await?;
                } else if arg.parse::<u32>().is_err() {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "501 PBSZ needs a decimal integer.\r\n",
                    )
                    .await?;
                } else {
                    session.pbsz_done = true;
                    send(&mut writer, ep, &events, "200 PBSZ=0\r\n").await?;
                }
            }
            Command::Prot(level) => {
                if !session.pbsz_done {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "503 PROT requires PBSZ first.\r\n",
                    )
                    .await?;
                } else {
                    match level.to_ascii_uppercase().as_str() {
                        "C" => {
                            session.prot_private = false;
                            send(&mut writer, ep, &events, "200 PROT now Clear.\r\n").await?;
                        }
                        "P" => {
                            session.prot_private = true;
                            send(&mut writer, ep, &events, "200 PROT now Private.\r\n").await?;
                        }
                        "S" | "E" => {
                            send(
                                &mut writer,
                                ep,
                                &events,
                                "536 Requested PROT level not supported by mechanism.\r\n",
                            )
                            .await?;
                        }
                        "" => {
                            send(
                                &mut writer,
                                ep,
                                &events,
                                "501 PROT needs a protection level.\r\n",
                            )
                            .await?
                        }
                        _ => send(&mut writer, ep, &events, "504 Unknown PROT level.\r\n").await?,
                    }
                }
            }
            Command::Ccc => {
                if !session.tls_active {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "533 Command channel is not protected.\r\n",
                    )
                    .await?;
                } else {
                    send(
                        &mut writer,
                        ep,
                        &events,
                        "534 Clearing the command channel is not permitted.\r\n",
                    )
                    .await?;
                }
            }
            Command::Unknown(verb) => {
                send(
                    &mut writer,
                    ep,
                    &events,
                    &format!("502 Command '{verb}' not implemented.\r\n"),
                )
                .await?;
            }
        }
    }

    emit(
        &events,
        ep,
        EventKind::TcpClose,
        Direction::ClientToServer,
        Vec::new(),
        "TCP control connection closed",
    );
    Ok(())
}

fn decode_line(raw: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut iter = raw.iter();
    while let Some(&byte) = iter.next() {
        match byte {
            0xFF => {
                iter.next();
            }
            _ => bytes.push(byte),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn list_path(arg: Option<&str>) -> &str {
    let mut rest = arg.unwrap_or_default().trim_start();
    while rest.starts_with('-') {
        rest = rest
            .split_once(' ')
            .map_or("", |(_, path)| path)
            .trim_start();
    }
    match rest {
        "" => ".",
        path => path,
    }
}

async fn build_listing(target: &Path, format: ListFormat) -> Result<String, &'static str> {
    let meta = fs::metadata(target)
        .await
        .map_err(|_| "550 No such file or directory.\r\n")?;
    let mut entries = Vec::new();
    if meta.is_dir() {
        let mut dir = fs::read_dir(target)
            .await
            .map_err(|_| "550 Failed to list directory.\r\n")?;
        while let Ok(Some(entry)) = dir.next_entry().await {
            if let Ok(meta) = entry.metadata().await {
                entries.push((entry.file_name().to_string_lossy().into_owned(), meta));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
    } else if matches!(format, ListFormat::Facts) {
        return Err("501 MLSD needs a directory.\r\n");
    } else {
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.push((name, meta));
    }
    let mut out = String::new();
    for (name, meta) in entries {
        let line = match format {
            ListFormat::Long => format_list_line(&name, &meta),
            ListFormat::Names => name,
            ListFormat::Facts => format!("{} {name}", format_mlsx_facts(&meta)),
        };
        out.push_str(&line);
        out.push_str("\r\n");
    }
    Ok(out)
}

async fn open_download(target: &Path, offset: u64) -> io::Result<fs::File> {
    if !fs::metadata(target).await?.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut file = fs::File::open(target).await?;
    if offset > 0 {
        file.seek(io::SeekFrom::Start(offset)).await?;
    }
    Ok(file)
}

async fn open_upload(path: &Path, append: bool, offset: u64) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create(true);
    match append {
        true => options.append(true),
        false => options.write(true).truncate(offset == 0),
    };
    let mut file = options.open(path).await?;
    if !append && offset > 0 {
        file.seek(io::SeekFrom::Start(offset)).await?;
    }
    Ok(file)
}

async fn run_transfer<W>(
    session: &mut Session,
    events: &EventSender,
    writer: &mut W,
    control: Endpoints,
    opening: &str,
    transfer: Transfer,
) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    if matches!(session.data_channel, DataChannel::None) {
        return send(writer, control, events, "425 Use PORT or PASV first.\r\n").await;
    }
    send(writer, control, events, opening).await?;
    let reply = match open_data_connection(session, events, control).await {
        Err(err) => err.reply(),
        Ok((mut data, ep)) => {
            let (direction, result) = match transfer {
                Transfer::Listing(body) => (
                    Direction::ServerToClient,
                    send_listing(&mut data, events, ep, body).await,
                ),
                Transfer::Download(mut file) => (
                    Direction::ServerToClient,
                    send_file(&mut data, events, ep, &mut file).await,
                ),
                Transfer::Upload {
                    path,
                    append,
                    offset,
                } => (
                    Direction::ClientToServer,
                    receive_file(&mut data, events, ep, &path, append, offset).await,
                ),
            };
            data.shutdown().await.ok();
            emit_close(events, ep, direction);
            match result {
                Ok(()) => "226 Transfer complete.\r\n",
                Err(err) => err.reply(),
            }
        }
    };
    send(writer, control, events, reply).await
}

async fn connect_active(local: IpAddr, port: u16, client: SocketAddr) -> io::Result<TcpStream> {
    let socket = match client {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    socket.set_reuseport(true)?;
    if port != 0 {
        let _ = socket.bind(SocketAddr::new(local, port));
    }
    socket.connect(client).await
}

async fn open_passive(bind_addr: IpAddr, ports: &DataPorts) -> io::Result<(TcpListener, u16)> {
    for port in ports.passive_start..=ports.passive_end.max(ports.passive_start) {
        if let Ok(listener) = TcpListener::bind((bind_addr, port)).await {
            return Ok((listener, port));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no free port in passive range",
    ))
}

fn parse_port_arg(arg: &str) -> Option<SocketAddr> {
    let parts: Vec<u8> = arg
        .split(',')
        .map(|p| p.trim().parse().ok())
        .collect::<Option<_>>()?;
    let [a, b, c, d, high, low] = parts[..] else {
        return None;
    };
    let port = u16::from_be_bytes([high, low]);
    Some(SocketAddr::new(IpAddr::from([a, b, c, d]), port))
}

fn emit(
    events: &EventSender,
    ep: Endpoints,
    kind: EventKind,
    direction: Direction,
    raw: Vec<u8>,
    parsed: impl Into<String>,
) {
    let encrypted = ep.encrypted && matches!(kind, EventKind::Message | EventKind::Data);
    let _ = events.send(
        MessageEvent::new(ep.protocol, kind, direction, ep.peer, ep.local, raw, parsed)
            .with_encrypted(encrypted)
            .with_session(ep.session),
    );
}

fn emit_data(
    events: &EventSender,
    ep: Endpoints,
    direction: Direction,
    length: usize,
    parsed: impl Into<String>,
) {
    let _ = events.send(
        MessageEvent::new(
            ep.protocol,
            EventKind::Data,
            direction,
            ep.peer,
            ep.local,
            Vec::new(),
            parsed,
        )
        .with_length(length)
        .with_encrypted(ep.encrypted)
        .with_session(ep.session),
    );
}

async fn accept_from(
    listener: &TcpListener,
    client: IpAddr,
    events: &EventSender,
    control: Endpoints,
) -> io::Result<TcpStream> {
    let deadline = Instant::now() + DATA_TIMEOUT;
    loop {
        let (tcp, from) = timeout_at(deadline, listener.accept())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if from.ip() == client {
            return Ok(tcp);
        }
        let intruder = Endpoints {
            peer: from,
            local: tcp.local_addr()?,
            ..control
        };
        emit(
            events,
            intruder,
            EventKind::TcpClose,
            Direction::ServerToClient,
            Vec::new(),
            format!("Data connection from {from} refused - only {client} may use this port"),
        );
    }
}

async fn open_data_connection(
    session: &mut Session,
    events: &EventSender,
    control: Endpoints,
) -> Result<(BoxedStream, Endpoints), TransferError> {
    let client = control.peer.ip();
    let control = Endpoints {
        encrypted: false,
        ..control
    };
    let channel = std::mem::replace(&mut session.data_channel, DataChannel::None);
    let connected = match channel {
        DataChannel::Passive(listener) => accept_from(&listener, client, events, control)
            .await
            .map(|tcp| (tcp, Direction::ClientToServer)),
        DataChannel::Active(addr) => {
            let connect = connect_active(control.local.ip(), session.active_port, addr);
            match timeout(DATA_TIMEOUT, connect).await {
                Ok(result) => result.map(|tcp| (tcp, Direction::ServerToClient)),
                Err(_) => Err(io::ErrorKind::TimedOut.into()),
            }
        }
        DataChannel::None => Err(io::ErrorKind::NotConnected.into()),
    };
    let (tcp, opener) = connected.map_err(|_| TransferError::Connect)?;
    let mut ep = Endpoints {
        peer: tcp.peer_addr().map_err(|_| TransferError::Connect)?,
        local: tcp.local_addr().map_err(|_| TransferError::Connect)?,
        ..control
    };
    let mut text =
        "TCP handshake complete (SYN, SYN-ACK, ACK) - data connection established".to_string();
    if opener == Direction::ServerToClient {
        text += &format!(" (active mode, from port {})", ep.local.port());
        if session.active_port != 0 && ep.local.port() != session.active_port {
            text += &format!(" - port {} is not available", session.active_port);
        }
    }
    emit(events, ep, EventKind::TcpOpen, opener, Vec::new(), text);

    let mut data: BoxedStream = Box::new(tcp);
    if session.prot_private
        && let Some(upgrader) = &session.tls
    {
        let (secured, info) = upgrader
            .upgrade(data, TlsRole::Data)
            .await
            .map_err(|_| TransferError::TlsNegotiation)?;
        data = secured;
        emit(
            events,
            ep,
            EventKind::Tls,
            Direction::ServerToClient,
            Vec::new(),
            format!("TLS handshake complete ({info}) - data connection encrypted"),
        );
        ep.encrypted = true;
    }
    Ok((data, ep))
}

fn emit_close(events: &EventSender, ep: Endpoints, direction: Direction) {
    emit(
        events,
        ep,
        EventKind::TcpClose,
        direction,
        Vec::new(),
        "TCP data connection closed",
    );
}

async fn send_listing(
    data: &mut BoxedStream,
    events: &EventSender,
    ep: Endpoints,
    body: String,
) -> Result<(), TransferError> {
    data.write_all(body.as_bytes())
        .await
        .map_err(|e| classify(e, ep.encrypted))?;
    emit(
        events,
        ep,
        EventKind::Data,
        Direction::ServerToClient,
        body.as_bytes().to_vec(),
        format!("Directory listing ({} bytes)", body.len()),
    );
    Ok(())
}

async fn send_file(
    data: &mut BoxedStream,
    events: &EventSender,
    ep: Endpoints,
    file: &mut fs::File,
) -> Result<(), TransferError> {
    let bytes = tokio::io::copy(file, data)
        .await
        .map_err(|e| classify(e, ep.encrypted))?;
    emit_data(
        events,
        ep,
        Direction::ServerToClient,
        bytes as usize,
        format!("File data sent ({bytes} bytes)"),
    );
    Ok(())
}

async fn receive_file(
    data: &mut BoxedStream,
    events: &EventSender,
    ep: Endpoints,
    path: &Path,
    append: bool,
    offset: u64,
) -> Result<(), TransferError> {
    let mut file = open_upload(path, append, offset)
        .await
        .map_err(|_| TransferError::LocalFile)?;
    let bytes = copy_until_eof(data, &mut file)
        .await
        .map_err(|e| classify(e, ep.encrypted))?;
    file.flush().await.map_err(|_| TransferError::LocalFile)?;
    emit_data(
        events,
        ep,
        Direction::ClientToServer,
        bytes as usize,
        format!("File data received ({bytes} bytes)"),
    );
    Ok(())
}

async fn copy_until_eof<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    Ok(total)
}

async fn send(
    writer: &mut (impl AsyncWriteExt + Unpin),
    ep: Endpoints,
    events: &EventSender,
    line: &str,
) -> io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    emit(
        events,
        ep,
        EventKind::Message,
        Direction::ServerToClient,
        line.as_bytes().to_vec(),
        line.trim_end(),
    );
    Ok(())
}

fn log_incoming(ep: Endpoints, events: &EventSender, line: &str) {
    let line = match line.get(..5) {
        Some(verb) if verb.eq_ignore_ascii_case("PASS ") => {
            let length = line.trim_end().chars().count().saturating_sub(5);
            format!("PASS ******** ({length} characters)\r\n")
        }
        _ => line.to_string(),
    };
    emit(
        events,
        ep,
        EventKind::Message,
        Direction::ClientToServer,
        line.as_bytes().to_vec(),
        line.trim_end(),
    );
}
