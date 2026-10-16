use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use proto_core::{Direction, EventKind, EventSender, MessageEvent, Protocol, UserDb};

use crate::command::Command;
use crate::listing::{format_list_line, format_mdtm, format_mlsx_facts};
use crate::session::{DataChannel, Session};
use crate::tls::{AsyncStream, BoxedStream, TlsUpgrader};

const FEATURES: &[&str] = &[
    "MDTM",
    "REST STREAM",
    "SIZE",
    "UTF8",
    "MLST type*;size*;modify*;",
    "MLSD",
    "HOST",
];

pub struct PassiveRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Copy)]
struct Endpoints {
    peer: SocketAddr,
    local: SocketAddr,
    protocol: Protocol,
    encrypted: bool,
}

enum TransferError {
    TlsNegotiation,
    Protection,
    Io,
}

impl From<io::Error> for TransferError {
    fn from(_: io::Error) -> Self {
        TransferError::Io
    }
}

fn failure_reply(err: &TransferError, io_reply: &'static str) -> &'static str {
    match err {
        TransferError::TlsNegotiation => "522 TLS negotiation on the data connection failed.\r\n",
        TransferError::Protection => "535 Data protection failed during the transfer.\r\n",
        TransferError::Io => io_reply,
    }
}

fn classify(err: io::Error, encrypted: bool) -> TransferError {
    if encrypted && err.kind() == io::ErrorKind::InvalidData {
        TransferError::Protection
    } else {
        TransferError::Io
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_client<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    users: Option<Arc<UserDb>>,
    root: PathBuf,
    pasv_range: PassiveRange,
    events: EventSender,
    mut shutdown: broadcast::Receiver<()>,
    protocol: Protocol,
    tls: Option<TlsUpgrader>,
    implicit_tls: bool,
) -> io::Result<()>
where
    S: AsyncStream + 'static,
{
    let mut ep = Endpoints {
        peer,
        local,
        protocol,
        encrypted: false,
    };
    let mut session = Session::new(root, protocol, tls.clone());
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
        let (secured, info) = upgrader.upgrade(stream).await?;
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

    let mut line = String::new();
    loop {
        line.clear();
        tokio::select! {
            result = reader.read_line(&mut line) => {
                if result? == 0 {
                    break;
                }
            }
            _ = shutdown.recv() => {
                let _ = send(&mut writer, ep, &events, "421 Service not available, closing control connection.\r\n").await;
                break;
            }
        }
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
                    session.cwd = PathBuf::from(
                        "/".to_string()
                            + target
                                .strip_prefix(&session.root)
                                .unwrap()
                                .to_string_lossy()
                                .as_ref(),
                    );
                    send(&mut writer, ep, &events, "250 Directory changed.\r\n").await?;
                } else {
                    send(&mut writer, ep, &events, "550 No such directory.\r\n").await?;
                }
            }
            Command::Cdup => {
                let target = session.resolve("..");
                session.cwd = PathBuf::from(
                    "/".to_string()
                        + target
                            .strip_prefix(&session.root)
                            .unwrap()
                            .to_string_lossy()
                            .as_ref(),
                );
                send(&mut writer, ep, &events, "250 Directory changed.\r\n").await?;
            }
            Command::Type(t) => {
                session.binary = t.eq_ignore_ascii_case("I");
                send(&mut writer, ep, &events, "200 Type set.\r\n").await?;
            }
            Command::Pasv => {
                session.data_channel = DataChannel::None;
                match open_passive(local.ip(), &pasv_range).await {
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
                if let Some(addr) = parse_port_arg(&arg) {
                    session.data_channel = DataChannel::Active(addr);
                    send(&mut writer, ep, &events, "200 PORT command successful.\r\n").await?;
                } else {
                    send(&mut writer, ep, &events, "501 Malformed PORT argument.\r\n").await?;
                }
            }
            Command::List(path) | Command::Nlst(path) => {
                let dir = session.resolve(path.as_deref().unwrap_or("."));
                send(
                    &mut writer,
                    ep,
                    &events,
                    "150 Opening data connection for directory listing.\r\n",
                )
                .await?;
                match send_listing(&mut session, &events, &dir, false).await {
                    Ok(_) => send(&mut writer, ep, &events, "226 Transfer complete.\r\n").await?,
                    Err(e) => {
                        send(
                            &mut writer,
                            ep,
                            &events,
                            failure_reply(&e, "451 Failed to list directory.\r\n"),
                        )
                        .await?
                    }
                }
            }
            Command::Mlsd(path) => {
                let dir = session.resolve(path.as_deref().unwrap_or("."));
                send(
                    &mut writer,
                    ep,
                    &events,
                    "150 Opening data connection (MLSD).\r\n",
                )
                .await?;
                match send_listing(&mut session, &events, &dir, true).await {
                    Ok(_) => send(&mut writer, ep, &events, "226 Transfer complete.\r\n").await?,
                    Err(e) => {
                        send(
                            &mut writer,
                            ep,
                            &events,
                            failure_reply(&e, "451 Failed to list directory.\r\n"),
                        )
                        .await?
                    }
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
                send(
                    &mut writer,
                    ep,
                    &events,
                    "150 Opening data connection for RETR.\r\n",
                )
                .await?;
                match send_file(&mut session, &events, &target).await {
                    Ok(_) => send(&mut writer, ep, &events, "226 Transfer complete.\r\n").await?,
                    Err(e) => {
                        send(
                            &mut writer,
                            ep,
                            &events,
                            failure_reply(&e, "550 Failed to open file.\r\n"),
                        )
                        .await?
                    }
                }
                session.rest_offset = 0;
            }
            Command::Stor(ref path) | Command::Appe(ref path) => {
                let target = session.resolve(path);
                let append = matches!(cmd, Command::Appe(_));
                send(
                    &mut writer,
                    ep,
                    &events,
                    "150 Opening data connection for upload.\r\n",
                )
                .await?;
                match receive_file(&mut session, &events, &target, append).await {
                    Ok(_) => send(&mut writer, ep, &events, "226 Transfer complete.\r\n").await?,
                    Err(e) => {
                        send(
                            &mut writer,
                            ep,
                            &events,
                            failure_reply(&e, "550 Failed to write file.\r\n"),
                        )
                        .await?
                    }
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
                        send(
                            &mut writer,
                            ep,
                            &events,
                            &format!("257 \"{path}\" created.\r\n"),
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
                match fs::remove_dir(&target).await {
                    Ok(_) => send(&mut writer, ep, &events, "250 Directory removed.\r\n").await?,
                    Err(_) => {
                        send(&mut writer, ep, &events, "550 Remove directory failed.\r\n").await?
                    }
                }
            }
            Command::Rnfr(path) => {
                session.rename_from = Some(session.resolve(&path));
                send(&mut writer, ep, &events, "350 Ready for RNTO.\r\n").await?;
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
                    let (secured, info) = upgrader.upgrade(plain).await?;
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

async fn open_passive(bind_addr: IpAddr, range: &PassiveRange) -> io::Result<(TcpListener, u16)> {
    for port in range.start..=range.end {
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
    let parts: Vec<u16> = arg
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    if parts.len() != 6 {
        return None;
    }
    let ip = IpAddr::from([
        parts[0] as u8,
        parts[1] as u8,
        parts[2] as u8,
        parts[3] as u8,
    ]);
    let port = (parts[4] << 8) | parts[5];
    Some(SocketAddr::new(ip, port))
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
            .with_encrypted(encrypted),
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
        .with_encrypted(ep.encrypted),
    );
}

async fn open_data_connection(
    session: &mut Session,
    events: &EventSender,
) -> Result<(BoxedStream, Endpoints), TransferError> {
    let channel = std::mem::replace(&mut session.data_channel, DataChannel::None);
    let (tcp, opener) = match channel {
        DataChannel::Passive(listener) => (listener.accept().await?.0, Direction::ClientToServer),
        DataChannel::Active(addr) => (TcpStream::connect(addr).await?, Direction::ServerToClient),
        DataChannel::None => {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "no PASV/PORT issued").into());
        }
    };
    let mut ep = Endpoints {
        peer: tcp.peer_addr()?,
        local: tcp.local_addr()?,
        protocol: session.protocol,
        encrypted: false,
    };
    emit(
        events,
        ep,
        EventKind::TcpOpen,
        opener,
        Vec::new(),
        "TCP handshake complete (SYN, SYN-ACK, ACK) - data connection established",
    );

    let mut data: BoxedStream = Box::new(tcp);
    if session.prot_private {
        if let Some(upgrader) = &session.tls {
            let (secured, info) = upgrader
                .upgrade(data)
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
    session: &mut Session,
    events: &EventSender,
    dir: &PathBuf,
    machine_readable: bool,
) -> Result<(), TransferError> {
    let (mut data, ep) = open_data_connection(session, events).await?;
    let mut entries = fs::read_dir(dir).await?;
    let mut out = String::new();
    while let Some(entry) = entries.next_entry().await? {
        let meta = entry.metadata().await?;
        let name = entry.file_name().to_string_lossy().to_string();
        if machine_readable {
            out.push_str(&format!("{} {name}\r\n", format_mlsx_facts(&meta)));
        } else {
            out.push_str(&format_list_line(&name, &meta));
            out.push_str("\r\n");
        }
    }
    data.write_all(out.as_bytes())
        .await
        .map_err(|e| classify(e, ep.encrypted))?;
    data.shutdown().await.ok();
    emit(
        events,
        ep,
        EventKind::Data,
        Direction::ServerToClient,
        out.as_bytes().to_vec(),
        format!("Directory listing ({} bytes)", out.len()),
    );
    emit_close(events, ep, Direction::ServerToClient);
    Ok(())
}

async fn send_file(
    session: &mut Session,
    events: &EventSender,
    path: &PathBuf,
) -> Result<(), TransferError> {
    let mut file = fs::File::open(path).await?;
    if session.rest_offset > 0 {
        file.seek(io::SeekFrom::Start(session.rest_offset)).await?;
    }
    let (mut data, ep) = open_data_connection(session, events).await?;
    let bytes = tokio::io::copy(&mut file, &mut data)
        .await
        .map_err(|e| classify(e, ep.encrypted))?;
    data.shutdown().await.ok();
    emit_data(
        events,
        ep,
        Direction::ServerToClient,
        bytes as usize,
        format!("File data sent ({bytes} bytes)"),
    );
    emit_close(events, ep, Direction::ServerToClient);
    Ok(())
}

async fn receive_file(
    session: &mut Session,
    events: &EventSender,
    path: &PathBuf,
    append: bool,
) -> Result<(), TransferError> {
    let mut file = if append {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?
    } else {
        fs::File::create(path).await?
    };
    let (mut data, ep) = open_data_connection(session, events).await?;
    let bytes = copy_until_eof(&mut data, &mut file)
        .await
        .map_err(|e| classify(e, ep.encrypted))?;
    file.flush().await?;
    emit_data(
        events,
        ep,
        Direction::ClientToServer,
        bytes as usize,
        format!("File data received ({bytes} bytes)"),
    );
    emit_close(events, ep, Direction::ClientToServer);
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
    emit(
        events,
        ep,
        EventKind::Message,
        Direction::ClientToServer,
        line.as_bytes().to_vec(),
        line.trim_end(),
    );
}
