use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use proto_core::{Direction, EventKind, EventSender, MessageEvent, Protocol};

use crate::command::Command;
use crate::listing::{format_list_line, format_mdtm, format_mlsx_facts};
use crate::session::{DataChannel, Session};

const FEATURES: &[&str] = &[
    "MDTM",
    "REST STREAM",
    "SIZE",
    "UTF8",
    "MLST type*;size*;modify*;",
    "MLSD",
    "HOST",
];

#[derive(Clone, Copy)]
struct Endpoints {
    peer: SocketAddr,
    local: SocketAddr,
}

pub struct PassiveRange {
    pub start: u16,
    pub end: u16,
}

pub async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    bind_addr: IpAddr,
    root: PathBuf,
    pasv_range: PassiveRange,
    events: EventSender,
) -> io::Result<()> {
    let local = stream.local_addr()?;
    let peer = Endpoints { peer, local };
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;
    let mut session = Session::new(root);

    emit(
        &events,
        peer,
        EventKind::TcpOpen,
        Direction::ClientToServer,
        Vec::new(),
        "TCP handshake complete (SYN, SYN-ACK, ACK) - control connection established",
    );
    send(
        &mut writer,
        peer,
        &events,
        "220 FTPeek FTP server ready.\r\n",
    )
    .await?;

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        log_incoming(peer, &events, &line);

        let cmd = Command::parse(&line);

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
                | Command::Help
        );
        if requires_auth && !session.authenticated {
            send(&mut writer, peer, &events, "530 Not logged in.\r\n").await?;
            continue;
        }

        match cmd {
            Command::User(name) => {
                session.username = Some(name.clone());
                send(
                    &mut writer,
                    peer,
                    &events,
                    &format!("331 Password required for {name}.\r\n"),
                )
                .await?;
            }
            Command::Pass(_) => {
                if session.username.is_some() {
                    session.authenticated = true;
                    send(&mut writer, peer, &events, "230 User logged in.\r\n").await?;
                } else {
                    send(&mut writer, peer, &events, "503 Login with USER first.\r\n").await?;
                }
            }
            Command::Host(name) => {
                if session.authenticated {
                    send(
                        &mut writer,
                        peer,
                        &events,
                        "503 HOST not allowed after login.\r\n",
                    )
                    .await?;
                } else {
                    session.host = Some(name);
                    send(&mut writer, peer, &events, "220 Host accepted.\r\n").await?;
                }
            }
            Command::Quit => {
                send(&mut writer, peer, &events, "221 Goodbye.\r\n").await?;
                break;
            }
            Command::Pwd => {
                let cwd = session.virtual_cwd();
                send(
                    &mut writer,
                    peer,
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
                    send(&mut writer, peer, &events, "250 Directory changed.\r\n").await?;
                } else {
                    send(&mut writer, peer, &events, "550 No such directory.\r\n").await?;
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
                send(&mut writer, peer, &events, "250 Directory changed.\r\n").await?;
            }
            Command::Type(t) => {
                session.binary = t.eq_ignore_ascii_case("I");
                send(&mut writer, peer, &events, "200 Type set.\r\n").await?;
            }
            Command::Pasv => match open_passive(bind_addr, &pasv_range).await {
                Ok((listener, port)) => {
                    session.data_channel = DataChannel::Passive(listener);
                    let ip = match bind_addr {
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
                    send(&mut writer, peer, &events, &reply).await?;
                }
                Err(_) => {
                    send(
                        &mut writer,
                        peer,
                        &events,
                        "425 Can't open passive connection.\r\n",
                    )
                    .await?;
                }
            },
            Command::Port(arg) => {
                if let Some(addr) = parse_port_arg(&arg) {
                    session.data_channel = DataChannel::Active(addr);
                    send(
                        &mut writer,
                        peer,
                        &events,
                        "200 PORT command successful.\r\n",
                    )
                    .await?;
                } else {
                    send(
                        &mut writer,
                        peer,
                        &events,
                        "501 Malformed PORT argument.\r\n",
                    )
                    .await?;
                }
            }
            Command::List(path) | Command::Nlst(path) => {
                let dir = session.resolve(path.as_deref().unwrap_or("."));
                send(
                    &mut writer,
                    peer,
                    &events,
                    "150 Opening data connection for directory listing.\r\n",
                )
                .await?;
                match send_listing(&mut session, &events, &dir, false).await {
                    Ok(_) => send(&mut writer, peer, &events, "226 Transfer complete.\r\n").await?,
                    Err(_) => {
                        send(
                            &mut writer,
                            peer,
                            &events,
                            "451 Failed to list directory.\r\n",
                        )
                        .await?
                    }
                }
            }
            Command::Mlsd(path) => {
                let dir = session.resolve(path.as_deref().unwrap_or("."));
                send(
                    &mut writer,
                    peer,
                    &events,
                    "150 Opening data connection (MLSD).\r\n",
                )
                .await?;
                match send_listing(&mut session, &events, &dir, true).await {
                    Ok(_) => send(&mut writer, peer, &events, "226 Transfer complete.\r\n").await?,
                    Err(_) => {
                        send(
                            &mut writer,
                            peer,
                            &events,
                            "451 Failed to list directory.\r\n",
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
                        send(&mut writer, peer, &events, "250-Listing:\r\n").await?;
                        send(&mut writer, peer, &events, &format!(" {facts} {name}\r\n")).await?;
                        send(&mut writer, peer, &events, "250 End.\r\n").await?;
                    }
                    Err(_) => {
                        send(
                            &mut writer,
                            peer,
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
                    peer,
                    &events,
                    "150 Opening data connection for RETR.\r\n",
                )
                .await?;
                match send_file(&mut session, &events, &target).await {
                    Ok(_) => send(&mut writer, peer, &events, "226 Transfer complete.\r\n").await?,
                    Err(_) => {
                        send(&mut writer, peer, &events, "550 Failed to open file.\r\n").await?
                    }
                }
                session.rest_offset = 0;
            }
            Command::Stor(ref path) | Command::Appe(ref path) => {
                let target = session.resolve(path);
                let append = matches!(cmd, Command::Appe(_));
                send(
                    &mut writer,
                    peer,
                    &events,
                    "150 Opening data connection for upload.\r\n",
                )
                .await?;
                match receive_file(&mut session, &events, &target, append).await {
                    Ok(_) => send(&mut writer, peer, &events, "226 Transfer complete.\r\n").await?,
                    Err(_) => {
                        send(&mut writer, peer, &events, "550 Failed to write file.\r\n").await?
                    }
                }
            }
            Command::Dele(path) => {
                let target = session.resolve(&path);
                match fs::remove_file(&target).await {
                    Ok(_) => send(&mut writer, peer, &events, "250 File deleted.\r\n").await?,
                    Err(_) => send(&mut writer, peer, &events, "550 Delete failed.\r\n").await?,
                }
            }
            Command::Mkd(path) => {
                let target = session.resolve(&path);
                match fs::create_dir(&target).await {
                    Ok(_) => {
                        send(
                            &mut writer,
                            peer,
                            &events,
                            &format!("257 \"{path}\" created.\r\n"),
                        )
                        .await?
                    }
                    Err(_) => {
                        send(
                            &mut writer,
                            peer,
                            &events,
                            "550 Create directory failed.\r\n",
                        )
                        .await?
                    }
                }
            }
            Command::Rmd(path) => {
                let target = session.resolve(&path);
                match fs::remove_dir(&target).await {
                    Ok(_) => send(&mut writer, peer, &events, "250 Directory removed.\r\n").await?,
                    Err(_) => {
                        send(
                            &mut writer,
                            peer,
                            &events,
                            "550 Remove directory failed.\r\n",
                        )
                        .await?
                    }
                }
            }
            Command::Rnfr(path) => {
                session.rename_from = Some(session.resolve(&path));
                send(&mut writer, peer, &events, "350 Ready for RNTO.\r\n").await?;
            }
            Command::Rnto(path) => {
                if let Some(from) = session.rename_from.take() {
                    let to = session.resolve(&path);
                    match fs::rename(&from, &to).await {
                        Ok(_) => {
                            send(&mut writer, peer, &events, "250 Rename successful.\r\n").await?
                        }
                        Err(_) => {
                            send(&mut writer, peer, &events, "550 Rename failed.\r\n").await?
                        }
                    }
                } else {
                    send(&mut writer, peer, &events, "503 RNFR required first.\r\n").await?;
                }
            }
            Command::Size(path) => {
                let target = session.resolve(&path);
                match fs::metadata(&target).await {
                    Ok(meta) => {
                        send(
                            &mut writer,
                            peer,
                            &events,
                            &format!("213 {}\r\n", meta.len()),
                        )
                        .await?
                    }
                    Err(_) => send(&mut writer, peer, &events, "550 No such file.\r\n").await?,
                }
            }
            Command::Mdtm(path) => {
                let target = session.resolve(&path);
                match fs::metadata(&target).await {
                    Ok(meta) => {
                        send(
                            &mut writer,
                            peer,
                            &events,
                            &format!("213 {}\r\n", format_mdtm(&meta)),
                        )
                        .await?
                    }
                    Err(_) => send(&mut writer, peer, &events, "550 No such file.\r\n").await?,
                }
            }
            Command::Rest(offset) => {
                session.rest_offset = offset;
                send(
                    &mut writer,
                    peer,
                    &events,
                    &format!("350 Restarting at {offset}.\r\n"),
                )
                .await?;
            }
            Command::Feat => {
                send(&mut writer, peer, &events, "211-Features:\r\n").await?;
                for feature in FEATURES {
                    send(&mut writer, peer, &events, &format!(" {feature}\r\n")).await?;
                }
                send(&mut writer, peer, &events, "211 End.\r\n").await?;
            }
            Command::Opts(arg) => {
                if arg.eq_ignore_ascii_case("UTF8 ON") {
                    send(&mut writer, peer, &events, "200 UTF8 mode enabled.\r\n").await?;
                } else {
                    send(&mut writer, peer, &events, "501 Option not recognized.\r\n").await?;
                }
            }
            Command::Syst => send(&mut writer, peer, &events, "215 UNIX Type: L8\r\n").await?,
            Command::Noop => send(&mut writer, peer, &events, "200 NOOP ok.\r\n").await?,
            Command::Help => {
                send(
                    &mut writer,
                    peer,
                    &events,
                    "214 Commands: see RFC 959, RFC 3659.\r\n",
                )
                .await?
            }
            Command::Abor => send(&mut writer, peer, &events, "226 Abort successful.\r\n").await?,
            Command::Auth(_) => {
                // AUTH TLS is handled by proto-ftps, which wraps this same
                // command loop with a TLS-capable listener. Plain FTP has
                // nothing to upgrade to.
                send(
                    &mut writer,
                    peer,
                    &events,
                    "502 AUTH not supported on this listener.\r\n",
                )
                .await?;
            }
            Command::Pbsz(_) | Command::Prot(_) => {
                send(
                    &mut writer,
                    peer,
                    &events,
                    "502 Command only valid after AUTH TLS.\r\n",
                )
                .await?;
            }
            Command::Unknown(verb) => {
                send(
                    &mut writer,
                    peer,
                    &events,
                    &format!("502 Command '{verb}' not implemented.\r\n"),
                )
                .await?;
            }
        }
    }

    emit(
        &events,
        peer,
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
    let _ = events.send(MessageEvent::new(
        Protocol::Ftp,
        kind,
        direction,
        ep.peer,
        ep.local,
        raw,
        parsed,
    ));
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
            Protocol::Ftp,
            EventKind::Data,
            direction,
            ep.peer,
            ep.local,
            Vec::new(),
            parsed,
        )
        .with_length(length),
    );
}

async fn open_data_connection(
    session: &mut Session,
    events: &EventSender,
) -> io::Result<(TcpStream, Endpoints)> {
    let (stream, opener) = match &mut session.data_channel {
        DataChannel::Passive(listener) => (listener.accept().await?.0, Direction::ClientToServer),
        DataChannel::Active(addr) => (TcpStream::connect(*addr).await?, Direction::ServerToClient),
        DataChannel::None => {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no PASV/PORT issued",
            ));
        }
    };
    let ep = Endpoints {
        peer: stream.peer_addr()?,
        local: stream.local_addr()?,
    };
    emit(
        events,
        ep,
        EventKind::TcpOpen,
        opener,
        Vec::new(),
        "TCP handshake complete (SYN, SYN-ACK, ACK) - data connection established",
    );
    Ok((stream, ep))
}

async fn send_listing(
    session: &mut Session,
    events: &EventSender,
    dir: &PathBuf,
    machine_readable: bool,
) -> io::Result<()> {
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
    data.write_all(out.as_bytes()).await?;
    emit(
        events,
        ep,
        EventKind::Data,
        Direction::ServerToClient,
        out.as_bytes().to_vec(),
        format!("Directory listing ({} bytes)", out.len()),
    );
    emit(
        events,
        ep,
        EventKind::TcpClose,
        Direction::ServerToClient,
        Vec::new(),
        "TCP data connection closed",
    );
    Ok(())
}

async fn send_file(session: &mut Session, events: &EventSender, path: &PathBuf) -> io::Result<()> {
    let mut file = fs::File::open(path).await?;
    if session.rest_offset > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(io::SeekFrom::Start(session.rest_offset)).await?;
    }
    let (mut data, ep) = open_data_connection(session, events).await?;
    let bytes = tokio::io::copy(&mut file, &mut data).await?;
    emit_data(
        events,
        ep,
        Direction::ServerToClient,
        bytes as usize,
        format!("File data sent ({bytes} bytes)"),
    );
    emit(
        events,
        ep,
        EventKind::TcpClose,
        Direction::ServerToClient,
        Vec::new(),
        "TCP data connection closed",
    );
    Ok(())
}

async fn receive_file(
    session: &mut Session,
    events: &EventSender,
    path: &PathBuf,
    append: bool,
) -> io::Result<()> {
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
    let bytes = tokio::io::copy(&mut data, &mut file).await?;
    emit_data(
        events,
        ep,
        Direction::ClientToServer,
        bytes as usize,
        format!("File data received ({bytes} bytes)"),
    );
    emit(
        events,
        ep,
        EventKind::TcpClose,
        Direction::ClientToServer,
        Vec::new(),
        "TCP data connection closed",
    );
    Ok(())
}

async fn send(
    writer: &mut (impl AsyncWriteExt + Unpin),
    ep: Endpoints,
    events: &EventSender,
    line: &str,
) -> io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
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
