use proto_core::{EventKind, MessageEvent, Protocol};
use proto_sftp::SftpServerConfig;

use super::{Cells, Channel, Opt, Options, Rows, SSH, ServeCtx, ServeFuture, Spec};
use crate::components::ClientInfo;

pub struct Sftp;

impl Spec for Sftp {
    fn id(&self) -> &'static str {
        "sftp"
    }

    fn label(&self) -> &'static str {
        "SFTP"
    }

    fn description(&self) -> &'static str {
        "Binary subsystem over SSH2"
    }

    fn core(&self) -> Protocol {
        Protocol::Sftp
    }

    fn options(&self) -> &'static [Opt] {
        &[Opt::Port {
            key: "port",
            label: "Port (TCP)",
            default: 22,
        }]
    }

    fn hints(&self) -> &'static [&'static str] {
        &[
            "A new SSH host key is generated on every start - the client will warn that the key changed. If port 22 is taken by the system SSH server, use 2222.",
        ]
    }

    fn capture_ports(&self, opts: &Options) -> Vec<u16> {
        vec![opts.port("port")]
    }

    fn serve(&self, ctx: ServeCtx) -> ServeFuture {
        let cfg = SftpServerConfig {
            bind_addr: ctx.bind,
            port: ctx.opts.port("port"),
            root_dir: ctx.root,
            users: ctx.users,
        };
        Box::pin(proto_sftp::serve(cfg, ctx.events, ctx.shutdown))
    }

    fn channel(&self) -> Channel {
        SSH
    }

    fn app_title(&self, e: &MessageEvent) -> String {
        match is_ssh(e) {
            true => "Secure Shell (SSH)".into(),
            false => "SSH File Transfer Protocol".into(),
        }
    }

    fn detail_rows(&self, e: &MessageEvent) -> Rows {
        rows(&e.raw)
    }

    fn diagram_cells(&self, e: &MessageEvent) -> Option<Cells> {
        cells(&e.raw)
    }

    fn proto_column(&self, e: &MessageEvent) -> String {
        match e.kind {
            EventKind::TcpOpen | EventKind::TcpClose => "TCP".into(),
            _ if is_ssh(e) => "SSH".into(),
            _ => "SFTP".into(),
        }
    }

    fn track(&self, client: &mut ClientInfo, e: &MessageEvent) {
        track_sftp(client, e);
    }
}

fn is_ssh(e: &MessageEvent) -> bool {
    e.parsed
        .as_deref()
        .is_some_and(|t| t.starts_with("SSH_MSG"))
}

fn type_name(kind: u8) -> &'static str {
    match kind {
        1 => "SSH_FXP_INIT",
        2 => "SSH_FXP_VERSION",
        3 => "SSH_FXP_OPEN",
        4 => "SSH_FXP_CLOSE",
        5 => "SSH_FXP_READ",
        6 => "SSH_FXP_WRITE",
        7 => "SSH_FXP_LSTAT",
        8 => "SSH_FXP_FSTAT",
        9 => "SSH_FXP_SETSTAT",
        10 => "SSH_FXP_FSETSTAT",
        11 => "SSH_FXP_OPENDIR",
        12 => "SSH_FXP_READDIR",
        13 => "SSH_FXP_REMOVE",
        14 => "SSH_FXP_MKDIR",
        15 => "SSH_FXP_RMDIR",
        16 => "SSH_FXP_REALPATH",
        17 => "SSH_FXP_STAT",
        18 => "SSH_FXP_RENAME",
        19 => "SSH_FXP_READLINK",
        20 => "SSH_FXP_SYMLINK",
        101 => "SSH_FXP_STATUS",
        102 => "SSH_FXP_HANDLE",
        103 => "SSH_FXP_DATA",
        104 => "SSH_FXP_NAME",
        105 => "SSH_FXP_ATTRS",
        200 => "SSH_FXP_EXTENDED",
        201 => "SSH_FXP_EXTENDED_REPLY",
        _ => "unknown",
    }
}

fn header(raw: &[u8]) -> Option<(u32, u8, &'static str, u32)> {
    let length = u32::from_be_bytes(raw.get(..4)?.try_into().ok()?);
    let kind = *raw.get(4)?;
    let next = u32::from_be_bytes(raw.get(5..9)?.try_into().ok()?);
    let label = if kind <= 2 { "Version" } else { "Request id" };
    Some((length, kind, label, next))
}

fn rows(raw: &[u8]) -> Rows {
    match header(raw) {
        Some((length, kind, label, next)) => vec![
            ("Length", format!("{length} bytes")),
            ("Type", format!("{} ({kind})", type_name(kind))),
            (label, next.to_string()),
        ],
        None => Vec::new(),
    }
}

fn cells(raw: &[u8]) -> Option<Cells> {
    let (length, kind, label, next) = header(raw)?;
    Some([
        ("LENGTH (4 B)".to_string(), length.to_string()),
        (
            "TYPE (1 B)".to_string(),
            format!(
                "{kind} = {}",
                type_name(kind).trim_start_matches("SSH_FXP_")
            ),
        ),
        (format!("{} (4 B)", label.to_uppercase()), next.to_string()),
    ])
}

fn track_sftp(client: &mut ClientInfo, e: &MessageEvent) {
    let text = e.parsed.as_deref().unwrap_or_default();
    if let Some(rest) = text.strip_prefix("SSH_MSG_USERAUTH_REQUEST user=") {
        client.user = rest.split(", method=").next().map(str::to_string);
        client.logged_in = false;
    } else if text == "SSH_MSG_USERAUTH_SUCCESS" {
        client.logged_in = true;
    } else if text.starts_with("SSH_MSG_USERAUTH_FAILURE") {
        client.logged_in = false;
    }
    match e.kind {
        EventKind::Data => {
            let bytes = text
                .rsplit_once('(')
                .and_then(|(_, n)| n.strip_suffix(" bytes)"))
                .and_then(|n| n.parse::<u64>().ok());
            client.data_bytes += bytes.unwrap_or(e.length as u64);
        }
        EventKind::TcpClose => client.connected = false,
        _ => {}
    }
}
