use proto_core::{Direction, EventKind, MessageEvent, Protocol};
use proto_tftp::{Packet, TftpServerConfig, error_name};

use super::{Cells, Opt, Options, Rows, ServeCtx, ServeFuture, Spec};
use crate::components::ClientInfo;
use crate::util::shorten;

pub struct Tftp;

impl Spec for Tftp {
    fn id(&self) -> &'static str {
        "tftp"
    }

    fn label(&self) -> &'static str {
        "TFTP"
    }

    fn description(&self) -> &'static str {
        "Lockstep opcodes over UDP/69"
    }

    fn core(&self) -> Protocol {
        Protocol::Tftp
    }

    fn options(&self) -> &'static [Opt] {
        &[
            Opt::Choice {
                key: "write",
                label: "Uploads (WRQ)",
                choices: &[("allow", "Allowed"), ("deny", "Disabled (read only)")],
                default: "allow",
            },
            Opt::Port {
                key: "port",
                label: "Port (UDP)",
                default: 69,
            },
        ]
    }

    fn login(&self) -> bool {
        false
    }

    fn hints(&self) -> &'static [&'static str] {
        &[
            "TFTP has no login: anyone who reaches this port can download every file in the root directory.",
        ]
    }

    fn capture_ports(&self, opts: &Options) -> Vec<u16> {
        vec![opts.port("port")]
    }

    fn serve(&self, ctx: ServeCtx) -> ServeFuture {
        let cfg = TftpServerConfig {
            bind_addr: ctx.bind,
            port: ctx.opts.port("port"),
            root_dir: ctx.root,
            allow_write: ctx.opts.is("write", "allow"),
        };
        Box::pin(proto_tftp::serve(cfg, ctx.events, ctx.shutdown))
    }

    fn transport_title(&self) -> &'static str {
        "User Datagram Protocol"
    }

    fn app_title(&self, _e: &MessageEvent) -> String {
        "Trivial File Transfer Protocol".into()
    }

    fn detail_rows(&self, e: &MessageEvent) -> Rows {
        tftp_rows(&e.raw)
    }

    fn diagram_cells(&self, e: &MessageEvent) -> Option<Cells> {
        tftp_cells(&e.raw)
    }

    fn proto_column(&self, e: &MessageEvent) -> String {
        match e.kind {
            EventKind::TcpOpen | EventKind::TcpClose => "TCP".into(),
            EventKind::Tls => "TLS".into(),
            _ => "TFTP".into(),
        }
    }

    fn info(&self, e: &MessageEvent) -> String {
        e.parsed.clone().unwrap_or_default()
    }

    fn starts_group(&self, e: &MessageEvent) -> bool {
        e.kind == EventKind::TcpOpen || e.direction == Direction::ClientToServer
    }

    fn track(&self, client: &mut ClientInfo, e: &MessageEvent) {
        track_tftp(client, e);
    }
}

fn tftp_rows(raw: &[u8]) -> Rows {
    let opcode = |n: u16, name: &str| ("Opcode", format!("{name} ({n})"));
    let options = |opts: &[(String, String)]| {
        opts.iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match Packet::parse(raw) {
        Some(Packet::Rrq(r)) | Some(Packet::Wrq(r)) => {
            let is_read = raw.get(1) == Some(&1);
            let mut rows = vec![
                if is_read {
                    opcode(1, "Read Request")
                } else {
                    opcode(2, "Write Request")
                },
                ("Source file", r.filename),
                ("Type", r.mode),
            ];
            if !r.options.is_empty() {
                rows.push(("Options", options(&r.options)));
            }
            rows
        }
        Some(Packet::Data { block, data }) => vec![
            opcode(3, "Data Packet"),
            ("Block", block.to_string()),
            ("Data length", format!("{} bytes", data.len())),
        ],
        Some(Packet::Ack { block }) => {
            vec![opcode(4, "Acknowledgement"), ("Block", block.to_string())]
        }
        Some(Packet::Error { code, message }) => vec![
            opcode(5, "Error Code"),
            ("Error code", format!("{} ({code})", error_name(code))),
            ("Error message", message),
        ],
        Some(Packet::Oack { options: o }) => {
            vec![
                opcode(6, "Option Acknowledgement"),
                ("Options", options(&o)),
            ]
        }
        None => vec![("Opcode", "malformed packet".to_string())],
    }
}

fn tftp_cells(raw: &[u8]) -> Option<Cells> {
    let field = |title: &str, value: String| (title.to_string(), value);
    let opcode = |n: u16, name: &str| field("OPCODE (2 B)", format!("{n} = {name}"));
    let options = |opts: &[(String, String)]| {
        let list: Vec<String> = opts.iter().map(|(n, v)| format!("{n}={v}")).collect();
        list.join(", ")
    };
    Some(match Packet::parse(raw)? {
        Packet::Rrq(r) | Packet::Wrq(r) => {
            let (n, name) = if raw.get(1) == Some(&1) {
                (1, "RRQ")
            } else {
                (2, "WRQ")
            };
            let rest = format!("{} {}", r.mode, options(&r.options));
            [
                opcode(n, name),
                field("FILENAME", shorten(&r.filename, 16)),
                field("MODE + OPTIONS", shorten(rest.trim(), 34)),
            ]
        }
        Packet::Data { block, data } => [
            opcode(3, "DATA"),
            field("BLOCK # (2 B)", block.to_string()),
            field("DATA (0-blksize B)", format!("{} bytes", data.len())),
        ],
        Packet::Ack { block } => [
            opcode(4, "ACK"),
            field("BLOCK # (2 B)", block.to_string()),
            field("(no payload)", "-".to_string()),
        ],
        Packet::Error { code, message } => [
            opcode(5, "ERROR"),
            field("ERROR CODE (2 B)", code.to_string()),
            field("MESSAGE", shorten(&message, 34)),
        ],
        Packet::Oack { options: o } => [
            opcode(6, "OACK"),
            field("OPTIONS", o.len().to_string()),
            field("NAME = VALUE", shorten(&options(&o), 34)),
        ],
    })
}

fn track_tftp(client: &mut ClientInfo, e: &MessageEvent) {
    let text = e.parsed.as_deref().unwrap_or_default();
    if let Some(file) = text.strip_prefix("Read Request, File: ") {
        client.transfer = Some(format!(
            "download {}",
            file.split(", ").next().unwrap_or(file)
        ));
    } else if let Some(file) = text.strip_prefix("Write Request, File: ") {
        client.transfer = Some(format!(
            "upload {}",
            file.split(", ").next().unwrap_or(file)
        ));
    }
    if e.kind == EventKind::Data && !text.contains("[retransmission]") {
        client.data_bytes += e.length.saturating_sub(4) as u64;
    }
    if text.contains("(last)") || text.starts_with("Error,") {
        client.connected = false;
    }
}
