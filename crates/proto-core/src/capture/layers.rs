use std::ops::Range;
use std::time::UNIX_EPOCH;

use crate::Direction;

use super::decrypt::{alert_name, handshake_messages};
use super::dissect::{ACK, App, Headers, LinkLayer, Packet, TcpOption, Transport, flag_names};
use super::tftp::{Tftp, error_name};
use super::tls;

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub label: String,
    pub value: String,
    pub range: Option<Range<usize>>,
}

impl Field {
    pub fn new(label: &str, value: String, range: Option<Range<usize>>) -> Self {
        Field {
            label: label.to_string(),
            value,
            range,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Layer {
    pub title: String,
    pub range: Range<usize>,
    pub fields: Vec<Field>,
}

pub fn layers(p: &Packet, number: usize) -> Vec<Layer> {
    let Some(h) = p.headers() else {
        return vec![frame_layer(p, number, "unknown")];
    };
    let mut out = vec![frame_layer(p, number, &protocol_chain(p, &h))];
    out.extend(link_layer(&h));
    out.push(ip_layer(&h));
    out.push(transport_layer(p, &h));
    let base = h.payload.start;
    let payload = &p.data[h.payload.clone()];
    match p.app {
        App::Tcp => {}
        App::Ftp => out.push(ftp_layer(payload, base, p.direction)),
        App::FtpData => out.push(Layer {
            title: format!("FTP Data ({} bytes data)", payload.len()),
            range: h.payload.clone(),
            fields: vec![Field::new(
                "Data",
                preview(payload),
                Some(h.payload.clone()),
            )],
        }),
        App::Tls => out.extend(tls::describe(payload, p.tls, base, &p.protocol)),
        App::Tftp => out.push(tftp_layer(payload, base)),
    }
    out
}

fn protocol_chain(p: &Packet, h: &Headers) -> String {
    let link = match h.link {
        LinkLayer::Ethernet { .. } => "eth:ethertype:",
        LinkLayer::Loopback { .. } => "null:",
        LinkLayer::LinuxCooked => "sll:",
        LinkLayer::RawIp => "raw:",
    };
    let l4 = match h.transport {
        Transport::Tcp(_) => "tcp",
        Transport::Udp(_) => "udp",
    };
    let app = match p.app {
        App::Tcp => "",
        App::Ftp => ":ftp",
        App::FtpData => ":ftp-data",
        App::Tls => ":tls",
        App::Tftp => ":tftp",
    };
    format!("{link}ip:{l4}{app}")
}

fn frame_layer(p: &Packet, number: usize, chain: &str) -> Layer {
    let epoch = p.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
    let encapsulation = match p.linktype {
        1 => "Ethernet (1)",
        0 => "BSD loopback (0)",
        108 => "OpenBSD loopback (108)",
        113 | 276 => "Linux cooked capture",
        _ => "Raw IP",
    };
    Layer {
        title: format!(
            "Frame {number}: {} bytes on wire, {} bytes captured on {}",
            p.wire_len,
            p.data.len(),
            p.interface
        ),
        range: 0..p.data.len(),
        fields: vec![
            Field::new("Interface", p.interface.to_string(), None),
            Field::new("Encapsulation type", encapsulation.into(), None),
            Field::new(
                "Epoch arrival time",
                format!("{:.6}", epoch.as_secs_f64()),
                None,
            ),
            Field::new("Frame length", format!("{} bytes", p.wire_len), None),
            Field::new("Capture length", format!("{} bytes", p.data.len()), None),
            Field::new("Protocols in frame", chain.into(), None),
        ],
    }
}

fn mac(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn link_layer(h: &Headers) -> Option<Layer> {
    match &h.link {
        LinkLayer::Ethernet {
            dst,
            src,
            ethertype,
        } => Some(Layer {
            title: format!("Ethernet II, Src: {}, Dst: {}", mac(src), mac(dst)),
            range: 0..h.ip_start,
            fields: vec![
                Field::new("Destination", mac(dst), Some(0..6)),
                Field::new("Source", mac(src), Some(6..12)),
                Field::new(
                    "Type",
                    format!("IPv4 (0x{ethertype:04x})"),
                    Some(h.ip_start - 2..h.ip_start),
                ),
            ],
        }),
        LinkLayer::Loopback { family } => Some(Layer {
            title: "Null/Loopback".into(),
            range: 0..4,
            fields: vec![Field::new("Family", format!("IP ({family})"), Some(0..4))],
        }),
        LinkLayer::LinuxCooked => Some(Layer {
            title: "Linux cooked capture".into(),
            range: 0..h.ip_start,
            fields: Vec::new(),
        }),
        LinkLayer::RawIp => None,
    }
}

fn ip_layer(h: &Headers) -> Layer {
    let ip = &h.ip;
    let i = h.ip_start;
    let mut flags = Vec::new();
    if ip.flags & 0b010 != 0 {
        flags.push("Don't fragment");
    }
    if ip.flags & 0b001 != 0 {
        flags.push("More fragments");
    }
    let protocol = match ip.protocol {
        6 => "TCP",
        17 => "UDP",
        _ => "Unknown",
    };
    Layer {
        title: format!(
            "Internet Protocol Version 4, Src: {}, Dst: {}",
            ip.src, ip.dst
        ),
        range: i..i + ip.header_len,
        fields: vec![
            Field::new("Version", "4".into(), Some(i..i + 1)),
            Field::new(
                "Header Length",
                format!("{} bytes ({})", ip.header_len, ip.header_len / 4),
                Some(i..i + 1),
            ),
            Field::new(
                "Differentiated Services",
                format!("0x{:02x}", ip.tos),
                Some(i + 1..i + 2),
            ),
            Field::new("Total Length", ip.total_len.to_string(), Some(i + 2..i + 4)),
            Field::new(
                "Identification",
                format!("0x{:04x} ({})", ip.id, ip.id),
                Some(i + 4..i + 6),
            ),
            Field::new(
                "Flags",
                format!("0x{:x} {}", ip.flags, flags.join(", ")),
                Some(i + 6..i + 7),
            ),
            Field::new(
                "Fragment Offset",
                ip.frag_offset.to_string(),
                Some(i + 6..i + 8),
            ),
            Field::new("Time to Live", ip.ttl.to_string(), Some(i + 8..i + 9)),
            Field::new(
                "Protocol",
                format!("{protocol} ({})", ip.protocol),
                Some(i + 9..i + 10),
            ),
            Field::new(
                "Header Checksum",
                format!("0x{:04x} [validation disabled]", ip.checksum),
                Some(i + 10..i + 12),
            ),
            Field::new("Source Address", ip.src.to_string(), Some(i + 12..i + 16)),
            Field::new(
                "Destination Address",
                ip.dst.to_string(),
                Some(i + 16..i + 20),
            ),
        ],
    }
}

fn transport_layer(p: &Packet, h: &Headers) -> Layer {
    let t = h.l4_start;
    let len = h.payload.len();
    match &h.transport {
        Transport::Udp(udp) => Layer {
            title: format!(
                "User Datagram Protocol, Src Port: {}, Dst Port: {}",
                udp.src_port, udp.dst_port
            ),
            range: t..t + 8,
            fields: vec![
                Field::new("Source Port", udp.src_port.to_string(), Some(t..t + 2)),
                Field::new(
                    "Destination Port",
                    udp.dst_port.to_string(),
                    Some(t + 2..t + 4),
                ),
                Field::new("Length", udp.length.to_string(), Some(t + 4..t + 6)),
                Field::new(
                    "Checksum",
                    format!("0x{:04x} [unverified]", udp.checksum),
                    Some(t + 6..t + 8),
                ),
                Field::new(
                    "UDP payload",
                    format!("{len} bytes"),
                    Some(h.payload.clone()),
                ),
            ],
        },
        Transport::Tcp(tcp) => {
            let ack = tcp.flags & ACK != 0;
            let mut title = format!(
                "Transmission Control Protocol, Src Port: {}, Dst Port: {}, Seq: {}",
                tcp.src_port, tcp.dst_port, p.rel_seq
            );
            if ack {
                title += &format!(", Ack: {}", p.rel_ack);
            }
            title += &format!(", Len: {len}");
            let options: Vec<String> = tcp.options.iter().map(option_name).collect();
            let mut fields = vec![
                Field::new("Source Port", tcp.src_port.to_string(), Some(t..t + 2)),
                Field::new(
                    "Destination Port",
                    tcp.dst_port.to_string(),
                    Some(t + 2..t + 4),
                ),
                Field::new(
                    "[Stream index]",
                    p.stream.map_or("-".into(), |s| s.to_string()),
                    None,
                ),
                Field::new("[TCP Segment Len]", len.to_string(), None),
                Field::new(
                    "Sequence Number",
                    format!("{} (relative sequence number)", p.rel_seq),
                    Some(t + 4..t + 8),
                ),
                Field::new(
                    "Sequence Number (raw)",
                    tcp.seq.to_string(),
                    Some(t + 4..t + 8),
                ),
                Field::new(
                    "Acknowledgment Number",
                    match ack {
                        true => format!("{} (relative ack number)", p.rel_ack),
                        false => "0".into(),
                    },
                    Some(t + 8..t + 12),
                ),
                Field::new(
                    "Acknowledgment number (raw)",
                    tcp.ack.to_string(),
                    Some(t + 8..t + 12),
                ),
                Field::new(
                    "Header Length",
                    format!("{} bytes ({})", tcp.header_len, tcp.header_len / 4),
                    Some(t + 12..t + 13),
                ),
                Field::new(
                    "Flags",
                    format!("0x{:03x} ({})", tcp.flags, flag_names(tcp.flags)),
                    Some(t + 12..t + 14),
                ),
                Field::new("Window", tcp.window.to_string(), Some(t + 14..t + 16)),
                Field::new("[Calculated window size]", p.window.to_string(), None),
                Field::new(
                    "Checksum",
                    format!("0x{:04x} [unverified]", tcp.checksum),
                    Some(t + 16..t + 18),
                ),
                Field::new(
                    "Urgent Pointer",
                    tcp.urgent.to_string(),
                    Some(t + 18..t + 20),
                ),
            ];
            if !options.is_empty() {
                fields.push(Field::new(
                    &format!("Options ({} bytes)", tcp.header_len - 20),
                    options.join(", "),
                    Some(t + 20..t + tcp.header_len),
                ));
            }
            if let Some(note) = p.analysis {
                fields.push(Field::new("[SEQ/ACK analysis]", note.into(), None));
            }
            if len > 0 {
                fields.push(Field::new(
                    "TCP payload",
                    format!("{len} bytes"),
                    Some(h.payload.clone()),
                ));
            }
            Layer {
                title,
                range: t..t + tcp.header_len,
                fields,
            }
        }
    }
}

fn option_name(o: &TcpOption) -> String {
    match o {
        TcpOption::Nop => "NOP".into(),
        TcpOption::Mss(v) => format!("MSS {v}"),
        TcpOption::WindowScale(s) => format!("Window scale {s} (multiply by {})", 1u32 << s),
        TcpOption::SackPermitted => "SACK permitted".into(),
        TcpOption::Sack(n) => format!("SACK ({n} blocks)"),
        TcpOption::Timestamps(a, b) => format!("Timestamps TSval {a}, TSecr {b}"),
        TcpOption::Other(k) => format!("Option {k}"),
    }
}

fn ftp_layer(payload: &[u8], base: usize, direction: Direction) -> Layer {
    let mut fields = Vec::new();
    let mut offset = base;
    for raw in payload.split_inclusive(|b| *b == b'\n') {
        let range = Some(offset..offset + raw.len());
        offset += raw.len();
        let line = String::from_utf8_lossy(raw).trim_end().to_string();
        if line.is_empty() {
            continue;
        }
        let (head, arg) = line.split_once(' ').unwrap_or((&line, ""));
        match direction {
            Direction::ClientToServer => {
                fields.push(Field::new(
                    "Request command",
                    head.to_string(),
                    range.clone(),
                ));
                if !arg.is_empty() {
                    fields.push(Field::new("Request arg", arg.to_string(), range));
                }
            }
            Direction::ServerToClient => {
                let code = head.get(..3).unwrap_or(head);
                let code = match reply_meaning(code) {
                    Some(meaning) => format!("{code} ({meaning})"),
                    None => code.to_string(),
                };
                fields.push(Field::new("Response code", code, range.clone()));
                let rest = line.get(4..).unwrap_or("");
                if !rest.is_empty() {
                    fields.push(Field::new("Response arg", rest.to_string(), range));
                }
            }
        }
    }
    Layer {
        title: "File Transfer Protocol (FTP)".into(),
        range: base..base + payload.len(),
        fields,
    }
}

fn reply_meaning(code: &str) -> Option<&'static str> {
    Some(match code {
        "150" => "File status okay; about to open data connection",
        "200" => "Command okay",
        "211" => "System status",
        "213" => "File status",
        "215" => "NAME system type",
        "220" => "Service ready for new user",
        "221" => "Service closing control connection",
        "226" => "Closing data connection",
        "227" => "Entering Passive Mode",
        "229" => "Entering Extended Passive Mode",
        "230" => "User logged in, proceed",
        "234" => "AUTH accepted",
        "250" => "Requested file action okay, completed",
        "257" => "PATHNAME created",
        "331" => "User name okay, need password",
        "350" => "Requested file action pending further information",
        "425" => "Can't open data connection",
        "500" => "Syntax error, command unrecognized",
        "502" => "Command not implemented",
        "530" => "Not logged in",
        "550" => "Requested action not taken: file unavailable",
        _ => return None,
    })
}

fn preview(data: &[u8]) -> String {
    let shown = &data[..data.len().min(48)];
    let text = shown
        .iter()
        .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace());
    let body = match text {
        true => String::from_utf8_lossy(shown).replace(['\r', '\n'], " "),
        false => shown.iter().map(|b| format!("{b:02x}")).collect(),
    };
    match data.len() > shown.len() {
        true => format!("{body}\u{2026}"),
        false => body,
    }
}

fn tftp_layer(payload: &[u8], base: usize) -> Layer {
    let b = base;
    let opcode = |name: &str, n: u16| Field::new("Opcode", format!("{name} ({n})"), Some(b..b + 2));
    let options = |opts: &[(String, String)]| {
        opts.iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let fields = match Tftp::parse(payload) {
        Some(Tftp::Request { read, request: r }) => {
            let name_end = b + 2 + r.filename.len() + 1;
            let mut fields = vec![
                if read {
                    opcode("Read Request", 1)
                } else {
                    opcode("Write Request", 2)
                },
                Field::new("Source File", r.filename.clone(), Some(b + 2..name_end)),
                Field::new(
                    "Type",
                    r.mode.clone(),
                    Some(name_end..name_end + r.mode.len() + 1),
                ),
            ];
            if !r.options.is_empty() {
                fields.push(Field::new("Options", options(&r.options), None));
            }
            fields
        }
        Some(Tftp::Data { block, data }) => vec![
            opcode("Data Packet", 3),
            Field::new("Block", block.to_string(), Some(b + 2..b + 4)),
            Field::new(
                "Data",
                format!("{} bytes", data.len()),
                Some(b + 4..b + payload.len()),
            ),
        ],
        Some(Tftp::Ack { block }) => vec![
            opcode("Acknowledgement", 4),
            Field::new("Block", block.to_string(), Some(b + 2..b + 4)),
        ],
        Some(Tftp::Error { code, message }) => vec![
            opcode("Error Code", 5),
            Field::new(
                "Error code",
                format!("{} ({code})", error_name(code)),
                Some(b + 2..b + 4),
            ),
            Field::new("Error message", message, Some(b + 4..b + payload.len())),
        ],
        Some(Tftp::Oack { options: o }) => vec![
            opcode("Option Acknowledgement", 6),
            Field::new("Options", options(&o), Some(b + 2..b + payload.len())),
        ],
        None => vec![Field::new(
            "Malformed",
            format!("{} bytes", payload.len()),
            None,
        )],
    };
    Layer {
        title: "Trivial File Transfer Protocol".into(),
        range: b..b + payload.len(),
        fields,
    }
}

pub fn decrypted_layers(p: &Packet) -> Vec<Layer> {
    let range = p.headers().map_or(0..0, |h| h.payload);
    p.decrypted
        .iter()
        .map(|plain| {
            let ct = plain.content_type;
            let mut fields = vec![
                Field::new(
                    "Decrypted with",
                    format!("{} (record #{})", plain.secret, plain.seq),
                    None,
                ),
                Field::new(
                    "Inner content type",
                    format!("{} ({ct})", tls::content_name(ct)),
                    None,
                ),
                Field::new(
                    "Plaintext length",
                    format!("{} bytes", plain.data.len()),
                    None,
                ),
            ];
            let summary = match ct {
                22 => {
                    let messages = handshake_messages(&plain.data);
                    for (kind, body) in &messages {
                        fields.push(Field::new(
                            "Handshake message",
                            format!("{} ({} bytes)", tls::handshake_name(*kind), body.len()),
                            None,
                        ));
                    }
                    let names: Vec<&str> = messages
                        .iter()
                        .map(|(k, _)| tls::handshake_name(*k))
                        .collect();
                    names.join(", ")
                }
                21 => {
                    let level = match plain.data.first() {
                        Some(2) => "fatal",
                        _ => "warning",
                    };
                    fields.push(Field::new("Alert level", level.into(), None));
                    fields.push(Field::new(
                        "Alert description",
                        alert_name(&plain.data),
                        None,
                    ));
                    format!("Alert: {}", alert_name(&plain.data))
                }
                23 if p.control => {
                    let ftp = ftp_layer(&plain.data, 0, p.direction);
                    fields.extend(ftp.fields.into_iter().map(|f| Field { range: None, ..f }));
                    "File Transfer Protocol (FTP)".into()
                }
                23 => {
                    fields.push(Field::new("Data", preview(&plain.data), None));
                    format!("FTP Data ({} bytes)", plain.data.len())
                }
                _ => tls::content_name(ct).into(),
            };
            Layer {
                title: format!("Decrypted TLS Record: {summary}"),
                range: range.clone(),
                fields,
            }
        })
        .collect()
}
