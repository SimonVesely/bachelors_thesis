use std::ops::Range;

use crate::Direction;

use super::layers::{Field, Layer};

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SshHalf {
    pub banner: bool,
    pub encrypted: bool,
    pub left: usize,
}

enum Item {
    Continuation(Range<usize>),
    Banner(Range<usize>),
    Message {
        range: Range<usize>,
        length: u32,
        code: u8,
        complete: bool,
    },
    Encrypted(Range<usize>),
}

const KEXINIT_LISTS: [&str; 8] = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
];

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn walk(payload: &[u8], state: &mut SshHalf) -> Vec<Item> {
    let mut items = Vec::new();
    let mut pos = state.left.min(payload.len());
    state.left -= pos;
    if pos > 0 {
        items.push(Item::Continuation(0..pos));
    }
    if !state.banner && pos < payload.len() {
        let end = match payload[pos..].iter().position(|b| *b == b'\n') {
            Some(n) => {
                state.banner = true;
                pos + n + 1
            }
            None => payload.len(),
        };
        items.push(Item::Banner(pos..end));
        pos = end;
    }
    while pos < payload.len() {
        if state.encrypted || payload.len() - pos < 6 {
            items.push(Item::Encrypted(pos..payload.len()));
            break;
        }
        let length = be32(payload, pos);
        if !(5..=35000).contains(&length) {
            items.push(Item::Encrypted(pos..payload.len()));
            break;
        }
        let total = 4 + length as usize;
        let end = (pos + total).min(payload.len());
        state.left = pos + total - end;
        let code = payload[pos + 5];
        items.push(Item::Message {
            range: pos..end,
            length,
            code,
            complete: state.left == 0,
        });
        pos = end;
        if code == 21 {
            state.encrypted = true;
        }
    }
    items
}

pub fn message_name(code: u8) -> String {
    match code {
        1 => "Disconnect".into(),
        2 => "Ignore".into(),
        3 => "Unimplemented".into(),
        4 => "Debug".into(),
        5 => "Service Request".into(),
        6 => "Service Accept".into(),
        7 => "Extension Info".into(),
        20 => "Key Exchange Init".into(),
        21 => "New Keys".into(),
        30 => "Elliptic Curve Diffie-Hellman Key Exchange Init".into(),
        31 => "Elliptic Curve Diffie-Hellman Key Exchange Reply".into(),
        n => format!("Message Code {n}"),
    }
}

fn banner_text(payload: &[u8], range: &Range<usize>) -> String {
    String::from_utf8_lossy(&payload[range.clone()])
        .trim_end()
        .to_string()
}

pub fn scan(payload: &[u8], state: &mut SshHalf, direction: Direction) -> String {
    let side = match direction {
        Direction::ClientToServer => "Client",
        Direction::ServerToClient => "Server",
    };
    let parts: Vec<String> = walk(payload, state)
        .iter()
        .map(|item| match item {
            Item::Continuation(r) => format!("Continuation ({} bytes)", r.len()),
            Item::Banner(r) => format!("Protocol ({})", banner_text(payload, r)),
            Item::Message { code, .. } => message_name(*code),
            Item::Encrypted(r) => format!("Encrypted packet (len={})", r.len()),
        })
        .collect();
    format!("{side}: {}", parts.join(", "))
}

fn name_lists(body: &[u8], base: usize) -> Vec<Field> {
    let mut fields = Vec::new();
    let mut pos = 6 + 16;
    for label in KEXINIT_LISTS {
        let Some(len) = body.get(pos..pos + 4).map(|_| be32(body, pos) as usize) else {
            break;
        };
        let Some(list) = body.get(pos + 4..pos + 4 + len) else {
            break;
        };
        let range = base + pos..base + pos + 4 + len;
        let value = String::from_utf8_lossy(list).replace(',', ", ");
        fields.push(Field::new(label, value, Some(range)));
        pos += 4 + len;
    }
    fields
}

pub fn describe(payload: &[u8], mut state: SshHalf, base: usize) -> Vec<Layer> {
    walk(payload, &mut state)
        .into_iter()
        .map(|item| match item {
            Item::Continuation(r) => Layer {
                title: format!(
                    "SSH Continuation ({} bytes of a packet from an earlier segment)",
                    r.len()
                ),
                range: base + r.start..base + r.end,
                fields: Vec::new(),
            },
            Item::Banner(r) => {
                let text = banner_text(payload, &r);
                let range = base + r.start..base + r.end;
                Layer {
                    title: format!("SSH Protocol: {text}"),
                    range: range.clone(),
                    fields: vec![Field::new("Protocol", text, Some(range))],
                }
            }
            Item::Message {
                range,
                length,
                code,
                complete,
            } => {
                let at = base + range.start;
                let padding = payload[range.start + 4];
                let mut title = format!("SSH Version 2, Message: {}", message_name(code));
                if !complete {
                    title += " [continues in the next segment]";
                }
                let mut fields = vec![
                    Field::new("Packet Length", length.to_string(), Some(at..at + 4)),
                    Field::new("Padding Length", padding.to_string(), Some(at + 4..at + 5)),
                    Field::new(
                        "Message Code",
                        format!("{} ({code})", message_name(code)),
                        Some(at + 5..at + 6),
                    ),
                ];
                if code == 20 {
                    fields.extend(name_lists(&payload[range.clone()], at));
                }
                if code == 21 {
                    fields.push(Field::new(
                        "Note",
                        "keys are in use from now on, everything after this packet is encrypted"
                            .into(),
                        None,
                    ));
                }
                Layer {
                    title,
                    range: at..base + range.end,
                    fields,
                }
            }
            Item::Encrypted(r) => {
                let range = base + r.start..base + r.end;
                let preview: String = payload[r.start..r.end.min(r.start + 16)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                Layer {
                    title: format!("SSH Version 2, Encrypted packet (len={})", r.len()),
                    range: range.clone(),
                    fields: vec![
                        Field::new(
                            "Encrypted Packet",
                            format!("{preview}\u{2026} ({} bytes)", r.len()),
                            Some(range),
                        ),
                        Field::new(
                            "Note",
                            "SSH session keys never leave the server, so this can't be decrypted - the event log shows the SFTP content".into(),
                            None,
                        ),
                    ],
                }
            }
        })
        .collect()
}
