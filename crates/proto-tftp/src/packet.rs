pub const NOT_DEFINED: u16 = 0;
pub const FILE_NOT_FOUND: u16 = 1;
pub const ACCESS_VIOLATION: u16 = 2;
pub const ILLEGAL_OPERATION: u16 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub filename: String,
    pub mode: String,
    pub options: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Rrq(Request),
    Wrq(Request),
    Data { block: u16, data: Vec<u8> },
    Ack { block: u16 },
    Error { code: u16, message: String },
    Oack { options: Vec<(String, String)> },
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Option<Packet> {
        let opcode = u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]);
        let body = &bytes[2..];
        let number = || Some(u16::from_be_bytes([*body.first()?, *body.get(1)?]));

        Some(match opcode {
            1 | 2 => {
                let mut fields = strings(body)?.into_iter();
                let filename = fields.next().filter(|f| !f.is_empty())?;
                let mode = fields.next()?.to_ascii_lowercase();
                let options = pairs(fields.collect())?;
                let request = Request {
                    filename,
                    mode,
                    options,
                };
                match opcode {
                    1 => Packet::Rrq(request),
                    _ => Packet::Wrq(request),
                }
            }
            3 => Packet::Data {
                block: number()?,
                data: body[2..].to_vec(),
            },
            4 => Packet::Ack { block: number()? },
            5 => {
                let text = body[2..].strip_suffix(&[0]).unwrap_or(&body[2..]);
                let message = String::from_utf8_lossy(text).into_owned();
                Packet::Error {
                    code: number()?,
                    message,
                }
            }
            6 => Packet::Oack {
                options: pairs(strings(body)?)?,
            },
            _ => return None,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Packet::Rrq(r) | Packet::Wrq(r) => {
                let opcode: u16 = if matches!(self, Packet::Rrq(_)) { 1 } else { 2 };
                out.extend(opcode.to_be_bytes());
                push(&mut out, &r.filename);
                push(&mut out, &r.mode);
                push_pairs(&mut out, &r.options);
            }
            Packet::Data { block, data } => {
                out.extend(3u16.to_be_bytes());
                out.extend(block.to_be_bytes());
                out.extend_from_slice(data);
            }
            Packet::Ack { block } => {
                out.extend(4u16.to_be_bytes());
                out.extend(block.to_be_bytes());
            }
            Packet::Error { code, message } => {
                out.extend(5u16.to_be_bytes());
                out.extend(code.to_be_bytes());
                push(&mut out, message);
            }
            Packet::Oack { options } => {
                out.extend(6u16.to_be_bytes());
                push_pairs(&mut out, options);
            }
        }
        out
    }

    pub fn summary(&self) -> String {
        let options = |o: &[(String, String)]| {
            o.iter()
                .map(|(n, v)| format!(", {n}={v}"))
                .collect::<String>()
        };
        match self {
            Packet::Rrq(r) | Packet::Wrq(r) => {
                let kind = if matches!(self, Packet::Rrq(_)) {
                    "Read"
                } else {
                    "Write"
                };
                let (file, mode, opts) = (&r.filename, &r.mode, options(&r.options));
                format!("{kind} Request, File: {file}, Mode: {mode}{opts}")
            }
            Packet::Data { block, data } => {
                format!("Data Packet, Block: {block} ({} bytes)", data.len())
            }
            Packet::Ack { block } => format!("Acknowledgement, Block: {block}"),
            Packet::Error { code, message } => format!(
                "Error, Code: {code} ({}), Message: {message}",
                error_name(*code)
            ),
            Packet::Oack { options: o } => format!("Option Acknowledgement{}", options(o)),
        }
    }
}

pub fn error_name(code: u16) -> &'static str {
    match code {
        0 => "Not defined",
        1 => "File not found",
        2 => "Access violation",
        3 => "Disk full",
        4 => "Illegal operation",
        5 => "Unknown transfer ID",
        6 => "File already exists",
        7 => "No such user",
        8 => "Option negotiation failed",
        _ => "Unknown",
    }
}

fn strings(body: &[u8]) -> Option<Vec<String>> {
    if body.is_empty() {
        return Some(Vec::new());
    }
    let mut fields: Vec<String> = body
        .strip_suffix(&[0])?
        .split(|b| *b == 0)
        .map(|f| String::from_utf8_lossy(f).into_owned())
        .collect();
    while fields.len() > 2 && fields.last().is_some_and(String::is_empty) {
        fields.pop();
    }
    Some(fields)
}

fn pairs(fields: Vec<String>) -> Option<Vec<(String, String)>> {
    if !fields.len().is_multiple_of(2) {
        return None;
    }
    Some(
        fields
            .chunks(2)
            .map(|p| (p[0].clone(), p[1].clone()))
            .collect(),
    )
}

fn push(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

fn push_pairs(out: &mut Vec<u8>, pairs: &[(String, String)]) {
    for (name, value) in pairs {
        push(out, name);
        push(out, value);
    }
}
