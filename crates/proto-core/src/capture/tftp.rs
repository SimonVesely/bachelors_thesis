pub struct Request {
    pub filename: String,
    pub mode: String,
    pub options: Vec<(String, String)>,
}

pub enum Tftp<'a> {
    Request { read: bool, request: Request },
    Data { block: u16, data: &'a [u8] },
    Ack { block: u16 },
    Error { code: u16, message: String },
    Oack { options: Vec<(String, String)> },
}

impl<'a> Tftp<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Tftp<'a>> {
        let opcode = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
        let body = &b[2..];
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
                Tftp::Request {
                    read: opcode == 1,
                    request,
                }
            }
            3 => Tftp::Data {
                block: number()?,
                data: &body[2..],
            },
            4 => Tftp::Ack { block: number()? },
            5 => {
                let text = body.get(2..)?;
                let text = text.strip_suffix(&[0]).unwrap_or(text);
                let message = String::from_utf8_lossy(text).into_owned();
                Tftp::Error {
                    code: number()?,
                    message,
                }
            }
            6 => Tftp::Oack {
                options: pairs(strings(body)?)?,
            },
            _ => return None,
        })
    }

    pub fn summary(&self) -> String {
        let opts = |o: &[(String, String)]| {
            o.iter()
                .map(|(n, v)| format!(", {n}={v}"))
                .collect::<String>()
        };
        match self {
            Tftp::Request { read, request: r } => {
                let kind = if *read { "Read" } else { "Write" };
                let options = opts(&r.options);
                format!(
                    "{kind} Request, File: {}, Mode: {}{options}",
                    r.filename, r.mode
                )
            }
            Tftp::Data { block, data } => {
                format!("Data Packet, Block: {block} ({} bytes)", data.len())
            }
            Tftp::Ack { block } => format!("Acknowledgement, Block: {block}"),
            Tftp::Error { code, message } => {
                format!(
                    "Error, Code: {code} ({}), Message: {message}",
                    error_name(*code)
                )
            }
            Tftp::Oack { options } => format!("Option Acknowledgement{}", opts(options)),
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
