use std::ops::Range;

use super::layers::{Field, Layer};

#[derive(Debug, Clone, Copy, Default)]
pub struct TlsHalf {
    pub left: usize,
    pub ccs: bool,
}

struct Record<'a> {
    start: usize,
    content_type: u8,
    version: u16,
    length: usize,
    body: &'a [u8],
    complete: bool,
    after_ccs: bool,
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn records<'a>(payload: &'a [u8], state: &mut TlsHalf) -> (usize, Vec<Record<'a>>) {
    let skip = state.left.min(payload.len());
    state.left -= skip;
    let mut pos = skip;
    let mut out = Vec::new();
    while pos + 5 <= payload.len() {
        let length = be16(payload, pos + 3) as usize;
        let end = pos + 5 + length;
        out.push(Record {
            start: pos,
            content_type: payload[pos],
            version: be16(payload, pos + 1),
            length,
            body: &payload[pos + 5..end.min(payload.len())],
            complete: end <= payload.len(),
            after_ccs: state.ccs,
        });
        if payload[pos] == 20 {
            state.ccs = true;
        }
        if end > payload.len() {
            state.left = end - payload.len();
            break;
        }
        pos = end;
    }
    (skip, out)
}

pub fn scan(payload: &[u8], state: &mut TlsHalf, version: &mut Option<u16>) -> String {
    let (skip, records) = records(payload, state);
    let mut names = Vec::new();
    for record in &records {
        for (kind, body) in handshakes(record) {
            if kind == 2
                && let Some(hello) = Hello::parse(&record.body[body], false)
            {
                *version = Some(hello.selected_version());
            }
        }
        names.extend(record_names(record));
    }
    if names.is_empty() && skip > 0 {
        return "Continuation Data".into();
    }
    names.join(", ")
}

pub fn protocol_name(version: Option<u16>) -> &'static str {
    match version {
        Some(0x0304) => "TLSv1.3",
        Some(0x0303) => "TLSv1.2",
        Some(0x0302) => "TLSv1.1",
        Some(0x0301) => "TLSv1",
        _ => "TLS",
    }
}

fn version_name(v: u16) -> String {
    let name = match v {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        _ => "Unknown",
    };
    format!("{name} (0x{v:04x})")
}

fn content_name(ct: u8) -> &'static str {
    match ct {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        24 => "Heartbeat",
        _ => "Unknown",
    }
}

fn handshake_name(kind: u8) -> &'static str {
    match kind {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        24 => "Key Update",
        _ => "Unknown Handshake Message",
    }
}

fn handshakes(record: &Record) -> Vec<(u8, Range<usize>)> {
    let mut out = Vec::new();
    if record.content_type != 22 || record.after_ccs {
        return out;
    }
    let b = record.body;
    let mut pos = 0;
    while pos + 4 <= b.len() {
        let len = u32::from_be_bytes([0, b[pos + 1], b[pos + 2], b[pos + 3]]) as usize;
        let end = (pos + 4 + len).min(b.len());
        out.push((b[pos], pos + 4..end));
        pos += 4 + len;
    }
    out
}

fn record_names(record: &Record) -> Vec<String> {
    match (record.content_type, record.after_ccs) {
        (21, true) => vec!["Encrypted Alert".into()],
        (22, true) => vec!["Encrypted Handshake Message".into()],
        (22, false) => handshakes(record)
            .into_iter()
            .map(|(kind, _)| handshake_name(kind).to_string())
            .collect(),
        (ct, _) => vec![content_name(ct).into()],
    }
}

struct Hello<'a> {
    version: u16,
    random: &'a [u8],
    session_id: &'a [u8],
    ciphers: Vec<u16>,
    extensions: Vec<(u16, &'a [u8])>,
}

impl<'a> Hello<'a> {
    fn parse(b: &'a [u8], client: bool) -> Option<Hello<'a>> {
        let mut c = Cursor { b, pos: 0 };
        let version = c.u16()?;
        let random = c.take(32)?;
        let sid_len = c.u8()? as usize;
        let session_id = c.take(sid_len)?;
        let ciphers = if client {
            let len = c.u16()? as usize;
            c.take(len)?.chunks(2).map(|p| be16(p, 0)).collect()
        } else {
            vec![c.u16()?]
        };
        let compression = if client { c.u8()? as usize } else { 1 };
        c.take(compression)?;
        let mut extensions = Vec::new();
        if let Some(len) = c.u16() {
            let mut e = Cursor {
                b: c.take(len as usize)?,
                pos: 0,
            };
            while let (Some(kind), Some(len)) = (e.u16(), e.u16()) {
                extensions.push((kind, e.take(len as usize)?));
            }
        }
        Some(Hello {
            version,
            random,
            session_id,
            ciphers,
            extensions,
        })
    }

    fn extension(&self, kind: u16) -> Option<&'a [u8]> {
        self.extensions
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, v)| *v)
    }

    fn selected_version(&self) -> u16 {
        match self.extension(43) {
            Some(v) if v.len() == 2 => be16(v, 0),
            _ => self.version,
        }
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.b.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(be16(self.take(2)?, 0))
    }
}

fn cipher_name(id: u16) -> String {
    let name = match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        _ => return format!("0x{id:04x}"),
    };
    format!("{name} (0x{id:04x})")
}

fn group_name(id: u16) -> String {
    match id {
        0x001d => "x25519".into(),
        0x0017 => "secp256r1".into(),
        0x0018 => "secp384r1".into(),
        0x11ec => "X25519MLKEM768".into(),
        _ => format!("0x{id:04x}"),
    }
}

fn extension_name(id: u16) -> String {
    match id {
        0 => "server_name".into(),
        10 => "supported_groups".into(),
        11 => "ec_point_formats".into(),
        13 => "signature_algorithms".into(),
        16 => "alpn".into(),
        21 => "padding".into(),
        22 => "encrypt_then_mac".into(),
        23 => "extended_master_secret".into(),
        35 => "session_ticket".into(),
        41 => "pre_shared_key".into(),
        43 => "supported_versions".into(),
        45 => "psk_key_exchange_modes".into(),
        49 => "post_handshake_auth".into(),
        51 => "key_share".into(),
        0xff01 => "renegotiation_info".into(),
        _ => format!("0x{id:04x}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn describe(payload: &[u8], mut state: TlsHalf, base: usize, protocol: &str) -> Vec<Layer> {
    let (skip, records) = records(payload, &mut state);
    let mut layers = Vec::new();
    if skip > 0 {
        layers.push(Layer {
            title: format!(
                "{protocol} Continuation Data ({skip} bytes of a record from an earlier segment)"
            ),
            range: base..base + skip,
            fields: Vec::new(),
        });
    }
    for r in &records {
        let at = base + r.start;
        let names = record_names(r).join(", ");
        let mut title = format!(
            "{protocol} Record Layer: {} Protocol: {names}",
            content_name(r.content_type)
        );
        if r.content_type == 23 || r.content_type == 20 {
            title = format!("{protocol} Record Layer: {names}");
        }
        if !r.complete {
            title += " [continues in the next segment]";
        }
        let mut fields = vec![
            Field::new(
                "Content Type",
                format!("{} ({})", content_name(r.content_type), r.content_type),
                Some(at..at + 1),
            ),
            Field::new("Version", version_name(r.version), Some(at + 1..at + 3)),
            Field::new("Length", r.length.to_string(), Some(at + 3..at + 5)),
        ];
        let body = at + 5..at + 5 + r.body.len();
        match r.content_type {
            23 => fields.push(Field::new(
                "Encrypted Application Data",
                format!(
                    "{}\u{2026} ({} bytes)",
                    hex(&r.body[..r.body.len().min(16)]),
                    r.body.len()
                ),
                Some(body),
            )),
            22 if r.after_ccs => fields.push(Field::new(
                "Encrypted Handshake Message",
                format!("{} bytes", r.body.len()),
                Some(body),
            )),
            22 => {
                for (kind, range) in handshakes(r) {
                    let start = at + 5 + range.start - 4;
                    fields.push(Field::new(
                        "Handshake Type",
                        format!("{} ({kind})", handshake_name(kind)),
                        Some(start..at + 5 + range.end),
                    ));
                    fields.push(Field::new(
                        "Handshake Length",
                        range.len().to_string(),
                        None,
                    ));
                    if kind == 1 || kind == 2 {
                        hello_fields(&r.body[range], kind == 1, &mut fields);
                    }
                }
            }
            _ => {}
        }
        layers.push(Layer {
            title,
            range: at..at + 5 + r.body.len(),
            fields,
        });
    }
    layers
}

fn hello_fields(body: &[u8], client: bool, fields: &mut Vec<Field>) {
    let Some(hello) = Hello::parse(body, client) else {
        return;
    };
    fields.push(Field::new("Version", version_name(hello.version), None));
    fields.push(Field::new("Random", hex(hello.random), None));
    fields.push(Field::new(
        "Session ID",
        match hello.session_id.len() {
            0 => "(empty)".into(),
            n => format!("{}\u{2026} ({n} bytes)", hex(&hello.session_id[..n.min(8)])),
        },
        None,
    ));
    if client {
        let names: Vec<String> = hello.ciphers.iter().map(|c| cipher_name(*c)).collect();
        fields.push(Field::new(
            &format!("Cipher Suites ({})", names.len()),
            names.join(", "),
            None,
        ));
    } else {
        fields.push(Field::new(
            "Cipher Suite",
            cipher_name(hello.ciphers[0]),
            None,
        ));
    }
    for (kind, data) in &hello.extensions {
        let value = match kind {
            0 if data.len() > 5 => format!("SNI = {}", String::from_utf8_lossy(&data[5..])),
            43 if client && !data.is_empty() => data[1..]
                .chunks(2)
                .filter(|p| p.len() == 2)
                .map(|p| version_name(be16(p, 0)))
                .collect::<Vec<_>>()
                .join(", "),
            43 if data.len() == 2 => version_name(be16(data, 0)),
            51 if !client && data.len() >= 2 => format!("group {}", group_name(be16(data, 0))),
            51 if data.len() >= 4 => format!("group {}", group_name(be16(data, 2))),
            _ => format!("{} bytes", data.len()),
        };
        fields.push(Field::new(
            &format!("Extension: {}", extension_name(*kind)),
            value,
            None,
        ));
    }
}
