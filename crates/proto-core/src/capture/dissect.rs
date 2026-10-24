use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::time::SystemTime;

use crate::{Direction, Protocol};

use super::tls::{self, TlsHalf};
use super::{CaptureConfig, RawFrame, tftp};

pub const FIN: u16 = 0x001;
pub const SYN: u16 = 0x002;
pub const ACK: u16 = 0x010;
const FLAG_NAMES: [&str; 9] = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "AE"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum App {
    Tcp,
    Ftp,
    FtpData,
    Tls,
    Tftp,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: SystemTime,
    pub linktype: i32,
    pub data: Vec<u8>,
    pub wire_len: u32,
    pub interface: Arc<str>,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub direction: Direction,
    pub app: App,
    pub protocol: String,
    pub info: String,
    pub stream: Option<usize>,
    pub tcp_flags: u16,
    pub rel_seq: u32,
    pub rel_ack: u32,
    pub window: u32,
    pub analysis: Option<&'static str>,
    pub tls: TlsHalf,
}

impl Packet {
    pub fn headers(&self) -> Option<Headers> {
        parse_headers(self.linktype, &self.data)
    }

    pub fn payload(&self) -> &[u8] {
        match self.headers() {
            Some(h) => &self.data[h.payload],
            None => &[],
        }
    }
}

#[derive(Debug, Clone)]
pub enum LinkLayer {
    Ethernet {
        dst: [u8; 6],
        src: [u8; 6],
        ethertype: u16,
    },
    Loopback {
        family: u32,
    },
    LinuxCooked,
    RawIp,
}

#[derive(Debug, Clone)]
pub struct Ipv4 {
    pub header_len: usize,
    pub tos: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags: u8,
    pub frag_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub enum TcpOption {
    Nop,
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(usize),
    Timestamps(u32, u32),
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct Tcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_len: usize,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub options: Vec<TcpOption>,
}

#[derive(Debug, Clone)]
pub struct Udp {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub enum Transport {
    Tcp(Tcp),
    Udp(Udp),
}

#[derive(Debug, Clone)]
pub struct Headers {
    pub link: LinkLayer,
    pub ip: Ipv4,
    pub transport: Transport,
    pub ip_start: usize,
    pub l4_start: usize,
    pub payload: Range<usize>,
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn parse_headers(linktype: i32, data: &[u8]) -> Option<Headers> {
    let (link, ip_start) = match linktype {
        1 => {
            let mut at = 12;
            if data.len() >= 18 && be16(data, 12) == 0x8100 {
                at = 16;
            }
            let ethertype = be16(data.get(..at + 2)?, at);
            let dst = data[0..6].try_into().ok()?;
            let src = data[6..12].try_into().ok()?;
            (
                LinkLayer::Ethernet {
                    dst,
                    src,
                    ethertype,
                },
                at + 2,
            )
        }
        0 | 108 => {
            let raw: [u8; 4] = data.get(..4)?.try_into().ok()?;
            let family = match linktype {
                108 => u32::from_be_bytes(raw),
                _ => u32::from_ne_bytes(raw),
            };
            (LinkLayer::Loopback { family }, 4)
        }
        113 => (LinkLayer::LinuxCooked, 16),
        276 => (LinkLayer::LinuxCooked, 20),
        12 | 14 | 101 => (LinkLayer::RawIp, 0),
        _ => return None,
    };

    let ip = data.get(ip_start..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let header_len = (ip[0] & 0x0f) as usize * 4;
    let total_len = be16(ip, 2);
    let frag = be16(ip, 6);
    let ipv4 = Ipv4 {
        header_len,
        tos: ip[1],
        total_len,
        id: be16(ip, 4),
        flags: (frag >> 13) as u8,
        frag_offset: frag & 0x1fff,
        ttl: ip[8],
        protocol: ip[9],
        checksum: be16(ip, 10),
        src: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
    };
    if ipv4.frag_offset != 0 || header_len < 20 {
        return None;
    }
    let end = (ip_start + total_len as usize).min(data.len());
    let l4_start = ip_start + header_len;
    let l4 = data.get(l4_start..end)?;

    let (transport, payload_start) = match ipv4.protocol {
        6 if l4.len() >= 20 => {
            let header_len = (l4[12] >> 4) as usize * 4;
            let tcp = Tcp {
                src_port: be16(l4, 0),
                dst_port: be16(l4, 2),
                seq: be32(l4, 4),
                ack: be32(l4, 8),
                header_len,
                flags: be16(l4, 12) & 0x01ff,
                window: be16(l4, 14),
                checksum: be16(l4, 16),
                urgent: be16(l4, 18),
                options: tcp_options(l4.get(20..header_len).unwrap_or_default()),
            };
            (Transport::Tcp(tcp), l4_start + header_len)
        }
        17 if l4.len() >= 8 => {
            let udp = Udp {
                src_port: be16(l4, 0),
                dst_port: be16(l4, 2),
                length: be16(l4, 4),
                checksum: be16(l4, 6),
            };
            (Transport::Udp(udp), l4_start + 8)
        }
        _ => return None,
    };

    Some(Headers {
        link,
        ip: ipv4,
        transport,
        ip_start,
        l4_start,
        payload: payload_start.min(end)..end,
    })
}

fn tcp_options(mut b: &[u8]) -> Vec<TcpOption> {
    let mut options = Vec::new();
    while let Some(&kind) = b.first() {
        if kind == 0 {
            break;
        }
        if kind == 1 {
            options.push(TcpOption::Nop);
            b = &b[1..];
            continue;
        }
        let len = *b.get(1).unwrap_or(&0) as usize;
        if len < 2 || len > b.len() {
            break;
        }
        let body = &b[2..len];
        options.push(match (kind, body.len()) {
            (2, 2) => TcpOption::Mss(be16(body, 0)),
            (3, 1) => TcpOption::WindowScale(body[0]),
            (4, 0) => TcpOption::SackPermitted,
            (5, n) => TcpOption::Sack(n / 8),
            (8, 8) => TcpOption::Timestamps(be32(body, 0), be32(body, 4)),
            _ => TcpOption::Other(kind),
        });
        b = &b[len..];
    }
    options
}

pub fn flag_names(flags: u16) -> String {
    let names: Vec<&str> = (0..9)
        .filter(|bit| flags & (1 << bit) != 0)
        .map(|bit| FLAG_NAMES[bit])
        .collect();
    names.join(", ")
}

#[derive(Default)]
struct Half {
    isn: Option<u32>,
    next_seq: Option<u32>,
    win_scale: Option<u8>,
    tls: TlsHalf,
}

struct Stream {
    index: usize,
    control: bool,
    tls: bool,
    tls_version: Option<u16>,
    seen_payload: bool,
    halves: [Half; 2],
}

pub struct Dissector {
    cfg: CaptureConfig,
    streams: HashMap<(SocketAddr, SocketAddr), Stream>,
    next_stream: usize,
    control_clients: HashSet<IpAddr>,
    tftp_clients: HashSet<SocketAddr>,
}

impl Dissector {
    pub fn new(cfg: CaptureConfig) -> Self {
        Dissector {
            cfg,
            streams: HashMap::new(),
            next_stream: 0,
            control_clients: HashSet::new(),
            tftp_clients: HashSet::new(),
        }
    }

    pub fn dissect(&mut self, frame: RawFrame) -> Option<Packet> {
        let h = parse_headers(frame.linktype, &frame.data)?;
        let src = SocketAddr::new(IpAddr::V4(h.ip.src), port(&h.transport, true));
        let dst = SocketAddr::new(IpAddr::V4(h.ip.dst), port(&h.transport, false));
        let payload = &frame.data[h.payload.clone()];

        let mut packet = Packet {
            timestamp: frame.timestamp,
            linktype: frame.linktype,
            data: Vec::new(),
            wire_len: frame.wire_len,
            interface: frame.interface.clone(),
            src,
            dst,
            direction: Direction::ClientToServer,
            app: App::Tcp,
            protocol: String::new(),
            info: String::new(),
            stream: None,
            tcp_flags: 0,
            rel_seq: 0,
            rel_ack: 0,
            window: 0,
            analysis: None,
            tls: TlsHalf::default(),
        };
        let kept = match &h.transport {
            Transport::Tcp(tcp) => self.tcp(&mut packet, tcp, payload),
            Transport::Udp(_) => self.udp(&mut packet, payload),
        };
        kept.then_some(Packet {
            data: frame.data,
            ..packet
        })
    }

    fn is_server(&self, addr: SocketAddr) -> bool {
        self.cfg.ports.contains(&addr.port())
            && (self.cfg.server_ip.is_unspecified() || addr.ip() == self.cfg.server_ip)
    }

    fn classify(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        flags: u16,
    ) -> Option<(SocketAddr, SocketAddr)> {
        if self.streams.contains_key(&(src, dst)) {
            return Some((src, dst));
        }
        if self.streams.contains_key(&(dst, src)) {
            return Some((dst, src));
        }
        let (client, server) = if self.is_server(dst) {
            (src, dst)
        } else if self.is_server(src)
            || (flags & (SYN | ACK) == SYN && self.control_clients.contains(&dst.ip()))
        {
            (dst, src)
        } else {
            return None;
        };
        let control = server.port() == self.cfg.ports[0];
        if control {
            self.control_clients.insert(client.ip());
        }
        self.streams.insert(
            (client, server),
            Stream {
                index: self.next_stream,
                control,
                tls: false,
                tls_version: None,
                seen_payload: false,
                halves: Default::default(),
            },
        );
        self.next_stream += 1;
        Some((client, server))
    }

    fn tcp(&mut self, p: &mut Packet, tcp: &Tcp, payload: &[u8]) -> bool {
        if self.cfg.protocol == Protocol::Tftp {
            return false;
        }
        let Some((client, server)) = self.classify(p.src, p.dst, tcp.flags) else {
            return false;
        };
        let old_isn = self.streams[&(client, server)].halves[0].isn;
        if tcp.flags & (SYN | ACK) == SYN && old_isn.is_some_and(|isn| isn != tcp.seq) {
            self.streams.remove(&(client, server));
            self.classify(p.src, p.dst, tcp.flags);
        }
        let stream = self.streams.get_mut(&(client, server)).expect("classified");
        let (me, other) = if p.src == client { (0, 1) } else { (1, 0) };
        p.direction = if me == 0 {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        p.stream = Some(stream.index);
        p.tcp_flags = tcp.flags;

        let syn = tcp.flags & SYN != 0;
        let fin = tcp.flags & FIN != 0;
        let seg_len = payload.len() as u32 + syn as u32 + fin as u32;
        let half = &mut stream.halves[me];
        if syn {
            half.isn = Some(tcp.seq);
            half.win_scale = tcp.options.iter().find_map(|o| match o {
                TcpOption::WindowScale(s) => Some(*s),
                _ => None,
            });
        }
        let isn = *half.isn.get_or_insert(tcp.seq.wrapping_sub(1));
        if let Some(next) = half.next_seq {
            let diff = tcp.seq.wrapping_sub(next) as i32;
            if seg_len > 0 && diff < 0 {
                p.analysis = Some(if seg_len == 1 && diff == -1 {
                    "TCP Keep-Alive"
                } else {
                    "TCP Retransmission"
                });
            } else if diff > 0 {
                p.analysis = Some("TCP Previous segment not captured");
                half.tls = TlsHalf::default();
            }
        }
        let end = tcp.seq.wrapping_add(seg_len);
        half.next_seq = match half.next_seq {
            Some(next) if (end.wrapping_sub(next) as i32) < 0 => Some(next),
            _ => Some(end),
        };

        p.rel_seq = tcp.seq.wrapping_sub(isn);
        p.rel_ack = match (tcp.flags & ACK != 0, stream.halves[other].isn) {
            (true, Some(isn)) => tcp.ack.wrapping_sub(isn),
            (true, None) => tcp.ack,
            _ => 0,
        };
        p.window = match (stream.halves[me].win_scale, stream.halves[other].win_scale) {
            (Some(shift), Some(_)) if !syn => (tcp.window as u32) << shift,
            _ => tcp.window as u32,
        };

        let resent = matches!(p.analysis, Some("TCP Retransmission" | "TCP Keep-Alive"));
        if payload.is_empty() || resent {
            p.app = App::Tcp;
            p.protocol = "TCP".into();
            p.info = tcp_info(p, tcp, payload.len());
        } else {
            let hello = payload.len() > 1 && payload[0] == 0x16 && payload[1] == 3;
            if hello && (stream.control || !stream.seen_payload) {
                stream.tls = true;
            }
            stream.seen_payload = true;
            if stream.tls {
                let half = &mut stream.halves[me].tls;
                p.tls = *half;
                p.app = App::Tls;
                p.info = tls::scan(payload, half, &mut stream.tls_version);
                p.protocol = tls::protocol_name(stream.tls_version).into();
            } else if stream.control {
                p.app = App::Ftp;
                p.protocol = "FTP".into();
                p.info = ftp_info(payload, p.direction);
            } else {
                p.app = App::FtpData;
                p.protocol = "FTP-DATA".into();
                p.info = format!("FTP Data: {} bytes", payload.len());
            }
        }
        if let Some(note) = p.analysis {
            p.info = format!("[{note}] {}", p.info);
        }
        true
    }

    fn udp(&mut self, p: &mut Packet, payload: &[u8]) -> bool {
        if self.cfg.protocol != Protocol::Tftp {
            return false;
        }
        if self.is_server(p.dst) {
            self.tftp_clients.insert(p.src);
        }
        p.direction = if self.tftp_clients.contains(&p.src) {
            Direction::ClientToServer
        } else if self.tftp_clients.contains(&p.dst) {
            Direction::ServerToClient
        } else {
            return false;
        };
        p.app = App::Tftp;
        p.protocol = "TFTP".into();
        p.info = match tftp::Tftp::parse(payload) {
            Some(packet) => packet.summary(),
            None => "Malformed TFTP packet".into(),
        };
        true
    }
}

fn port(t: &Transport, src: bool) -> u16 {
    match (t, src) {
        (Transport::Tcp(t), true) => t.src_port,
        (Transport::Tcp(t), false) => t.dst_port,
        (Transport::Udp(u), true) => u.src_port,
        (Transport::Udp(u), false) => u.dst_port,
    }
}

fn tcp_info(p: &Packet, tcp: &Tcp, len: usize) -> String {
    let mut info = format!(
        "{} \u{2192} {} [{}] Seq={}",
        p.src.port(),
        p.dst.port(),
        flag_names(tcp.flags),
        p.rel_seq
    );
    if tcp.flags & ACK != 0 {
        info += &format!(" Ack={}", p.rel_ack);
    }
    info += &format!(" Win={} Len={len}", p.window);
    for option in &tcp.options {
        match option {
            TcpOption::Mss(mss) => info += &format!(" MSS={mss}"),
            TcpOption::SackPermitted => info += " SACK_PERM",
            TcpOption::WindowScale(shift) => info += &format!(" WS={}", 1u32 << shift),
            _ => {}
        }
    }
    info
}

fn ftp_info(payload: &[u8], direction: Direction) -> String {
    let text = String::from_utf8_lossy(payload);
    let mut lines = text.lines().filter(|l| !l.is_empty());
    let first = lines.next().unwrap_or_default();
    let more = lines.count();
    let kind = match direction {
        Direction::ClientToServer => "Request",
        Direction::ServerToClient => "Response",
    };
    match more {
        0 => format!("{kind}: {first}"),
        n => format!("{kind}: {first} (+{n} lines)"),
    }
}
