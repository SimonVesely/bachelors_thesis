use dioxus::prelude::*;
use proto_core::capture::{LinkLayer, Packet, TcpOption, Transport, flag_names};

const LEFT: f64 = 24.0;
const BIT: f64 = 16.0;
const GRID_TOP: f64 = 96.0;
const ROW: f64 = 34.0;

type Cell = (usize, u32, u32, String, String, &'static str);

#[component]
pub fn FrameDiagram(packets: Signal<Vec<Packet>>, selected: Signal<Option<usize>>) -> Element {
    let packet = selected().and_then(|i| packets.read().get(i).cloned());
    rsx! {
        div { class: "diagram-panel",
            div { class: "diagram-panel__header", "Packet structure" }
            div { class: "diagram-panel__body",
                match packet.as_ref().and_then(|p| p.headers().map(|h| (p, h))) {
                    Some((p, h)) => render(p, &h),
                    None => rsx! { p { class: "diagram-panel__empty", "Select a packet to see its structure." } },
                }
            }
        }
    }
}

fn render(p: &Packet, h: &proto_core::capture::Headers) -> Element {
    let link = match h.link {
        LinkLayer::Ethernet { .. } => "ETHERNET II",
        LinkLayer::Loopback { .. } => "LOOPBACK",
        LinkLayer::LinuxCooked => "LINUX COOKED",
        LinkLayer::RawIp => "RAW",
    };
    let payload = h.payload.len();
    let (l4_name, l4_len, cells, title) = match &h.transport {
        Transport::Tcp(t) => (
            "TCP",
            t.header_len,
            tcp_cells(p, t, payload),
            format!("TCP header - {} bytes (RFC 9293)", t.header_len),
        ),
        Transport::Udp(u) => (
            "UDP",
            8,
            vec![
                (
                    0,
                    0,
                    16,
                    "SOURCE PORT".into(),
                    u.src_port.to_string(),
                    "#dbe7f7",
                ),
                (
                    0,
                    16,
                    16,
                    "DESTINATION PORT".into(),
                    u.dst_port.to_string(),
                    "#dbe7f7",
                ),
                (1, 0, 16, "LENGTH".into(), u.length.to_string(), "#e3f2e6"),
                (
                    1,
                    16,
                    16,
                    "CHECKSUM".into(),
                    format!("0x{:04x}", u.checksum),
                    "#fdf0d5",
                ),
                (
                    2,
                    0,
                    32,
                    format!("DATA - {}", p.protocol),
                    format!("{payload} bytes"),
                    "#fff3c4",
                ),
            ],
            "UDP header - 8 bytes (RFC 768)".to_string(),
        ),
    };
    let rows = cells.iter().map(|c| c.0).max().unwrap_or(0) + 1;
    let height = GRID_TOP + rows as f64 * ROW + 8.0;
    let app = if payload > 0 {
        p.protocol.to_uppercase()
    } else {
        "NO PAYLOAD".into()
    };
    let layers = [
        (link, format!("{} B", h.ip_start), "#8a8d93"),
        ("IPV4", format!("{} B", h.ip.header_len), "#2f6fb5"),
        (l4_name, format!("{l4_len} B"), "#0a7d8c"),
        (app.as_str(), format!("{payload} B"), "#d98a1f"),
    ];

    rsx! {
        svg {
            "viewBox": "0 0 560 {height}",
            width: "100%",
            height: "{height}",

            text { x: "280", y: "12", "text-anchor": "middle", "font-size": "11", "font-weight": "700", fill: "#16171a", "Encapsulation" }
            for (n, (name, size, fill)) in layers.iter().enumerate() {
                rect { key: "{n}", x: "{LEFT + n as f64 * 128.0}", y: "18", width: "128", height: "34", fill: *fill, stroke: "#16171a", "stroke-width": "1" }
                text { x: "{LEFT + n as f64 * 128.0 + 64.0}", y: "32", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "{name}" }
                text { x: "{LEFT + n as f64 * 128.0 + 64.0}", y: "46", "text-anchor": "middle", "font-size": "11", "font-weight": "700", fill: "#ffffff", "{size}" }
            }

            text { x: "280", y: "72", "text-anchor": "middle", "font-size": "11", "font-weight": "700", fill: "#16171a", "{title}" }
            for bit in [0u32, 8, 16, 24, 31] {
                text { key: "{bit}", x: "{LEFT + bit as f64 * BIT + BIT / 2.0}", y: "88", "text-anchor": "middle", "font-size": "8", fill: "#55585f", "{bit}" }
            }
            for (n, (row, start, bits, label, value, fill)) in cells.iter().enumerate() {
                rect {
                    key: "{n}",
                    x: "{LEFT + *start as f64 * BIT}", y: "{GRID_TOP + *row as f64 * ROW}",
                    width: "{*bits as f64 * BIT}", height: "{ROW}",
                    fill: *fill, stroke: "#16171a", "stroke-width": "1",
                }
                text {
                    x: "{LEFT + (*start as f64 + *bits as f64 / 2.0) * BIT}", y: "{GRID_TOP + *row as f64 * ROW + 13.0}",
                    "text-anchor": "middle", "font-size": "8", "font-weight": "700", fill: "#3a3d42",
                    "{label}"
                }
                text {
                    x: "{LEFT + (*start as f64 + *bits as f64 / 2.0) * BIT}", y: "{GRID_TOP + *row as f64 * ROW + 27.0}",
                    "text-anchor": "middle", "font-size": "10", fill: "#16171a",
                    "{value}"
                }
            }
        }
    }
}

fn tcp_cells(p: &Packet, t: &proto_core::capture::Tcp, payload: usize) -> Vec<Cell> {
    let options: Vec<String> = t
        .options
        .iter()
        .filter_map(|o| match o {
            TcpOption::Nop => None,
            TcpOption::Mss(v) => Some(format!("MSS {v}")),
            TcpOption::WindowScale(s) => Some(format!("WS {s}")),
            TcpOption::SackPermitted => Some("SACK_PERM".into()),
            TcpOption::Sack(n) => Some(format!("SACK x{n}")),
            TcpOption::Timestamps(..) => Some("Timestamps".into()),
            TcpOption::Other(k) => Some(format!("#{k}")),
        })
        .collect();
    let mut cells: Vec<Cell> = vec![
        (
            0,
            0,
            16,
            "SOURCE PORT".into(),
            t.src_port.to_string(),
            "#dbe7f7",
        ),
        (
            0,
            16,
            16,
            "DESTINATION PORT".into(),
            t.dst_port.to_string(),
            "#dbe7f7",
        ),
        (
            1,
            0,
            32,
            "SEQUENCE NUMBER".into(),
            format!("{} (relative {})", t.seq, p.rel_seq),
            "#e8e0f5",
        ),
        (
            2,
            0,
            32,
            "ACKNOWLEDGMENT NUMBER".into(),
            format!("{} (relative {})", t.ack, p.rel_ack),
            "#f5e3ea",
        ),
        (
            3,
            0,
            4,
            "OFF".into(),
            format!("{}", t.header_len / 4),
            "#e3f2e6",
        ),
        (3, 4, 3, "RSV".into(), "0".into(), "#e3f2e6"),
        (3, 7, 9, "FLAGS".into(), flag_names(t.flags), "#c9ebd0"),
        (3, 16, 16, "WINDOW".into(), t.window.to_string(), "#e3f2e6"),
        (
            4,
            0,
            16,
            "CHECKSUM".into(),
            format!("0x{:04x}", t.checksum),
            "#fdf0d5",
        ),
        (
            4,
            16,
            16,
            "URGENT POINTER".into(),
            t.urgent.to_string(),
            "#fdf0d5",
        ),
    ];
    let mut row = 5;
    if t.header_len > 20 {
        let title = format!("OPTIONS ({} B)", t.header_len - 20);
        cells.push((row, 0, 32, title, options.join(", "), "#eeeeee"));
        row += 1;
    }
    if payload > 0 {
        let title = format!("DATA - {}", p.protocol);
        cells.push((row, 0, 32, title, format!("{payload} bytes"), "#fff3c4"));
    }
    cells
}
