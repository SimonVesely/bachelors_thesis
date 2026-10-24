use dioxus::prelude::*;
use proto_core::{Direction, EventKind, MessageEvent, Protocol};
use proto_tftp::Packet;

#[component]
pub fn PacketDiagram(logs: Signal<Vec<MessageEvent>>, selected: Signal<Option<usize>>) -> Element {
    let idx = selected();
    let entry = idx.and_then(|i| logs.read().get(i).cloned());

    rsx! {
        div { class: "diagram-panel",
            div { class: "diagram-panel__header", "Packet structure" }
            div { class: "diagram-panel__body",
                if let Some(e) = entry {
                    { render_diagram(&e) }
                } else {
                    p { class: "diagram-panel__empty", "Select a packet to see its structure." }
                }
            }
        }
    }
}

fn render_diagram(e: &MessageEvent) -> Element {
    let dir_fill = match e.direction {
        Direction::ClientToServer => "#e08a00",
        Direction::ServerToClient => "#2a8f3f",
    };
    let dir_label = match e.direction {
        Direction::ClientToServer => "IN",
        Direction::ServerToClient => "OUT",
    };
    let kind_label = match e.kind {
        EventKind::TcpOpen => "TCP OPEN",
        EventKind::TcpClose => "TCP CLOSE",
        EventKind::Data => "DATA",
        EventKind::Message => "MESSAGE",
        EventKind::Tls => "TLS HANDSHAKE",
    };
    let proto_label = format!("{:?}", e.protocol);
    let len_label = format!("{} B", e.length);

    let (sec_label, sec_fill) = match e.kind {
        EventKind::TcpOpen | EventKind::TcpClose => ("N/A (TCP)", "#8a8d93"),
        EventKind::Tls => ("TLS HANDSHAKE", "#7b2fb0"),
        _ if e.encrypted => ("TLS ENCRYPTED", "#5b2a86"),
        _ => ("PLAINTEXT", "#c0392b"),
    };

    let (src, dst) = match e.direction {
        Direction::ClientToServer => (e.peer, e.local),
        Direction::ServerToClient => (e.local, e.peer),
    };
    let src_label = src.to_string();
    let dst_label = dst.to_string();

    let ts_label = match e.timestamp.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{:.3}", d.as_secs_f64()),
        Err(_) => "unknown".to_string(),
    };

    let data_title = if e.encrypted {
        "DATA (decrypted view - TLS on the wire)"
    } else {
        "DATA (variable)"
    };
    let payload_short = shorten(&e.parsed.clone().unwrap_or_default(), 52);
    let tftp = (e.protocol == Protocol::Tftp)
        .then(|| tftp_fields(&e.raw))
        .flatten();

    rsx! {
        svg {
            "viewBox": "0 0 560 240",
            width: "100%",
            height: "240",

            defs {
                marker {
                    id: "arrowStart", "viewBox": "0 0 10 10",
                    "refX": "1", "refY": "5",
                    "markerWidth": "6", "markerHeight": "6",
                    "orient": "auto-start-reverse",
                    path { d: "M 10 0 L 0 5 L 10 10 z", fill: "#16171a" }
                }
                marker {
                    id: "arrowEnd", "viewBox": "0 0 10 10",
                    "refX": "9", "refY": "5",
                    "markerWidth": "6", "markerHeight": "6",
                    "orient": "auto",
                    path { d: "M 0 0 L 10 5 L 0 10 z", fill: "#16171a" }
                }
            }

            text { x: "280", y: "12", "text-anchor": "middle", "font-size": "11", "font-weight": "700", fill: "#16171a", "FTPeek Event Record" }
            line {
                x1: "20", y1: "20", x2: "540", y2: "20",
                stroke: "#16171a", "stroke-width": "1.5",
                "marker-start": "url(#arrowStart)", "marker-end": "url(#arrowEnd)",
            }

            rect { x: "20", y: "30", width: "130", height: "38", fill: dir_fill, stroke: "#16171a", "stroke-width": "1" }
            text { x: "85", y: "44", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "DIRECTION" }
            text { x: "85", y: "60", "text-anchor": "middle", "font-size": "12", "font-weight": "700", fill: "#ffffff", "{dir_label}" }

            rect { x: "150", y: "30", width: "130", height: "38", fill: "#7b2fb0", stroke: "#16171a", "stroke-width": "1" }
            text { x: "215", y: "44", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "KIND" }
            text { x: "215", y: "60", "text-anchor": "middle", "font-size": "11", "font-weight": "700", fill: "#ffffff", "{kind_label}" }

            rect { x: "280", y: "30", width: "130", height: "38", fill: "#0a7d8c", stroke: "#16171a", "stroke-width": "1" }
            text { x: "345", y: "44", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "PROTOCOL" }
            text { x: "345", y: "60", "text-anchor": "middle", "font-size": "11", "font-weight": "700", fill: "#ffffff", "{proto_label}" }

            rect { x: "410", y: "30", width: "130", height: "38", fill: "#d98a1f", stroke: "#16171a", "stroke-width": "1" }
            text { x: "475", y: "44", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "LENGTH" }
            text { x: "475", y: "60", "text-anchor": "middle", "font-size": "12", "font-weight": "700", fill: "#ffffff", "{len_label}" }

            rect { x: "20", y: "68", width: "520", height: "38", fill: "#2f6fb5", stroke: "#16171a", "stroke-width": "1" }
            text { x: "280", y: "82", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "SOURCE ADDRESS" }
            text { x: "280", y: "98", "text-anchor": "middle", "font-size": "12", "font-weight": "700", fill: "#ffffff", "{src_label}" }

            rect { x: "20", y: "106", width: "520", height: "38", fill: "#b5406a", stroke: "#16171a", "stroke-width": "1" }
            text { x: "280", y: "120", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "DESTINATION ADDRESS" }
            text { x: "280", y: "136", "text-anchor": "middle", "font-size": "12", "font-weight": "700", fill: "#ffffff", "{dst_label}" }

            rect { x: "20", y: "144", width: "260", height: "38", fill: "#3f9169", stroke: "#16171a", "stroke-width": "1" }
            text { x: "150", y: "158", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "TIMESTAMP" }
            text { x: "150", y: "174", "text-anchor": "middle", "font-size": "12", "font-weight": "700", fill: "#ffffff", "{ts_label}" }

            rect { x: "280", y: "144", width: "260", height: "38", fill: sec_fill, stroke: "#16171a", "stroke-width": "1" }
            text { x: "410", y: "158", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#ffffff", "SECURITY" }
            text { x: "410", y: "174", "text-anchor": "middle", "font-size": "12", "font-weight": "700", fill: "#ffffff", "{sec_label}" }

            if let Some([(l1, v1), (l2, v2), (l3, v3)]) = tftp {
                rect { x: "20", y: "182", width: "130", height: "48", fill: "#fff3c4", stroke: "#16171a", "stroke-width": "1" }
                text { x: "85", y: "197", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#5c4b00", "{l1}" }
                text { x: "85", y: "216", "text-anchor": "middle", "font-size": "11", fill: "#3a2f00", "{v1}" }
                rect { x: "150", y: "182", width: "130", height: "48", fill: "#ffe9a8", stroke: "#16171a", "stroke-width": "1" }
                text { x: "215", y: "197", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#5c4b00", "{l2}" }
                text { x: "215", y: "216", "text-anchor": "middle", "font-size": "11", fill: "#3a2f00", "{v2}" }
                rect { x: "280", y: "182", width: "260", height: "48", fill: "#fff3c4", stroke: "#16171a", "stroke-width": "1" }
                text { x: "410", y: "197", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#5c4b00", "{l3}" }
                text { x: "410", y: "216", "text-anchor": "middle", "font-size": "11", fill: "#3a2f00", "{v3}" }
            } else {
                rect { x: "20", y: "182", width: "520", height: "48", fill: "#fff3c4", stroke: "#16171a", "stroke-width": "1" }
                text { x: "280", y: "197", "text-anchor": "middle", "font-size": "9", "font-weight": "700", fill: "#5c4b00", "{data_title}" }
                text { x: "280", y: "216", "text-anchor": "middle", "font-size": "11", fill: "#3a2f00", "{payload_short}" }
            }
        }
    }
}

fn tftp_fields(raw: &[u8]) -> Option<[(String, String); 3]> {
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

fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        let truncated: String = text.chars().take(max - 3).collect();
        format!("{truncated}...")
    } else {
        text.to_string()
    }
}
