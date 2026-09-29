use dioxus::prelude::*;
use proto_core::{Direction, EventKind, MessageEvent, Protocol};

struct Row {
    class: &'static str,
    no: usize,
    time: String,
    src: String,
    dst: String,
    proto: &'static str,
    len: usize,
    info: String,
}

fn proto_label(e: &MessageEvent) -> &'static str {
    match (e.kind, e.protocol) {
        (EventKind::TcpOpen | EventKind::TcpClose, _) => "TCP",
        (EventKind::Data, Protocol::Ftp) => "FTP-DATA",
        (EventKind::Data, Protocol::Ftps) => "FTPS-DATA",
        (EventKind::Data, Protocol::Tftp) => "TFTP",
        (EventKind::Data, Protocol::Sftp) => "SFTP",
        (EventKind::Message, Protocol::Ftp) => "FTP",
        (EventKind::Message, Protocol::Ftps) => "FTPS",
        (EventKind::Message, Protocol::Tftp) => "TFTP",
        (EventKind::Message, Protocol::Sftp) => "SFTP",
    }
}

fn info_text(e: &MessageEvent) -> String {
    let text = e.parsed.clone().unwrap_or_default();
    match (e.kind, e.direction) {
        (EventKind::Message, Direction::ClientToServer) => format!("Request: {text}"),
        (EventKind::Message, Direction::ServerToClient) => format!("Response: {text}"),
        _ => text,
    }
}

#[component]
pub fn PacketLog(logs: Signal<Vec<MessageEvent>>) -> Element {
    let mut logs = logs;
    let mut autoscroll = use_signal(|| true);

    let rows: Vec<Row> = {
        let entries = logs.read();
        let t0 = entries.first().map(|e| e.timestamp);
        entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let elapsed = t0
                    .and_then(|t| e.timestamp.duration_since(t).ok())
                    .unwrap_or_default()
                    .as_secs_f64();
                let (src, dst) = match e.direction {
                    Direction::ClientToServer => (e.peer, e.local),
                    Direction::ServerToClient => (e.local, e.peer),
                };
                let class = match (e.kind, e.direction) {
                    (EventKind::TcpOpen | EventKind::TcpClose, _) => "pkt--tcp",
                    (_, Direction::ClientToServer) => "pkt--in",
                    (_, Direction::ServerToClient) => "pkt--out",
                };
                Row {
                    class,
                    no: i + 1,
                    time: format!("{elapsed:.6}"),
                    src: src.to_string(),
                    dst: dst.to_string(),
                    proto: proto_label(e),
                    len: e.length,
                    info: info_text(e),
                }
            })
            .collect()
    };
    let total = rows.len();

    use_effect(move || {
        let count = logs.read().len();
        if autoscroll() && count > 0 {
            let _ = document::eval(
                "var el = document.getElementById('packet-scroll'); if (el) { el.scrollTop = el.scrollHeight; }",
            );
        }
    });

    rsx! {
        div { class: "packet-log",
            div { class: "packet-log__toolbar",
                span { class: "packet-log__title", "Packet log" }
                span { class: "packet-log__count", "{total} packets" }
                div { class: "packet-log__spacer" }
                label { class: "packet-log__autoscroll",
                    input {
                        r#type: "checkbox",
                        checked: autoscroll(),
                        onchange: move |e| autoscroll.set(e.checked()),
                    }
                    "Auto-scroll"
                }
                button {
                    class: "btn btn--ghost",
                    onclick: move |_| logs.write().clear(),
                    "Clear"
                }
            }
            div { id: "packet-scroll", class: "packet-log__body",
                if rows.is_empty() {
                    p { class: "packet-log__empty", "No packets captured yet." }
                } else {
                    table { class: "packet-table",
                        thead {
                            tr {
                                th { class: "packet-table__num", "No." }
                                th { "Time" }
                                th { "Source" }
                                th { "Destination" }
                                th { "Protocol" }
                                th { class: "packet-table__num", "Length" }
                                th { "Info" }
                            }
                        }
                        tbody {
                            for row in rows.iter() {
                                tr { key: "{row.no}", class: "{row.class}",
                                    td { class: "packet-table__num", "{row.no}" }
                                    td { "{row.time}" }
                                    td { "{row.src}" }
                                    td { "{row.dst}" }
                                    td { "{row.proto}" }
                                    td { class: "packet-table__num", "{row.len}" }
                                    td { class: "packet-table__info", "{row.info}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
