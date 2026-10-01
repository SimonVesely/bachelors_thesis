use dioxus::prelude::*;
use proto_core::{Direction, EventKind, MessageEvent, Protocol};

struct Row {
    class: String,
    no: usize,
    time: String,
    src: String,
    dst: String,
    proto: &'static str,
    len: usize,
    info: String,
    end_of_group: bool,
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

fn group_boundaries(entries: &[MessageEvent]) -> Vec<bool> {
    let mut group_id = 0usize;
    let mut ids = Vec::with_capacity(entries.len());

    for e in entries {
        let starts_new_group = matches!(e.kind, EventKind::TcpOpen)
            || matches!(
                (e.kind, e.direction),
                (EventKind::Message, Direction::ClientToServer)
            );
        if starts_new_group && !ids.is_empty() {
            group_id += 1;
        }
        ids.push(group_id);
    }

    (0..ids.len())
        .map(|i| i == ids.len() - 1 || ids[i + 1] != ids[i])
        .collect()
}

#[component]
pub fn PacketLog(logs: Signal<Vec<MessageEvent>>, selected: Signal<Option<usize>>) -> Element {
    let mut logs = logs;
    let mut selected = selected;
    let mut autoscroll = use_signal(|| true);

    let rows: Vec<Row> = {
        let entries = logs.read();
        let t0 = entries.first().map(|e| e.timestamp);
        let current = selected();
        let ends = group_boundaries(&entries);

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
                let mut class = match (e.kind, e.direction) {
                    (EventKind::TcpOpen | EventKind::TcpClose, _) => "pkt--tcp".to_string(),
                    (_, Direction::ClientToServer) => "pkt--in".to_string(),
                    (_, Direction::ServerToClient) => "pkt--out".to_string(),
                };
                if current == Some(i) {
                    class.push_str(" pkt--selected");
                }
                Row {
                    class,
                    no: i + 1,
                    time: format!("{elapsed:.6}"),
                    src: src.to_string(),
                    dst: dst.to_string(),
                    proto: proto_label(e),
                    len: e.length,
                    info: info_text(e),
                    end_of_group: ends[i],
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
                    onclick: move |_| {
                        logs.write().clear();
                        selected.set(None);
                    },
                    "Clear"
                }
            }
            div { id: "packet-scroll", class: "packet-log__body",
                if rows.is_empty() {
                    p { class: "packet-log__empty", "No packets captured yet." }
                } else {
                    table { class: "packet-table",
                        colgroup {
                            col { class: "col-no" }
                            col { class: "col-time" }
                            col { class: "col-src" }
                            col { class: "col-dst" }
                            col { class: "col-proto" }
                            col { class: "col-len" }
                            col { class: "col-info" }
                        }
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
                                tr {
                                    key: "{row.no}",
                                    class: if row.end_of_group { format!("{} pkt--group-end", row.class) } else { row.class.clone() },
                                    onclick: {
                                        let no = row.no;
                                        move |_| selected.set(Some(no - 1))
                                    },
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
