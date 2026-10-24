use dioxus::prelude::*;
use proto_core::{Direction, EventKind, MessageEvent, Protocol};

use super::ClientInfo;

struct Row {
    class: String,
    no: usize,
    time: String,
    src: String,
    dst: String,
    proto: String,
    len: usize,
    info: String,
    end_of_group: bool,
}

fn proto_label(e: &MessageEvent) -> String {
    let base = match (e.kind, e.protocol) {
        (EventKind::TcpOpen | EventKind::TcpClose, _) => return "TCP".to_string(),
        (EventKind::Tls, _) => return "TLS".to_string(),
        (EventKind::Data, Protocol::Ftp) => "FTP-DATA",
        (EventKind::Data, Protocol::Ftps) => "FTPS-DATA",
        (EventKind::Data, Protocol::Tftp) => "TFTP",
        (EventKind::Data, Protocol::Sftp) => "SFTP",
        (EventKind::Message, Protocol::Ftp) => "FTP",
        (EventKind::Message, Protocol::Ftps) => "FTPS",
        (EventKind::Message, Protocol::Tftp) => "TFTP",
        (EventKind::Message, Protocol::Sftp) => "SFTP",
    };
    if e.encrypted {
        format!("{base}+TLS")
    } else {
        base.to_string()
    }
}

fn info_text(e: &MessageEvent) -> String {
    let text = e.parsed.clone().unwrap_or_default();
    if e.protocol == Protocol::Tftp {
        return text;
    }
    match (e.kind, e.direction) {
        (EventKind::Message, Direction::ClientToServer) => format!("Request: {text}"),
        (EventKind::Message, Direction::ServerToClient) => format!("Response: {text}"),
        _ => text,
    }
}

fn group_boundaries(entries: &[&MessageEvent]) -> Vec<bool> {
    let mut group_id = 0usize;
    let mut ids = Vec::with_capacity(entries.len());

    for e in entries {
        let starts_new_group = matches!(e.kind, EventKind::TcpOpen)
            || matches!(
                (e.kind, e.direction),
                (EventKind::Message, Direction::ClientToServer)
            )
            || (e.protocol == Protocol::Tftp && e.direction == Direction::ClientToServer);
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
pub fn PacketLog(
    logs: Signal<Vec<MessageEvent>>,
    selected: Signal<Option<usize>>,
    clients: Signal<Vec<ClientInfo>>,
    filter: Signal<Option<u64>>,
) -> Element {
    let mut logs = logs;
    let mut selected = selected;
    let mut filter = filter;
    let mut autoscroll = use_signal(|| true);

    let (rows, total): (Vec<Row>, usize) = {
        let all = logs.read();
        let t0 = all.first().map(|e| e.timestamp);
        let current = selected();
        let only = filter();
        let shown: Vec<(usize, &MessageEvent)> = all
            .iter()
            .enumerate()
            .filter(|(_, e)| only.is_none_or(|id| e.session == id))
            .collect();
        let events: Vec<&MessageEvent> = shown.iter().map(|(_, e)| *e).collect();
        let ends = group_boundaries(&events);

        let rows = shown
            .iter()
            .zip(ends)
            .map(|(&(i, e), end_of_group)| {
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
                    (EventKind::Tls, _) => "pkt--tls".to_string(),
                    (_, Direction::ClientToServer) => "pkt--in".to_string(),
                    (_, Direction::ServerToClient) => "pkt--out".to_string(),
                };
                if e.encrypted {
                    class.push_str(" pkt--enc");
                }
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
                    end_of_group,
                }
            })
            .collect();
        (rows, all.len())
    };
    let count_label = if filter().is_some() {
        format!("{} of {total} packets", rows.len())
    } else {
        format!("{total} packets")
    };
    let client_options: Vec<(u64, String)> = clients
        .read()
        .iter()
        .map(|c| (c.session, c.label()))
        .collect();

    use_effect(move || {
        let count = logs.read().len();
        let _ = filter(); // also jump to the bottom when the filter changes
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
                span { class: "packet-log__count", "{count_label}" }
                div { class: "packet-log__spacer" }
                select {
                    class: "status-summary__input packet-log__filter",
                    value: filter().map(|id| id.to_string()).unwrap_or_default(),
                    onchange: move |e| filter.set(e.value().parse().ok()),
                    option { value: "", "All clients" }
                    for (id, label) in client_options {
                        option { key: "{id}", value: "{id}", "{label}" }
                    }
                }
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
                    p { class: "packet-log__empty",
                        if filter().is_some() { "No packets from this client." } else { "No packets captured yet." }
                    }
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
