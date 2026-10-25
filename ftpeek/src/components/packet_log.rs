use std::net::SocketAddr;
use std::time::SystemTime;

use dioxus::prelude::*;
use proto_core::capture::{ACK, App, Packet, SYN};
use proto_core::{Direction, EventKind, MessageEvent, Protocol};

use super::ClientInfo;

const ROW_HEIGHT: f64 = 20.0;
const OVERSCAN: usize = 15;

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

fn event_proto(e: &MessageEvent) -> String {
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

fn event_info(e: &MessageEvent) -> String {
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

fn event_starts_group(e: &MessageEvent) -> bool {
    e.kind == EventKind::TcpOpen
        || (e.kind == EventKind::Message && e.direction == Direction::ClientToServer)
        || (e.protocol == Protocol::Tftp && e.direction == Direction::ClientToServer)
}

fn packet_starts_group(p: &Packet) -> bool {
    p.tcp_flags & (SYN | ACK) == SYN
        || (p.direction == Direction::ClientToServer
            && matches!(p.app, App::Ftp | App::Tls | App::Tftp))
}

fn event_row(no: usize, e: &MessageEvent, t0: SystemTime, current: Option<usize>) -> Row {
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
    if current == Some(no - 1) {
        class.push_str(" pkt--selected");
    }
    Row {
        class,
        no,
        time: elapsed(e.timestamp, t0),
        src: src.to_string(),
        dst: dst.to_string(),
        proto: event_proto(e),
        len: e.length,
        info: event_info(e),
        end_of_group: false,
    }
}

fn packet_row(no: usize, p: &Packet, t0: SystemTime, current: Option<usize>, decrypt: bool) -> Row {
    let mut class = match (p.app, p.direction) {
        (App::Tcp, _) => "pkt--tcp".to_string(),
        (App::Tls, _) => "pkt--tls".to_string(),
        (_, Direction::ClientToServer) => "pkt--in".to_string(),
        (_, Direction::ServerToClient) => "pkt--out".to_string(),
    };
    let plain = match (decrypt, &p.plain_protocol, &p.plain_info) {
        (true, Some(protocol), Some(info)) => Some((protocol.clone(), info.clone())),
        _ => None,
    };
    if plain.is_some() {
        class.push_str(" pkt--dec");
    }
    if current == Some(no - 1) {
        class.push_str(" pkt--selected");
    }
    let (proto, info) = plain.unwrap_or_else(|| (p.protocol.clone(), p.info.clone()));
    Row {
        class,
        no,
        time: elapsed(p.timestamp, t0),
        src: p.src.to_string(),
        dst: p.dst.to_string(),
        proto,
        len: p.wire_len as usize,
        info,
        end_of_group: false,
    }
}

fn elapsed(t: SystemTime, t0: SystemTime) -> String {
    let secs = t.duration_since(t0).unwrap_or_default().as_secs_f64();
    format!("{secs:.6}")
}

#[component]
pub fn PacketLog(
    logs: Signal<Vec<MessageEvent>>,
    packets: Signal<Vec<Packet>>,
    wire: Signal<bool>,
    selected: Signal<Option<usize>>,
    clients: Signal<Vec<ClientInfo>>,
    filter: Signal<Option<u64>>,
    decrypt: Signal<bool>,
    can_decrypt: bool,
) -> Element {
    let mut decrypt = decrypt;
    let mut logs = logs;
    let mut packets = packets;
    let mut selected = selected;
    let mut filter = filter;
    let mut autoscroll = use_signal(|| true);
    let mut scroll_top = use_signal(|| 0.0f64);
    let mut view_height = use_signal(|| 600.0f64);

    let current = selected();
    let only = filter();
    let addrs: Vec<SocketAddr> = only
        .and_then(|id| {
            clients
                .read()
                .iter()
                .find(|c| c.session == id)
                .map(|c| c.addrs.clone())
        })
        .unwrap_or_default();

    let (rows, shown, total) = if wire() {
        let all = packets.read();
        let t0 = all.first().map_or(SystemTime::UNIX_EPOCH, |p| p.timestamp);
        let shown: Vec<usize> = (0..all.len())
            .filter(|&i| {
                only.is_none() || addrs.contains(&all[i].src) || addrs.contains(&all[i].dst)
            })
            .collect();
        let rows = visible(
            &shown,
            scroll_top(),
            view_height(),
            |i| packet_row(i + 1, &all[i], t0, current, decrypt()),
            |i| packet_starts_group(&all[i]),
        );
        (rows, shown.len(), all.len())
    } else {
        let all = logs.read();
        let t0 = all.first().map_or(SystemTime::UNIX_EPOCH, |e| e.timestamp);
        let shown: Vec<usize> = (0..all.len())
            .filter(|&i| only.is_none_or(|id| all[i].session == id))
            .collect();
        let rows = visible(
            &shown,
            scroll_top(),
            view_height(),
            |i| event_row(i + 1, &all[i], t0, current),
            |i| event_starts_group(&all[i]),
        );
        (rows, shown.len(), all.len())
    };
    let (first, last) = window(shown, scroll_top(), view_height());

    let count_label = if only.is_some() {
        format!("{shown} of {total} packets")
    } else {
        format!("{total} packets")
    };
    let client_options: Vec<(u64, String)> = clients
        .read()
        .iter()
        .map(|c| (c.session, c.label()))
        .collect();

    use_effect(move || {
        let count = logs.read().len() + packets.read().len();
        let _ = filter();
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
                if can_decrypt {
                    button {
                        class: if decrypt() { "btn btn--ghost btn--on" } else { "btn btn--ghost" },
                        title: "Show TLS records decrypted with the session keys the server logged",
                        onclick: move |_| decrypt.toggle(),
                        if decrypt() { "Decrypted" } else { "Decrypt" }
                    }
                }
                button {
                    class: "btn btn--ghost",
                    onclick: move |_| {
                        logs.write().clear();
                        packets.write().clear();
                        selected.set(None);
                    },
                    "Clear"
                }
            }
            div {
                id: "packet-scroll",
                class: "packet-log__body",
                onscroll: move |e| {
                    scroll_top.set(e.data().scroll_top());
                    view_height.set(e.data().client_height() as f64);
                },
                if shown == 0 {
                    p { class: "packet-log__empty",
                        if only.is_some() { "No packets from this client." } else { "No packets captured yet." }
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
                            tr { class: "packet-table__spacer", style: "height: {first as f64 * ROW_HEIGHT}px",
                                td { colspan: 7 }
                            }
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
                                    td { class: "packet-table__info", title: "{row.info}", "{row.info}" }
                                }
                            }
                            tr { class: "packet-table__spacer", style: "height: {(shown - last) as f64 * ROW_HEIGHT}px",
                                td { colspan: 7 }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn window(shown: usize, scroll_top: f64, view_height: f64) -> (usize, usize) {
    let first = ((scroll_top / ROW_HEIGHT) as usize)
        .saturating_sub(OVERSCAN)
        .min(shown);
    let last = (first + (view_height / ROW_HEIGHT) as usize + 2 * OVERSCAN).min(shown);
    (first, last)
}

fn visible(
    shown: &[usize],
    scroll_top: f64,
    view_height: f64,
    row: impl Fn(usize) -> Row,
    starts_group: impl Fn(usize) -> bool,
) -> Vec<Row> {
    let (first, last) = window(shown.len(), scroll_top, view_height);
    (first..last)
        .map(|pos| {
            let mut r = row(shown[pos]);
            r.end_of_group = shown.get(pos + 1).is_none_or(|&next| starts_group(next));
            r
        })
        .collect()
}
