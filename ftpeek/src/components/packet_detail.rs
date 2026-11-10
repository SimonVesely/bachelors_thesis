use std::time::{SystemTime, UNIX_EPOCH};

use dioxus::prelude::*;
use proto_core::{Direction, EventKind, MessageEvent};

use crate::protocols::{Proto, Rows};

struct DetailView {
    frame_title: String,
    relative: String,
    timestamp: String,
    length: String,
    kind: String,
    direction: String,
    peer: String,
    local: String,
    protocol_title: String,
    info: String,
    hex: String,
    hex_label: &'static str,
    show_app: bool,
    tls_rows: Rows,
    security_title: &'static str,
    transport_title: &'static str,
    app_rows: Rows,
}

fn kind_name(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Message => "Command / reply",
        EventKind::Data => "File data",
        EventKind::TcpOpen => "TCP connection opened",
        EventKind::TcpClose => "TCP connection closed",
        EventKind::Tls => "TLS handshake",
    }
}

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::ClientToServer => "Client \u{2192} server",
        Direction::ServerToClient => "Server \u{2192} client",
    }
}

fn build_view(idx: usize, e: &MessageEvent, t0: SystemTime) -> DetailView {
    let timestamp = match e.timestamp.duration_since(UNIX_EPOCH) {
        Ok(d) => format!("{:.6}", d.as_secs_f64()),
        Err(_) => "unknown".to_string(),
    };
    let relative = format!(
        "{:.6} s",
        e.timestamp
            .duration_since(t0)
            .unwrap_or_default()
            .as_secs_f64()
    );
    let info = e.parsed.clone().unwrap_or_default();

    let spec = Proto::of(e.protocol).spec();
    let channel = spec.channel();
    let tls_rows = if e.kind == EventKind::Tls {
        vec![("Handshake", info.clone())]
    } else if e.encrypted {
        vec![
            (channel.record.0, channel.record.1.to_string()),
            (
                "In this view",
                format!(
                    "Decrypted by the server - on the wire this is {} ciphertext",
                    channel.name
                ),
            ),
        ]
    } else {
        Vec::new()
    };

    DetailView {
        frame_title: format!("Frame {}: {} bytes", idx + 1, e.length),
        relative,
        timestamp,
        length: format!("{} bytes", e.length),
        kind: kind_name(e.kind).to_string(),
        direction: direction_name(e.direction).to_string(),
        peer: e.peer.to_string(),
        local: e.local.to_string(),
        protocol_title: spec.app_title(e),
        info,
        hex: hex_dump(&e.raw),
        hex_label: if e.encrypted {
            "Raw bytes (decrypted)"
        } else {
            "Raw bytes"
        },
        show_app: !matches!(e.kind, EventKind::Tls),
        tls_rows,
        security_title: channel.title,
        transport_title: spec.transport_title(),
        app_rows: spec.detail_rows(e),
    }
}

#[component]
pub fn PacketDetail(logs: Signal<Vec<MessageEvent>>, selected: Signal<Option<usize>>) -> Element {
    let idx = selected();
    let view = idx.and_then(|i| {
        let all = logs.read();
        let t0 = all.first().map_or(UNIX_EPOCH, |e| e.timestamp);
        all.get(i).map(|e| build_view(i, e, t0))
    });

    let mut frame_open = use_signal(|| true);
    let mut transport_open = use_signal(|| true);
    let mut tls_open = use_signal(|| true);
    let mut app_open = use_signal(|| true);

    rsx! {
        div { class: "detail-panel",
            div { class: "detail-panel__header", "Packet detail" }
            div { class: "detail-panel__body",
                if let Some(v) = view {
                    div { class: "detail-tree",
                        div { class: "detail-section",
                            div {
                                class: "detail-section__title",
                                onclick: move |_| frame_open.toggle(),
                                span { class: "detail-section__arrow", if frame_open() { "\u{25be}" } else { "\u{25b8}" } }
                                "{v.frame_title}"
                            }
                            if frame_open() {
                                div { class: "detail-section__body",
                                    div { class: "detail-row", span { class: "detail-row__label", "Time since first packet" } span { class: "detail-row__value", "{v.relative}" } }
                                    div { class: "detail-row", span { class: "detail-row__label", "Epoch time" } span { class: "detail-row__value", "{v.timestamp}" } }
                                    div { class: "detail-row", span { class: "detail-row__label", "Frame length" } span { class: "detail-row__value", "{v.length}" } }
                                    div { class: "detail-row", span { class: "detail-row__label", "Kind" } span { class: "detail-row__value", "{v.kind}" } }
                                }
                            }
                        }

                        div { class: "detail-section",
                            div {
                                class: "detail-section__title",
                                onclick: move |_| transport_open.toggle(),
                                span { class: "detail-section__arrow", if transport_open() { "\u{25be}" } else { "\u{25b8}" } }
                                "{v.transport_title}"
                            }
                            if transport_open() {
                                div { class: "detail-section__body",
                                    div { class: "detail-row", span { class: "detail-row__label", "Direction" } span { class: "detail-row__value", "{v.direction}" } }
                                    div { class: "detail-row", span { class: "detail-row__label", "Peer address" } span { class: "detail-row__value", "{v.peer}" } }
                                    div { class: "detail-row", span { class: "detail-row__label", "Local address" } span { class: "detail-row__value", "{v.local}" } }
                                }
                            }
                        }

                        if !v.tls_rows.is_empty() {
                            div { class: "detail-section",
                                div {
                                    class: "detail-section__title",
                                    onclick: move |_| tls_open.toggle(),
                                    span { class: "detail-section__arrow", if tls_open() { "\u{25be}" } else { "\u{25b8}" } }
                                    "{v.security_title}"
                                }
                                if tls_open() {
                                    div { class: "detail-section__body",
                                        for (label, value) in v.tls_rows.iter() {
                                            div { key: "{label}", class: "detail-row",
                                                span { class: "detail-row__label", "{label}" }
                                                span { class: "detail-row__value", "{value}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if v.show_app {
                            div { class: "detail-section",
                                div {
                                    class: "detail-section__title",
                                    onclick: move |_| app_open.toggle(),
                                    span { class: "detail-section__arrow", if app_open() { "\u{25be}" } else { "\u{25b8}" } }
                                    "{v.protocol_title}"
                                }
                                if app_open() {
                                    div { class: "detail-section__body",
                                        for (label, value) in v.app_rows.iter() {
                                            div { key: "{label}", class: "detail-row",
                                                span { class: "detail-row__label", "{label}" }
                                                span { class: "detail-row__value", "{value}" }
                                            }
                                        }
                                        div { class: "detail-row", span { class: "detail-row__label", "Info" } span { class: "detail-row__value", "{v.info}" } }
                                        if !v.hex.is_empty() {
                                            div { class: "detail-hex",
                                                div { class: "detail-hex__label", "{v.hex_label}" }
                                                pre { class: "detail-hex__pre", "{v.hex}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    p { class: "detail-panel__empty", "Select a packet from the log to see its detail." }
                }
            }
        }
    }
}

fn hex_dump(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{:04x}  {:<48}  {}\n", i * 16, hex, ascii));
    }
    out
}
