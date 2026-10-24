use dioxus::prelude::*;
use proto_core::{EventKind, MessageEvent, Protocol};
use proto_tftp::{Packet, error_name};

struct DetailView {
    frame_title: String,
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
    tls_rows: Vec<(&'static str, String)>,
    transport_title: &'static str,
    app_rows: Vec<(&'static str, String)>,
}

fn build_view(idx: usize, e: &MessageEvent) -> DetailView {
    let timestamp = match e.timestamp.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{:.6}", d.as_secs_f64()),
        Err(_) => "unknown".to_string(),
    };
    let info = e.parsed.clone().unwrap_or_default();

    let tls_rows = if e.kind == EventKind::Tls {
        vec![("Handshake", info.clone())]
    } else if e.encrypted {
        vec![
            ("Record layer", "Application Data (encrypted)".to_string()),
            (
                "In this view",
                "Decrypted by the server - on the wire this is ciphertext".to_string(),
            ),
        ]
    } else {
        Vec::new()
    };

    DetailView {
        frame_title: format!("Frame {}: {} bytes", idx + 1, e.length),
        timestamp,
        length: format!("{} bytes", e.length),
        kind: format!("{:?}", e.kind),
        direction: format!("{:?}", e.direction),
        peer: e.peer.to_string(),
        local: e.local.to_string(),
        protocol_title: match e.protocol {
            Protocol::Tftp => "Trivial File Transfer Protocol".to_string(),
            other => format!("Application ({other:?})"),
        },
        info,
        hex: hex_dump(&e.raw),
        hex_label: if e.encrypted {
            "Raw bytes (decrypted)"
        } else {
            "Raw bytes"
        },
        show_app: !matches!(e.kind, EventKind::Tls),
        tls_rows,
        transport_title: match e.protocol {
            Protocol::Tftp => "User Datagram Protocol",
            _ => "Transmission Control Protocol",
        },
        app_rows: match e.protocol {
            Protocol::Tftp => tftp_rows(&e.raw),
            _ => Vec::new(),
        },
    }
}

fn tftp_rows(raw: &[u8]) -> Vec<(&'static str, String)> {
    let opcode = |n: u16, name: &str| ("Opcode", format!("{name} ({n})"));
    let options = |opts: &[(String, String)]| {
        opts.iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match Packet::parse(raw) {
        Some(Packet::Rrq(r)) | Some(Packet::Wrq(r)) => {
            let is_read = raw.get(1) == Some(&1);
            let mut rows = vec![
                if is_read {
                    opcode(1, "Read Request")
                } else {
                    opcode(2, "Write Request")
                },
                ("Source file", r.filename),
                ("Type", r.mode),
            ];
            if !r.options.is_empty() {
                rows.push(("Options", options(&r.options)));
            }
            rows
        }
        Some(Packet::Data { block, data }) => vec![
            opcode(3, "Data Packet"),
            ("Block", block.to_string()),
            ("Data length", format!("{} bytes", data.len())),
        ],
        Some(Packet::Ack { block }) => {
            vec![opcode(4, "Acknowledgement"), ("Block", block.to_string())]
        }
        Some(Packet::Error { code, message }) => vec![
            opcode(5, "Error Code"),
            ("Error code", format!("{} ({code})", error_name(code))),
            ("Error message", message),
        ],
        Some(Packet::Oack { options: o }) => {
            vec![
                opcode(6, "Option Acknowledgement"),
                ("Options", options(&o)),
            ]
        }
        None => vec![("Opcode", "malformed packet".to_string())],
    }
}

#[component]
pub fn PacketDetail(logs: Signal<Vec<MessageEvent>>, selected: Signal<Option<usize>>) -> Element {
    let idx = selected();
    let view = idx.and_then(|i| logs.read().get(i).map(|e| build_view(i, e)));

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
                                    div { class: "detail-row", span { class: "detail-row__label", "Timestamp" } span { class: "detail-row__value", "{v.timestamp}" } }
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
                                    "Transport Layer Security"
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
