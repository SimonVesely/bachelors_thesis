use dioxus::prelude::*;
use proto_core::MessageEvent;

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
}

fn build_view(idx: usize, e: &MessageEvent) -> DetailView {
    let timestamp = match e.timestamp.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{:.6}", d.as_secs_f64()),
        Err(_) => "unknown".to_string(),
    };

    DetailView {
        frame_title: format!("Frame {}: {} bytes", idx + 1, e.length),
        timestamp,
        length: format!("{} bytes", e.length),
        kind: format!("{:?}", e.kind),
        direction: format!("{:?}", e.direction),
        peer: e.peer.to_string(),
        local: e.local.to_string(),
        protocol_title: format!("Application ({:?})", e.protocol),
        info: e.parsed.clone().unwrap_or_default(),
        hex: hex_dump(&e.raw),
    }
}

#[component]
pub fn PacketDetail(logs: Signal<Vec<MessageEvent>>, selected: Signal<Option<usize>>) -> Element {
    let idx = selected();
    let view = idx.and_then(|i| logs.read().get(i).map(|e| build_view(i, e)));

    let mut frame_open = use_signal(|| true);
    let mut transport_open = use_signal(|| true);
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
                                "Transmission Control Protocol"
                            }
                            if transport_open() {
                                div { class: "detail-section__body",
                                    div { class: "detail-row", span { class: "detail-row__label", "Direction" } span { class: "detail-row__value", "{v.direction}" } }
                                    div { class: "detail-row", span { class: "detail-row__label", "Peer address" } span { class: "detail-row__value", "{v.peer}" } }
                                    div { class: "detail-row", span { class: "detail-row__label", "Local address" } span { class: "detail-row__value", "{v.local}" } }
                                }
                            }
                        }

                        div { class: "detail-section",
                            div {
                                class: "detail-section__title",
                                onclick: move |_| app_open.toggle(),
                                span { class: "detail-section__arrow", if app_open() { "\u{25be}" } else { "\u{25b8}" } }
                                "{v.protocol_title}"
                            }
                            if app_open() {
                                div { class: "detail-section__body",
                                    div { class: "detail-row", span { class: "detail-row__label", "Info" } span { class: "detail-row__value", "{v.info}" } }
                                    if !v.hex.is_empty() {
                                        div { class: "detail-hex",
                                            div { class: "detail-hex__label", "Raw bytes" }
                                            pre { class: "detail-hex__pre", "{v.hex}" }
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
