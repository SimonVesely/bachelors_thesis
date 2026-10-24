use std::collections::HashSet;
use std::ops::Range;

use dioxus::prelude::*;
use proto_core::capture::{Packet, layers};

const HEX_LIMIT: usize = 4096;

#[component]
pub fn FrameDetail(packets: Signal<Vec<Packet>>, selected: Signal<Option<usize>>) -> Element {
    let idx = selected();
    let packet = idx.and_then(|i| packets.read().get(i).cloned());
    let mut collapsed = use_signal(HashSet::<String>::new);
    let mut highlight = use_signal(|| None::<(usize, Range<usize>)>);

    let Some((i, p)) = idx.zip(packet) else {
        return rsx! {
            div { class: "detail-panel",
                div { class: "detail-panel__header", "Packet detail" }
                div { class: "detail-panel__body",
                    p { class: "detail-panel__empty", "Select a packet from the log to see its detail." }
                }
            }
        };
    };
    let tree = layers(&p, i + 1);
    let marked = highlight().filter(|(at, _)| *at == i).map(|(_, r)| r);
    let rows = hex_rows(&p.data, marked.clone());
    let cut = p.data.len().saturating_sub(HEX_LIMIT);

    rsx! {
        div { class: "detail-panel",
            div { class: "detail-panel__header", "Packet detail" }
            div { class: "detail-panel__body",
                div { class: "detail-tree",
                    for (n, layer) in tree.into_iter().enumerate() {
                        div { key: "{n}", class: "detail-section",
                            div {
                                class: "detail-section__title",
                                onclick: {
                                    let kind = kind_of(&layer.title);
                                    let range = layer.range.clone();
                                    move |_| {
                                        let mut set = collapsed.write();
                                        if !set.remove(&kind) {
                                            set.insert(kind.clone());
                                        }
                                        highlight.set(Some((i, range.clone())));
                                    }
                                },
                                span { class: "detail-section__arrow",
                                    if collapsed.read().contains(&kind_of(&layer.title)) { "\u{25b8}" } else { "\u{25be}" }
                                }
                                "{layer.title}"
                            }
                            if !collapsed.read().contains(&kind_of(&layer.title)) {
                                div { class: "detail-section__body",
                                    for (k, field) in layer.fields.into_iter().enumerate() {
                                        div {
                                            key: "{k}",
                                            class: if field.range.is_some() && field.range == marked { "detail-row detail-row--marked" } else { "detail-row" },
                                            onclick: {
                                                let range = field.range.clone();
                                                move |_| {
                                                    if let Some(r) = range.clone() {
                                                        highlight.set(Some((i, r)));
                                                    }
                                                }
                                            },
                                            span { class: "detail-row__label", "{field.label}" }
                                            span { class: "detail-row__value", "{field.value}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "detail-hex",
                        div { class: "detail-hex__label", "Frame bytes ({p.data.len()} B)" }
                        pre { class: "detail-hex__pre",
                            for (n, row) in rows.into_iter().enumerate() {
                                div { key: "{n}",
                                    "{row.offset}  {row.hex[0]}"
                                    span { class: "hex-mark", "{row.hex[1]}" }
                                    "{row.hex[2]} {row.ascii[0]}"
                                    span { class: "hex-mark", "{row.ascii[1]}" }
                                    "{row.ascii[2]}"
                                }
                            }
                            if cut > 0 {
                                div { "\u{2026} {cut} more bytes not shown" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn kind_of(title: &str) -> String {
    title.split([',', ':']).next().unwrap_or(title).to_string()
}

struct HexRow {
    offset: String,
    hex: [String; 3],
    ascii: [String; 3],
}

fn hex_rows(data: &[u8], marked: Option<Range<usize>>) -> Vec<HexRow> {
    let shown = &data[..data.len().min(HEX_LIMIT)];
    let marked = marked.unwrap_or(0..0);
    shown
        .chunks(16)
        .enumerate()
        .map(|(n, chunk)| {
            let mut row = HexRow {
                offset: format!("{:04x}", n * 16),
                hex: Default::default(),
                ascii: Default::default(),
            };
            for (k, b) in chunk.iter().enumerate() {
                let at = n * 16 + k;
                let part = if at < marked.start {
                    0
                } else if at < marked.end {
                    1
                } else {
                    2
                };
                row.hex[part] += &format!("{b:02x} ");
                row.ascii[part].push(if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                });
            }
            row.hex[2] += &"   ".repeat(16 - chunk.len());
            row
        })
        .collect()
}
