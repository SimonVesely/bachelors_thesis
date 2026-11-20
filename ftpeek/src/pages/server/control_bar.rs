//! # Server control bar
//! ## About:
//! - Title, back link, status chips (interface, access mode, listening/stopped), Start/Stop
//! - Settings rendered from `spec.options()`: dropdowns before Root directory, ports after it;
//!   all inputs are disabled while the server runs
//! - Root directory input with native folder picker (rfd)
//! - Type of capture: [L7 capture] (event log) / [L7-L2 capture] (pcap, Wireshark-like),
//!   switchable any time, also while a transfer runs; L7-L2 is disabled when pcap is unavailable
//!   (the reason is in its tooltip and in the note below)
//! - Protocol hints and the last server error
//! - Client list on the right side (filters the log by session)
//! ```text
//! +--------------------------------------------------------------------------+----------------------+
//! | [<- Main menu]  FTP SERVER                               [START SERVER]  | CLIENTS 2 connected  |
//! |                 (Interface eth0 · 192.0.2.2) (Access anonymous) (o stopped)| #1 192.0.2.2:37582 |
//! |--------------------------------------------------------------------------|    anonymous  23 pkts|
//! | Root directory              PI port  Active port Passive from Passive to Type of capture         |
//! | [/home/simon/FTPeek][Browse…] [21 ^v] [20    ^v] [50000  ^v] [50019 ^v] [L7 CAPTURE][L7-L2 CAPTURE]|
//! | hints / last error                                                live on eth0 + lo           |
//! +--------------------------------------------------------------------------+----------------------+
//! ```

use dioxus::prelude::*;

use super::capture::{CaptureState, LogView};
use crate::components::{ClientInfo, ClientList, OptionField};
use crate::protocols::{Opt, Options, Proto};
use crate::util::plural;
use crate::{AppState, Route};

#[component]
pub fn ControlBar(
    protocol: Proto,
    mode: String,
    options: Signal<Options>,
    root_dir: Signal<String>,
    running: ReadSignal<bool>,
    capture: CaptureState,
    error_msg: ReadSignal<Option<String>>,
    clients: Signal<Vec<ClientInfo>>,
    filter: Signal<Option<u64>>,
    on_start: EventHandler,
    on_stop: EventHandler,
) -> Element {
    let state = use_context::<AppState>();
    let spec = protocol.spec();
    let mut root_dir = root_dir;
    let mut view = capture.view;
    let wire = capture.shows_wire();
    let unavailable = capture.unavailable.read().clone();
    let wire_title = match &unavailable {
        Some(err) => format!("pcap unavailable: {err}"),
        None => "Frames captured with pcap, L7 down to L2".to_string(),
    };

    let access_label = if !spec.login() {
        format!("none ({} has no login)", spec.label())
    } else if (state.anonymous)() {
        "anonymous".to_string()
    } else {
        plural(state.user_names.read().len(), "user")
    };

    let selected_ip = state.selected_interface.read().clone().unwrap_or_default();
    let iface_label = match state
        .interfaces
        .read()
        .iter()
        .find(|i| i.ip.to_string() == selected_ip)
    {
        Some(i) => format!("{} \u{00b7} {}", i.name, i.ip),
        None if selected_ip == "127.0.0.1" => "loopback \u{00b7} 127.0.0.1".to_string(),
        None => "all interfaces \u{00b7} 0.0.0.0".to_string(),
    };

    let title = spec.title(&options.read());
    let choices = spec
        .options()
        .iter()
        .filter(|o| matches!(o, Opt::Choice { .. }));
    let ports = spec
        .options()
        .iter()
        .filter(|o| matches!(o, Opt::Port { .. }));

    rsx! {
        div { class: "control-bar",
            div { class: "control-bar__main",
                div { class: "control-bar__top",
                    Link { class: "control-bar__back", to: Route::ModeSelect {}, "\u{2190} Main menu" }
                    div { class: "control-bar__heading",
                        span { class: "control-bar__title", "{title} {mode}" }
                        div { class: "control-bar__meta",
                            span { class: "control-bar__chip",
                                span { class: "control-bar__chip-label", "Interface" }
                                "{iface_label}"
                            }
                            span { class: "control-bar__chip",
                                span { class: "control-bar__chip-label", "Access" }
                                "{access_label}"
                            }
                            span { class: if running() { "control-bar__chip control-bar__chip--on" } else { "control-bar__chip" },
                                span { class: "control-bar__dot" }
                                if running() { "listening" } else { "stopped" }
                            }
                        }
                    }
                    div { class: "control-bar__spacer" }
                    if !running() {
                        button { class: "btn btn--primary", onclick: move |_| on_start.call(()), "Start server" }
                    } else {
                        button { class: "btn btn--danger", onclick: move |_| on_stop.call(()), "Stop server" }
                    }
                }
                div { class: "control-bar__settings",
                    for opt in choices {
                        OptionField { key: "{opt.key()}", protocol, opt, options, disabled: running() }
                    }
                    div { class: "control-bar__field control-bar__field--grow",
                        span { class: "control-bar__label", "Root directory" }
                        div { class: "status-summary__field-row",
                            input {
                                class: "status-summary__input",
                                r#type: "text",
                                value: "{root_dir}",
                                disabled: running(),
                                oninput: move |e| root_dir.set(e.value()),
                            }
                            button {
                                class: "browse-btn",
                                r#type: "button",
                                disabled: running(),
                                onclick: move |_| {
                                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                        root_dir.set(folder.display().to_string());
                                    }
                                },
                                "Browse\u{2026}"
                            }
                        }
                    }
                    for opt in ports {
                        OptionField { key: "{opt.key()}", protocol, opt, options, disabled: running() }
                    }
                    div { class: "control-bar__field",
                        span { class: "control-bar__label", "Type of capture" }
                        div { class: "segmented",
                            button {
                                class: if wire { "btn btn--ghost" } else { "btn btn--ghost btn--on" },
                                r#type: "button",
                                title: "Messages as the server sees them (commands, replies, data), already decrypted",
                                onclick: move |_| view.set(LogView::L7),
                                "L7 capture"
                            }
                            button {
                                class: if wire { "btn btn--ghost btn--on" } else { "btn btn--ghost" },
                                r#type: "button",
                                title: "{wire_title}",
                                disabled: unavailable.is_some(),
                                onclick: move |_| view.set(LogView::Wire),
                                "L7-L2 capture"
                            }
                        }
                        if let Some(note) = (capture.note)() {
                            span { class: if unavailable.is_none() { "status-summary__note status-summary__note--ok" } else { "status-summary__note" }, "{note}" }
                        }
                    }
                }
                if !spec.hints().is_empty() || error_msg().is_some() {
                    div { class: "control-bar__notes",
                        for hint in spec.hints() {
                            span { key: "{hint}", class: "status-hint", "{hint}" }
                        }
                        if let Some(err) = error_msg() {
                            span { class: "status-error", "{err}" }
                        }
                    }
                }
            }
            div { class: "control-bar__clients",
                ClientList { clients, filter }
            }
        }
    }
}
