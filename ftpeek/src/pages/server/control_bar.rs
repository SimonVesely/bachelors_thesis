use dioxus::prelude::*;

use super::capture::CaptureState;
use crate::components::{ClientInfo, ClientList, OptionField};
use crate::protocols::{Opt, Options, Proto};
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
    let mut enabled = capture.enabled;

    let access_label = if !spec.login() {
        format!("none ({} has no login)", spec.label())
    } else if (state.anonymous)() {
        "anonymous".to_string()
    } else {
        format!("{} user(s)", state.user_names.read().len())
    };
    let iface_label = state
        .selected_interface
        .read()
        .as_ref()
        .and_then(|ip| {
            state
                .interfaces
                .read()
                .iter()
                .find(|i| &i.ip.to_string() == ip)
                .map(|i| format!("{} \u{00b7} {}", i.name, i.ip))
        })
        .unwrap_or_else(|| "all interfaces \u{00b7} 0.0.0.0".to_string());

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
                        span { class: "control-bar__label", "Packet capture" }
                        label { class: "status-summary__check",
                            input {
                                r#type: "checkbox",
                                checked: enabled(),
                                disabled: running(),
                                onchange: move |e| enabled.set(e.checked()),
                            }
                            "pcap (Wireshark view)"
                        }
                        if let Some(note) = (capture.note)() {
                            span { class: if (capture.wire)() { "status-summary__note status-summary__note--ok" } else { "status-summary__note" }, "{note}" }
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
