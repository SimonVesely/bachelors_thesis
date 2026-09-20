use crate::{AppState, Route};
use dioxus::prelude::*;

#[component]
pub fn ModeSelect() -> Element {
    let mut state = use_context::<AppState>();
    let interfaces = state.interfaces.read().clone();
    let selected = state.selected_interface.read().clone();

    rsx! {
        section { class: "mode-select",
            h2 { class: "section-title", "Choose application mode" }
            p { class: "section-subtitle",
                "Select how this instance of the app should run."
            }
            div { class: "mode-grid",
                Link {
                    class: "mode-card mode-card--server",
                    to: Route::ProtocolSelect { mode: "server".to_string() },
                    span { class: "mode-card__label", "Server only" }
                    span { class: "mode-card__desc",
                        "Run a protocol server that other clients (FileZilla, curl, ...) connect to."
                    }
                }
                Link {
                    class: "mode-card mode-card--client",
                    to: Route::Unavailable { mode: "client".to_string() },
                    span { class: "mode-card__label", "Client only" }
                    span { class: "mode-card__desc",
                        "Connect to an existing server as a client and log the exchange."
                    }
                }
                Link {
                    class: "mode-card mode-card--fold",
                    to: Route::Unavailable { mode: "fold".to_string() },
                    span { class: "mode-card__label", "Fold" }
                    span { class: "mode-card__desc",
                        "Server + client together — run and inspect a full session locally."
                    }
                }
            }

            div { class: "interface-picker",
                h3 { class: "interface-picker__title", "Network interface" }
                if interfaces.is_empty() {
                    p { class: "interface-picker__empty", "No non-loopback interfaces found." }
                } else {
                    select {
                        class: "interface-picker__select",
                        value: "{selected.clone().unwrap_or_default()}",
                        onchange: move |evt| {
                            state.selected_interface.set(Some(evt.value()));
                        },
                        for iface in interfaces.iter() {
                            option {
                                key: "{iface.name}",
                                value: "{iface.name}",
                                "{iface.name} — {iface.ip}"
                            }
                        }
                    }
                }
            }
        }
    }
}
