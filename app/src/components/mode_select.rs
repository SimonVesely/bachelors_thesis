use crate::components::UserManager;
use crate::{AppState, Route};
use dioxus::prelude::*;

#[component]
pub fn ModeSelect() -> Element {
    let mut state = use_context::<AppState>();
    let interfaces = state.interfaces.read().clone();
    let selected = state.selected_interface.read().clone();
    let mut show_users = use_signal(|| false);

    let anonymous = (state.anonymous)();
    let user_count = state.user_names.read().len();
    let db_ok = state.users.read().is_ok();

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

            div { class: "access-panel",
                h3 { class: "interface-picker__title", "User access" }
                div { class: "access-panel__row",
                    label { class: "access-toggle",
                        input {
                            r#type: "checkbox",
                            checked: anonymous,
                            onchange: move |e| state.anonymous.set(e.checked()),
                        }
                        span { class: "access-toggle__track",
                            span { class: "access-toggle__thumb" }
                        }
                        span { class: "access-toggle__label", "Anonymous access" }
                    }
                    button {
                        class: "browse-btn",
                        onclick: move |_| show_users.set(true),
                        "Manage users"
                    }
                }
                if anonymous {
                    p { class: "access-panel__hint",
                        "Any user name and password is accepted. The user database is ignored."
                    }
                } else if !db_ok {
                    p { class: "access-panel__hint access-panel__hint--warn",
                        "The user database could not be opened - open Manage users for details."
                    }
                } else if user_count == 0 {
                    p { class: "access-panel__hint access-panel__hint--warn",
                        "No users yet - nobody will be able to log in. Add one in Manage users."
                    }
                } else {
                    p { class: "access-panel__hint",
                        "Only the {user_count} registered user(s) can log in."
                    }
                }
            }

            if show_users() {
                UserManager { on_close: move |_| show_users.set(false) }
            }
        }
    }
}
