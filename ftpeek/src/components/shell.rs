use crate::Route;
use dioxus::prelude::*;

const GITHUB_URL: &str = "https://github.com/SimonVesely/bachelors_thesis";
const LICENSE: &str = "GPL-3.0";
const AUTHOR: &str = "Simon Veselý";

#[component]
pub fn AppShell() -> Element {
    let mut show_info = use_signal(|| false);
    let route = use_route::<Route>();
    let show_header = !matches!(route, Route::Status { .. });

    rsx! {
        div { class: "app-shell",
            if show_header {
                header { class: "app-header",
                    div { class: "app-header__mark" }
                    div { class: "app-header__titles",
                        span { class: "app-header__eyebrow", "VUT FEKT — Semestral project - Application for analyzing the communication of file transfer protocols" }
                        h1 { class: "app-header__title", "FTPeek" }
                    }
                }
            }
            main { class: "app-main",
                Outlet::<Route> {}
            }

            button {
                class: "help-button",
                onclick: move |_| show_info.set(true),
                "?"
            }

            if show_info() {
                div {
                    class: "info-backdrop",
                    onclick: move |_| show_info.set(false),
                    div {
                        class: "info-modal",
                        onclick: move |e| e.stop_propagation(),
                        div { class: "info-modal__header",
                            h3 { class: "info-modal__title", "FTPeek" }
                            button {
                                class: "info-modal__close",
                                onclick: move |_| show_info.set(false),
                                "\u{2715}"
                            }
                        }
                        p { class: "info-modal__desc",
                            "Application for analyzing the communication of file transfer protocols — "
                            "a semester project analyzing FTP, FTPS, TFTP and SFTP client-server "
                            "communication, built at VUT FEKT."
                        }
                        div { class: "info-modal__row",
                            span { class: "info-modal__label", "Author" }
                            span { class: "info-modal__value", "{AUTHOR}" }
                        }
                        div { class: "info-modal__row",
                            span { class: "info-modal__label", "License" }
                            span { class: "info-modal__value", "{LICENSE}" }
                        }
                        div { class: "info-modal__row",
                            span { class: "info-modal__label", "Source" }
                            a {
                                class: "info-modal__link",
                                href: "{GITHUB_URL}",
                                target: "_blank",
                                "{GITHUB_URL}"
                            }
                        }
                        div { class: "info-modal__row info-modal__row--stack",
                            span { class: "info-modal__label", "Built with" }
                            div { class: "info-modal__tags",
                                span { class: "info-modal__tag", "Rust" }
                                span { class: "info-modal__tag", "Tokio" }
                                span { class: "info-modal__tag", "Dioxus" }
                                span { class: "info-modal__tag", "rustls" }
                                span { class: "info-modal__tag", "russh" }
                                span { class: "info-modal__tag", "rcgen" }
                                span { class: "info-modal__tag", "Serde" }
                                span { class: "info-modal__tag", "Tracing" }
                                span { class: "info-modal__tag", "Anyhow/thiserror" }
                                span { class: "info-modal__tag", "Bytes" }
                                span { class: "info-modal__tag", "if-addrs" }
                                span { class: "info-modal__tag", "directories" }
                                span { class: "info-modal__tag", "redb" }
                                span { class: "info-modal__tag", "argon2" }
                            }
                        }
                    }
                }
            }
        }
    }
}
