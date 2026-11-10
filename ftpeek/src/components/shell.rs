use crate::Route;
use dioxus::prelude::*;

const GITHUB_URL: &str = "https://github.com/SimonVesely/bachelors_thesis";
const LICENSE: &str = "GPL-3.0";
const AUTHOR: &str = "Simon Veselý";
const BUILT_WITH: [&str; 13] = [
    "Rust",
    "Tokio",
    "Dioxus",
    "rustls",
    "russh",
    "rcgen",
    "pcap",
    "Tracing",
    "Bytes",
    "if-addrs",
    "directories",
    "redb",
    "argon2",
];

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
                        span { class: "app-header__eyebrow", "VUT FEKT \u{2014} Semester project \u{2014} Application for analyzing the communication of file transfer protocols" }
                        h1 { class: "app-header__title", "FTPeek" }
                    }
                }
            }
            main { class: "app-main",
                Outlet::<Route> {}
            }

            button {
                class: "help-button",
                title: "About FTPeek",
                onclick: move |_| show_info.set(true),
                "?"
            }

            if show_info() {
                div {
                    class: "info-backdrop",
                    onclick: move |_| show_info.set(false),
                    onkeydown: move |e| {
                        if e.key() == Key::Escape {
                            show_info.set(false);
                        }
                    },
                    div {
                        class: "info-modal",
                        tabindex: "-1",
                        onmounted: move |e| async move {
                            let _ = e.set_focus(true).await;
                        },
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
                            "Application for analyzing the communication of file transfer protocols \u{2014} "
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
                                for name in BUILT_WITH {
                                    span { key: "{name}", class: "info-modal__tag", "{name}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
