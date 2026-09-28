use std::net::IpAddr;
use std::path::PathBuf;

use dioxus::prelude::*;
use dioxus_core::Task;

use proto_core::{event_channel, Direction, MessageEvent};
use proto_ftp::{serve, FtpServerConfig};

use crate::{AppState, Route};

#[component]
pub fn Status(mode: String, protocol: String) -> Element {
    let state = use_context::<AppState>();

    let mut root_dir = use_signal(|| "shared".to_string());
    let mut pi_port = use_signal(|| 21u16);
    let mut dtp_port = use_signal(|| 20u16);
    let mut running = use_signal(|| false);
    let mut logs = use_signal(Vec::<MessageEvent>::new);
    let mut server_task = use_signal(|| None::<Task>);
    let mut error_msg = use_signal(|| None::<String>);

    let is_ftp_server = mode == "server" && protocol == "ftp";

    let start_server = move |_| {
        let bind_ip: IpAddr = state
            .interfaces
            .read()
            .iter()
            .find(|iface| Some(iface.name.clone()) == state.selected_interface.read().clone())
            .map(|iface| iface.ip)
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));

        let root = PathBuf::from(root_dir.read().clone());
        if let Err(err) = std::fs::create_dir_all(&root) {
            error_msg.set(Some(format!("Couldn't create root directory: {err}")));
            return;
        }

        let (tx, mut rx) = event_channel();
        let cfg = FtpServerConfig {
            bind_addr: bind_ip,
            control_port: pi_port(),
            pasv_port_start: dtp_port(),
            pasv_port_end: dtp_port(),
            root_dir: root,
        };

        let task = spawn(async move {
            if let Err(err) = serve(cfg, tx).await {
                tracing::error!(%err, "FTP server exited");
            }
        });
        server_task.set(Some(task));

        spawn(async move {
            while let Some(event) = rx.recv().await {
                logs.write().push(event);
            }
        });

        error_msg.set(None);
        running.set(true);
    };

    let stop_server = move |_| {
        if let Some(task) = server_task.write().take() {
            task.cancel();
        }
        running.set(false);
    };

    rsx! {
        section { class: "status-view",
            Link { class: "back-link", to: Route::ModeSelect {}, "\u{2190} start over" }
            h2 { class: "section-title", "Session status" }

            if !is_ftp_server {
                p { class: "section-subtitle",
                    "Only the FTP server is wired up so far — {protocol} for {mode} isn't running yet."
                }
            } else {
                div { class: "status-summary",
                    div { class: "status-summary__item",
                        span { class: "status-summary__label", "Mode" }
                        span { class: "status-summary__value", "{mode}" }
                    }
                    div { class: "status-summary__item",
                        span { class: "status-summary__label", "Protocol" }
                        span { class: "status-summary__value", "FTP" }
                    }
                    div { class: "status-summary__item",
                        span { class: "status-summary__label", "State" }
                        span {
                            class: if running() { "status-summary__value status-summary__value--ok" } else { "status-summary__value status-summary__value--pending" },
                            if running() { "listening" } else { "stopped" }
                        }
                    }
                }

                div { class: "server-config",
                    label { class: "server-config__field",
                        span { "Root directory" }
                        div { class: "server-config__field-row",
                            input {
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
                    label { class: "server-config__field",
                        span { "PI port (control)" }
                        input {
                            r#type: "number",
                            value: "{pi_port}",
                            disabled: running(),
                            oninput: move |e| {
                                if let Ok(v) = e.value().parse() {
                                    pi_port.set(v);
                                }
                            },
                        }
                    }
                    label { class: "server-config__field",
                        span { "DTP port (PASV)" }
                        input {
                            r#type: "number",
                            value: "{dtp_port}",
                            disabled: running(),
                            oninput: move |e| {
                                if let Ok(v) = e.value().parse() {
                                    dtp_port.set(v);
                                }
                            },
                        }
                    }
                }

                if let Some(err) = error_msg() {
                    p { class: "status-error", "{err}" }
                }

                div { class: "server-controls",
                    if !running() {
                        button { class: "btn btn--primary", onclick: start_server, "Start server" }
                    } else {
                        button { class: "btn btn--danger", onclick: stop_server, "Stop server" }
                    }
                }
            }

            div { class: "log-panel",
                if logs.read().is_empty() {
                    p { class: "log-panel__placeholder", "No messages yet." }
                } else {
                    for (i, entry) in logs.read().iter().enumerate() {
                        div { key: "{i}", class: "log-line",
                            span { class: "log-line__dir",
                                if entry.direction == Direction::ClientToServer { "\u{2192}" } else { "\u{2190}" }
                            }
                            span { class: "log-line__peer", "{entry.peer}" }
                            span { class: "log-line__text", "{entry.parsed.clone().unwrap_or_default()}" }
                        }
                    }
                }
            }
        }
    }
}
