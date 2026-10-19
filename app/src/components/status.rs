use std::net::IpAddr;
use std::path::PathBuf;

use dioxus::prelude::*;
use tokio::sync::broadcast;

use proto_core::{MessageEvent, event_channel};
use proto_ftp::FtpServerConfig;
use proto_ftps::{FtpsMode, FtpsServerConfig};

use super::{
    ClientInfo, ClientList, DirectoryPreview, PacketDetail, PacketDiagram, PacketLog, track_client,
};
use crate::{AppState, Route};

#[component]
pub fn Status(mode: String, protocol: String) -> Element {
    let state = use_context::<AppState>();

    let mut root_dir = use_signal(|| "shared".to_string());
    let mut pi_port = use_signal(|| 21u16);
    let mut dtp_port = use_signal(|| 20u16);
    let mut running = use_signal(|| false);
    let mut logs = use_signal(Vec::<MessageEvent>::new);
    let selected = use_signal(|| None::<usize>);
    let mut clients = use_signal(Vec::<ClientInfo>::new);
    let filter = use_signal(|| None::<u64>);
    let mut error_msg = use_signal(|| None::<String>);
    let mut shutdown_tx = use_signal(|| None::<broadcast::Sender<()>>);
    let mut ftps_implicit = use_signal(|| false);

    let is_ftps = protocol == "ftps";
    let is_supported = mode == "server" && (protocol == "ftp" || is_ftps);

    let access_label = if (state.anonymous)() {
        "anonymous".to_string()
    } else {
        format!("{} user(s)", state.user_names.read().len())
    };

    let protocol_label = if !is_ftps {
        "FTP"
    } else if ftps_implicit() {
        "FTPS (implicit)"
    } else {
        "FTPS (explicit)"
    };

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
        let (shutdown_send, shutdown_recv) = broadcast::channel(4);
        shutdown_tx.set(Some(shutdown_send));

        let users = if (state.anonymous)() {
            None
        } else {
            match &*state.users.read() {
                Ok(store) => Some(store.db.clone()),
                Err(e) => {
                    error_msg.set(Some(format!("User database unavailable: {e}")));
                    return;
                }
            }
        };

        let cfg = FtpServerConfig {
            bind_addr: bind_ip,
            control_port: pi_port(),
            pasv_port_start: dtp_port(),
            pasv_port_end: dtp_port(),
            root_dir: root,
            users,
        };
        let ftps_mode = if ftps_implicit() {
            FtpsMode::Implicit
        } else {
            FtpsMode::Explicit
        };

        spawn(async move {
            let result = if is_ftps {
                proto_ftps::serve(
                    FtpsServerConfig {
                        ftp: cfg,
                        mode: ftps_mode,
                    },
                    tx,
                    shutdown_recv,
                )
                .await
            } else {
                proto_ftp::serve(cfg, tx, shutdown_recv).await
            };
            if let Err(err) = result {
                error_msg.set(Some(format!("Server error: {err}")));
            }
            running.set(false);
        });

        spawn(async move {
            while let Some(event) = rx.recv().await {
                track_client(&mut clients.write(), &event);
                logs.write().push(event);
            }
        });

        error_msg.set(None);
        running.set(true);
    };

    let stop_server = move |_| {
        if let Some(tx) = shutdown_tx.write().take() {
            let _ = tx.send(());
        }
    };

    rsx! {
        section { class: "status-view",
            Link { class: "back-link", to: Route::ModeSelect {}, "\u{2190} start over" }
            h2 { class: "section-title", "Session status" }

            if !is_supported {
                p { class: "section-subtitle",
                    "Only the FTP and FTPS servers are wired up so far - {protocol} for {mode} isn't running yet."
                }
            } else {
                div { class: "status-grid",
                    div { class: "status-grid__cell",
                        div { class: "status-summary",
                            div { class: "status-summary__item",
                                span { class: "status-summary__label", "Mode" }
                                span { class: "status-summary__value", "{mode}" }
                            }
                            div { class: "status-summary__item",
                                span { class: "status-summary__label", "Protocol" }
                                span { class: "status-summary__value", "{protocol_label}" }
                            }
                            div { class: "status-summary__item",
                                span { class: "status-summary__label", "Access" }
                                span { class: "status-summary__value", "{access_label}" }
                            }
                            div { class: "status-summary__item",
                                span { class: "status-summary__label", "State" }
                                span {
                                    class: if running() { "status-summary__value status-summary__value--ok" } else { "status-summary__value status-summary__value--pending" },
                                    if running() { "listening" } else { "stopped" }
                                }
                            }
                            div { class: "status-summary__item status-summary__item--action",
                                if !running() {
                                    button { class: "btn btn--primary", onclick: start_server, "Start server" }
                                } else {
                                    button { class: "btn btn--danger", onclick: stop_server, "Stop server" }
                                }
                            }
                            if is_ftps {
                                div { class: "status-summary__item status-summary__item--wide",
                                    span { class: "status-summary__label", "FTPS mode" }
                                    select {
                                        class: "status-summary__input",
                                        disabled: running(),
                                        value: if ftps_implicit() { "implicit" } else { "explicit" },
                                        onchange: move |e| {
                                            let implicit = e.value() == "implicit";
                                            ftps_implicit.set(implicit);
                                            if implicit && pi_port() == 21 {
                                                pi_port.set(990);
                                            } else if !implicit && pi_port() == 990 {
                                                pi_port.set(21);
                                            }
                                        },
                                        option { value: "explicit", "Explicit - AUTH TLS (RFC 4217)" }
                                        option { value: "implicit", "Implicit - legacy, TLS from the first byte" }
                                    }
                                }
                            }
                            div { class: "status-summary__item status-summary__item--wide",
                                span { class: "status-summary__label", "Root directory" }
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
                            div { class: "status-summary__item",
                                span { class: "status-summary__label", "PI port (control)" }
                                input {
                                    class: "status-summary__input",
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
                            div { class: "status-summary__item",
                                span { class: "status-summary__label", "DTP port (PASV)" }
                                input {
                                    class: "status-summary__input",
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
                            if is_ftps {
                                p { class: "status-hint",
                                    "A self-signed certificate is generated on every start - the client will ask you to trust it."
                                }
                            }
                            if let Some(err) = error_msg() {
                                p { class: "status-error", "{err}" }
                            }
                        }
                    }

                    div { class: "status-grid__cell status-grid__cell--row",
                        div { class: "status-grid__sub",
                            DirectoryPreview { root_dir, logs }
                        }
                        div { class: "status-grid__sub",
                            ClientList { clients, filter }
                        }
                    }

                    div { class: "status-grid__cell",
                        PacketLog { logs, selected, clients, filter }
                    }

                    div { class: "status-grid__cell status-grid__cell--split",
                        div { class: "status-grid__sub",
                            PacketDetail { logs, selected }
                        }
                        div { class: "status-grid__sub",
                            PacketDiagram { logs, selected }
                        }
                    }
                }
            }
        }
    }
}
