use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use dioxus::prelude::*;
use tokio::sync::broadcast;

use proto_core::capture::{Capture, CaptureConfig, Dissector, Packet};
use proto_core::{MessageEvent, Protocol, event_channel};
use proto_ftp::FtpServerConfig;
use proto_ftps::{FtpsMode, FtpsServerConfig};
use proto_tftp::TftpServerConfig;

use super::{
    ClientInfo, ClientList, DirectoryPreview, FrameDetail, FrameDiagram, PacketDetail,
    PacketDiagram, PacketLog, track_client,
};
use crate::{AppState, Route};

#[component]
pub fn Status(mode: String, protocol: String) -> Element {
    let state = use_context::<AppState>();

    let is_ftps = protocol == "ftps";
    let is_tftp = protocol == "tftp";
    let is_supported = mode == "server" && (protocol == "ftp" || is_ftps || is_tftp);
    let default_port: u16 = if is_tftp { 69 } else { 21 };

    let mut root_dir = use_signal(|| "shared".to_string());
    let mut pi_port = use_signal(move || default_port);
    let mut dtp_port = use_signal(|| 20u16);
    let mut running = use_signal(|| false);
    let mut logs = use_signal(Vec::<MessageEvent>::new);
    let mut selected = use_signal(|| None::<usize>);
    let mut clients = use_signal(Vec::<ClientInfo>::new);
    let filter = use_signal(|| None::<u64>);
    let mut error_msg = use_signal(|| None::<String>);
    let mut shutdown_tx = use_signal(|| None::<broadcast::Sender<()>>);
    let mut ftps_implicit = use_signal(|| false);
    let mut tftp_allow_write = use_signal(|| true);
    let mut packets = use_signal(Vec::<Packet>::new);
    let mut use_pcap = use_signal(|| true);
    let mut wire = use_signal(|| false);
    let mut capture = use_signal(|| None::<Capture>);
    let mut capture_note = use_signal(|| None::<String>);
    let decrypt = use_signal(|| false);

    let access_label = if is_tftp {
        "none (TFTP has no login)".to_string()
    } else if (state.anonymous)() {
        "anonymous".to_string()
    } else {
        format!("{} user(s)", state.user_names.read().len())
    };

    let protocol_label = if is_tftp {
        "TFTP"
    } else if !is_ftps {
        "FTP"
    } else if ftps_implicit() {
        "FTPS (implicit)"
    } else {
        "FTPS (explicit)"
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

    let start_server = move |_| {
        let bind_ip: IpAddr = state
            .interfaces
            .read()
            .iter()
            .find(|iface| Some(iface.ip.to_string()) == *state.selected_interface.read())
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

        let users = if is_tftp || (state.anonymous)() {
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

        let tftp_cfg = TftpServerConfig {
            bind_addr: bind_ip,
            port: pi_port(),
            root_dir: root.clone(),
            allow_write: tftp_allow_write(),
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

        let capture_cfg = CaptureConfig {
            server_ip: bind_ip,
            protocol: match (is_tftp, is_ftps) {
                (true, _) => Protocol::Tftp,
                (_, true) => Protocol::Ftps,
                _ => Protocol::Ftp,
            },
            ports: if is_tftp {
                vec![pi_port()]
            } else {
                vec![pi_port(), dtp_port()]
            },
        };
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel();
        let started = match use_pcap() {
            true => proto_core::capture::start(&capture_cfg, frame_tx)
                .map_err(|e| format!("unavailable: {e}")),
            false => Err("off".to_string()),
        };
        selected.set(None);
        match started {
            Ok(cap) => {
                capture_note.set(Some(format!("live on {}", cap.interfaces.join(" + "))));
                capture.set(Some(cap));
                wire.set(true);
                spawn(async move {
                    let mut dissector = Dissector::new(capture_cfg);
                    while let Some(frame) = frame_rx.recv().await {
                        let mut batch: Vec<Packet> = dissector.dissect(frame).into_iter().collect();
                        while let Ok(frame) = frame_rx.try_recv() {
                            batch.extend(dissector.dissect(frame));
                        }
                        if !batch.is_empty() {
                            packets.write().extend(batch);
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });
            }
            Err(err) => {
                capture_note.set(Some(format!("{err} - showing the app-level log")));
                wire.set(false);
            }
        }

        spawn(async move {
            let result = if is_tftp {
                proto_tftp::serve(tftp_cfg, tx, shutdown_recv).await
            } else if is_ftps {
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
            if capture.write().take().is_some() {
                capture_note.set(Some("stopped - captured frames stay in the log".into()));
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
            if !is_supported {
                Link { class: "back-link", to: Route::ModeSelect {}, "\u{2190} main menu" }
                p { class: "section-subtitle",
                    "Only the FTP, FTPS and TFTP servers are wired up so far - {protocol} for {mode} isn't running yet."
                }
            } else {
                div { class: "control-bar",
                    div { class: "control-bar__main",
                    div { class: "control-bar__top",
                        Link { class: "control-bar__back", to: Route::ModeSelect {}, "\u{2190} Main menu" }
                        div { class: "control-bar__heading",
                            span { class: "control-bar__title", "{protocol_label} {mode}" }
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
                            button { class: "btn btn--primary", onclick: start_server, "Start server" }
                        } else {
                            button { class: "btn btn--danger", onclick: stop_server, "Stop server" }
                        }
                    }
                    div { class: "control-bar__settings",
                        if is_ftps {
                            label { class: "control-bar__field",
                                span { class: "control-bar__label", "FTPS mode" }
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
                                    option { value: "explicit", "Explicit - AUTH TLS" }
                                    option { value: "implicit", "Implicit - TLS from first byte" }
                                }
                            }
                        }
                        if is_tftp {
                            label { class: "control-bar__field",
                                span { class: "control-bar__label", "Uploads (WRQ)" }
                                select {
                                    class: "status-summary__input",
                                    disabled: running(),
                                    value: if tftp_allow_write() { "allow" } else { "deny" },
                                    onchange: move |e| tftp_allow_write.set(e.value() == "allow"),
                                    option { value: "allow", "Allowed" }
                                    option { value: "deny", "Disabled (read only)" }
                                }
                            }
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
                        label { class: "control-bar__field control-bar__field--port",
                            span { class: "control-bar__label", if is_tftp { "Port (UDP)" } else { "PI port" } }
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
                        if !is_tftp {
                            label { class: "control-bar__field control-bar__field--port",
                                span { class: "control-bar__label", "DTP port" }
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
                        }
                        div { class: "control-bar__field",
                            span { class: "control-bar__label", "Packet capture" }
                            label { class: "status-summary__check",
                                input {
                                    r#type: "checkbox",
                                    checked: use_pcap(),
                                    disabled: running(),
                                    onchange: move |e| use_pcap.set(e.checked()),
                                }
                                "pcap (Wireshark view)"
                            }
                            if let Some(note) = capture_note() {
                                span { class: if wire() { "status-summary__note status-summary__note--ok" } else { "status-summary__note" }, "{note}" }
                            }
                        }
                    }
                    if is_tftp || is_ftps || error_msg().is_some() {
                        div { class: "control-bar__notes",
                            if is_tftp {
                                span { class: "status-hint", "TFTP has no login: anyone who reaches this port can download every file in the root directory." }
                            }
                            if is_ftps {
                                span { class: "status-hint", "A self-signed certificate is generated on every start - the client will ask you to trust it." }
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

                div { class: "status-grid status-grid--wide",
                    div { class: "status-grid__cell status-grid__cell--log",
                        PacketLog { logs, packets, wire, selected, clients, filter, decrypt, can_decrypt: is_ftps && wire() }
                    }
                    div { class: "status-grid__cell status-grid__cell--split",
                        div { class: "status-grid__sub status-grid__sub--row",
                            div { class: "status-grid__sub status-grid__sub--detail",
                                if wire() {
                                    FrameDetail { packets, selected, decrypt }
                                } else {
                                    PacketDetail { logs, selected }
                                }
                            }
                            div { class: "status-grid__sub status-grid__sub--dir",
                                DirectoryPreview { root_dir, logs }
                            }
                        }
                        div { class: "status-grid__sub",
                            if wire() {
                                FrameDiagram { packets, selected }
                            } else {
                                PacketDiagram { logs, selected }
                            }
                        }
                    }
                }
            }
        }
    }
}
