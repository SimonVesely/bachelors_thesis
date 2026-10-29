use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use dioxus::prelude::*;
use tokio::sync::broadcast;

use proto_core::capture::{Capture, CaptureConfig, Dissector, Packet};
use proto_core::{MessageEvent, event_channel};

use super::{
    ClientInfo, ClientList, DirectoryPreview, FrameDetail, FrameDiagram, OptionField, PacketDetail,
    PacketDiagram, PacketLog, track_client,
};
use crate::protocols::{Opt, Options, Proto, ServeCtx};
use crate::{AppState, Route};

#[component]
pub fn Status(mode: String, protocol: Proto) -> Element {
    let state = use_context::<AppState>();
    let spec = protocol.spec();
    let is_supported = mode == "server";

    let mut root_dir = use_signal(|| "shared".to_string());
    let options = use_signal(|| Options::defaults(spec));
    let mut running = use_signal(|| false);
    let mut logs = use_signal(Vec::<MessageEvent>::new);
    let mut selected = use_signal(|| None::<usize>);
    let mut clients = use_signal(Vec::<ClientInfo>::new);
    let filter = use_signal(|| None::<u64>);
    let mut error_msg = use_signal(|| None::<String>);
    let mut shutdown_tx = use_signal(|| None::<broadcast::Sender<()>>);
    let mut packets = use_signal(Vec::<Packet>::new);
    let mut use_pcap = use_signal(|| true);
    let mut wire = use_signal(|| false);
    let mut capture = use_signal(|| None::<Capture>);
    let mut capture_note = use_signal(|| None::<String>);
    let decrypt = use_signal(|| false);

    let access_label = if !spec.login() {
        format!("none ({} has no login)", spec.label())
    } else if (state.anonymous)() {
        "anonymous".to_string()
    } else {
        format!("{} user(s)", state.user_names.read().len())
    };

    let protocol_label = spec.title(&options.read());
    let choices = spec
        .options()
        .iter()
        .filter(|o| matches!(o, Opt::Choice { .. }));
    let ports = spec
        .options()
        .iter()
        .filter(|o| matches!(o, Opt::Port { .. }));

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

        let users = if !spec.login() || (state.anonymous)() {
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

        let capture_cfg = CaptureConfig {
            server_ip: bind_ip,
            protocol: spec.core(),
            ports: spec.capture_ports(&options.read()),
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

        let server = spec.serve(ServeCtx {
            bind: bind_ip,
            root,
            users,
            opts: options(),
            events: tx,
            shutdown: shutdown_recv,
        });
        spawn(async move {
            let result = server.await;
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
                    "Only the server mode is wired up so far - {spec.label()} for {mode} isn't running yet."
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

                div { class: "status-grid status-grid--wide",
                    div { class: "status-grid__cell status-grid__cell--log",
                        PacketLog { logs, packets, wire, selected, clients, filter, decrypt, can_decrypt: spec.can_decrypt() && wire() }
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
