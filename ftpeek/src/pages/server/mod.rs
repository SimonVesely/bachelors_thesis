mod capture;
mod control_bar;

use std::net::IpAddr;
use std::path::PathBuf;

use dioxus::prelude::*;
use proto_core::capture::CaptureConfig;
use proto_core::{MessageEvent, event_channel};
use tokio::sync::broadcast;

use crate::components::{
    ClientInfo, DirectoryPreview, FrameDetail, FrameDiagram, PacketDetail, PacketDiagram,
    PacketLog, track_client,
};
use crate::protocols::{Options, Proto, ServeCtx};
use crate::{AppState, Route};

use capture::use_capture;
use control_bar::ControlBar;

#[component]
pub fn Status(mode: String, protocol: Proto) -> Element {
    let state = use_context::<AppState>();
    let spec = protocol.spec();

    let root_dir = use_signal(|| "shared".to_string());
    let options = use_signal(|| Options::defaults(spec));
    let mut running = use_signal(|| false);
    let mut logs = use_signal(Vec::<MessageEvent>::new);
    let mut selected = use_signal(|| None::<usize>);
    let mut clients = use_signal(Vec::<ClientInfo>::new);
    let filter = use_signal(|| None::<u64>);
    let mut error_msg = use_signal(|| None::<String>);
    let mut shutdown_tx = use_signal(|| None::<broadcast::Sender<()>>);
    let decrypt = use_signal(|| false);
    let mut capture = use_capture();
    let packets = capture.packets;
    let wire = capture.wire;

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

        let (tx, mut rx) = event_channel();
        let (shutdown_send, shutdown_recv) = broadcast::channel(4);
        shutdown_tx.set(Some(shutdown_send));

        selected.set(None);
        capture.start(CaptureConfig {
            server_ip: bind_ip,
            protocol: spec.core(),
            ports: spec.capture_ports(&options.read()),
        });

        let server = spec.serve(ServeCtx {
            bind: bind_ip,
            root,
            users,
            opts: options(),
            events: tx,
            shutdown: shutdown_recv,
        });
        spawn(async move {
            if let Err(err) = server.await {
                error_msg.set(Some(format!("Server error: {err}")));
            }
            capture.stop();
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

    if mode != "server" {
        return rsx! {
            section { class: "status-view",
                Link { class: "back-link", to: Route::ModeSelect {}, "\u{2190} main menu" }
                p { class: "section-subtitle",
                    "Only the server mode is wired up so far - {spec.label()} for {mode} isn't running yet."
                }
            }
        };
    }

    rsx! {
        section { class: "status-view",
            ControlBar {
                protocol,
                mode,
                options,
                root_dir,
                running,
                capture,
                error_msg,
                clients,
                filter,
                on_start: start_server,
                on_stop: stop_server,
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
