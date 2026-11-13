//! # `use_capture` hook
//! ## About:
//! - Starts `proto_core::capture` for the server's address, protocol and ports
//! - Frames are dissected on a spawned task in batches every 50 ms (one signal write per batch)
//!   into a `RollingLog` (oldest packets dropped above `MAX_LOG_ROWS`)
//! - `wire` = pcap view active; if pcap is off or fails (no Npcap, no permission) it stays false
//!   and the page falls back to the event log, the reason is shown in `note`
//! - `stop` drops the `Capture` handle, captured packets stay visible

use std::time::Duration;

use dioxus::prelude::*;
use proto_core::capture::{Capture, CaptureConfig, Dissector, Packet};

use crate::util::RollingLog;

#[derive(Clone, Copy, PartialEq)]
pub struct CaptureState {
    pub packets: Signal<RollingLog<Packet>>,
    pub enabled: Signal<bool>,
    pub wire: Signal<bool>,
    pub note: Signal<Option<String>>,
    live: Signal<Option<Capture>>,
}

pub fn use_capture() -> CaptureState {
    CaptureState {
        packets: use_signal(RollingLog::default),
        enabled: use_signal(|| true),
        wire: use_signal(|| false),
        note: use_signal(|| None),
        live: use_signal(|| None),
    }
}

impl CaptureState {
    pub fn start(&mut self, cfg: CaptureConfig) {
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel();
        let started = match (self.enabled)() {
            true => {
                proto_core::capture::start(&cfg, frame_tx).map_err(|e| format!("unavailable: {e}"))
            }
            false => Err("off".to_string()),
        };
        let cap = match started {
            Ok(cap) => cap,
            Err(err) => {
                self.note
                    .set(Some(format!("{err} - showing the app-level log")));
                self.wire.set(false);
                return;
            }
        };
        self.note
            .set(Some(format!("live on {}", cap.interfaces.join(" + "))));
        self.live.set(Some(cap));
        self.wire.set(true);

        let mut packets = self.packets;
        spawn(async move {
            let mut dissector = Dissector::new(cfg);
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

    pub fn stop(&mut self) {
        if self.live.write().take().is_some() {
            self.note
                .set(Some("stopped - captured frames stay in the log".into()));
        }
    }
}
