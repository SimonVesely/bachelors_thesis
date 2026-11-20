//! # `use_capture` hook
//! ## About:
//! - `LogView` = what the log panes show: `L7` (the server's `MessageEvent` log) or `Wire`
//!   (L7-L2, pcap frames dissected like Wireshark)
//! - `probe()` runs once when the page opens; if pcap can't work (no Npcap, no permission to
//!   the capture device) `unavailable` holds the reason and the L7-L2 button is disabled
//! - While the server runs, pcap captures whenever it is available, no matter which view is
//!   selected. Both logs are always filled, so switching the view is instant even mid-transfer
//!   and the pcap log is complete (TCP handshake, TLS handshake needed for decryption)
//! - Start re-checks availability: success clears `unavailable`, an error sets it and the page
//!   falls back to the L7 view, the reason is shown in `note`
//! - Frames are dissected on a spawned task in batches every 50 ms (one signal write per batch)
//!   into a `RollingLog` (oldest packets dropped above `MAX_LOG_ROWS`)
//! - `stop` drops the `Capture` handle, captured packets stay visible

use std::time::Duration;

use dioxus::prelude::*;
use proto_core::capture::{Capture, CaptureConfig, Dissector, Packet};

use crate::util::RollingLog;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogView {
    L7,
    Wire,
}

#[derive(Clone, Copy, PartialEq)]
pub struct CaptureState {
    pub packets: Signal<RollingLog<Packet>>,
    pub view: Signal<LogView>,
    pub unavailable: Signal<Option<String>>,
    pub note: Signal<Option<String>>,
    live: Signal<Option<Capture>>,
}

pub fn use_capture() -> CaptureState {
    let probe = use_hook(|| proto_core::capture::probe().err());
    let note = probe.as_ref().map(|err| format!("pcap unavailable: {err}"));
    let wire_ok = probe.is_none();
    CaptureState {
        packets: use_signal(RollingLog::default),
        view: use_signal(|| if wire_ok { LogView::Wire } else { LogView::L7 }),
        unavailable: use_signal(|| probe),
        note: use_signal(|| note),
        live: use_signal(|| None),
    }
}

impl CaptureState {
    pub fn shows_wire(&self) -> bool {
        (self.view)() == LogView::Wire && self.unavailable.read().is_none()
    }

    pub fn start(&mut self, cfg: CaptureConfig) {
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel();
        let cap = match proto_core::capture::start(&cfg, frame_tx) {
            Ok(cap) => cap,
            Err(err) => {
                self.note.set(Some(format!("pcap unavailable: {err}")));
                self.unavailable.set(Some(err));
                return;
            }
        };
        self.note
            .set(Some(format!("capture on {}", cap.interfaces.join(" + "))));
        self.unavailable.set(None);
        self.live.set(Some(cap));

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
            self.note.set(Some("Capture stopped".into()));
        }
    }
}
