//! # Shared helpers
//! ## About:
//! - `RollingLog<T>` - storage of the event log and captured packets (ring buffer)
//!   - holds at most `MAX_LOG_ROWS` (100 000) rows and `MAX_LOG_BYTES` (256 MiB), whichever
//!     is hit first, so memory stays bounded on long sessions and with large frames
//!   - when full, the oldest rows are dropped in one go down to 90 % of both limits - new
//!     traffic is always visible, rows aren't shifted on every packet
//!   - `dropped` counts removed rows: `No.` keeps counting (`dropped + index + 1`) and the
//!     selection is an absolute index, so a selected row never turns into a different packet
//!     (`get_abs` returns `None` once it was dropped)
//!   - `start` is the time of the very first row, so the Time column doesn't jump after a drop
//!   - derefs to `[T]` for reading; `clear` resets everything (Clear button)
//! - `Timed` - rows that carry their timestamp and approximate size (`MessageEvent`, `Packet`)
//! - `shorten` / `shorten_start` - truncate by chars with `...` / `…` (paths keep their end)
//! - `plural` - `1 user` / `3 users`

use std::ops::Deref;
use std::time::SystemTime;

use proto_core::MessageEvent;
use proto_core::capture::Packet;

pub const MAX_LOG_ROWS: usize = 100_000;
const DROP_CHUNK: usize = MAX_LOG_ROWS / 10;
pub const MAX_LOG_BYTES: usize = 256 << 20;

pub trait Timed {
    fn timestamp(&self) -> SystemTime;
    fn bytes(&self) -> usize;
}

impl Timed for MessageEvent {
    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    fn bytes(&self) -> usize {
        size_of::<Self>() + self.raw.len() + self.parsed.as_ref().map_or(0, String::len)
    }
}

impl Timed for Packet {
    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    fn bytes(&self) -> usize {
        size_of::<Self>()
            + self.data.len()
            + self.info.len()
            + self.decrypted.iter().map(|p| p.data.len()).sum::<usize>()
    }
}

pub struct RollingLog<T> {
    rows: Vec<T>,
    dropped: usize,
    bytes: usize,
    start: Option<SystemTime>,
}

impl<T> Default for RollingLog<T> {
    fn default() -> Self {
        RollingLog {
            rows: Vec::new(),
            dropped: 0,
            bytes: 0,
            start: None,
        }
    }
}

impl<T: Timed> RollingLog<T> {
    pub fn push(&mut self, row: T) {
        self.extend([row]);
    }

    pub fn extend(&mut self, rows: impl IntoIterator<Item = T>) {
        for row in rows {
            self.start.get_or_insert(row.timestamp());
            self.bytes += row.bytes();
            self.rows.push(row);
        }
        if self.rows.len() <= MAX_LOG_ROWS && self.bytes <= MAX_LOG_BYTES {
            return;
        }
        let keep_rows = MAX_LOG_ROWS - DROP_CHUNK;
        let keep_bytes = MAX_LOG_BYTES - MAX_LOG_BYTES / 10;
        let (mut n, mut freed) = (0, 0);
        while n < self.rows.len()
            && (self.rows.len() - n > keep_rows || self.bytes - freed > keep_bytes)
        {
            freed += self.rows[n].bytes();
            n += 1;
        }
        self.rows.drain(..n);
        self.bytes -= freed;
        self.dropped += n;
    }
}

impl<T> RollingLog<T> {
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn dropped(&self) -> usize {
        self.dropped
    }

    pub fn start(&self) -> SystemTime {
        self.start.unwrap_or(SystemTime::UNIX_EPOCH)
    }

    pub fn get_abs(&self, index: usize) -> Option<&T> {
        self.rows.get(index.checked_sub(self.dropped)?)
    }
}

impl<T> Deref for RollingLog<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.rows
    }
}

pub fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        let truncated: String = text.chars().take(max - 3).collect();
        format!("{truncated}...")
    } else {
        text.to_string()
    }
}

pub fn shorten_start(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count > max {
        let tail: String = text.chars().skip(count - (max - 1)).collect();
        format!("\u{2026}{tail}")
    } else {
        text.to_string()
    }
}

pub fn plural(count: usize, word: &str) -> String {
    match count {
        1 => format!("1 {word}"),
        n => format!("{n} {word}s"),
    }
}
