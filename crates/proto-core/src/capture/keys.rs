//! # TLS key log
//! ## About:
//! - Process-wide map client_random -> {NSS label -> secret}
//! - Filled by the FTPS server through rustls `KeyLog` (`record_secret`), read by decrypt.rs (`secret`)
//! - `keylog()` exports it in NSS key log format (`LABEL client_random secret`, hex), which
//!   Wireshark accepts as (Pre)-Master-Secret log file
//! - Poisoned mutex is recovered instead of panicking

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{LazyLock, Mutex};

type Secrets = HashMap<String, Vec<u8>>;

static KEYS: LazyLock<Mutex<HashMap<Vec<u8>, Secrets>>> = LazyLock::new(Default::default);

pub fn record_secret(label: &str, client_random: &[u8], secret: &[u8]) {
    let mut keys = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    keys.entry(client_random.to_vec())
        .or_default()
        .insert(label.to_string(), secret.to_vec());
}

pub fn secret(client_random: &[u8], label: &str) -> Option<Vec<u8>> {
    let keys = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    keys.get(client_random)?.get(label).cloned()
}

pub fn keylog() -> String {
    let keys = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    let hex = |b: &[u8]| {
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    };
    let mut out = String::new();
    for (random, secrets) in keys.iter() {
        for (label, secret) in secrets {
            let _ = writeln!(out, "{label} {} {}", hex(random), hex(secret));
        }
    }
    out
}
