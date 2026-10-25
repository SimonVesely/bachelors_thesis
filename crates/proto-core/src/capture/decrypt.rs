use ring::{aead, hkdf, hmac};

use super::keys;
use super::tls::Hello;

#[derive(Debug, Clone)]
pub struct Plain {
    pub content_type: u8,
    pub data: Vec<u8>,
    pub secret: &'static str,
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Epoch {
    #[default]
    Clear,
    Handshake,
    Application,
}

struct Key {
    aead: aead::LessSafeKey,
    iv: [u8; 12],
    explicit_nonce: bool,
}

#[derive(Default)]
struct Direction {
    epoch: Epoch,
    seq: u64,
    key: Option<Key>,
}

#[derive(Default)]
pub struct Session {
    client_random: Option<Vec<u8>>,
    server_random: Option<Vec<u8>>,
    version: Option<u16>,
    suite: Option<u16>,
    dirs: [Direction; 2],
}

struct Suite {
    aead: &'static aead::Algorithm,
    key_len: usize,
    hkdf: hkdf::Algorithm,
    hmac: hmac::Algorithm,
    explicit_nonce: bool,
}

fn suite(id: u16) -> Option<Suite> {
    use aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
    let (aead, key_len, sha384, explicit_nonce) = match id {
        0x1301 => (&AES_128_GCM, 16, false, false),
        0x1302 => (&AES_256_GCM, 32, true, false),
        0x1303 => (&CHACHA20_POLY1305, 32, false, false),
        0xc02b | 0xc02f => (&AES_128_GCM, 16, false, true),
        0xc02c | 0xc030 => (&AES_256_GCM, 32, true, true),
        0xcca8 | 0xcca9 => (&CHACHA20_POLY1305, 32, false, false),
        _ => return None,
    };
    let (hkdf, hmac) = match sha384 {
        true => (hkdf::HKDF_SHA384, hmac::HMAC_SHA384),
        false => (hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    };
    Some(Suite {
        aead,
        key_len,
        hkdf,
        hmac,
        explicit_nonce,
    })
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label(alg: hkdf::Algorithm, secret: &[u8], label: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut info = Vec::new();
    info.extend((len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend(b"tls13 ");
    info.extend(label);
    info.push(0);
    let mut out = vec![0; len];
    let prk = hkdf::Prk::new_less_safe(alg, secret);
    prk.expand(&[&info], Len(len)).ok()?.fill(&mut out).ok()?;
    Some(out)
}

fn prf(alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let key = hmac::Key::new(alg, secret);
    let seed = [label, seed].concat();
    let mut a = hmac::sign(&key, &seed).as_ref().to_vec();
    let mut out = Vec::new();
    while out.len() < len {
        out.extend(hmac::sign(&key, &[a.as_slice(), &seed].concat()).as_ref());
        a = hmac::sign(&key, &a).as_ref().to_vec();
    }
    out.truncate(len);
    out
}

fn make_key(suite: &Suite, key: &[u8], iv: &[u8]) -> Option<Key> {
    let mut nonce = [0u8; 12];
    nonce[..iv.len()].copy_from_slice(iv);
    let unbound = aead::UnboundKey::new(suite.aead, key).ok()?;
    Some(Key {
        aead: aead::LessSafeKey::new(unbound),
        iv: nonce,
        explicit_nonce: suite.explicit_nonce,
    })
}

fn label(dir: usize, epoch: Epoch, tls12: bool) -> &'static str {
    match (tls12, dir, epoch) {
        (true, _, _) => "CLIENT_RANDOM",
        (false, 0, Epoch::Handshake) => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        (false, _, Epoch::Handshake) => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        (false, 0, _) => "CLIENT_TRAFFIC_SECRET_0",
        (false, _, _) => "SERVER_TRAFFIC_SECRET_0",
    }
}

pub fn reassemble(buf: &mut Vec<u8>, payload: &[u8]) -> Vec<Vec<u8>> {
    buf.extend_from_slice(payload);
    let mut records = Vec::new();
    while buf.len() >= 5 {
        let end = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < end {
            break;
        }
        records.push(buf.drain(..end).collect());
    }
    if buf.len() > 1 << 20 {
        buf.clear();
    }
    records
}

impl Session {
    pub fn process(&mut self, dir: usize, record: &[u8]) -> Option<Plain> {
        let content_type = record[0];
        let body = &record[5..];
        let epoch = self.dirs[dir].epoch;
        match (content_type, epoch) {
            (20, _) => {
                if self.version == Some(0x0303) {
                    self.dirs[dir] = Direction {
                        epoch: Epoch::Application,
                        ..Default::default()
                    };
                }
                None
            }
            (22, Epoch::Clear) => {
                self.observe(body);
                None
            }
            (_, Epoch::Clear) => None,
            _ => self.decrypt(dir, record),
        }
    }

    fn observe(&mut self, body: &[u8]) {
        for (kind, msg) in handshake_messages(body) {
            match kind {
                1 => {
                    if let Some(hello) = Hello::parse(msg, true) {
                        self.client_random = Some(hello.random.to_vec());
                    }
                }
                2 => {
                    if let Some(hello) = Hello::parse(msg, false) {
                        self.server_random = Some(hello.random.to_vec());
                        self.suite = hello.ciphers.first().copied();
                        let version = hello.selected_version();
                        self.version = Some(version);
                        if version == 0x0304 {
                            for d in &mut self.dirs {
                                *d = Direction {
                                    epoch: Epoch::Handshake,
                                    ..Default::default()
                                };
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn key(&self, dir: usize, epoch: Epoch) -> Option<Key> {
        let suite = suite(self.suite?)?;
        let random = self.client_random.as_ref()?;
        if self.version == Some(0x0303) {
            let master = keys::secret(random, "CLIENT_RANDOM")?;
            let iv_len = if suite.explicit_nonce { 4 } else { 12 };
            let seed = [self.server_random.as_ref()?.as_slice(), random].concat();
            let block = prf(
                suite.hmac,
                &master,
                b"key expansion",
                &seed,
                2 * (suite.key_len + iv_len),
            );
            let (keys, ivs) = block.split_at(2 * suite.key_len);
            let key = &keys[dir * suite.key_len..(dir + 1) * suite.key_len];
            let iv = &ivs[dir * iv_len..(dir + 1) * iv_len];
            return make_key(&suite, key, iv);
        }
        let secret = keys::secret(random, label(dir, epoch, false))?;
        let key = expand_label(suite.hkdf, &secret, b"key", suite.key_len)?;
        let iv = expand_label(suite.hkdf, &secret, b"iv", 12)?;
        make_key(&suite, &key, &iv)
    }

    fn decrypt(&mut self, dir: usize, record: &[u8]) -> Option<Plain> {
        let tls12 = self.version == Some(0x0303);
        let epoch = self.dirs[dir].epoch;
        if self.dirs[dir].key.is_none() {
            self.dirs[dir].key = self.key(dir, epoch);
        }
        if self.dirs[dir].key.is_none() {
            self.dirs[dir].seq += 1;
            return None;
        }
        if let Some(plain) = self.try_epoch(dir, epoch, record) {
            return Some(plain);
        }
        if tls12 || epoch != Epoch::Handshake {
            return None;
        }
        self.dirs[dir] = Direction {
            epoch: Epoch::Application,
            ..Default::default()
        };
        self.try_epoch(dir, Epoch::Application, record)
    }

    fn try_epoch(&mut self, dir: usize, epoch: Epoch, record: &[u8]) -> Option<Plain> {
        let tls12 = self.version == Some(0x0303);
        if self.dirs[dir].key.is_none() {
            self.dirs[dir].key = self.key(dir, epoch);
        }
        let state = &mut self.dirs[dir];
        let key = state.key.as_ref()?;
        let seq = state.seq;
        let (data, content_type) = open(key, seq, record, tls12)?;
        state.seq += 1;
        let finished = content_type == 22 && data.first() == Some(&20);
        if !tls12 && epoch == Epoch::Handshake && finished {
            *state = Direction {
                epoch: Epoch::Application,
                ..Default::default()
            };
        }
        Some(Plain {
            content_type,
            data,
            secret: label(dir, epoch, tls12),
            seq,
        })
    }
}

fn open(key: &Key, seq: u64, record: &[u8], tls12: bool) -> Option<(Vec<u8>, u8)> {
    let (header, fragment) = record.split_at(5);
    let mut nonce = key.iv;
    let ciphertext = if key.explicit_nonce {
        nonce[4..].copy_from_slice(fragment.get(..8)?);
        &fragment[8..]
    } else {
        for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= s;
        }
        fragment
    };
    let plain_len = ciphertext.len().checked_sub(16)?;
    let aad = if tls12 {
        let mut aad = seq.to_be_bytes().to_vec();
        aad.extend(&header[..3]);
        aad.extend((plain_len as u16).to_be_bytes());
        aad
    } else {
        header.to_vec()
    };
    let mut buf = ciphertext.to_vec();
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let len = key
        .aead
        .open_in_place(nonce, aead::Aad::from(aad), &mut buf)
        .ok()?
        .len();
    buf.truncate(len);
    if tls12 {
        return Some((buf, header[0]));
    }
    while buf.last() == Some(&0) {
        buf.pop();
    }
    let content_type = buf.pop()?;
    Some((buf, content_type))
}

pub fn handshake_messages(b: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= b.len() {
        let len = u32::from_be_bytes([0, b[pos + 1], b[pos + 2], b[pos + 3]]) as usize;
        out.push((b[pos], &b[pos + 4..(pos + 4 + len).min(b.len())]));
        pos += 4 + len;
    }
    out
}

pub fn alert_name(b: &[u8]) -> String {
    let name = match b.get(1) {
        Some(0) => "close_notify",
        Some(10) => "unexpected_message",
        Some(20) => "bad_record_mac",
        Some(40) => "handshake_failure",
        Some(42) => "bad_certificate",
        Some(46) => "certificate_unknown",
        Some(48) => "unknown_ca",
        Some(70) => "protocol_version",
        Some(80) => "internal_error",
        Some(90) => "user_canceled",
        Some(109) => "missing_extension",
        Some(116) => "certificate_required",
        Some(n) => return format!("alert {n}"),
        None => "malformed",
    };
    name.to_string()
}
