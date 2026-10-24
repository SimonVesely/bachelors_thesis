use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use crate::Protocol;
use pcap::{Active, Device};

use super::{CaptureConfig, RawFrame};
use tokio::sync::mpsc::UnboundedSender;

pub struct Capture {
    stop: Arc<AtomicBool>,
    pub interfaces: Vec<String>,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn start(cfg: &CaptureConfig, frames: UnboundedSender<RawFrame>) -> Result<Capture, String> {
    load_library()?;
    let devices = Device::list().map_err(|e| format!("cannot list interfaces: {e}"))?;

    let primary = if cfg.server_ip.is_unspecified() {
        Device::lookup().ok().flatten()
    } else {
        devices
            .iter()
            .find(|d| d.addresses.iter().any(|a| a.addr == cfg.server_ip))
            .cloned()
    };
    let primary = primary.ok_or(format!(
        "no capture interface has address {}",
        cfg.server_ip
    ))?;
    let loopback = devices
        .iter()
        .find(|d| d.flags.is_loopback() && d.name != primary.name)
        .cloned();

    let filter = match cfg.protocol {
        Protocol::Tftp => "udp",
        _ => "tcp",
    };
    let filter = match cfg.server_ip.is_unspecified() {
        true => filter.to_string(),
        false => format!("host {} and {filter}", cfg.server_ip),
    };

    let stop = Arc::new(AtomicBool::new(false));
    let cap = open(&primary, &filter).map_err(|e| format!("{}: {e}", label(&primary)))?;
    let mut interfaces = vec![label(&primary)];
    spawn_reader(cap, label(&primary), frames.clone(), stop.clone());
    if let Some(lo) = loopback
        && let Ok(cap) = open(&lo, &filter)
    {
        interfaces.push(label(&lo));
        spawn_reader(cap, label(&lo), frames, stop.clone());
    }
    Ok(Capture { stop, interfaces })
}

fn open(device: &Device, filter: &str) -> Result<pcap::Capture<Active>, pcap::Error> {
    let mut cap = pcap::Capture::from_device(device.clone())?
        .promisc(false)
        .snaplen(65535)
        .buffer_size(32 << 20)
        .timeout(100)
        .immediate_mode(true)
        .open()?;
    cap.filter(filter, true)?;
    Ok(cap)
}

fn spawn_reader(
    mut cap: pcap::Capture<Active>,
    name: String,
    frames: UnboundedSender<RawFrame>,
    stop: Arc<AtomicBool>,
) {
    let interface: Arc<str> = name.into();
    let linktype = cap.get_datalink().0;
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    let ts = packet.header.ts;
                    let since_epoch = Duration::from_secs(ts.tv_sec as u64)
                        + Duration::from_micros(ts.tv_usec as u64);
                    let frame = RawFrame {
                        timestamp: UNIX_EPOCH + since_epoch,
                        linktype,
                        data: packet.data.to_vec(),
                        wire_len: packet.header.len,
                        interface: interface.clone(),
                    };
                    if frames.send(frame).is_err() {
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(_) => break,
            }
        }
    });
}

fn label(device: &Device) -> String {
    match &device.desc {
        Some(desc) if cfg!(windows) => desc.clone(),
        _ => device.name.clone(),
    }
}

#[cfg(not(windows))]
fn load_library() -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn load_library() -> Result<(), String> {
    use std::ffi::{OsStr, c_void};
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        fn SetDllDirectoryW(path: *const u16) -> i32;
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
    }
    let wide = |s: &str| -> Vec<u16> { OsStr::new(s).encode_wide().chain(Some(0)).collect() };

    unsafe {
        let mut buffer = [0u16; 260];
        let len = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) as usize;
        let npcap = format!("{}\\Npcap", String::from_utf16_lossy(&buffer[..len]));
        SetDllDirectoryW(wide(&npcap).as_ptr());
        if LoadLibraryW(wide("wpcap.dll").as_ptr()).is_null() {
            return Err("Npcap is not installed (install Wireshark or Npcap)".into());
        }
    }
    Ok(())
}
