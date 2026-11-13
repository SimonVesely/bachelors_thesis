//! # TFTP Protocol implementation using RFCs 1350(TFTP), 2347(Option Extension), 2348(Blocksize Option) and 2349(Transfer Size Option)
//! ## About:
//! - TFTP server made in pure Rust on top of tokio UDP sockets
//! - TFTP has no login, anyone who reaches the port can read every file in the root directory
//! - Every transfer (RRQ / WRQ) runs on its own UDP socket with a new port, so more clients
//!   can transfer at the same time
//! - Lockstep transfer, every DATA block waits for its ACK, lost packets are retransmitted
//!   after 2 seconds, after 5 retries the transfer is aborted
//! - Supported options (answered with OACK):
//!   - blksize - block size, capped at MAX_BLKSIZE (1468 bytes), default 512
//!   - tsize - transfer size, server answers with the real file size
//! - Uploads (WRQ) can be disabled with allow_write: false, server is then read only
//! - All paths are confined to the root directory, errors are answered with TFTP ERROR packets
//!   (FILE_NOT_FOUND, ACCESS_VIOLATION, ILLEGAL_OPERATION, ...)
//! - Every received and sent packet is sent as MessageEvent, retransmissions are marked
//! ## Structure:
//! - lib.rs - Module connection, serves public API for TFTP server usage
//! - packet.rs - Contains all TFTP packets (RRQ, WRQ, DATA, ACK, ERROR, OACK), parser,
//!   encoder, error codes and human readable summary
//! - server.rs - Contains public functions that enables TFTP server, transfers, option
//!   negotiation and event logging
//! ## Public API usage example:
//! ```
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::path::PathBuf;
//! use std::thread::sleep;
//! use std::time::Duration;
//! use tokio::sync::broadcast;
//!
//! use proto_core::event_channel;
//! use proto_tftp::{TftpServerConfig, serve};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = TftpServerConfig {
//!         bind_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
//!         port: 6969,
//!         root_dir: PathBuf::from("./tftp_root"),
//!         allow_write: true,
//!     };
//!
//!     // Initialize the event channel provided by proto_core
//!     let (events_tx, mut _events_rx) = event_channel();
//!
//!     // Initialize the broadcast channel for graceful shutdown
//!     let (shutdown_tx, shutdown_rx) = broadcast::channel(16);
//!
//!     let server_handle = tokio::spawn(async move {
//!         if let Err(err) = serve(config, events_tx, shutdown_rx).await {
//!             eprintln!("TFTP server error: {err}");
//!         }
//!     });
//!
//!     println!("TFTP server is running on 127.0.0.1:6969. Press Ctrl+C to stop.");
//!     sleep(Duration::from_millis(50));
//!
//!     println!("Shutdown signal received, stopping server...");
//!     let _ = shutdown_tx.send(());
//!
//!     server_handle.await?;
//!     println!("TFTP server successfully shut down.");
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Transfer process:
//! TFTP has no encryption and no login - every byte below is plaintext UDP.
//! Real sessions, client `curl` -> FTPeek on 127.0.0.1:6969. C = client, S = server,
//! sizes are UDP payload (4 B header + data).
//! ```text
//! Download (RRQ) of c.bin, 1300 B, blksize 512
//!   C:60554 -> S:6969   RRQ  "c.bin" octet, tsize=0, blksize=512, timeout=6
//!                       -> main socket only accepts the request; S opens a new UDP socket
//!                          (new TID = new port) for this transfer
//!   S:49495 -> C:60554  OACK tsize=1300, blksize=512        (timeout is not supported -> omitted)
//!   C -> S:49495        ACK  block 0                        (client accepts the options)
//!   S -> C              DATA block 1  (516 B = 4 + 512)
//!   C -> S              ACK  block 1
//!   S -> C              DATA block 2  (516 B)
//!   C -> S              ACK  block 2
//!   S -> C              DATA block 3  (280 B = 4 + 276)     < blksize -> last block
//!   C -> S              ACK  block 3                        -> transfer complete, socket closed
//!
//! Upload (WRQ) of up.bin, 2500 B, blksize 1024
//!   C:35624 -> S:6969   WRQ  "up.bin" octet, tsize=2500, blksize=1024, timeout=6
//!   S:35582 -> C:35624  OACK tsize=2500, blksize=1024       (no options -> ACK block 0 instead)
//!   C -> S              DATA block 1  (1028 B)
//!   S -> C              ACK  block 1
//!   C -> S              DATA block 2  (1028 B)
//!   S -> C              ACK  block 2
//!   C -> S              DATA block 3  (456 B = 4 + 452)     < blksize -> last block
//!   S -> C              ACK  block 3                        -> file flushed, socket closed
//!
//! Error
//!   C:54687 -> S:6969   RRQ  "missing.txt" octet, tsize=0, blksize=512, timeout=6
//!   S:53545 -> C:54687  ERROR code 1 (File not found) "File not found"
//! ```
//! - Lockstep: only one unacknowledged packet at a time; every sent packet waits 2 s for
//!   its reply, then it is retransmitted (logged as `[retransmission]`), after 5 retries the
//!   transfer is dropped silently
//! - RRQ: a duplicate ACK is ignored (no resend - avoids the Sorcerer's Apprentice bug);
//!   WRQ: a duplicate of the previous DATA block makes the server resend its last ACK
//! - Block numbers are `u16` and wrap around, so files larger than 65535 blocks still work
//! - Options: `blksize` 8..=1468 (larger requests are lowered to 1468 = 1500 MTU - IP/UDP/TFTP
//!   headers), `tsize` = real size for RRQ, echoed for WRQ, anything else is ignored
//! - Datagrams from any other address/port than the transfer's client are ignored;
//!   an ERROR from the client aborts the transfer, server shutdown sends ERROR 0

mod packet;
mod server;

pub use packet::{
    ACCESS_VIOLATION, FILE_NOT_FOUND, ILLEGAL_OPERATION, NOT_DEFINED, Packet, Request, error_name,
};
pub use server::{MAX_BLKSIZE, TftpServerConfig, serve};
