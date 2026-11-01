//! # TFTP Protocol implementation using RFCs 1350(TFTP), 2347(Option Extension), 2348(Blocksize Option) and 2349(Transfer Size Option)
//! ## About:
//! - TFTP server made in pure Rust on top of tokio UDP sockets
//! - TFTP has no login, anyone who reaches the port can read every file in the root directory
//! - Every transfer (RRQ / WRQ) runs on its own UDP socket with a new port, so more clients
//! can transfer at the same time
//! - Lockstep transfer, every DATA block waits for its ACK, lost packets are retransmitted
//! after 2 seconds, after 5 retries the transfer is aborted
//! - Supported options (answered with OACK):
//!   - blksize - block size, capped at MAX_BLKSIZE (1468 bytes), default 512
//!   - tsize - transfer size, server answers with the real file size
//! - Uploads (WRQ) can be disabled with allow_write: false, server is then read only
//! - All paths are confined to the root directory, errors are answered with TFTP ERROR packets
//! (FILE_NOT_FOUND, ACCESS_VIOLATION, ILLEGAL_OPERATION, ...)
//! - Every received and sent packet is sent as MessageEvent, retransmissions are marked
//! ## Structure:
//! - lib.rs - Module connection, serves public API for TFTP server usage
//! - packet.rs - Contains all TFTP packets (RRQ, WRQ, DATA, ACK, ERROR, OACK), parser,
//! encoder, error codes and human readable summary
//! - server.rs - Contains public functions that enables TFTP server, transfers, option
//! negotiation and event logging
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

mod packet;
mod server;

pub use packet::{
    ACCESS_VIOLATION, FILE_NOT_FOUND, ILLEGAL_OPERATION, NOT_DEFINED, Packet, Request, error_name,
};
pub use server::{MAX_BLKSIZE, TftpServerConfig, serve};
