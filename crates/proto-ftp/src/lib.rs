//! # FTP Protocol implementation using RFCs 959(Plain FTP) and 2228(FTPS extension)
//! ## About:
//! - FTP implementation made in pure Rust, supports also FTPS, however for
//! explicit FTPS server proto-ftps crate was created
//! ## Structure:
//! - lib.rs - Module connection, serves public API for FTP server usage
//! - command.rs - Contains all FTP/S commands and parser
//! - connection.rs - Contains handling of client
//! - listing.rs - Contains formater for listing commands
//! - server.rs - Contains public functions that enables FTP server
//! - tls.rs - FTPS extension, enables FTP to be upgraded to FTPS
//! ## Public API usage example:
//! ```
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::path::PathBuf;
//! use std::thread::sleep;
//! use std::time::Duration;
//! use tokio::sync::broadcast;
//!
//! use proto_core::event_channel;
//! use proto_ftp::{FtpServerConfig, serve};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = FtpServerConfig {
//!         bind_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
//!         control_port: 2121,
//!         pasv_port_start: 30000,
//!         pasv_port_end: 30100,
//!         root_dir: PathBuf::from("./ftp_root"),
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
//!             eprintln!("FTP server error: {err}");
//!         }
//!     });
//!
//!     println!("FTP server is running on 127.0.0.1:2121. Press Ctrl+C to stop.");
//!     sleep(Duration::from_millis(50));
//!
//!     println!("Shutdown signal received, stopping server...");
//!     let _ = shutdown_tx.send(());
//!
//!     server_handle.await?;
//!     println!("FTP server successfully shut down.");
//!
//!     Ok(())
//! }
//! ```

mod command;
mod connection;
mod listing;
mod server;
mod session;
mod tls;

pub use server::{FtpServerConfig, serve, serve_with};
pub use tls::{AsyncStream, BoxedStream, TlsUpgrader, UpgradeFuture};
