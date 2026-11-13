//! # Pages
//! ## About:
//! - Full-screen routes with their own state; only the server page for now
//!   (`Status`, route `/status/:mode/:protocol`)
//! - Menu screens live in `components/` because they have no page state

mod server;

pub use server::Status;
