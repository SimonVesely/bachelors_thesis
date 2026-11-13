//! # Protocol menu
//! ## About:
//! - One card per `Proto::ALL`, label and description from its `Spec`
//! - Card links to `Route::Status { mode, protocol }`
//! ```text
//! <- change mode
//! CHOOSE PROTOCOL
//! Mode: server
//! +----------------------------------+ +----------------------------------+
//! | FTP                              | | FTPS                             |
//! | Plaintext control channel, TCP/21| | FTP over TLS (explicit or impl.) |
//! +----------------------------------+ +----------------------------------+
//! | TFTP                             | | SFTP                             |
//! | Lockstep opcodes over UDP/69     | | Binary subsystem over SSH2       |
//! +----------------------------------+ +----------------------------------+
//! ```

use crate::Route;
use crate::protocols::Proto;
use dioxus::prelude::*;

#[component]
pub fn ProtocolSelect(mode: String) -> Element {
    rsx! {
        section { class: "protocol-select",
            Link { class: "back-link", to: Route::ModeSelect {}, "\u{2190} change mode" }
            h2 { class: "section-title", "Choose protocol" }
            p { class: "section-subtitle", "Mode: {mode}" }
            div { class: "protocol-grid",
                for protocol in Proto::ALL {
                    Link {
                        key: "{protocol}",
                        class: "protocol-card",
                        to: Route::Status { mode: mode.clone(), protocol },
                        span { class: "protocol-card__label", "{protocol.spec().label()}" }
                        span { class: "protocol-card__desc", "{protocol.spec().description()}" }
                    }
                }
            }
        }
    }
}
