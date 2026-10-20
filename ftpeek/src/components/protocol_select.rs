use crate::Route;
use dioxus::prelude::*;

const PROTOCOLS: [(&str, &str, &str); 4] = [
    ("ftp", "FTP", "Plaintext control channel, TCP/21"),
    ("ftps", "FTPS", "FTP over TLS (explicit AUTH TLS)"),
    ("tftp", "TFTP", "Lockstep opcodes over UDP/69"),
    ("sftp", "SFTP", "Binary subsystem over SSH2"),
];

#[component]
pub fn ProtocolSelect(mode: String) -> Element {
    rsx! {
        section { class: "protocol-select",
            Link { class: "back-link", to: Route::ModeSelect {}, "\u{2190} change mode" }
            h2 { class: "section-title", "Choose protocol" }
            p { class: "section-subtitle", "Mode: {mode}" }
            div { class: "protocol-grid",
                for (id, label, desc) in PROTOCOLS {
                    Link {
                        key: "{id}",
                        class: "protocol-card",
                        to: Route::Status { mode: mode.clone(), protocol: id.to_string() },
                        span { class: "protocol-card__label", "{label}" }
                        span { class: "protocol-card__desc", "{desc}" }
                    }
                }
            }
        }
    }
}
