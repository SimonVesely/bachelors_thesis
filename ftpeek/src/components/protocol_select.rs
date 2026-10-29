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
