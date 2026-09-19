use crate::Route;
use dioxus::prelude::*;

#[component]
pub fn Status(mode: String, protocol: String) -> Element {
    rsx! {
        section { class: "status-view",
            Link { class: "back-link", to: Route::ModeSelect {}, "\u{2190} start over" }
            h2 { class: "section-title", "Session status" }
            div { class: "status-summary",
                div { class: "status-summary__item",
                    span { class: "status-summary__label", "Mode" }
                    span { class: "status-summary__value", "{mode}" }
                }
                div { class: "status-summary__item",
                    span { class: "status-summary__label", "Protocol" }
                    span { class: "status-summary__value", "{protocol}" }
                }
                div { class: "status-summary__item",
                    span { class: "status-summary__label", "State" }
                    span { class: "status-summary__value status-summary__value--pending", "not started" }
                }
            }
            div { class: "log-panel",
                p { class: "log-panel__placeholder",
                    "Message log will appear here once the {protocol} server is wired up."
                }
            }
        }
    }
}
