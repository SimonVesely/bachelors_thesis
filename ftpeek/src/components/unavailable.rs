use crate::Route;
use dioxus::prelude::*;

#[component]
pub fn Unavailable(mode: String) -> Element {
    let label = match mode.as_str() {
        "client" => "Client only",
        "fold" => "Fold (server + client)",
        _ => "This mode",
    };

    rsx! {
        section { class: "unavailable-view",
            Link { class: "back-link", to: Route::ModeSelect {}, "\u{2190} back" }
            h2 { class: "section-title", "{label} isn't available yet" }
            p { class: "section-subtitle",
                "This build only implements the protocol servers. Client-side and combined "
                "server+client sessions are planned for a later stage of the project."
            }
            div { class: "unavailable-card",
                span { class: "unavailable-card__badge", "Not implemented" }
                p { class: "unavailable-card__text",
                    "Pick \"Server only\" for now — it's the part that's actually running."
                }
                Link { class: "unavailable-card__cta", to: Route::ModeSelect {}, "Choose server mode" }
            }
        }
    }
}
