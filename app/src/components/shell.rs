use crate::Route;
use dioxus::prelude::*;

#[component]
pub fn AppShell() -> Element {
    rsx! {
        div { class: "app-shell",
            header { class: "app-header",
                div { class: "app-header__mark" }
                div { class: "app-header__titles",
                    span { class: "app-header__eyebrow", "VUT FEKT — semestrální práce" }
                    h1 { class: "app-header__title", "Protocol Analyzer" }
                }
            }
            main { class: "app-main",
                Outlet::<Route> {}
            }
        }
    }
}
