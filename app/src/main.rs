use dioxus::prelude::*;

mod components;
use components::{AppShell, ModeSelect, ProtocolSelect, Status};

const VAFLE_REGULAR: Asset = asset!("/assets/fonts/VafleVUT-Regular.otf");
const VAFLE_LIGHT: Asset = asset!("/assets/fonts/VafleVUT-Light.otf");
const VAFLE_BOLD: Asset = asset!("/assets/fonts/VafleVUT-Bold.otf");
const MAIN_CSS: Asset = asset!("/assets/CSS/main.css");

#[derive(Clone, Debug, PartialEq, Routable)]
enum Route {
    #[layout(AppShell)]
    #[route("/")]
    ModeSelect {},

    #[route("/setup/:mode")]
    ProtocolSelect { mode: String },

    #[route("/status/:mode/:protocol")]
    Status { mode: String, protocol: String },
}

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Style {
            {format!(
                "@font-face {{ font-family: 'Vafle VUT'; font-weight: 300; src: url('{VAFLE_LIGHT}') format('opentype'); }}
                 @font-face {{ font-family: 'Vafle VUT'; font-weight: 400; src: url('{VAFLE_REGULAR}') format('opentype'); }}
                 @font-face {{ font-family: 'Vafle VUT'; font-weight: 700; src: url('{VAFLE_BOLD}') format('opentype'); }}"
            )}
        }
        document::Stylesheet { href: MAIN_CSS }
        Router::<Route> {}
    }
}
