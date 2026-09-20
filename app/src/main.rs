use dioxus::prelude::*;
use dioxus_desktop::{Config, WindowBuilder};

#[cfg(target_os = "macos")]
use dioxus_desktop::tao::platform::macos::WindowBuilderExtMacOS;

mod components;
use components::{AppShell, ModeSelect, ProtocolSelect, Status, Unavailable};

#[derive(Clone, Copy)]
pub struct AppState {
    pub interfaces: Signal<Vec<proto_core::NetInterface>>,
    pub selected_interface: Signal<Option<String>>,
}

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

    #[route("/unavailable/:mode")]
    Unavailable { mode: String },
}

fn main() {
    let mut window = WindowBuilder::new()
        .with_title("FTPeek")
        .with_min_inner_size(dioxus_desktop::tao::dpi::LogicalSize::new(760.0, 500.0));

    #[cfg(target_os = "macos")]
    {
        window = window
            .with_titlebar_transparent(true)
            .with_title_hidden(true)
            .with_fullsize_content_view(true)
            .with_movable_by_window_background(true);
    }

    dioxus::LaunchBuilder::desktop()
        .with_cfg(Config::new().with_window(window))
        .launch(App);
}

#[component]
fn App() -> Element {
    let interfaces = proto_core::list_interfaces();
    let default_selection = interfaces.first().map(|i| i.name.clone());

    use_context_provider(|| AppState {
        interfaces: Signal::new(interfaces),
        selected_interface: Signal::new(default_selection),
    });

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
