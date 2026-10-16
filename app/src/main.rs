#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
use std::sync::LazyLock;

use base64::prelude::*;
use dioxus::prelude::*;
use dioxus_desktop::{Config, WindowBuilder};

#[cfg(target_os = "macos")]
use dioxus_desktop::tao::platform::macos::WindowBuilderExtMacOS;

mod components;
use components::{AppShell, ModeSelect, ProtocolSelect, Status, Unavailable, UserStore};

const MAIN_CSS: &str = include_str!("../assets/CSS/main.css");
const FONT_LIGHT: &[u8] = include_bytes!("../assets/fonts/VafleVUT-Light.otf");
const FONT_REGULAR: &[u8] = include_bytes!("../assets/fonts/VafleVUT-Regular.otf");
const FONT_BOLD: &[u8] = include_bytes!("../assets/fonts/VafleVUT-Bold.otf");

static APP_CSS: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}\n{}\n{}\n{}",
        font_face(300, FONT_LIGHT),
        font_face(400, FONT_REGULAR),
        font_face(700, FONT_BOLD),
        MAIN_CSS
    )
});

fn font_face(weight: u16, bytes: &[u8]) -> String {
    format!(
        "@font-face {{ font-family: 'Vafle VUT'; font-weight: {weight}; \
         src: url('data:font/otf;base64,{}') format('opentype'); }}",
        BASE64_STANDARD.encode(bytes)
    )
}

#[derive(Clone, Copy)]
pub struct AppState {
    pub interfaces: Signal<Vec<proto_core::NetInterface>>,
    pub selected_interface: Signal<Option<String>>,
    pub users: Signal<Result<UserStore, String>>,
    pub user_names: Signal<Vec<String>>,
    pub anonymous: Signal<bool>,
}

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

    let config = Config::new().with_window(window);
    #[cfg(not(target_os = "macos"))]
    let config = config.with_menu(None);

    dioxus::LaunchBuilder::desktop()
        .with_cfg(config)
        .launch(App);
}

#[component]
fn App() -> Element {
    let interfaces = proto_core::list_interfaces();
    let default_selection = interfaces.first().map(|i| i.name.clone());

    use_context_provider(|| {
        let users = components::open_user_db();
        let names = match &users {
            Ok(store) => store.db.list_users().unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        AppState {
            interfaces: Signal::new(interfaces),
            selected_interface: Signal::new(default_selection),
            users: Signal::new(users),
            user_names: Signal::new(names),
            anonymous: Signal::new(true),
        }
    });

    rsx! {
        document::Style { {APP_CSS.as_str()} }
        Router::<Route> {}
    }
}
