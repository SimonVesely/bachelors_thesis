use dioxus::prelude::*;
use dioxus_desktop::{Config, WindowBuilder};

#[cfg(target_os = "macos")]
use dioxus_desktop::tao::platform::macos::WindowBuilderExtMacOS;

mod components;
use components::{AppShell, ModeSelect, ProtocolSelect, Status, Unavailable, UserStore};

#[derive(Clone, Copy)]
pub struct AppState {
    pub interfaces: Signal<Vec<proto_core::NetInterface>>,
    pub selected_interface: Signal<Option<String>>,
    /// The user database, opened once at startup (`Err` holds why it could not be opened).
    pub users: Signal<Result<UserStore, String>>,
    /// User names currently in the database, kept in sync by the "Manage users" popup.
    pub user_names: Signal<Vec<String>>,
    /// `true` = any user name and password is accepted, the database is ignored.
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

    dioxus::LaunchBuilder::desktop()
        .with_cfg(Config::new().with_window(window))
        .launch(App);
}

#[component]
fn App() -> Element {
    let interfaces = proto_core::list_interfaces();
    let default_selection = interfaces.first().map(|i| i.name.clone());

    // This closure runs only once, which matters: redb refuses to open the same file twice.
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
        document::Style {
                    {format!(
                        "@font-face {{ font-family: 'Vafle VUT'; font-weight: 300; src: url('{}') format('opentype'); }}
                         @font-face {{ font-family: 'Vafle VUT'; font-weight: 400; src: url('{}') format('opentype'); }}
                         @font-face {{ font-family: 'Vafle VUT'; font-weight: 700; src: url('{}') format('opentype'); }}",
                        asset!("/assets/fonts/VafleVUT-Light.otf"),
                        asset!("/assets/fonts/VafleVUT-Regular.otf"),
                        asset!("/assets/fonts/VafleVUT-Bold.otf"),
                    )}
                }
                document::Stylesheet { href: asset!("/assets/CSS/main.css") }
        Router::<Route> {}
    }
}
