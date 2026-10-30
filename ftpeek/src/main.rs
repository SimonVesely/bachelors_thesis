//! # FTPeek - desktop GUI for analyzing FTP, FTPS, TFTP and SFTP traffic
//! ## About:
//! - Dioxus 0.7 desktop app. It runs one of the protocol servers from the `proto-*` crates and
//!   shows every exchange between server and clients
//! - Two views of the same traffic:
//!   - Wireshark view: real frames captured with pcap (`proto_core::capture`), including the TCP
//!     handshake, TLS records and optional TLS decryption (FTPS only)
//!   - Event log (fallback when pcap is off or unavailable): `MessageEvent`s that the server
//!     crates send through `proto_core::event_channel`, already decrypted by the server
//! - FTPeek itself contains no protocol logic, it only configures, starts and displays.
//!   Everything protocol-specific lives in `src/protocols/`
//!
//! ## Structure:
//! - main.rs - window setup, fonts and CSS, global `AppState`, `Route`
//! - util.rs - small shared helpers
//! - protocols/ - one file per protocol, the only place that knows protocol details
//!   - mod.rs - `Proto` enum (list of protocols), `Spec` trait, settings schema (`Opt`, `Options`),
//!     `ServeCtx`, `Channel` (TLS / SSH)
//!   - ftp.rs, ftps.rs, tftp.rs, sftp.rs - `impl Spec` for each protocol
//! - pages/server/ - the server page (route `/status/:mode/:protocol`)
//!   - mod.rs - `Status` page: state, Start/Stop logic, layout of the panels
//!   - control_bar.rs - top box: title, chips, settings, capture checkbox, hints, client list
//!   - capture.rs - `use_capture()` hook: starts pcap + dissector, falls back to the event log
//! - components/ - reusable UI, protocol independent
//!   - mode_select.rs, protocol_select.rs, unavailable.rs, shell.rs - menu screens and app frame
//!   - user_manager.rs - user database dialog (redb + argon2 from `proto-core`)
//!   - option_field.rs - renders one `Opt` (port input or dropdown)
//!   - packet_log.rs - virtualized packet table for both views
//!   - frame_detail.rs, frame_diagram.rs - detail and structure of a captured frame (pcap view)
//!   - packet_detail.rs, packet_diagram.rs - detail and structure of a `MessageEvent` (event log)
//!   - client_list.rs - connected clients, `track_client` feeds it from events
//!   - directory_preview.rs - tree of the server root directory
//! - assets/ - CSS, fonts, icon (CSS is embedded at compile time, see `MAIN_CSS`)
//!
//! ## How it works:
//! 1. `ModeSelect` -> `ProtocolSelect` (cards built from `Proto::ALL`) -> `Status { mode, protocol }`
//! 2. `Status` builds `Options` from `spec.options()` defaults, `ControlBar` edits them
//! 3. Start server:
//!    - `capture.start(CaptureConfig { protocol: spec.core(), ports: spec.capture_ports(..) })`
//!    - `spec.serve(ServeCtx { bind, root, users, opts, events, shutdown })` spawns the server
//!    - every `MessageEvent` goes to `logs` and `track_client`, every frame to `capture.packets`
//! 4. Panels read `logs` / `packets`. For an event they look up its protocol with
//!    `Proto::of(event.protocol).spec()` and ask the spec for texts, rows and cells
//! 5. Stop server sends on the `shutdown` broadcast, the serve future ends, capture stops
//!
//! ## Adding a new protocol:
//! 1. Write the server crate (see `proto-tftp` or `proto-sftp`), it needs
//!    `serve(config, EventSender, broadcast::Receiver<()>) -> io::Result<()>` and a new
//!    `proto_core::Protocol` variant, then add it to `ftpeek/Cargo.toml`
//! 2. Add a variant to `Proto` and to `Proto::ALL`, and a match arm to `Proto::spec()`
//! 3. Create `protocols/xyz.rs` and implement `Spec`. Only these methods are required,
//!    the rest have defaults that fit FTP-like protocols:
//! ```rust,ignore
//! pub struct Xyz;
//!
//! impl Spec for Xyz {
//!     fn id(&self) -> &'static str { "xyz" }                    // URL segment
//!     fn label(&self) -> &'static str { "XYZ" }                 // menu card, title, log column
//!     fn description(&self) -> &'static str { "One line for the menu card" }
//!     fn core(&self) -> Protocol { Protocol::Xyz }              // proto_core protocol of its events
//!     fn options(&self) -> &'static [Opt] {
//!         &[Opt::Port { key: "port", label: "Port (TCP)", default: 1234 }]
//!     }
//!     fn capture_ports(&self, opts: &Options) -> Vec<u16> {
//!         vec![opts.port("port")]                               // first port = control port
//!     }
//!     fn serve(&self, ctx: ServeCtx) -> ServeFuture {
//!         let cfg = XyzServerConfig { bind_addr: ctx.bind, port: ctx.opts.port("port"), root_dir: ctx.root };
//!         Box::pin(proto_xyz::serve(cfg, ctx.events, ctx.shutdown))
//!     }
//! }
//! ```
//! 4. Optional overrides in the same file:
//!    - server page: `title`, `login` (false = no user database), `hints`, `on_change`,
//!      `can_decrypt` (Decrypt button, needs TLS keys from the server crate)
//!    - event log: `proto_column`, `info`, `starts_group` (red separators), `channel` (TLS / SSH)
//!    - packet detail: `app_title`, `transport_title`, `detail_rows`
//!    - packet structure: `diagram_cells` (3 boxes under the event record)
//!    - client list: `track` (user name, login state, transfer; call `track_common` for bytes)
//! 5. pcap view: frames are dissected in `proto-core` (`capture/dissect.rs`, `App` enum), a new
//!    protocol shows as plain TCP/UDP there until it gets its own dissector
//!
//! No component or page has to change for a new protocol.
//!
//! ## Common modifications:
//! - new setting for a protocol: add an `Opt` to its `options()`, read it in `serve` with
//!   `ctx.opts.port(key)` / `ctx.opts.is(key, value)`. Dropdowns are drawn before Root directory,
//!   ports after it. A new kind of input = new `Opt` variant + its arm in `option_field.rs`
//! - setting shared by all protocols (like Root directory): signal in `pages/server/mod.rs`,
//!   input in `control_bar.rs`, value passed through `ServeCtx`
//! - new panel on the server page: component in `components/`, placed in the grid in
//!   `pages/server/mod.rs`, styles in `assets/CSS/main.css`
//! - new mode (client, fold): new route in `Route` + page in `pages/`, today they lead to `Unavailable`
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
use std::sync::LazyLock;

use base64::prelude::*;
use dioxus::prelude::*;
use dioxus_desktop::{Config, WindowBuilder};

#[cfg(target_os = "macos")]
use dioxus_desktop::tao::platform::macos::WindowBuilderExtMacOS;

mod components;
mod pages;
mod protocols;
mod util;
use components::{AppShell, ModeSelect, ProtocolSelect, Unavailable, UserStore};
use pages::Status;
use protocols::Proto;

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
    Status { mode: String, protocol: Proto },

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
    let default_selection = interfaces.first().map(|i| i.ip.to_string());

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
