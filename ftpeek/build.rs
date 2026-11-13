//! # Build script
//! ## About:
//! - Windows MSVC: delay-loads `wpcap.dll`, so FTPeek starts without Npcap and only the capture
//!   fails (proto_core::capture::live loads it at runtime)
//! - Windows without `dx bundle`: embeds `assets/icon/ftpeek.ico` into the exe
//!   (`dx bundle` sets DIOXUS_PRODUCT_NAME and embeds the icon itself)

fn main() {
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows && msvc {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
    println!("cargo:rerun-if-env-changed=DIOXUS_PRODUCT_NAME");
    let dx_bundle = std::env::var_os("DIOXUS_PRODUCT_NAME").is_some();
    if windows && !dx_bundle {
        winresource::WindowsResource::new()
            .set_icon("assets/icon/ftpeek.ico")
            .compile()
            .expect("failed to embed the icon into FTPeek.exe");
    }
}
