fn main() {
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows && msvc {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
    if windows {
        winresource::WindowsResource::new()
            .set_icon("assets/icon/ftpeek.ico")
            .compile()
            .expect("failed to embed the icon into FTPeek.exe");
    }
}
