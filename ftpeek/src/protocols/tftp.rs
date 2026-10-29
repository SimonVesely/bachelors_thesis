use proto_core::Protocol;
use proto_tftp::TftpServerConfig;

use super::{Opt, Options, ServeCtx, ServeFuture, Spec};

pub struct Tftp;

impl Spec for Tftp {
    fn id(&self) -> &'static str {
        "tftp"
    }

    fn label(&self) -> &'static str {
        "TFTP"
    }

    fn description(&self) -> &'static str {
        "Lockstep opcodes over UDP/69"
    }

    fn core(&self) -> Protocol {
        Protocol::Tftp
    }

    fn options(&self) -> &'static [Opt] {
        &[
            Opt::Choice {
                key: "write",
                label: "Uploads (WRQ)",
                choices: &[("allow", "Allowed"), ("deny", "Disabled (read only)")],
                default: "allow",
            },
            Opt::Port {
                key: "port",
                label: "Port (UDP)",
                default: 69,
            },
        ]
    }

    fn login(&self) -> bool {
        false
    }

    fn hints(&self) -> &'static [&'static str] {
        &[
            "TFTP has no login: anyone who reaches this port can download every file in the root directory.",
        ]
    }

    fn capture_ports(&self, opts: &Options) -> Vec<u16> {
        vec![opts.port("port")]
    }

    fn serve(&self, ctx: ServeCtx) -> ServeFuture {
        let cfg = TftpServerConfig {
            bind_addr: ctx.bind,
            port: ctx.opts.port("port"),
            root_dir: ctx.root,
            allow_write: ctx.opts.is("write", "allow"),
        };
        Box::pin(proto_tftp::serve(cfg, ctx.events, ctx.shutdown))
    }
}
