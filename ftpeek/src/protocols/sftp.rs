use proto_core::Protocol;
use proto_sftp::SftpServerConfig;

use super::{Opt, Options, ServeCtx, ServeFuture, Spec};

pub struct Sftp;

impl Spec for Sftp {
    fn id(&self) -> &'static str {
        "sftp"
    }

    fn label(&self) -> &'static str {
        "SFTP"
    }

    fn description(&self) -> &'static str {
        "Binary subsystem over SSH2"
    }

    fn core(&self) -> Protocol {
        Protocol::Sftp
    }

    fn options(&self) -> &'static [Opt] {
        &[Opt::Port {
            key: "port",
            label: "Port (TCP)",
            default: 22,
        }]
    }

    fn hints(&self) -> &'static [&'static str] {
        &[
            "A new SSH host key is generated on every start - the client will warn that the key changed. If port 22 is taken by the system SSH server, use 2222.",
        ]
    }

    fn capture_ports(&self, opts: &Options) -> Vec<u16> {
        vec![opts.port("port")]
    }

    fn serve(&self, ctx: ServeCtx) -> ServeFuture {
        let cfg = SftpServerConfig {
            bind_addr: ctx.bind,
            port: ctx.opts.port("port"),
            root_dir: ctx.root,
            users: ctx.users,
        };
        Box::pin(proto_sftp::serve(cfg, ctx.events, ctx.shutdown))
    }
}
