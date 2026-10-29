use proto_core::Protocol;
use proto_ftp::FtpServerConfig;

use super::{Opt, Options, ServeCtx, ServeFuture, Spec};

pub struct Ftp;

pub(super) const PI_PORT: Opt = Opt::Port {
    key: "port",
    label: "PI port",
    default: 21,
};

pub(super) const DTP_PORT: Opt = Opt::Port {
    key: "dtp",
    label: "DTP port",
    default: 20,
};

pub(super) fn config(ctx: &ServeCtx) -> FtpServerConfig {
    FtpServerConfig {
        bind_addr: ctx.bind,
        control_port: ctx.opts.port("port"),
        pasv_port_start: ctx.opts.port("dtp"),
        pasv_port_end: ctx.opts.port("dtp"),
        root_dir: ctx.root.clone(),
        users: ctx.users.clone(),
    }
}

pub(super) fn ports(opts: &Options) -> Vec<u16> {
    vec![opts.port("port"), opts.port("dtp")]
}

impl Spec for Ftp {
    fn id(&self) -> &'static str {
        "ftp"
    }

    fn label(&self) -> &'static str {
        "FTP"
    }

    fn description(&self) -> &'static str {
        "Plaintext control channel, TCP/21"
    }

    fn core(&self) -> Protocol {
        Protocol::Ftp
    }

    fn options(&self) -> &'static [Opt] {
        &[PI_PORT, DTP_PORT]
    }

    fn capture_ports(&self, opts: &Options) -> Vec<u16> {
        ports(opts)
    }

    fn serve(&self, ctx: ServeCtx) -> ServeFuture {
        let cfg = config(&ctx);
        Box::pin(proto_ftp::serve(cfg, ctx.events, ctx.shutdown))
    }
}
