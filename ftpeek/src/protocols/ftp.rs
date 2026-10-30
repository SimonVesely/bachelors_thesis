use proto_core::{Direction, EventKind, MessageEvent, Protocol};
use proto_ftp::FtpServerConfig;

use super::{Opt, Options, ServeCtx, ServeFuture, Spec, track_common};
use crate::components::ClientInfo;

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

pub(super) fn track_login(client: &mut ClientInfo, e: &MessageEvent) {
    let text = e.parsed.as_deref().unwrap_or_default();
    match (e.kind, e.direction) {
        (EventKind::Message, Direction::ClientToServer) => {
            if let Some(name) = strip_verb(text, "USER") {
                client.user = Some(name.to_string());
                client.logged_in = false;
            }
        }
        (EventKind::Message, Direction::ServerToClient) => {
            if text.starts_with("230") {
                client.logged_in = true;
            } else if text.starts_with("530") || text.starts_with("234") {
                client.logged_in = false;
            }
        }
        _ => track_common(client, e),
    }
}

fn strip_verb<'a>(line: &'a str, verb: &str) -> Option<&'a str> {
    let (head, rest) = line.split_once(' ')?;
    head.eq_ignore_ascii_case(verb).then(|| rest.trim())
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

    fn track(&self, client: &mut ClientInfo, e: &MessageEvent) {
        track_login(client, e);
    }
}
