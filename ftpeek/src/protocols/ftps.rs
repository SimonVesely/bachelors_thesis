use proto_core::{MessageEvent, Protocol};
use proto_ftps::{FtpsMode, FtpsServerConfig};

use super::ftp::{DTP_PORT, PI_PORT, config, ports, track_login};
use super::{Opt, Options, ServeCtx, ServeFuture, Spec};
use crate::components::ClientInfo;

pub struct Ftps;

impl Spec for Ftps {
    fn id(&self) -> &'static str {
        "ftps"
    }

    fn label(&self) -> &'static str {
        "FTPS"
    }

    fn description(&self) -> &'static str {
        "FTP over TLS (explicit AUTH TLS)"
    }

    fn core(&self) -> Protocol {
        Protocol::Ftps
    }

    fn options(&self) -> &'static [Opt] {
        &[
            Opt::Choice {
                key: "mode",
                label: "FTPS mode",
                choices: &[
                    ("explicit", "Explicit - AUTH TLS"),
                    ("implicit", "Implicit - TLS from first byte"),
                ],
                default: "explicit",
            },
            PI_PORT,
            DTP_PORT,
        ]
    }

    fn title(&self, opts: &Options) -> String {
        format!("FTPS ({})", opts.get("mode"))
    }

    fn can_decrypt(&self) -> bool {
        true
    }

    fn hints(&self) -> &'static [&'static str] {
        &[
            "A self-signed certificate is generated on every start - the client will ask you to trust it.",
        ]
    }

    fn on_change(&self, key: &str, opts: &mut Options) {
        match (key, opts.get("mode"), opts.port("port")) {
            ("mode", "implicit", 21) => opts.set("port", "990".into()),
            ("mode", "explicit", 990) => opts.set("port", "21".into()),
            _ => {}
        }
    }

    fn capture_ports(&self, opts: &Options) -> Vec<u16> {
        ports(opts)
    }

    fn serve(&self, ctx: ServeCtx) -> ServeFuture {
        let mode = match ctx.opts.is("mode", "implicit") {
            true => FtpsMode::Implicit,
            false => FtpsMode::Explicit,
        };
        let cfg = FtpsServerConfig {
            ftp: config(&ctx),
            mode,
        };
        Box::pin(proto_ftps::serve(cfg, ctx.events, ctx.shutdown))
    }

    fn track(&self, client: &mut ClientInfo, e: &MessageEvent) {
        track_login(client, e);
    }
}
