use std::net::SocketAddr;

use dioxus::prelude::*;
use proto_core::{Direction, EventKind, MessageEvent, Protocol};

#[derive(Clone, Debug, PartialEq)]
pub struct ClientInfo {
    pub session: u64,
    pub addr: SocketAddr,
    pub user: Option<String>,
    pub logged_in: bool,
    pub connected: bool,
    pub packets: usize,
    pub data_bytes: u64,
    pub transfer: Option<String>,
    pub addrs: Vec<SocketAddr>,
}

impl ClientInfo {
    pub fn label(&self) -> String {
        if let Some(transfer) = &self.transfer {
            return format!("#{} {} ({transfer})", self.session, self.addr);
        }
        match (&self.user, self.logged_in) {
            (Some(user), true) => format!("#{} {} ({user})", self.session, self.addr),
            _ => format!("#{} {}", self.session, self.addr),
        }
    }
}

pub fn track_client(clients: &mut Vec<ClientInfo>, e: &MessageEvent) {
    if e.session == 0 {
        return;
    }
    let idx = match clients.iter().position(|c| c.session == e.session) {
        Some(idx) => idx,
        None => {
            clients.push(ClientInfo {
                session: e.session,
                addr: e.peer,
                user: None,
                logged_in: false,
                connected: true,
                packets: 0,
                data_bytes: 0,
                transfer: None,
                addrs: Vec::new(),
            });
            clients.len() - 1
        }
    };
    let client = &mut clients[idx];
    client.packets += 1;
    if !client.addrs.contains(&e.peer) {
        client.addrs.push(e.peer);
    }

    let text = e.parsed.as_deref().unwrap_or_default();
    if e.protocol == Protocol::Tftp {
        track_tftp(client, e, text);
        return;
    }
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
        (EventKind::Data, _) => client.data_bytes += e.length as u64,
        (EventKind::TcpClose, _) if e.peer == client.addr => client.connected = false,
        _ => {}
    }
}

fn track_tftp(client: &mut ClientInfo, e: &MessageEvent, text: &str) {
    if let Some(file) = text.strip_prefix("Read Request, File: ") {
        client.transfer = Some(format!(
            "download {}",
            file.split(", ").next().unwrap_or(file)
        ));
    } else if let Some(file) = text.strip_prefix("Write Request, File: ") {
        client.transfer = Some(format!(
            "upload {}",
            file.split(", ").next().unwrap_or(file)
        ));
    }
    if e.kind == EventKind::Data && !text.contains("[retransmission]") {
        client.data_bytes += e.length.saturating_sub(4) as u64;
    }
    if text.contains("(last)") || text.starts_with("Error,") {
        client.connected = false;
    }
}

fn strip_verb<'a>(line: &'a str, verb: &str) -> Option<&'a str> {
    let (head, rest) = line.split_once(' ')?;
    head.eq_ignore_ascii_case(verb).then(|| rest.trim())
}

fn format_bytes(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.1} kB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

#[component]
pub fn ClientList(clients: Signal<Vec<ClientInfo>>, filter: Signal<Option<u64>>) -> Element {
    let mut clients = clients;
    let mut filter = filter;

    let list = clients.read().clone();
    let online = list.iter().filter(|c| c.connected).count();
    let has_offline = list.iter().any(|c| !c.connected);
    let active = filter();

    rsx! {
        div { class: "client-list",
            div { class: "client-list__header",
                span { "Clients" }
                span { class: "client-list__count", "{online} connected" }
                div { class: "packet-log__spacer" }
                if has_offline {
                    button {
                        class: "client-list__clear",
                        title: "Remove disconnected clients from the list",
                        onclick: move |_| {
                            clients.write().retain(|c| c.connected);
                            if let Some(id) = filter() {
                                if !clients.read().iter().any(|c| c.session == id) {
                                    filter.set(None);
                                }
                            }
                        },
                        "Clear"
                    }
                }
            }
            div { class: "client-list__body",
                if list.is_empty() {
                    p { class: "client-list__empty", "No clients yet." }
                } else {
                    for c in list.iter() {
                        div {
                            key: "{c.session}",
                            class: match (active == Some(c.session), c.connected) {
                                (true, _) => "client-list__row client-list__row--active",
                                (false, true) => "client-list__row",
                                (false, false) => "client-list__row client-list__row--offline",
                            },
                            title: "Click to show only this client's packets",
                            onclick: {
                                let id = c.session;
                                move |_| filter.set(if filter() == Some(id) { None } else { Some(id) })
                            },
                            span { class: if c.connected { "client-list__dot client-list__dot--on" } else { "client-list__dot" } }
                            span { class: "client-list__addr",
                                span { class: "client-list__id", "#{c.session}" }
                                "{c.addr}"
                            }
                            span { class: "client-list__num", "{c.packets} pkts" }
                            span { class: "client-list__user",
                                match (&c.transfer, &c.user, c.logged_in) {
                                    (Some(transfer), _, _) => rsx! { "{transfer}" },
                                    (None, Some(user), true) => rsx! { "{user}" },
                                    (None, Some(user), false) => rsx! { span { class: "client-list__pending", "{user} (not logged in)" } },
                                    (None, None, _) => rsx! { span { class: "client-list__pending", "not logged in" } },
                                }
                            }
                            span { class: "client-list__num", "{format_bytes(c.data_bytes)}" }
                        }
                    }
                }
            }
        }
    }
}
