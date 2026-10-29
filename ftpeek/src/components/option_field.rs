use dioxus::prelude::*;

use crate::protocols::{Opt, Options, Proto};

#[component]
pub fn OptionField(
    protocol: Proto,
    opt: &'static Opt,
    options: Signal<Options>,
    disabled: bool,
) -> Element {
    let mut options = options;
    let key = opt.key();
    let value = options.read().get(key).to_string();
    let mut update = move |value: String| {
        let mut opts = options.write();
        opts.set(key, value);
        protocol.spec().on_change(key, &mut opts);
    };

    match opt {
        Opt::Port { label, .. } => rsx! {
            label { class: "control-bar__field control-bar__field--port",
                span { class: "control-bar__label", "{label}" }
                input {
                    class: "status-summary__input",
                    r#type: "number",
                    value: "{value}",
                    disabled,
                    oninput: move |e| {
                        if e.value().parse::<u16>().is_ok() {
                            update(e.value());
                        }
                    },
                }
            }
        },
        Opt::Choice { label, choices, .. } => rsx! {
            label { class: "control-bar__field",
                span { class: "control-bar__label", "{label}" }
                select {
                    class: "status-summary__input",
                    disabled,
                    value: "{value}",
                    onchange: move |e| update(e.value()),
                    for (id, text) in choices.iter() {
                        option { key: "{id}", value: "{id}", "{text}" }
                    }
                }
            }
        },
    }
}
