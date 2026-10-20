use std::path::PathBuf;
use std::sync::Arc;

use dioxus::prelude::*;
use proto_core::UserDb;

use crate::AppState;

#[derive(Clone)]
pub struct UserStore {
    pub db: Arc<UserDb>,
    pub path: PathBuf,
}

pub fn open_user_db() -> Result<UserStore, String> {
    open_in(PathBuf::from("database")).or_else(|local_err| {
        let dirs = directories::ProjectDirs::from("cz", "simonvesely", "ftpeek")
            .ok_or_else(|| format!("{local_err}; no fallback folder found"))?;
        open_in(dirs.data_dir().to_path_buf())
    })
}

fn open_in(dir: PathBuf) -> Result<UserStore, String> {
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let path = dir.join("users.redb");
    let db = UserDb::open(&path).map_err(|e| e.to_string())?;
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    Ok(UserStore {
        db: Arc::new(db),
        path,
    })
}

pub fn refresh_user_names(mut state: AppState) {
    let names = match &*state.users.read() {
        Ok(store) => store.db.list_users().unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    state.user_names.set(names);
}

const PASSWORD_MASK: &str = "********";

#[component]
pub fn UserManager(on_close: EventHandler<()>) -> Element {
    let state = use_context::<AppState>();

    let mut new_name = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut new_confirm = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    let mut form_generation = use_signal(|| 0u32);

    let add_user = use_callback(move |_: ()| {
        let store = match &*state.users.read() {
            Ok(store) => store.clone(),
            Err(e) => {
                error_msg.set(Some(format!("User database unavailable: {e}")));
                return;
            }
        };
        let name = new_name().trim().to_string();
        let password = new_password();
        if password != new_confirm() {
            error_msg.set(Some("Passwords do not match.".to_string()));
            return;
        }
        match store.db.add_user(&name, &password) {
            Ok(()) => {
                new_name.set(String::new());
                new_password.set(String::new());
                new_confirm.set(String::new());
                error_msg.set(None);
                form_generation += 1;
                refresh_user_names(state);
            }
            Err(e) => error_msg.set(Some(capitalize(&e.to_string()))),
        }
    });

    let names = state.user_names.read().clone();
    let db_path = match &*state.users.read() {
        Ok(store) => Some(store.path.display().to_string()),
        Err(_) => None,
    };
    let db_error = state.users.read().as_ref().err().cloned();

    rsx! {
        div {
            class: "info-backdrop info-backdrop--top",
            onclick: move |_| on_close.call(()),
            div {
                class: "info-modal users-modal",
                onclick: move |e| e.stop_propagation(),
                onkeydown: move |e| {
                    if e.key() == Key::Escape {
                        on_close.call(());
                    }
                },

                div { class: "info-modal__header",
                    h3 { class: "info-modal__title", "User database" }
                    button {
                        class: "info-modal__close",
                        onclick: move |_| on_close.call(()),
                        "\u{2715}"
                    }
                }
                p { class: "info-modal__desc",
                    "Accounts that may log in when anonymous access is off. "
                    "Passwords are stored only as Argon2id hashes and cannot be displayed."
                }

                if let Some(err) = db_error {
                    p { class: "users-modal__error", "User database unavailable: {err}" }
                } else {
                    div { class: "users-table",
                        div { class: "users-table__head",
                            span { "User name" }
                            span { "Password" }
                            span {}
                        }
                        if names.is_empty() {
                            p { class: "users-table__empty", "No users yet." }
                        }
                        for name in names.iter() {
                            div { key: "{name}", class: "users-table__row",
                                span { class: "users-table__name", "{name}" }
                                span { class: "users-table__mask", "{PASSWORD_MASK}" }
                                button {
                                    class: "users-table__delete",
                                    onclick: {
                                        let name = name.clone();
                                        move |_| {
                                            if let Ok(store) = &*state.users.read() {
                                                match store.db.remove_user(&name) {
                                                    Ok(()) => error_msg.set(None),
                                                    Err(e) => error_msg.set(Some(capitalize(&e.to_string()))),
                                                }
                                            }
                                            refresh_user_names(state);
                                        }
                                    },
                                    "Delete"
                                }
                            }
                        }
                    }

                    for generation in [form_generation()] {
                    div { key: "{generation}", class: "users-form",
                        h4 { class: "users-form__title", "Add user" }
                        input {
                            class: "status-summary__input",
                            r#type: "text",
                            placeholder: "User name",
                            autocomplete: "off",
                            oninput: move |e| new_name.set(e.value()),
                        }
                        input {
                            class: "status-summary__input",
                            r#type: "password",
                            placeholder: "Password",
                            autocomplete: "new-password",
                            oninput: move |e| new_password.set(e.value()),
                        }
                        input {
                            class: "status-summary__input",
                            r#type: "password",
                            placeholder: "Confirm password",
                            autocomplete: "new-password",
                            oninput: move |e| new_confirm.set(e.value()),
                            onkeydown: move |e| {
                                if e.key() == Key::Enter {
                                    add_user.call(());
                                }
                            },
                        }
                        if let Some(err) = error_msg() {
                            p { class: "users-modal__error", "{err}" }
                        }
                        button {
                            class: "btn btn--primary",
                            onclick: move |_| add_user.call(()),
                            "Add user"
                        }
                    }
                    }

                    if let Some(path) = db_path {
                        p { class: "users-modal__path", "Stored in {path}" }
                    }
                }
            }
        }
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}
