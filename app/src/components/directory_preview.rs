use dioxus::prelude::*;
use proto_core::MessageEvent;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, PartialEq)]
struct Entry {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

fn read_entries(dir: &Path) -> Option<Vec<Entry>> {
    let read_dir = fs::read_dir(dir).ok()?;
    let mut items: Vec<Entry> = read_dir
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            Some(Entry {
                name: e.file_name().to_string_lossy().to_string(),
                path: e.path(),
                is_dir: meta.is_dir(),
                size: meta.len(),
            })
        })
        .collect();
    items.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
    Some(items)
}

#[component]
pub fn DirectoryPreview(root_dir: Signal<String>, logs: Signal<Vec<MessageEvent>>) -> Element {
    let _tick = logs.read().len();

    let expanded = use_signal(HashSet::<PathBuf>::new);
    let path = PathBuf::from(root_dir());

    rsx! {
        div { class: "dir-preview",
            div { class: "dir-preview__header",
                span { "Root directory" }
                span { class: "dir-preview__path", "{path.display()}" }
            }
            div { class: "dir-preview__body",
                match read_entries(&path) {
                    Some(items) if !items.is_empty() => rsx! {
                        for entry in items {
                            DirectoryNode { entry, depth: 0, expanded }
                        }
                    },
                    Some(_) => rsx! { p { class: "dir-preview__empty", "Directory is empty." } },
                    None => rsx! { p { class: "dir-preview__empty", "Directory doesn't exist yet — start the server to create it." } },
                }
            }
        }
    }
}

#[component]
fn DirectoryNode(entry: Entry, depth: usize, expanded: Signal<HashSet<PathBuf>>) -> Element {
    let is_open = expanded.read().contains(&entry.path);
    let indent = format!("{}px", 14 + depth * 16);

    let children = if entry.is_dir && is_open {
        read_entries(&entry.path)
    } else {
        None
    };

    let icon = if entry.is_dir {
        if is_open {
            "\u{1F4C2}"
        } else {
            "\u{1F4C1}"
        }
    } else {
        "\u{1F4C4}"
    };
    let arrow = if !entry.is_dir {
        ""
    } else if is_open {
        "\u{25be}"
    } else {
        "\u{25b8}"
    };

    let path_for_click = entry.path.clone();

    rsx! {
        div {
            class: "dir-preview__row",
            style: "padding-left: {indent};",
            onclick: move |_| {
                if entry.is_dir {
                    let mut set = expanded.write();
                    if !set.remove(&path_for_click) {
                        set.insert(path_for_click.clone());
                    }
                }
            },
            span { class: "dir-preview__arrow", "{arrow}" }
            span {
                class: if entry.is_dir { "dir-preview__icon dir-preview__icon--dir" } else { "dir-preview__icon" },
                "{icon}"
            }
            span { class: "dir-preview__name", "{entry.name}" }
            span { class: "dir-preview__size",
                if !entry.is_dir { "{entry.size} B" }
            }
        }
        if let Some(kids) = children {
            for child in kids {
                DirectoryNode { entry: child, depth: depth + 1, expanded }
            }
        }
    }
}
