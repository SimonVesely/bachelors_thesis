use std::fs::Metadata;
use time::OffsetDateTime;

pub fn format_mdtm(meta: &Metadata) -> String {
    let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let dt: OffsetDateTime = modified.into();
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

pub fn format_mlsx_facts(meta: &Metadata) -> String {
    let kind = if meta.is_dir() { "dir" } else { "file" };
    let mut facts = format!("type={};modify={};", kind, format_mdtm(meta));
    if meta.is_file() {
        facts.push_str(&format!("size={};", meta.len()));
    }
    facts
}

pub fn format_list_line(name: &str, meta: &Metadata) -> String {
    let kind = if meta.is_dir() { 'd' } else { '-' };
    let perms = unix_perms(meta);
    let dt: OffsetDateTime = meta
        .modified()
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        .into();
    format!(
        "{kind}{perms} 1 owner group {:>10} {:02}-{:02} {:02}:{:02} {name}",
        meta.len(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute()
    )
}

#[cfg(unix)]
fn unix_perms(meta: &Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    let bit = |mask: u32, ch: char| if mode & mask != 0 { ch } else { '-' };
    format!(
        "{}{}{}{}{}{}{}{}{}",
        bit(0o400, 'r'),
        bit(0o200, 'w'),
        bit(0o100, 'x'),
        bit(0o040, 'r'),
        bit(0o020, 'w'),
        bit(0o010, 'x'),
        bit(0o004, 'r'),
        bit(0o002, 'w'),
        bit(0o001, 'x'),
    )
}

#[cfg(not(unix))]
fn unix_perms(_meta: &Metadata) -> String {
    "rwxr-xr-x".to_string()
}
