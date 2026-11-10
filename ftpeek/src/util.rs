pub fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        let truncated: String = text.chars().take(max - 3).collect();
        format!("{truncated}...")
    } else {
        text.to_string()
    }
}

pub fn shorten_start(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count > max {
        let tail: String = text.chars().skip(count - (max - 1)).collect();
        format!("\u{2026}{tail}")
    } else {
        text.to_string()
    }
}

pub fn plural(count: usize, word: &str) -> String {
    match count {
        1 => format!("1 {word}"),
        n => format!("{n} {word}s"),
    }
}
