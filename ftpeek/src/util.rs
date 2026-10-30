pub fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        let truncated: String = text.chars().take(max - 3).collect();
        format!("{truncated}...")
    } else {
        text.to_string()
    }
}
