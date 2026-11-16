//! Desktop UI translations. Chinese source text is the lookup key; unknown
//! keys fall back unchanged. Server names, command output and model prompts are not looked up.

use std::collections::HashMap;
use std::sync::{LazyLock, atomic::{AtomicBool, Ordering}};
use wisp_ops_core::settings::Language;

static ENGLISH: AtomicBool = AtomicBool::new(false);
static EN: LazyLock<HashMap<String, String>> = LazyLock::new(|| serde_json::from_str(include_str!("../locales/en.json")).expect("valid English UI catalog"));

pub fn set_language(language: Language) {
    ENGLISH.store(language == Language::En, Ordering::Relaxed);
}

pub fn is_english() -> bool {
    ENGLISH.load(Ordering::Relaxed)
}

pub fn translate(language: Language, text: &str) -> &str {
    if language == Language::En { EN.get(text).map_or(text, String::as_str) } else { text }
}

pub fn t(text: &str) -> &str {
    translate(if is_english() { Language::En } else { Language::Zh }, text)
}

/// Both format literals are checked by Rust, including named captures and
/// precision specifiers. Values are formatted only by the selected branch.
macro_rules! tf {
    ($zh:literal, $en:literal $(, $args:expr)* $(,)?) => {
        if crate::i18n::is_english() { format!($en $(, $args)*) } else { format!($zh $(, $args)*) }
    };
}

#[cfg(test)]
mod tests {
    use super::{Language, translate};

    #[test]
    fn language_lookup_preserves_unknown_and_user_content() {
        assert_eq!(translate(Language::En, "设置"), "Settings");
        assert_eq!(translate(Language::Zh, "设置"), "设置");
        assert_eq!(translate(Language::En, "gpu-01"), "gpu-01");
    }
}
