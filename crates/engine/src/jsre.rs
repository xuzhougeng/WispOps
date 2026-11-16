//! Compile JavaScript-flavoured regular expressions with the `regex` crate.
//!
//! The classifier tables and the deployment deny list were written for JavaScript, whose
//! `\s`, `\d`, `\w`, `\b` and `.` differ from the `regex` crate's Unicode-aware defaults.
//! [`compile`] rewrites a pattern so those classes keep their JavaScript meaning. Look-around
//! is not available in the `regex` crate and is reported as an error.

use regex::Regex;

/// The members of JavaScript's `\s`, written for use inside a character class.
const JS_SPACE: &str = r"\t\n\x0B\x0C\r \u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}";
/// Everything JavaScript's `.` refuses to match, written for use inside a character class.
const JS_LINE_END: &str = r"\n\r\u{2028}\u{2029}";

/// Translate a JavaScript pattern (no delimiters) into `regex` crate syntax.
pub fn translate(pattern: &str) -> Result<String, String> {
    translate_with(pattern, false)
}

fn swap_case(c: char) -> char {
    if c.is_ascii_lowercase() { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() }
}

/// With `ignore_case`, every ASCII letter is spelled out in both cases. JavaScript's `i` flag
/// (without `u`) never folds a non-ASCII character onto an ASCII one, which the `regex` crate's
/// `(?i)` would (`ſ` for `s`, the Kelvin sign for `k`).
fn translate_with(pattern: &str, ignore_case: bool) -> Result<String, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut in_class = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            let Some(&next) = chars.get(i + 1) else { return Err("trailing backslash".to_string()) };
            i += 2;
            match (next, in_class) {
                ('s', false) => { out.push('['); out.push_str(JS_SPACE); out.push(']'); }
                ('s', true) => out.push_str(JS_SPACE),
                ('S', _) => { out.push_str("[^"); out.push_str(JS_SPACE); out.push(']'); }
                ('d', false) => out.push_str("[0-9]"),
                ('d', true) => out.push_str("0-9"),
                ('D', _) => out.push_str("[^0-9]"),
                ('w', false) => out.push_str("[A-Za-z0-9_]"),
                ('w', true) => out.push_str("A-Za-z0-9_"),
                ('W', _) => out.push_str("[^A-Za-z0-9_]"),
                ('b', false) => out.push_str(r"(?-u:\b)"),
                ('B', false) => out.push_str(r"(?-u:\B)"),
                ('b', true) => out.push_str(r"\x08"),
                ('/', _) => out.push('/'),
                ('0', _) => out.push_str(r"\x00"),
                ('1'..='9', _) => return Err("backreferences are not supported".to_string()),
                ('x' | 'u', _) => {
                    // A code point escape: copy its hex digits verbatim.
                    out.push('\\');
                    out.push(next);
                    let digits = if next == 'x' { 2 } else { 4 };
                    for _ in 0..digits {
                        match chars.get(i) {
                            Some(digit) if digit.is_ascii_hexdigit() => { out.push(*digit); i += 1; }
                            _ => return Err("invalid code point escape".to_string()),
                        }
                    }
                }
                (other, _) => { out.push('\\'); out.push(other); }
            }
            continue;
        }
        if in_class {
            match c {
                ']' => { in_class = false; out.push(']'); }
                // Unescaped in JavaScript, but set syntax in the `regex` crate.
                '[' | '&' | '~' => { out.push('\\'); out.push(c); }
                _ if ignore_case && c.is_ascii_alphabetic() => {
                    let end = chars.get(i + 2).copied().filter(|end| chars.get(i + 1) == Some(&'-') && end.is_ascii_alphabetic());
                    match end {
                        Some(end) => {
                            out.extend([c, '-', end, swap_case(c), '-', swap_case(end)]);
                            i += 2;
                        }
                        None => out.extend([c, swap_case(c)]),
                    }
                }
                _ => out.push(c),
            }
            i += 1;
            continue;
        }
        match c {
            _ if ignore_case && c.is_ascii_alphabetic() => out.extend(['[', c, swap_case(c), ']']),
            '[' => {
                in_class = true;
                out.push('[');
                if chars.get(i + 1) == Some(&'^') { out.push('^'); i += 1; }
                // A leading `]` is a literal in neither dialect's favour; JavaScript treats `[]` as empty.
            }
            '.' => { out.push_str("[^"); out.push_str(JS_LINE_END); out.push(']'); }
            '(' if chars.get(i + 1) == Some(&'?') => {
                let rest: String = chars[i + 2..].iter().take(2).collect();
                if rest.starts_with('=') || rest.starts_with('!') || rest.starts_with("<=") || rest.starts_with("<!") {
                    return Err("look-around is not supported".to_string());
                }
                out.push('(');
                if rest.starts_with('<') {
                    // A group name is copied as written.
                    while let Some(&name_char) = chars.get(i + 1) {
                        out.push(name_char);
                        i += 1;
                        if name_char == '>' { break }
                    }
                }
            }
            _ => out.push(c),
        }
        i += 1;
    }
    if in_class { return Err("unterminated character class".to_string()) }
    Ok(out)
}

/// Compile a JavaScript pattern; `flags` may contain `i` (ignore case) and `m` (multi-line anchors).
pub fn compile(pattern: &str, flags: &str) -> Result<Regex, String> {
    let mut prefix = String::new();
    let mut ignore_case = false;
    for flag in flags.chars() {
        match flag {
            'i' => ignore_case = true,
            'm' => prefix.push_str("(?m)"),
            other => return Err(format!("unsupported regular expression flag {other}")),
        }
    }
    let translated = translate_with(pattern, ignore_case)?;
    Regex::new(&format!("{prefix}{translated}")).map_err(|error| error.to_string())
}

/// Whether JavaScript's `\s` (and `String.prototype.trim`) treats this character as whitespace.
pub fn is_js_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

/// `String.prototype.trim`.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_space)
}

/// A lazily compiled JavaScript pattern, usable in expression position.
macro_rules! js_re {
    ($pattern:expr) => { $crate::jsre::js_re!($pattern, "") };
    ($pattern:expr, $flags:expr) => {{
        static RE: ::std::sync::LazyLock<::regex::Regex> =
            ::std::sync::LazyLock::new(|| $crate::jsre::compile($pattern, $flags).expect("valid built-in pattern"));
        &*RE
    }};
}
pub(crate) use js_re;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_javascript_class_meanings() {
        let word = compile(r"\bkill\b", "").unwrap();
        assert!(word.is_match("x; kill 1"));
        // A non-ASCII letter is not a word character in JavaScript, so a boundary exists here.
        assert!(word.is_match("ékill"));
        assert!(!word.is_match("skill"));
        let digits = compile(r"^\d+$", "").unwrap();
        assert!(digits.is_match("123"));
        assert!(!digits.is_match("١٢٣"));
        let dot = compile("a.b", "").unwrap();
        assert!(dot.is_match("a b"));
        assert!(!dot.is_match("a\rb"));
        let space = compile(r"a\sb", "").unwrap();
        assert!(space.is_match("a\u{3000}b"));
        assert!(!space.is_match("a\u{85}b"));
    }

    #[test]
    fn translates_classes_and_rejects_look_around() {
        let class = compile(r#"(?:^|[\s;&|(`'"])rm(?:\s|$)"#, "").unwrap();
        assert!(class.is_match("a && rm x"));
        assert!(class.is_match("a &rm"));
        assert!(!class.is_match("farm x"));
        assert!(compile(r"a(?=b)", "").is_err());
        assert!(compile(r"(?<![<>])&", "").is_err());
        assert!(compile(r"DROP", "i").unwrap().is_match("drop"));
        // JavaScript's `i` never folds non-ASCII onto ASCII: no long s for `s`, no Kelvin sign for `k`.
        let insensitive = compile(r"\bdrop\s+(?:task|[a-c]x)\b", "i").unwrap();
        assert!(insensitive.is_match("DROP  TaSk"));
        assert!(insensitive.is_match("drop Bx"));
        assert!(!insensitive.is_match("drop ta\u{17f}k"));
        assert!(!insensitive.is_match("drop tas\u{212a}"));
        assert!(compile(r"^[^-\s][^\s]*$", "").unwrap().is_match("user@host"));
        assert!(!compile(r"^[^-\s][^\s]*$", "").unwrap().is_match("-oProxyCommand=evil"));
    }
}
