//! Small helpers that keep the port faithful to the TypeScript original: JavaScript number
//! parsing and formatting, ISO timestamps, shell quoting, single-pass script templates, and a
//! JSON object that keeps its key order.

use std::fmt;
use std::marker::PhantomData;
use std::sync::LazyLock;

use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use regex::Regex;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

static DECIMAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

/// JavaScript `Number(text)`: surrounding whitespace is ignored, the empty string is 0, and
/// anything that is not a numeric literal is NaN.
pub fn js_number(text: &str) -> f64 {
    let t = text.trim();
    if t.is_empty() {
        return 0.0;
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(digits) = t.strip_prefix(prefix) {
            return if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                f64::NAN
            } else {
                digits.chars().fold(0.0, |acc, c| acc * f64::from(radix) + f64::from(c.to_digit(radix).unwrap_or(0)))
            };
        }
    }
    if DECIMAL.is_match(t) { t.parse().unwrap_or(f64::NAN) } else { f64::NAN }
}

/// Number or `None` for a non-numeric field.
pub fn num(value: &str) -> Option<f64> {
    let parsed = js_number(value);
    parsed.is_finite().then_some(parsed)
}

/// [`num`] of a field that may be missing.
pub fn num_opt(value: Option<&str>) -> Option<f64> {
    value.and_then(num)
}

/// JavaScript `Math.round`: halves round toward positive infinity.
pub fn js_round(x: f64) -> f64 {
    (x + 0.5).floor()
}

/// A number as JavaScript prints it in a template string (`85`, `85.5`).
pub fn n(x: f64) -> String {
    if x == 0.0 {
        "0".into()
    } else if x.is_nan() {
        "NaN".into()
    } else if x.is_infinite() {
        if x > 0.0 { "Infinity".into() } else { "-Infinity".into() }
    } else {
        format!("{x}")
    }
}

/// [`n`] of an optional number, with JavaScript's `undefined` for a missing one.
pub fn n_or(x: Option<f64>, missing: &str) -> String {
    x.map_or_else(|| missing.to_string(), n)
}

/// JavaScript `Number.prototype.toFixed`: an exact half rounds away from zero.
pub fn to_fixed(x: f64, digits: usize) -> String {
    if !x.is_finite() {
        return n(x);
    }
    if x == 0.0 {
        return format!("{:.digits$}", 0.0);
    }
    let scale = 10f64.powi(digits as i32);
    let scaled = x.abs() * scale;
    if scaled.fract() == 0.5 {
        let rounded = (scaled.floor() + 1.0) / scale;
        return format!("{:.digits$}", if x < 0.0 { -rounded } else { rounded });
    }
    format!("{x:.digits$}")
}

/// JavaScript `text.split(/\s+/)`: leading or trailing whitespace yields empty fields.
pub fn split_ws(text: &str) -> Vec<&str> {
    WHITESPACE.split(text).collect()
}

/// `text.trim().split(/\s+/)`.
pub fn fields(text: &str) -> Vec<&str> {
    split_ws(text.trim())
}

/// The first `count` characters of `text`.
pub fn take_chars(text: &str, count: usize) -> &str {
    match text.char_indices().nth(count) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// ISO 8601 with milliseconds and `Z`, as `Date.prototype.toISOString` prints it.
pub fn to_iso(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// [`to_iso`] of epoch milliseconds; a fraction of a millisecond is dropped.
pub fn iso_from_millis(ms: f64) -> String {
    let at = if ms.is_finite() { DateTime::from_timestamp_millis(ms.trunc() as i64) } else { None };
    to_iso(at.unwrap_or_default())
}

/// Epoch milliseconds of `at`.
pub fn millis(at: DateTime<Utc>) -> f64 {
    at.timestamp_millis() as f64
}

/// JavaScript `Date.parse` for the ISO forms the plugin writes: epoch milliseconds, or NaN.
/// A date-only string is UTC and a date-time without an offset is local time.
pub fn date_parse(text: &str) -> f64 {
    let t = text.trim();
    if let Ok(at) = DateTime::parse_from_rfc3339(t) {
        return at.timestamp_millis() as f64;
    }
    if let Ok(date) = NaiveDate::parse_from_str(t, "%Y-%m-%d") {
        return date.and_hms_opt(0, 0, 0).map_or(f64::NAN, |d| d.and_utc().timestamp_millis() as f64);
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(t, format) {
            return Local.from_local_datetime(&naive).earliest().map_or(f64::NAN, |d| d.timestamp_millis() as f64);
        }
    }
    f64::NAN
}

/// Quote a value for a POSIX shell.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Fill `{{name}}` placeholders of a script template in one pass, so a substituted value is never
/// scanned for placeholders itself.
pub(crate) fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = &after[..end];
        match values.iter().find(|(key, _)| *key == name) {
            Some((_, value)) => out.push_str(value),
            None => panic!("script template has no value for {name}"),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// `text` right-aligned to `width` characters.
pub(crate) fn pad_start(text: &str, width: usize) -> String {
    format!("{text:>width$}")
}

/// Descending order of two numbers for a stable sort.
pub(crate) fn desc(a: f64, b: f64) -> std::cmp::Ordering {
    b.partial_cmp(&a).unwrap_or(std::cmp::Ordering::Equal)
}

/// A JSON object that keeps the order its keys were inserted or read in, as JavaScript objects
/// do; reports print their entries in that order.
#[derive(Clone, Debug, PartialEq)]
pub struct OrderedMap<V>(Vec<(String, V)>);

impl<V> Default for OrderedMap<V> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<V> OrderedMap<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.0.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Set a key; an existing key keeps its position.
    pub fn insert(&mut self, key: impl Into<String>, value: V) {
        let key = key.into();
        match self.get_mut(&key) {
            Some(slot) => *slot = value,
            None => self.0.push((key, value)),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.0.iter().map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<K: Into<String>, V> FromIterator<(K, V)> for OrderedMap<V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::new();
        for (key, value) in iter {
            map.insert(key, value);
        }
        map
    }
}

impl<V: Serialize> Serialize for OrderedMap<V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for OrderedMap<V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor<V>(PhantomData<V>);
        impl<'de, V: Deserialize<'de>> Visitor<'de> for MapVisitor<V> {
            type Value = OrderedMap<V>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = OrderedMap::new();
                while let Some((key, value)) = access.next_entry::<String, V>()? {
                    map.insert(key, value);
                }
                Ok(map)
            }
        }
        deserializer.deserialize_map(MapVisitor(PhantomData))
    }
}

/// Deserialize an optional number, treating anything that is not a finite number (a string or
/// `null` from a damaged file) as absent.
pub(crate) fn lenient_number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<f64>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| v.as_f64()).filter(|v| v.is_finite()))
}

/// Deserialize a map of numbers, dropping entries that are not finite numbers.
pub(crate) fn lenient_number_map<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OrderedMap<f64>, D::Error> {
    let raw = Option::<OrderedMap<serde_json::Value>>::deserialize(deserializer)?.unwrap_or_default();
    Ok(raw.iter().filter_map(|(k, v)| v.as_f64().filter(|v| v.is_finite()).map(|v| (k, v))).collect())
}

#[cfg(test)]
pub(crate) mod testing {
    use serde_json::Value;

    /// Numbers as floats and no `null` members, so `85` equals `85.0` and an absent field equals
    /// one JavaScript left out.
    pub fn normalize(value: Value) -> Value {
        match value {
            Value::Number(number) => serde_json::json!(number.as_f64().unwrap()),
            Value::Array(items) => Value::Array(items.into_iter().map(normalize).collect()),
            Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (k, normalize(v))).collect()),
            other => other,
        }
    }

    /// Assert that `actual` serializes to the JSON the TypeScript original produced.
    #[track_caller]
    pub fn assert_golden<T: serde::Serialize>(actual: &T, golden: &str) {
        let actual = normalize(serde_json::to_value(actual).unwrap());
        let expected = normalize(serde_json::from_str(golden).unwrap());
        assert_eq!(actual, expected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numbers_like_javascript() {
        assert_eq!(num(""), Some(0.0));
        assert_eq!(num(" 12.5 "), Some(12.5));
        assert_eq!(num("1e3"), Some(1000.0));
        assert_eq!(num("0x10"), Some(16.0));
        assert_eq!(num("-"), None);
        assert_eq!(num("12abc"), None);
        assert_eq!(num("inf"), None);
        assert_eq!(num("Infinity"), None);
        assert_eq!(num("[N/A]"), None);
    }

    #[test]
    fn formats_numbers_like_javascript() {
        assert_eq!(n(85.0), "85");
        assert_eq!(n(85.5), "85.5");
        assert_eq!(n(-0.0), "0");
        assert_eq!(to_fixed(0.25, 1), "0.3");
        assert_eq!(to_fixed(2.5, 0), "3");
        assert_eq!(to_fixed(1.005, 2), "1.00");
        assert_eq!(to_fixed(-1.5, 0), "-2");
        assert_eq!(to_fixed(4.2, 1), "4.2");
        assert_eq!(js_round(2.5), 3.0);
        assert_eq!(js_round(-2.5), -2.0);
    }

    #[test]
    fn handles_dates_and_templates() {
        assert_eq!(iso_from_millis(0.0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_from_millis(1_793_000_000_123.9), "2026-10-26T07:33:20.123Z");
        assert_eq!(date_parse("2026-10-28T00:00:00Z"), 1_793_145_600_000.0);
        assert_eq!(date_parse("2026-10-28"), 1_793_145_600_000.0);
        assert!(date_parse("soon").is_nan());
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(fill("a={{x}} b={{y}}", &[("x", "{{y}}"), ("y", "2")]), "a={{y}} b=2");
    }

    #[test]
    fn keeps_object_key_order() {
        let map: OrderedMap<f64> = serde_json::from_str(r#"{"/z":1,"/a":2,"/z":3}"#).unwrap();
        assert_eq!(map.keys().collect::<Vec<_>>(), ["/z", "/a"]);
        assert_eq!(serde_json::to_string(&map).unwrap(), r#"{"/z":3.0,"/a":2.0}"#);
    }
}
