//! Clock helpers: epoch milliseconds, ISO-8601 formatting and parsing as the plugin's records use them.

use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};

/// Milliseconds since the Unix epoch, now.
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// `2026-10-27T00:30:00.000Z`, the format of JavaScript's `Date.prototype.toISOString`.
pub fn to_iso(ms: i64) -> String {
    match Utc.timestamp_millis_opt(ms).single() {
        Some(at) => at.to_rfc3339_opts(SecondsFormat::Millis, true),
        None => String::new(),
    }
}

/// Parse the timestamps found in stored records: RFC 3339, a date-time without zone (taken as UTC),
/// or a bare `YYYY-MM-DD` (midnight UTC). Returns epoch milliseconds.
pub fn parse_iso(text: &str) -> Option<i64> {
    let text = text.trim();
    if let Ok(at) = DateTime::parse_from_rfc3339(text) {
        return Some(at.timestamp_millis());
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(at) = NaiveDateTime::parse_from_str(text, format) {
            return Some(at.and_utc().timestamp_millis());
        }
    }
    if let Ok(day) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return Some(day.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis());
    }
    if let Ok(day) = NaiveDate::parse_from_str(&format!("{text}-01"), "%Y-%m-%d") {
        return Some(day.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis());
    }
    None
}

/// The `YYYY-MM` month of an instant, in UTC.
pub fn utc_month(ms: i64) -> String {
    to_iso(ms).chars().take(7).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses_like_javascript() {
        assert_eq!(to_iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(parse_iso("2026-10-27T00:30:00Z"), Some(1_793_061_000_000));
        assert_eq!(parse_iso("2026-10-27T08:30:00+08:00"), Some(1_793_061_000_000));
        assert_eq!(parse_iso("2026-10-01"), parse_iso("2026-10-01T00:00:00.000Z"));
        assert_eq!(parse_iso("2026-10"), parse_iso("2026-10-01T00:00:00Z"));
        assert_eq!(parse_iso("nonsense"), None);
        assert_eq!(utc_month(parse_iso("2026-09-30T23:59:00Z").unwrap()), "2026-09");
    }
}
