//! Muted findings: the owner acknowledges a known problem on one server (a finding code,
//! optionally for one path such as a mount) until a date or until unmuted. A muted finding is
//! still recorded and reported to the agent, but it no longer colors the server's state or raises
//! an alert.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::inspect::Finding;
use crate::util::date_parse;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mute {
    pub code: String,
    /// What a finding is about (a mount, a service), or absent for every finding with this code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// ISO time the mute ends; absent until unmuted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

pub const MAX_MUTES: usize = 50;

/// What a finding is about: its recorded subject, or for older records the leading path of its message.
pub fn finding_subject(finding: &Finding) -> Option<&str> {
    if let Some(subject) = &finding.subject {
        return Some(subject);
    }
    let message = finding.message.as_str();
    message.starts_with('/').then(|| message.split(char::is_whitespace).next().unwrap_or(message))
}

/// Validate a host's mute list; anything malformed is rejected rather than dropped.
pub fn validate_mutes(value: &Value) -> Result<Vec<Mute>, String> {
    let list = value.as_array().filter(|list| list.len() <= MAX_MUTES).ok_or_else(|| format!("Mutes must be a list of at most {MAX_MUTES}"))?;
    list.iter()
        .map(|mute| {
            let code = mute.get("code").and_then(Value::as_str).ok_or("Invalid mute")?;
            if code.is_empty() || code.len() > 40 || !code.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return Err("Invalid mute".to_string());
            }
            let subject = match mute.get("subject") {
                None => None,
                Some(Value::String(subject)) if !subject.is_empty() && subject.encode_utf16().count() <= 2048 => Some(subject.clone()),
                Some(_) => return Err("Invalid mute subject".to_string()),
            };
            let until = match mute.get("until") {
                None => None,
                Some(Value::String(until)) if date_parse(until).is_finite() => Some(until.clone()),
                Some(_) => return Err("Invalid mute end".to_string()),
            };
            Ok(Mute { code: code.to_string(), subject, until })
        })
        .collect()
}

/// The mute covering a finding at `now_ms` (epoch milliseconds), if any.
pub fn mute_for<'a>(finding: &Finding, mutes: &'a [Mute], now_ms: f64) -> Option<&'a Mute> {
    mutes.iter().find(|m| {
        m.code == finding.code
            && m.subject.as_deref().is_none_or(|subject| Some(subject) == finding_subject(finding))
            && m.until.as_deref().is_none_or(|until| date_parse(until) > now_ms)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::Severity;
    use serde_json::json;

    fn mute(code: &str, subject: Option<&str>, until: Option<&str>) -> Mute {
        Mute { code: code.into(), subject: subject.map(Into::into), until: until.map(Into::into) }
    }

    #[test]
    fn covers_one_subject_or_a_whole_code_until_the_mute_ends() {
        let now = date_parse("2026-10-29T12:00:00Z");
        let finding = Finding::new(Severity::Crit, "disk-full", "/data5 99% used").about("/data5");
        assert!(mute_for(&finding, &[mute("disk-full", Some("/data5"), None)], now).is_some());
        assert!(mute_for(&finding, &[mute("disk-full", Some("/home"), None)], now).is_none());
        // Older records have no subject; the leading path of the message stands in.
        assert!(mute_for(&Finding::new(Severity::Crit, "disk-full", "/data5 99% used"), &[mute("disk-full", Some("/data5"), None)], now).is_some());
        assert!(mute_for(&finding, &[mute("disk-full", None, Some("2026-10-29T11:00:00Z"))], now).is_none());
        assert!(mute_for(&finding, &[mute("disk-full", None, Some("2026-10-29T13:00:00Z"))], now).is_some());
        assert!(mute_for(&finding, &[mute("memory-low", None, None)], now).is_none());
    }

    #[test]
    fn validates_mute_lists() {
        assert_eq!(validate_mutes(&json!([{ "code": "disk-full", "subject": "/data", "until": "2026-11-05T00:00:00Z" }, { "code": "zombies" }])).unwrap().len(), 2);
        for bad in [json!("x"), json!([{ "code": "Disk Full" }]), json!([{ "code": "a", "subject": "" }]), json!([{ "code": "a", "subject": null }]), json!([{ "code": "a", "until": "soon" }]), json!([7])] {
            assert!(validate_mutes(&bad).is_err(), "{bad}");
        }
        assert!(validate_mutes(&Value::Array(vec![json!({ "code": "a" }); 51])).is_err());
    }
}
