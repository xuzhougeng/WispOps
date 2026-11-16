//! Outgoing notifications, ported from the plugin's `notifier.ts` and the
//! alert half of `auto-inspect.ts`: the Markdown a message carries, the
//! request each kind of channel wants (WeCom, DingTalk, Feishu or a plain
//! webhook), whether a run is worth sending, and the reply check. Sending is
//! the caller's: `deliver` takes a function that posts the request, so this
//! stays free of the network and is tested without one.
//!
//! Endpoints carry their token in the URL and channels may carry a signing
//! secret; neither ever enters a `Delivery`, an error or a message.

use crate::config::QuietHours;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The byte budget of a message: within the smallest provider limit.
pub const MAX_BYTES: usize = 3400;

/// The longest reply read from a provider.
pub const MAX_REPLY_BYTES: usize = 16_384;

/// Count keys that make a run a problem worth a notification.
pub const PROBLEM_KEYS: [&str; 5] = ["warn", "crit", "unreachable", "incomplete", "commandFailed"];

/// Which service a channel posts to; each wants its own body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Wecom,
    Dingtalk,
    Feishu,
    #[default]
    Webhook,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Wecom, Kind::Dingtalk, Kind::Feishu, Kind::Webhook];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Wecom => "wecom",
            Kind::Dingtalk => "dingtalk",
            Kind::Feishu => "feishu",
            Kind::Webhook => "webhook",
        }
    }

    pub fn parse(text: &str) -> Kind {
        Kind::ALL.into_iter().find(|kind| kind.as_str() == text).unwrap_or_default()
    }
}

/// One configured destination.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Channel {
    pub name: String,
    pub kind: Kind,
    /// The endpoint, token included.
    pub url: String,
    /// DingTalk/Feishu signing secret, or the plain webhook's bearer token; empty for none.
    pub secret: String,
}

/// What to post: never logged, it holds the endpoint and maybe a token.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Sent,
    Failed,
    Skipped,
}

/// What became of one message to one channel. `detail` never holds the endpoint, a token or the provider's reply text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    pub channel: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Delivery {
    fn new(channel: &str, status: Status, detail: Option<String>) -> Delivery {
        Delivery { channel: channel.to_string(), status, detail }
    }
}

/// The posting itself: the reply's status and up to `MAX_REPLY_BYTES` of its body, or why there is none.
pub type Send<'a> = &'a dyn Fn(&Request) -> Result<(u16, String), String>;

/// Cut `text` to `MAX_BYTES` without splitting a UTF-8 character; `tail` marks a cut.
pub fn bound(text: &str, tail: &str) -> String {
    if text.len() <= MAX_BYTES { return text.to_string() }
    let mut end = MAX_BYTES;
    while !text.is_char_boundary(end) { end -= 1 }
    format!("{}{tail}", &text[..end])
}

fn number(value: f64) -> String {
    if value.fract() == 0. && value.abs() < 1e15 { format!("{}", value as i64) } else { value.to_string() }
}

/// The message of one task run.
pub fn task_summary(task: &str, at: &str, hosts: &[String], counts: &BTreeMap<String, f64>, excerpt: &str) -> String {
    let counts: Vec<String> = counts.iter().map(|(key, value)| format!("{key}={}", number(*value))).collect();
    let counts = if counts.is_empty() { "No findings reported".to_string() } else { counts.join(", ") };
    let text = format!("## WispOps: {task}\n{at}\nHosts: {}\n{counts}\n\n{excerpt}", hosts.join(", "));
    bound(&text, "\n… (truncated; full report in WispOps)")
}

/// The problem counts of a run, in a fixed order, so two runs compare as strings.
pub fn problem_signature(counts: &BTreeMap<String, f64>) -> String {
    PROBLEM_KEYS.iter().map(|key| format!("{key}={}", number(counts.get(*key).copied().unwrap_or(0.)))).collect::<Vec<_>>().join(" ")
}

pub fn has_problems(counts: &BTreeMap<String, f64>) -> bool {
    PROBLEM_KEYS.iter().any(|key| counts.get(*key).is_some_and(|count| *count > 0.))
}

/// Wall-clock `HH:MM` of an instant in a zone; falls back to UTC for an unknown zone.
pub fn local_clock(ms: i64, time_zone: &str) -> String {
    let parts = crate::schedule::zoned_parts(ms, time_zone).or_else(|_| crate::schedule::zoned_parts(ms, "UTC"));
    parts.map(|parts| format!("{:02}:{:02}", parts.hour, parts.minute)).unwrap_or_default()
}

/// Whether `ms` falls inside the quiet window; a window that ends before it starts crosses midnight.
pub fn in_quiet_hours(quiet: Option<&QuietHours>, ms: i64, fallback_zone: &str) -> bool {
    let Some(quiet) = quiet else { return false };
    if quiet.start == quiet.end { return false }
    let now = local_clock(ms, quiet.time_zone.as_deref().unwrap_or(fallback_zone));
    let (start, end) = (quiet.start.as_str(), quiet.end.as_str());
    if start < end { now.as_str() >= start && now.as_str() < end } else { now.as_str() >= start || now.as_str() < end }
}

/// When a task's run is sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskRules {
    /// Skip runs without problems.
    pub only_problems: bool,
    /// Skip runs whose problem counts equal the previous run's.
    pub on_change: bool,
    pub quiet_hours: Option<QuietHours>,
    /// Zone for quiet hours without their own.
    pub time_zone: String,
}

/// Why a run is not sent, or `None` when it is.
pub fn task_skip(rules: &TaskRules, counts: &BTreeMap<String, f64>, previous: Option<&BTreeMap<String, f64>>, at_ms: i64) -> Option<String> {
    if rules.only_problems && !has_problems(counts) { return Some("no problems".into()) }
    if rules.on_change && previous.is_some_and(|previous| problem_signature(previous) == problem_signature(counts)) { return Some("unchanged since the previous run".into()) }
    if in_quiet_hours(rules.quiet_hours.as_ref(), at_ms, if rules.time_zone.is_empty() { "UTC" } else { &rules.time_zone }) {
        let quiet = rules.quiet_hours.as_ref().map(|quiet| format!("{}–{}", quiet.start, quiet.end)).unwrap_or_default();
        return Some(format!("quiet hours {quiet}"));
    }
    None
}

/// The parts of an endpoint this code needs: whether it is plain HTTP, and its host.
fn endpoint(url: &str) -> Result<(bool, String), String> {
    let url = url.trim();
    let (plain, rest) = if let Some(rest) = url.strip_prefix("https://") { (false, rest) } else if let Some(rest) = url.strip_prefix("http://") { (true, rest) } else { return Err("endpoint must be HTTPS without user info".into()) };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') || url.chars().any(char::is_whitespace) { return Err("endpoint must be HTTPS without user info".into()) }
    let host = if let Some(inner) = authority.strip_prefix('[') { inner.split(']').next().unwrap_or("").to_string() } else { authority.rsplit_once(':').map_or(authority, |(host, _)| host).to_string() };
    if host.is_empty() { return Err("endpoint has no host".into()) }
    Ok((plain, host.to_lowercase()))
}

/// What is wrong with an endpoint, if anything: HTTPS without user info, as
/// the plugin asks. Plain HTTP is accepted for this machine only
/// (`localhost`, `127.0.0.1`, `::1`), for a receiver of one's own.
pub fn url_problem(url: &str) -> Option<String> {
    match endpoint(url) {
        Err(err) => Some(err),
        Ok((true, host)) if !matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") => Some("endpoint must be HTTPS without user info".into()),
        Ok(_) => None,
    }
}

/// The host part of an endpoint, to name it without its token.
pub fn url_host(url: &str) -> String {
    endpoint(url).map(|(_, host)| host).unwrap_or_default()
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 { block[..32].copy_from_slice(&Sha256::digest(key)) } else { block[..key.len()].copy_from_slice(key) }
    let pad = |byte: u8| block.iter().map(|b| b ^ byte).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

fn base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn percent(text: &str) -> String {
    text.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Set a query parameter, replacing one of the same name.
fn with_param(url: &str, name: &str, value: &str) -> String {
    let (base, fragment) = url.split_once('#').map_or((url, None), |(base, fragment)| (base, Some(fragment)));
    let (path, query) = base.split_once('?').map_or((base, ""), |(path, query)| (path, query));
    let mut pairs: Vec<String> = query.split('&').filter(|pair| !pair.is_empty() && pair.split('=').next() != Some(name)).map(str::to_string).collect();
    pairs.push(format!("{name}={}", percent(value)));
    format!("{path}?{}{}", pairs.join("&"), fragment.map(|f| format!("#{f}")).unwrap_or_default())
}

/// The request one channel wants for a Markdown message, signed when it has a secret. `now_ms` is the signing time.
pub fn request(channel: &Channel, markdown: &str, now_ms: i64) -> Result<Request, String> {
    let url = channel.url.trim();
    if url.is_empty() { return Err("missing endpoint".into()) }
    if let Some(problem) = url_problem(url) { return Err(problem) }
    let secret = channel.secret.trim();
    let mut url = url.to_string();
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body = match channel.kind {
        Kind::Wecom => json!({"msgtype": "markdown", "markdown": {"content": markdown}}),
        Kind::Dingtalk => {
            if !secret.is_empty() {
                url = with_param(&url, "timestamp", &now_ms.to_string());
                url = with_param(&url, "sign", &base64(&hmac_sha256(secret.as_bytes(), format!("{now_ms}\n{secret}").as_bytes())));
            }
            json!({"msgtype": "markdown", "markdown": {"title": "WispOps", "text": markdown}})
        }
        Kind::Feishu => {
            let mut body = json!({"msg_type": "interactive", "card": {"elements": [{"tag": "markdown", "content": markdown}]}});
            if !secret.is_empty() {
                let timestamp = now_ms.div_euclid(1000).to_string();
                body["timestamp"] = json!(timestamp);
                body["sign"] = json!(base64(&hmac_sha256(format!("{timestamp}\n{secret}").as_bytes(), b"")));
            }
            body
        }
        Kind::Webhook => {
            if !secret.is_empty() { headers.push(("authorization".into(), format!("Bearer {secret}"))) }
            json!({"title": "WispOps", "markdown": markdown})
        }
    };
    Ok(Request { url, headers, body })
}

/// Whether the provider took the message: HTTP 2xx, and for the chat services a zero error code in the reply.
/// The error names a status or a code, never the reply's text.
pub fn check_reply(kind: Kind, status: u16, body: &str) -> Result<(), String> {
    if !(200..300).contains(&status) { return Err(format!("HTTP {status}")) }
    if kind == Kind::Webhook { return Ok(()) }
    if body.len() > MAX_REPLY_BYTES { return Err("response too large".into()) }
    let reply: Value = serde_json::from_str(body).map_err(|_| "the reply is not JSON".to_string())?;
    let code = match kind {
        Kind::Feishu => reply.get("code").filter(|code| !code.is_null()).or_else(|| reply.get("StatusCode")),
        _ => reply.get("errcode"),
    };
    match code.and_then(Value::as_i64) {
        Some(0) => Ok(()),
        Some(code) => Err(format!("provider rejected message (code {code})")),
        None => Err("provider rejected message".into()),
    }
}

/// Send one message to a channel and say how it went. Why it failed is kept
/// short and free of the endpoint, the secret and the reply's text.
pub fn deliver(channel: &Channel, markdown: &str, now_ms: i64, send: Send<'_>) -> Delivery {
    let outcome = request(channel, markdown, now_ms).and_then(|request| {
        let (status, body) = send(&request).map_err(|err| scrub(&err, channel))?;
        check_reply(channel.kind, status, &body)
    });
    match outcome {
        Ok(()) => Delivery::new(&channel.name, Status::Sent, None),
        Err(err) => Delivery::new(&channel.name, Status::Failed, Some(scrub(&err, channel))),
    }
}

/// Take the endpoint, its query and the secret out of an error, should a transport have put them there.
pub fn scrub(text: &str, channel: &Channel) -> String {
    let mut text = text.to_string();
    let url = channel.url.trim();
    let mut needles: Vec<&str> = vec![url, channel.secret.trim()];
    if let Some((_, query)) = url.split_once('?') { needles.push(query) }
    if let Some(path) = url.split_once("://").and_then(|(_, rest)| rest.split_once('/')).map(|(_, path)| path) { needles.push(path) }
    for needle in needles.into_iter().filter(|needle| needle.len() >= 4) { text = text.replace(needle, "…") }
    text.chars().take(200).collect()
}

/// Send a task's run to its channels, each name once; a name without a channel fails.
pub fn notify_task(channels: &[Channel], names: &[String], message: &str, skip: Option<&str>, now_ms: i64, send: Send<'_>) -> Vec<Delivery> {
    let mut seen = std::collections::HashSet::new();
    names.iter().filter(|name| seen.insert(name.as_str())).map(|name| {
        match (channels.iter().find(|channel| &channel.name == name), skip) {
            (None, _) => Delivery::new(name, Status::Failed, Some("unknown channel".into())),
            (Some(_), Some(why)) => Delivery::new(name, Status::Skipped, Some(why.to_string())),
            (Some(channel), None) => deliver(channel, message, now_ms, send),
        }
    }).collect()
}

/// A server's state as the overview and the alerts see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Ok,
    Warn,
    Crit,
    Unreachable,
}

impl HostState {
    /// From an inspection's worst severity (`info` counts as healthy).
    pub fn from_severity(severity: &str) -> HostState {
        match severity {
            "crit" => HostState::Crit,
            "warn" => HostState::Warn,
            "unreachable" => HostState::Unreachable,
            _ => HostState::Ok,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            HostState::Ok => "healthy",
            HostState::Warn => "warning",
            HostState::Crit => "critical",
            HostState::Unreachable => "unreachable",
        }
    }
}

/// One server whose state changed, with what it is about now (its unmuted warnings and critical findings).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub host: String,
    pub before: HostState,
    pub after: HostState,
    pub problems: Vec<String>,
}

/// Compare the states last reported with the newest: the new map to keep, and the changes.
/// A server seen for the first time is a baseline, not a change.
pub fn state_changes(reported: &BTreeMap<String, HostState>, now: &[(String, HostState, Vec<String>)]) -> (BTreeMap<String, HostState>, Vec<Change>) {
    let mut kept = reported.clone();
    let mut changes = vec![];
    for (host, after, problems) in now {
        if let Some(before) = reported.get(host) && before != after { changes.push(Change { host: host.clone(), before: *before, after: *after, problems: problems.clone() }) }
        kept.insert(host.clone(), *after);
    }
    (kept, changes)
}

/// One line per server whose state changed.
pub fn alert_message(changes: &[Change], now_ms: i64) -> String {
    let lines: Vec<String> = changes.iter().map(|change| {
        let detail = if change.after == HostState::Ok {
            String::new()
        } else {
            let shown: Vec<String> = change.problems.iter().take(2).map(|problem| problem.chars().take(160).collect()).collect();
            let more = if change.problems.len() > 2 { format!(" (+{})", change.problems.len() - 2) } else { String::new() };
            if shown.is_empty() { String::new() } else { format!(" — {}{more}", shown.join("; ")) }
        };
        format!("- **{}**: {} → {}{detail}", change.host, change.before.label(), change.after.label())
    }).collect();
    bound(&format!("## WispOps: server state changed\n{}\n\n{}", crate::time::to_iso(now_ms), lines.join("\n")), "")
}

/// The message of a test.
pub fn test_message(now_ms: i64) -> String {
    format!("## WispOps: test notification\n{}\n\nThis channel is set up: WispOps can reach it.", crate::time::to_iso(now_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn counts(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs.iter().map(|(key, value)| (key.to_string(), *value)).collect()
    }

    fn channel(kind: Kind, url: &str, secret: &str) -> Channel {
        Channel { name: "chat".into(), kind, url: url.into(), secret: secret.into() }
    }

    fn ms(iso: &str) -> i64 {
        crate::time::parse_iso(iso).unwrap()
    }

    #[test]
    fn bounds_utf8_summaries_and_signs_the_provider_payloads() {
        let text = task_summary("daily", "2026-10-27T00:00:00Z", &["a".into()], &counts(&[("warn", 1.)]), &"磁盘告警".repeat(2000));
        assert!(text.len() < 3500);
        assert!(text.starts_with("## WispOps: daily\n2026-10-27T00:00:00Z\nHosts: a\nwarn=1\n\n"));
        assert!(text.ends_with("(truncated; full report in WispOps)"));
        let d = request(&channel(Kind::Dingtalk, "https://example.org/hook?token=private", "secret"), "hello", 1_000_000).unwrap();
        assert!(d.url.starts_with("https://example.org/hook?token=private&timestamp=1000000&sign="));
        assert_eq!(d.body["msgtype"], "markdown");
        assert_eq!(d.body["markdown"]["text"], "hello");
        let f = request(&channel(Kind::Feishu, "https://example.org/hook", "secret"), "hello", 1_000_000).unwrap();
        assert_eq!(f.body["timestamp"], "1000");
        assert_eq!(f.body["msg_type"], "interactive");
        assert!(f.body["sign"].as_str().is_some_and(|sign| !sign.is_empty()));
        assert_eq!(request(&channel(Kind::Wecom, "https://example.org", ""), "hello", 0).unwrap().body, json!({"msgtype": "markdown", "markdown": {"content": "hello"}}));
        let w = request(&channel(Kind::Webhook, "https://example.org", "tok"), "hello", 0).unwrap();
        assert_eq!(w.body, json!({"title": "WispOps", "markdown": "hello"}));
        assert!(w.headers.contains(&("authorization".into(), "Bearer tok".into())));
    }

    #[test]
    fn the_signatures_match_the_providers_recipes() {
        // RFC 4231 test case 2.
        assert_eq!(hmac_sha256(b"Jefe", b"what do ya want for nothing?").iter().map(|b| format!("{b:02x}")).collect::<String>(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // DingTalk: HMAC(secret, "<ms>\n<secret>"); Feishu: HMAC("<s>\n<secret>", "").
        let d = request(&channel(Kind::Dingtalk, "https://example.org/robot/send?access_token=t", "s"), "x", 1_000_000).unwrap();
        assert!(d.url.ends_with(&format!("&sign={}", percent(&base64(&hmac_sha256(b"s", b"1000000\ns"))))));
        let f = request(&channel(Kind::Feishu, "https://example.org", "s"), "x", 1_000_000).unwrap();
        assert_eq!(f.body["sign"], base64(&hmac_sha256(b"1000\ns", b"")));
    }

    #[test]
    fn rejects_unsafe_urls_and_keeps_secrets_out_of_failures() {
        assert!(request(&channel(Kind::Webhook, "http://example.org", ""), "x", 0).unwrap_err().contains("HTTPS"));
        assert!(url_problem("https://user:pw@example.org/x").is_some());
        assert!(url_problem("ftp://example.org").is_some());
        assert!(url_problem("http://127.0.0.1:9000/hook").is_none());
        assert!(url_problem("http://localhost/hook").is_none());
        assert_eq!(url_host("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc"), "qyapi.weixin.qq.com");
        let hook = channel(Kind::Webhook, "https://example.org/secret-token", "bearer-secret");
        let send = |_: &Request| -> Result<(u16, String), String> { Err("failed to reach https://example.org/secret-token with bearer-secret".into()) };
        let results = notify_task(std::slice::from_ref(&hook), &["chat".into()], "x", None, 0, &send);
        assert_eq!(results[0].status, Status::Failed);
        let text = serde_json::to_string(&results).unwrap();
        assert!(!text.contains("secret-token") && !text.contains("bearer-secret"), "{text}");
    }

    #[test]
    fn checks_provider_errors_even_on_http_200_and_keeps_per_channel_results() {
        let calls = RefCell::new(0);
        let send = |_: &Request| -> Result<(u16, String), String> {
            *calls.borrow_mut() += 1;
            Ok((200, r#"{"errcode":93000,"errmsg":"token-secret"}"#.into()))
        };
        let wecom = channel(Kind::Wecom, "https://example.org", "");
        let results = notify_task(&[wecom], &["chat".into(), "missing".into(), "chat".into()], "x", None, 0, &send);
        assert_eq!(results.iter().map(|r| r.status).collect::<Vec<_>>(), vec![Status::Failed, Status::Failed]);
        assert_eq!(*calls.borrow(), 1);
        assert!(!serde_json::to_string(&results).unwrap().contains("token-secret"));
        assert!(check_reply(Kind::Feishu, 200, r#"{"code":0}"#).is_ok());
        assert!(check_reply(Kind::Feishu, 200, r#"{"StatusCode":0}"#).is_ok());
        assert!(check_reply(Kind::Dingtalk, 200, r#"{"errcode":0}"#).is_ok());
        assert!(check_reply(Kind::Webhook, 204, "").is_ok());
        assert_eq!(check_reply(Kind::Webhook, 500, ""), Err("HTTP 500".into()));
        assert_eq!(check_reply(Kind::Webhook, 302, ""), Err("HTTP 302".into()));
    }

    #[test]
    fn skips_healthy_runs_in_problems_only_mode_but_sends_incomplete_runs() {
        let rules = TaskRules { only_problems: true, ..Default::default() };
        assert_eq!(task_skip(&rules, &counts(&[]), None, 0).as_deref(), Some("no problems"));
        assert_eq!(task_skip(&rules, &counts(&[("ok", 3.)]), None, 0).as_deref(), Some("no problems"));
        assert_eq!(task_skip(&rules, &counts(&[("incomplete", 1.)]), None, 0), None);
    }

    #[test]
    fn delivers_only_when_problem_counts_change_with_the_first_run_as_baseline() {
        let rules = TaskRules { on_change: true, ..Default::default() };
        let first = counts(&[("warn", 1.)]);
        assert_eq!(task_skip(&rules, &first, None, 0), None);
        assert!(task_skip(&rules, &first, Some(&first), 0).is_some_and(|why| why.contains("unchanged")));
        assert_eq!(task_skip(&rules, &counts(&[("warn", 2.)]), Some(&first), 0), None);
        // The same counts with extra non-problem keys still count as unchanged.
        assert!(task_skip(&rules, &counts(&[("newBytes", 5.), ("warn", 1.)]), Some(&counts(&[("warn", 1.), ("newBytes", 9.)])), 0).is_some());
        assert_ne!(problem_signature(&counts(&[("crit", 1.)])), problem_signature(&counts(&[("warn", 1.)])));
    }

    #[test]
    fn stays_silent_during_quiet_hours_including_windows_that_cross_midnight() {
        let quiet = |start: &str, end: &str, zone: Option<&str>| Some(QuietHours { start: start.into(), end: end.into(), time_zone: zone.map(str::to_string) });
        let night = TaskRules { quiet_hours: quiet("22:00", "08:00", Some("Asia/Shanghai")), ..Default::default() };
        let none = counts(&[]);
        // 2026-10-27T00:00Z is 08:00 in Shanghai: the window has just ended.
        assert_eq!(task_skip(&night, &none, None, ms("2026-10-27T00:00:00Z")), None);
        assert!(task_skip(&night, &none, None, ms("2026-10-26T23:59:00Z")).is_some_and(|why| why.contains("quiet hours")));
        assert!(task_skip(&night, &none, None, ms("2026-10-27T15:00:00Z")).is_some());
        let day = |zone: &str| TaskRules { quiet_hours: quiet("09:00", "17:00", None), time_zone: zone.into(), ..Default::default() };
        assert!(task_skip(&day("UTC"), &none, None, ms("2026-10-27T12:00:00Z")).is_some());
        assert_eq!(task_skip(&day("Asia/Shanghai"), &none, None, ms("2026-10-27T12:00:00Z")), None);
        assert!(in_quiet_hours(quiet("22:00", "08:00", None).as_ref(), ms("2026-10-27T23:00:00Z"), "UTC"));
        assert!(!in_quiet_hours(quiet("22:00", "08:00", None).as_ref(), ms("2026-10-27T08:00:00Z"), "UTC"));
        assert!(in_quiet_hours(quiet("22:00", "08:00", Some("Not/AZone")).as_ref(), ms("2026-10-27T23:00:00Z"), "UTC"));
        assert_eq!(local_clock(ms("2026-10-27T00:30:00Z"), "Asia/Shanghai"), "08:30");
    }

    #[test]
    fn a_skipped_run_posts_nothing() {
        let calls = RefCell::new(0);
        let send = |_: &Request| -> Result<(u16, String), String> {
            *calls.borrow_mut() += 1;
            Ok((204, String::new()))
        };
        let hook = channel(Kind::Webhook, "https://example.org", "");
        let skipped = notify_task(std::slice::from_ref(&hook), &["chat".into()], "x", Some("no problems"), 0, &send);
        assert_eq!(skipped[0].status, Status::Skipped);
        assert_eq!(*calls.borrow(), 0);
        assert_eq!(notify_task(&[hook], &["chat".into()], "x", None, 0, &send)[0].status, Status::Sent);
    }

    #[test]
    fn sets_a_baseline_then_reports_only_changes() {
        let empty = BTreeMap::new();
        let (kept, changes) = state_changes(&empty, &[("a".into(), HostState::Ok, vec![])]);
        assert!(changes.is_empty());
        let (kept, changes) = state_changes(&kept, &[("a".into(), HostState::Unreachable, vec!["ssh: connect timed out".into()]), ("b".into(), HostState::Ok, vec![])]);
        assert_eq!(changes.len(), 1);
        let text = alert_message(&changes, ms("2026-10-29T08:05:00Z"));
        assert!(text.contains("**a**: healthy → unreachable — ssh: connect timed out"), "{text}");
        assert!(!text.contains("**b**"));
        let (kept, changes) = state_changes(&kept, &[("a".into(), HostState::Unreachable, vec![]), ("b".into(), HostState::Ok, vec![])]);
        assert!(changes.is_empty());
        let (_, changes) = state_changes(&kept, &[("a".into(), HostState::Ok, vec![])]);
        assert!(alert_message(&changes, 0).contains("**a**: unreachable → healthy"));
    }

    #[test]
    fn keeps_alert_text_short() {
        let change = Change { host: "h".into(), before: HostState::Ok, after: HostState::Crit, problems: vec!["/ 99% used".into()] };
        assert_eq!(alert_message(std::slice::from_ref(&change), ms("2026-10-29T00:00:00Z")), "## WispOps: server state changed\n2026-10-29T00:00:00.000Z\n\n- **h**: healthy → critical — / 99% used");
        let many = Change { problems: (0..5).map(|n| format!("p{n}")).collect(), ..change };
        assert!(alert_message(&[many], 0).ends_with("— p0; p1 (+3)"));
        let flood: Vec<Change> = (0..500).map(|n| Change { host: format!("host-{n}"), before: HostState::Ok, after: HostState::Warn, problems: vec!["磁盘".repeat(60)] }).collect();
        assert!(alert_message(&flood, 0).len() <= MAX_BYTES);
    }
}
