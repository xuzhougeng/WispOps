//! Service checks: what must be up on a server, as the owner lists it — a systemd unit active, a
//! TCP port listening, an HTTP URL answering — checked read-only on the server during every
//! inspection. Each value is validated and single-quoted, so a check cannot add shell syntax to
//! the inspection script.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::{shell_quote, take_chars};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ServiceCheck {
    Unit { name: String },
    Port { port: u16 },
    Http { url: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    Unit,
    Port,
    Http,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceResult {
    pub kind: ServiceKind,
    pub target: String,
    pub result: String,
    pub ok: bool,
}

pub const MAX_CHECKS: usize = 20;

fn valid_unit(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes.len() <= 128 && bytes[0].is_ascii_alphanumeric() && bytes.iter().all(|b| b.is_ascii_alphanumeric() || b"@._:-".contains(b))
}

/// What `new URL(text)` reports that the check needs: the scheme, and whether credentials are present.
struct ParsedUrl {
    http: bool,
    credentials: bool,
}

/// A hand-written subset of URL parsing: `scheme://authority…` with a non-empty host and a valid port.
fn parse_url(text: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = text.split_once(':')?;
    let mut chars = scheme.chars();
    if !chars.next()?.is_ascii_alphabetic() || !chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    let http = scheme == "http" || scheme == "https";
    if !http {
        return Some(ParsedUrl { http, credentials: false });
    }
    let authority = rest.strip_prefix("//")?.split(['/', '?', '#']).next().unwrap_or("");
    let (credentials, host_port) = match authority.rsplit_once('@') {
        Some((user, host)) => (!user.is_empty() && user != ":", host),
        None => (false, authority),
    };
    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']')?;
        (host, after.strip_prefix(':'))
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        }
    };
    if host.is_empty() || host.contains(['<', '>', '[', ']', '^', '|', '%', '\\']) {
        return None;
    }
    if let Some(port) = port
        && !port.is_empty()
        && (!port.bytes().all(|b| b.is_ascii_digit()) || port.parse::<u16>().is_err())
    {
        return None;
    }
    Some(ParsedUrl { http, credentials })
}

fn validate_check(check: &Value) -> Result<ServiceCheck, String> {
    let invalid = || "Invalid service check".to_string();
    match check.get("kind").and_then(Value::as_str) {
        Some("unit") => match check.get("name").and_then(Value::as_str) {
            Some(name) if valid_unit(name) => Ok(ServiceCheck::Unit { name: name.to_string() }),
            _ => Err(invalid()),
        },
        Some("port") => match check.get("port").and_then(Value::as_f64) {
            Some(port) if port.fract() == 0.0 && (1.0..=65535.0).contains(&port) => Ok(ServiceCheck::Port { port: port as u16 }),
            _ => Err(invalid()),
        },
        Some("http") => match check.get("url").and_then(Value::as_str) {
            Some(url) if url.encode_utf16().count() <= 2048 && !url.contains(char::is_whitespace) => {
                let parsed = parse_url(url).ok_or_else(|| format!("Invalid URL {}", take_chars(url, 80)))?;
                if parsed.http && !parsed.credentials { Ok(ServiceCheck::Http { url: url.to_string() }) } else { Err(invalid()) }
            }
            _ => Err(invalid()),
        },
        _ => Err(invalid()),
    }
}

/// Validate a host's check list; anything malformed is rejected rather than dropped.
pub fn validate_checks(value: &Value) -> Result<Vec<ServiceCheck>, String> {
    let list = value.as_array().filter(|list| list.len() <= MAX_CHECKS).ok_or_else(|| format!("Service checks must be a list of at most {MAX_CHECKS}"))?;
    let checks = list.iter().map(validate_check).collect::<Result<Vec<_>, _>>()?;
    let keys: HashSet<String> = checks.iter().map(describe_check).collect();
    if keys.len() != checks.len() {
        return Err("Duplicate service check".to_string());
    }
    Ok(checks)
}

pub fn describe_check(check: &ServiceCheck) -> String {
    match check {
        ServiceCheck::Unit { name } => name.clone(),
        ServiceCheck::Port { port } => port.to_string(),
        ServiceCheck::Http { url } => url.clone(),
    }
}

/// The shell line that runs one check; also what the deny list is matched against.
pub fn check_line(check: &ServiceCheck) -> String {
    let target = shell_quote(&describe_check(check));
    match check {
        ServiceCheck::Unit { .. } => format!(r#"printf 'unit\t%s\t%s\n' {target} "$(systemctl is-active {target} 2>/dev/null | head -n 1)""#),
        ServiceCheck::Port { .. } => {
            format!(r#"printf 'port\t%s\t%s\n' {target} "$( (ss -tln 2>/dev/null || netstat -tln 2>/dev/null) | awk '{{print $4}}' | grep -qE '[:.]'{target}'$' && echo listening || echo closed)""#)
        }
        ServiceCheck::Http { .. } => format!(
            r#"printf 'http\t%s\t%s\n' {target} "$(if command -v curl >/dev/null 2>&1; then curl -ksS -o /dev/null -m 8 -w '%{{http_code}}' {target} 2>/dev/null; elif command -v wget >/dev/null 2>&1; then wget -q -O /dev/null -T 8 --no-check-certificate --server-response {target} 2>&1 | awk '/^  HTTP\//{{c=$2}} END{{print c}}'; else echo no-client; fi)""#
        ),
    }
}

/// The inspection script with this host's checks added before its end marker.
pub fn with_service_checks(script: &str, checks: &[ServiceCheck]) -> String {
    if checks.is_empty() {
        return script.to_string();
    }
    let end = script.rfind("echo @@end").unwrap_or(script.len());
    let lines: Vec<String> = checks.iter().map(check_line).collect();
    format!("{}echo @@svc\n{}\n{}", &script[..end], lines.join("\n"), &script[end..])
}

/// Results of the `@@svc` section; an HTTP check passes on 2xx and 3xx.
pub fn parse_service_results(lines: &[String]) -> Vec<ServiceResult> {
    lines
        .iter()
        .filter_map(|text| {
            let mut cells = text.split('\t');
            let kind = match cells.next()? {
                "unit" => ServiceKind::Unit,
                "port" => ServiceKind::Port,
                "http" => ServiceKind::Http,
                _ => return None,
            };
            let target = cells.next().filter(|target| !target.is_empty())?;
            let result = cells.next().unwrap_or("");
            let ok = match kind {
                ServiceKind::Unit => result == "active",
                ServiceKind::Port => result == "listening",
                ServiceKind::Http => result.len() == 3 && result.starts_with(['2', '3']) && result.bytes().all(|b| b.is_ascii_digit()),
            };
            Some(ServiceResult { kind, target: target.to_string(), result: take_chars(result, 40).to_string(), ok })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::INSPECT_SCRIPT;
    use serde_json::json;

    #[test]
    fn accepts_units_ports_and_http_urls_and_rejects_anything_else() {
        assert_eq!(validate_checks(&json!([{ "kind": "unit", "name": "nginx.service" }, { "kind": "port", "port": 443 }, { "kind": "http", "url": "https://127.0.0.1:8443/health" }])).unwrap().len(), 3);
        for bad in [
            json!([{ "kind": "unit", "name": "x; rm -rf /" }]),
            json!([{ "kind": "port", "port": 70000 }]),
            json!([{ "kind": "http", "url": "file:///etc/passwd" }]),
            json!([{ "kind": "http", "url": "http://u:p@h/" }]),
            json!([{ "kind": "http", "url": "http://h/a b" }]),
            json!([{ "kind": "unit", "name": "a" }, { "kind": "unit", "name": "a" }]),
            json!([{ "kind": "exec", "cmd": "id" }]),
            json!("nginx"),
            json!([{ "kind": "http", "url": "not a url" }]),
            json!([{ "kind": "http", "url": "http://h:99999/" }]),
            json!([{ "kind": "port", "port": 80.5 }]),
        ] {
            assert!(validate_checks(&bad).is_err(), "{bad}");
        }
        assert!(validate_checks(&Value::Array((1..=21).map(|i| json!({ "kind": "port", "port": i })).collect())).is_err());
        assert_eq!(validate_checks(&json!([{ "kind": "http", "url": "nope" }])).unwrap_err(), "Invalid URL nope");
    }

    #[test]
    fn adds_quoted_checks_before_the_end_marker() {
        let checks = validate_checks(&json!([{ "kind": "unit", "name": "nginx" }, { "kind": "port", "port": 8080 }, { "kind": "http", "url": "http://127.0.0.1/a'$(id)'" }])).unwrap();
        let script = with_service_checks(INSPECT_SCRIPT, &checks);
        assert!(script.find("@@svc").unwrap() < script.rfind("@@end").unwrap());
        assert!(script.contains(r"'http://127.0.0.1/a'\''$(id)'\'''"));
        assert_eq!(script, include_str!("testdata/inspect-checks.golden.sh"));
        assert_eq!(with_service_checks(INSPECT_SCRIPT, &[]), INSPECT_SCRIPT);
    }

    #[cfg(unix)]
    #[test]
    fn keeps_the_script_valid_shell() {
        use std::io::Write;
        let checks = [ServiceCheck::Unit { name: "nginx".into() }, ServiceCheck::Port { port: 8080 }, ServiceCheck::Http { url: "http://127.0.0.1/a'$(id)'".into() }];
        let mut child = std::process::Command::new("sh").arg("-n").stdin(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(with_service_checks(INSPECT_SCRIPT, &checks).as_bytes()).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn reads_results_and_serializes_checks_like_the_plugin() {
        let lines: Vec<String> = ["unit\tnginx\tactive", "unit\tredis\tfailed", "port\t8080\tclosed", "http\thttps://h/health\t200", "http\thttps://h/api\t502", "http\thttps://h/x\t000", "bogus\tline"].map(String::from).to_vec();
        assert_eq!(parse_service_results(&lines).iter().map(|r| r.ok).collect::<Vec<_>>(), [true, false, false, true, false, false]);
        assert_eq!(serde_json::to_value(ServiceCheck::Port { port: 443 }).unwrap(), json!({ "kind": "port", "port": 443 }));
        assert_eq!(serde_json::from_value::<ServiceCheck>(json!({ "kind": "http", "url": "http://h/" })).unwrap(), ServiceCheck::Http { url: "http://h/".into() });
    }
}
