//! Security triage (网络攻击排查), read-only: SSH brute force and successful logins by source,
//! connection floods, listening services, crypto-miner and deleted-binary processes, processes
//! running from world-writable places, outbound connections to common mining/C2 ports, and
//! recently changed persistence points (authorized_keys, cron, systemd units, extra UID 0). Root
//! (sudo) sees the auth log and every process; without it the report says what it could not read.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::inspect::{Finding, Severity};
use crate::sections::{num, num_opt, parse_sections};
use crate::util::{OrderedMap, fields, fill, iso_from_millis, js_number, n, take_chars};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityOptions {
    /// Look-back window for logins and changed files, in hours.
    pub hours: u32,
}

/// Process names of common crypto miners and the malware that drops them.
pub static MINER_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:xmrig|xmr-stak|kdevtmpfsi|kinsing|minerd|cpuminer|ethminer|nbminer|t-rex|lolminer|phoenixminer|teamredminer|nanominer|srbminer|gminer|bminer|xmrig-notls|\.?sysupdate|networkservice|dbused|kthreaddi)$").unwrap()
});
static MINER_ARGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)stratum\+tcp:|--donate-level|-o\s+\S*pool\S*:[0-9]+").unwrap());

/// Tool and package-manager locations whose binaries disappear on ordinary upgrades.
static MANAGED_TOOL_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/\.(?:nvm|pyenv|rbenv|rustup|cargo|sdkman|volta|bun|deno)/|/(?:mini|ana)?conda[0-9]?/|/miniforge[0-9]?/|/mambaforge/|^/usr/(?:lib|libexec|bin|sbin|local/bin)/|^/opt/|^/snap/").unwrap());
static PRIVATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|::1$|fe80:|fc|fd)").unwrap());
static COUNTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*([0-9]+)\s+(.*)$").unwrap());
static PROCESS_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^users:\(\("?"#).unwrap());

/// Remote ports often used by miners and command-and-control servers.
pub const SUSPICIOUS_PORTS: [f64; 12] = [3333.0, 4444.0, 5555.0, 6666.0, 7777.0, 14433.0, 14444.0, 45560.0, 45700.0, 6667.0, 1337.0, 31337.0];

pub fn security_script(o: &SecurityOptions) -> String {
    let days = o.hours.div_ceil(24).max(1);
    fill(include_str!("scripts/security.sh.tpl"), &[("o.hours", &o.hours.to_string()), ("days", &days.to_string())])
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCount {
    pub source: String,
    pub count: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedLogin {
    pub method: String,
    pub user: String,
    pub source: String,
    pub count: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    pub proto: String,
    pub local: String,
    pub process: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub local: String,
    pub remote: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MinerProcess {
    pub pid: i64,
    pub user: String,
    pub cpu_pct: f64,
    pub command: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BadExecutable {
    pub pid: i64,
    pub comm: String,
    pub exe: String,
    pub replaced: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangedFile {
    pub path: String,
    pub owner: String,
    pub modified: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReport {
    pub auth_log_readable: bool,
    pub full_visibility: bool,
    pub failed_by_source: Vec<SourceCount>,
    pub accepted: Vec<AcceptedLogin>,
    pub current_sessions: Vec<String>,
    pub listening: Vec<Listener>,
    pub established_by_source: Vec<SourceCount>,
    pub syn_recv: f64,
    pub suspicious_outbound: Vec<Connection>,
    pub miners: Vec<MinerProcess>,
    pub bad_executables: Vec<BadExecutable>,
    #[serde(rename = "extraUid0")]
    pub extra_uid0: Vec<String>,
    pub changed_keys: Vec<ChangedFile>,
    pub changed_cron: Vec<ChangedFile>,
    pub changed_units: Vec<ChangedFile>,
    pub sshd: OrderedMap<String>,
    #[serde(rename = "fail2ban")]
    pub fail2ban: Vec<String>,
    pub findings: Vec<Finding>,
}

fn counted(lines: &[String]) -> Vec<(f64, String)> {
    lines.iter().filter_map(|line| COUNTED.captures(line).map(|m| (js_number(&m[1]), m[2].trim().to_string()))).collect()
}

fn changed(lines: &[String]) -> Vec<ChangedFile> {
    lines
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let (at, owner) = (num_opt(cells.next())?, cells.next()?);
            Some(ChangedFile { path: cells.collect::<Vec<_>>().join("\t"), owner: owner.to_string(), modified: iso_from_millis(at * 1000.0) })
        })
        .collect()
}

fn paths(files: &[ChangedFile]) -> String {
    files.iter().take(5).map(|f| f.path.as_str()).collect::<Vec<_>>().join(", ")
}

pub fn parse_security(output: &str, o: &SecurityOptions) -> SecurityReport {
    let s = parse_sections(output);
    let mut findings: Vec<Finding> = Vec::new();
    let mut add = |severity: Severity, code: &str, message: String| findings.push(Finding::new(severity, code, message));

    let full_visibility = s.first("whoami") == Some("0");
    let auth_log_readable = s.first("authsrc") == Some("readable");
    let failed_by_source: Vec<SourceCount> = counted(s.get("failed")).into_iter().map(|(count, source)| SourceCount { source, count }).collect();
    let accepted: Vec<AcceptedLogin> = counted(s.get("accepted"))
        .into_iter()
        .filter_map(|(count, rest)| {
            let mut cells = rest.split(' ');
            Some(AcceptedLogin { method: cells.next()?.to_string(), user: cells.next()?.to_string(), source: cells.next()?.to_string(), count })
        })
        .collect();
    let listening: Vec<Listener> = s
        .get("listen")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let (proto, local) = (cells.next()?, cells.next()?);
            let process = PROCESS_PREFIX.replace(cells.next().unwrap_or(""), "");
            Some(Listener { proto: proto.to_string(), local: local.to_string(), process: process.split('"').next().unwrap_or("").to_string() })
        })
        .collect();
    let established_by_source: Vec<SourceCount> = counted(s.get("estab")).into_iter().map(|(count, source)| SourceCount { source, count }).collect();
    let syn_recv = num_opt(s.first("synrecv")).unwrap_or(0.0);
    let suspicious_outbound: Vec<Connection> = s
        .get("outbound")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let (local, remote) = (cells.next()?, cells.next()?);
            let port = num(remote.rsplit(':').next().unwrap_or(remote))?;
            SUSPICIOUS_PORTS.contains(&port).then(|| Connection { local: local.to_string(), remote: remote.to_string() })
        })
        .collect();
    let miners: Vec<MinerProcess> = s
        .get("procs")
        .iter()
        .filter_map(|line| {
            let f = fields(line);
            let pid = num(f[0])?;
            let (user, comm) = (f.get(1)?, f.get(4)?);
            let command = f[4..].join(" ");
            (MINER_NAMES.is_match(comm) || MINER_ARGS.is_match(&command)).then(|| MinerProcess { pid: pid as i64, user: user.to_string(), cpu_pct: num(f[2]).unwrap_or(0.0), command })
        })
        .collect();
    let bad_executables: Vec<BadExecutable> = s
        .get("badexe")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let pid = num_opt(cells.next())?;
            let comm = cells.next().unwrap_or("");
            let exe = cells.next()?;
            Some(BadExecutable { pid: pid as i64, comm: comm.to_string(), exe: exe.to_string(), replaced: cells.next() == Some("replaced") })
        })
        .collect();
    let extra_uid0: Vec<String> = s.get("uid0").iter().filter(|name| *name != "root").cloned().collect();
    let mut sshd: OrderedMap<String> = OrderedMap::new();
    for line in s.get("sshd") {
        let f = fields(line);
        sshd.insert(f[0].to_lowercase(), f[1..].join(" ").to_lowercase());
    }

    if !auth_log_readable {
        add(Severity::Info, "auth-log-unreadable", "SSH auth log not readable; run with sudo for login analysis".to_string());
    }
    if !full_visibility {
        add(Severity::Info, "partial-visibility", "not running as root: other users' processes and sockets may be hidden".to_string());
    }
    let total: f64 = failed_by_source.iter().map(|f| f.count).sum();
    for f in failed_by_source.iter().take(5) {
        let message = format!("{} failed SSH logins from {} in {}h", n(f.count), f.source, o.hours);
        if f.count >= 1000.0 {
            add(Severity::Crit, "ssh-bruteforce", message);
        } else if f.count >= 100.0 {
            add(Severity::Warn, "ssh-bruteforce", message);
        }
    }
    if total >= 100.0 && failed_by_source.len() >= 20 {
        add(Severity::Warn, "ssh-distributed", format!("failed SSH logins from at least {} sources ({} total) in {}h", failed_by_source.len(), n(total), o.hours));
    }
    let attackers: Vec<&str> = failed_by_source.iter().filter(|f| f.count >= 20.0).map(|f| f.source.as_str()).collect();
    for a in &accepted {
        if attackers.contains(&a.source.as_str()) {
            add(Severity::Crit, "login-after-bruteforce", format!("successful {} login as {} from {}, which also had many failed attempts", a.method, a.user, a.source));
        }
        if a.user == "root" && a.method == "password" {
            add(Severity::Warn, "root-password-login", format!("root logged in with a password from {}", a.source));
        }
    }
    let mut public_sources: Vec<String> = Vec::new();
    for a in accepted.iter().filter(|a| !PRIVATE.is_match(&a.source)) {
        let who = format!("{}@{}", a.user, a.source);
        if !public_sources.contains(&who) {
            public_sources.push(who);
        }
    }
    if !public_sources.is_empty() {
        public_sources.truncate(8);
        add(Severity::Info, "public-logins", format!("logins from public addresses: {}", public_sources.join(", ")));
    }
    if syn_recv >= 200.0 {
        add(Severity::Warn, "syn-flood", format!("{} half-open (SYN-RECV) connections: possible SYN flood", n(syn_recv)));
    }
    if let Some(flood) = established_by_source.iter().find(|e| e.count >= 200.0 && !PRIVATE.is_match(&e.source)) {
        add(Severity::Warn, "connection-flood", format!("{} established connections from {}", n(flood.count), flood.source));
    }
    for m in &miners {
        add(Severity::Crit, "crypto-miner", format!("crypto-miner-like process {} [pid {}, {}, {}% CPU]", take_chars(&m.command, 120), m.pid, m.user, n(m.cpu_pct)));
    }
    for b in &bad_executables {
        let deleted = b.exe.ends_with(" (deleted)");
        if b.replaced {
            add(Severity::Info, "binary-replaced", format!("process {}[{}] still runs a binary replaced since it started ({}); usually an upgrade — restart it to pick up the new version", b.comm, b.pid, b.exe));
        } else if deleted && MANAGED_TOOL_PATH.is_match(&b.exe) {
            add(Severity::Info, "binary-removed", format!("process {}[{}] runs {}, removed by an upgrade or uninstall of a managed tool; restart it if it should keep running", b.comm, b.pid, b.exe));
        } else if deleted {
            add(Severity::Warn, "deleted-exe", format!("process {}[{}] runs a binary that no longer exists on disk ({}); malware often deletes itself after starting", b.comm, b.pid, b.exe));
        } else {
            add(Severity::Crit, "suspicious-exe", format!("process {}[{}] runs from a world-writable location: {}", b.comm, b.pid, b.exe));
        }
    }
    for out in suspicious_outbound.iter().take(5) {
        add(Severity::Warn, "suspicious-outbound", format!("outbound connection {} → {} (port often used by miners/C2)", out.local, out.remote));
    }
    if !extra_uid0.is_empty() {
        add(Severity::Crit, "extra-uid0", format!("accounts with UID 0 besides root: {}", extra_uid0.join(", ")));
    }
    let keys = changed(s.get("keys"));
    let cron = changed(s.get("cron"));
    let units = changed(s.get("units"));
    for k in &keys {
        add(Severity::Warn, "authorized-keys-changed", format!("{} changed at {}", k.path, k.modified));
    }
    if !cron.is_empty() {
        add(Severity::Info, "cron-changed", format!("cron files changed: {}", paths(&cron)));
    }
    if !units.is_empty() {
        add(Severity::Info, "units-changed", format!("systemd units changed: {}", paths(&units)));
    }
    if sshd.get("permitrootlogin").map(String::as_str) == Some("yes") && sshd.get("passwordauthentication").map(String::as_str) == Some("yes") {
        add(Severity::Warn, "sshd-weak", "sshd allows root login with passwords (PermitRootLogin yes, PasswordAuthentication yes)".to_string());
    }
    if total >= 100.0 && s.get("fail2ban").is_empty() {
        add(Severity::Info, "no-fail2ban", "brute force is ongoing and fail2ban (sshd jail) is not active".to_string());
    }

    SecurityReport {
        auth_log_readable,
        full_visibility,
        failed_by_source,
        accepted,
        current_sessions: s.get("who").to_vec(),
        listening,
        established_by_source,
        syn_recv,
        suspicious_outbound,
        miners,
        bad_executables,
        extra_uid0,
        changed_keys: keys,
        changed_cron: cron,
        changed_units: units,
        sshd,
        fail2ban: s.get("fail2ban").to_vec(),
        findings,
    }
}

pub fn render_security(host: &str, r: &SecurityReport, hours: u32) -> String {
    let mut lines = vec![format!("## {host}: security triage, last {hours}h")];
    let mut sorted: Vec<&Finding> = r.findings.iter().collect();
    sorted.sort_by_key(|f| match f.severity {
        Severity::Crit => 0,
        Severity::Warn => 1,
        Severity::Info => 2,
    });
    lines.push(if sorted.is_empty() { "No findings.".to_string() } else { sorted.iter().map(|f| format!("{}: {}", f.severity.as_str(), f.message)).collect::<Vec<_>>().join("\n") });
    let counts = |rows: &[SourceCount], keep: usize| rows.iter().take(keep).map(|f| format!("{} ×{}", f.source, n(f.count))).collect::<Vec<_>>().join(", ");
    if !r.failed_by_source.is_empty() {
        lines.extend([String::new(), format!("Failed SSH logins by source: {}", counts(&r.failed_by_source, 10))]);
    }
    if !r.accepted.is_empty() {
        lines.push(format!("Successful logins: {}", r.accepted.iter().take(10).map(|a| format!("{}@{} ({}) ×{}", a.user, a.source, a.method, n(a.count))).collect::<Vec<_>>().join(", ")));
    }
    if !r.current_sessions.is_empty() {
        lines.push(format!("Logged in now: {}", r.current_sessions.iter().take(8).cloned().collect::<Vec<_>>().join(" | ")));
    }
    if !r.listening.is_empty() {
        let listed: Vec<String> = r.listening.iter().take(25).map(|l| if l.process.is_empty() { l.local.clone() } else { format!("{} {}", l.local, l.process) }).collect();
        lines.extend([String::new(), format!("Listening: {}", listed.join(", "))]);
    }
    if !r.established_by_source.is_empty() {
        lines.push(format!("Established connections by peer: {}; SYN-RECV {}", counts(&r.established_by_source, 8), n(r.syn_recv)));
    }
    if !r.sshd.is_empty() {
        lines.push(format!("sshd: {}", r.sshd.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")));
    }
    if !r.fail2ban.is_empty() {
        lines.push(format!("fail2ban sshd: {}", r.fail2ban.join("; ")));
    }
    lines.extend([
        String::new(),
        "Treat findings as leads: confirm with logs and process details before blocking addresses or killing processes; containment steps (firewall rules, killing processes, disabling accounts) are changes that need approval.".to_string(),
    ]);
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testing::assert_golden;

    const SECURITY: &str = include_str!("testdata/security.txt");

    #[test]
    fn builds_the_script_the_plugin_built() {
        assert_eq!(security_script(&SecurityOptions { hours: 30 }), include_str!("testdata/security.golden.sh"));
        assert!(security_script(&SecurityOptions { hours: 0 }).contains("-mtime -1 "));
    }

    #[test]
    fn raises_the_right_alarms() {
        let report = parse_security(SECURITY, &SecurityOptions { hours: 24 });
        let codes: Vec<String> = report.findings.iter().map(|f| format!("{}:{}", f.severity.as_str(), f.code)).collect();
        for expected in [
            "crit:ssh-bruteforce", "warn:ssh-bruteforce", "crit:login-after-bruteforce", "warn:root-password-login", "warn:connection-flood", "crit:crypto-miner", "crit:suspicious-exe", "warn:suspicious-outbound",
            "info:binary-replaced", "warn:deleted-exe", "info:binary-removed", "crit:extra-uid0", "warn:authorized-keys-changed", "warn:sshd-weak", "info:no-fail2ban",
        ] {
            assert!(codes.iter().any(|c| c == expected), "{expected} missing from {codes:?}");
        }
        assert_eq!(report.miners.iter().map(|m| m.pid).collect::<Vec<_>>(), [31337]);
        assert!(render_security("web-01", &report, 24).contains("203.0.113.9 ×2400"));
    }

    #[test]
    fn matches_the_plugin_report_and_rendering() {
        let report = parse_security(SECURITY, &SecurityOptions { hours: 24 });
        assert_golden(&report, include_str!("testdata/security.report.json"));
        assert_eq!(serde_json::from_str::<SecurityReport>(include_str!("testdata/security.report.json")).unwrap(), report);
        assert_eq!(render_security("web-01", &report, 24), include_str!("testdata/security.render.txt"));
    }

    #[test]
    fn is_quiet_on_a_clean_host() {
        let clean = parse_security("@@whoami\n0\n@@authsrc\nreadable\n@@synrecv\n0\n@@uid0\nroot\n@@end\n", &SecurityOptions { hours: 24 });
        assert!(clean.findings.is_empty());
        assert!(render_security("h", &clean, 24).contains("No findings."));
    }
}
