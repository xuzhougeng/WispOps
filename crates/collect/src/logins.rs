//! Who logged in to a host, from where, and who failed to: read with the accounts
//! (`scripts/logins.sh` is part of `ACCOUNTS_SCRIPT`). Sessions come from wtmp (`last`), which
//! anyone may read; the SSH logins accepted and refused come from sshd's log lines in the journal
//! or the auth log, or failing both from btmp (`lastb`), which take root. The host reduces the
//! log to counts by account, address and method, so a server under attack sends little.

use chrono::{DateTime, FixedOffset, NaiveDate, SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::sections::Sections;

/// How far back the journal is read.
pub const LOG_DAYS: u32 = 30;

/// How a session ended, as `last` tells.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionEnd {
    /// Still logged in.
    Open,
    /// Logged out at this time.
    At(String),
    /// The machine crashed (or lost power) during it.
    Crash,
    /// The machine was shut down during it.
    Down,
    /// The session is gone without a logout record.
    #[default]
    Gone,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LoginSession {
    pub user: String,
    pub tty: String,
    /// The address logged in from; empty for a local login.
    pub from: String,
    pub start: String,
    pub end: SessionEnd,
}

/// Logins of one account from one address by one method, counted.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LoginSource {
    pub user: String,
    pub from: String,
    /// `password`, `publickey`, `keyboard-interactive`…; empty when not known (btmp).
    pub method: String,
    pub count: u64,
    pub first: String,
    pub last: String,
}

/// The failed logins of one account name, all addresses together.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FailTotal {
    pub user: String,
    pub count: u64,
    /// Distinct addresses they came from.
    pub sources: u64,
    /// sshd said no such account exists.
    pub invalid: bool,
    pub first: String,
    pub last: String,
}

/// Where the SSH logins were read from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogSource {
    /// The journal, the last `LOG_DAYS` days.
    Journal,
    /// `/var/log/auth.log` or `/var/log/secure` and their uncompressed rotations.
    File,
    /// btmp: failures only, without the method.
    Btmp,
    /// Nothing readable (or nothing there).
    #[default]
    None,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LoginReport {
    /// `last` ran: the sessions are known (maybe none).
    pub sessions_read: bool,
    /// Newest first.
    pub sessions: Vec<LoginSession>,
    /// The first time wtmp covers.
    pub sessions_since: Option<String>,
    pub log: LogSource,
    /// The earliest event read from the log.
    pub log_since: Option<String>,
    /// Logins accepted, by account, address and method; most first.
    pub accepted: Vec<LoginSource>,
    /// Logins refused for existing account names, by account, address and method; most first.
    pub failed: Vec<LoginSource>,
    /// Failures by account name, the names that do not exist included; most first.
    pub fail_totals: Vec<FailTotal>,
}

/// What one account's logins come to.
pub struct AccountLogins<'a> {
    pub sessions: Vec<&'a LoginSession>,
    pub accepted: Vec<&'a LoginSource>,
    pub failed: Vec<&'a LoginSource>,
    pub failures: Option<&'a FailTotal>,
}

impl LoginReport {
    pub fn of(&self, user: &str) -> AccountLogins<'_> {
        AccountLogins {
            sessions: self.sessions.iter().filter(|session| session.user == user).collect(),
            accepted: self.accepted.iter().filter(|row| row.user == user).collect(),
            failed: self.failed.iter().filter(|row| row.user == user).collect(),
            failures: self.fail_totals.iter().find(|row| row.user == user),
        }
    }

    /// The latest login of an account and where it came from: a session's start, or a login the log accepted.
    pub fn last_login(&self, user: &str) -> Option<(&str, &str)> {
        let session = self.sessions.iter().filter(|session| session.user == user).map(|session| (session.start.as_str(), session.from.as_str()));
        let accepted = self.accepted.iter().filter(|row| row.user == user).map(|row| (row.last.as_str(), row.from.as_str()));
        // RFC 3339 in UTC sorts as text.
        session.chain(accepted).max_by(|a, b| a.0.cmp(b.0))
    }

    /// Failed logins for account names that do not exist on the host: how many, and the names tried most.
    pub fn unknown_names<'a>(&'a self, known: &dyn Fn(&str) -> bool) -> (u64, Vec<&'a FailTotal>) {
        let rows: Vec<&FailTotal> = self.fail_totals.iter().filter(|row| row.invalid || !known(&row.user)).collect();
        (rows.iter().map(|row| row.count).sum(), rows)
    }
}

/// `+0800` as an offset.
fn offset(text: &str) -> Option<FixedOffset> {
    let text = text.trim();
    let sign = match text.as_bytes().first()? { b'+' => 1, b'-' => -1, _ => return None };
    let digits: String = text[1..].chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 4 { return None }
    let (hours, minutes): (i32, i32) = (digits[..2].parse().ok()?, digits[2..].parse().ok()?);
    FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60))
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// A time as the host printed it, in UTC: ISO 8601 with its offset (`last`, the journal, newer
/// auth logs), or syslog's `Nov 16 13:05:00` in the host's zone and without a year.
fn utc(text: &str, zone: FixedOffset, now: DateTime<Utc>) -> Option<String> {
    let text = text.trim();
    let parsed = DateTime::parse_from_rfc3339(text).or_else(|_| DateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f%z")).map(|time| time.with_timezone(&Utc));
    let time = match parsed {
        Ok(time) => time,
        Err(_) => {
            let mut words = text.split_whitespace();
            let name = words.next()?;
            let month = MONTHS.iter().position(|month| *month == name)? as u32 + 1;
            let day: u32 = words.next()?.parse().ok()?;
            let clock = chrono::NaiveTime::parse_from_str(words.next()?, "%H:%M:%S").ok()?;
            let local_now = now.with_timezone(&zone);
            let at = |year: i32| NaiveDate::from_ymd_opt(year, month, day).and_then(|date| zone.from_local_datetime(&date.and_time(clock)).single()).map(|time| time.with_timezone(&Utc));
            // No year: this year's, unless that is more than a day ahead.
            at(chrono::Datelike::year(&local_now)).filter(|time| *time <= now + chrono::Duration::days(1)).or_else(|| at(chrono::Datelike::year(&local_now) - 1))?
        }
    };
    Some(time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// An address as the host printed it: `0.0.0.0` and `::` (local logins under `last -i`) are none.
fn address(text: &str) -> String {
    match text { "0.0.0.0" | "::" | "-" => String::new(), other => other.to_string() }
}

/// One line of `last -i -w --time-format iso`.
fn session(line: &str, zone: FixedOffset, now: DateTime<Utc>) -> Option<LoginSession> {
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.len() < 4 || matches!(words[0], "reboot" | "shutdown" | "runlevel") || words[1] == "system" { return None }
    let start = utc(words[3], zone, now)?;
    let end = match words.get(4..).unwrap_or(&[]) {
        ["still", ..] => SessionEnd::Open,
        ["-", "crash", ..] => SessionEnd::Crash,
        ["-", "down", ..] => SessionEnd::Down,
        ["-", time, ..] => utc(time, zone, now).map(SessionEnd::At).unwrap_or_default(),
        _ => SessionEnd::Gone,
    };
    Some(LoginSession { user: words[0].into(), tty: words[1].into(), from: address(words[2]), start, end })
}

/// Read the sections `scripts/logins.sh` printed.
pub fn parse_logins(s: &Sections) -> LoginReport {
    let tz = s.get("tz");
    let zone = tz.first().and_then(|line| offset(line)).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
    let now = tz.get(1).and_then(|line| line.trim().parse::<i64>().ok()).and_then(|secs| DateTime::from_timestamp(secs, 0)).unwrap_or_else(Utc::now);
    let mut report = LoginReport { sessions_read: s.has("sessions"), ..Default::default() };
    for line in s.get("sessions") {
        if let Some(rest) = line.strip_prefix("wtmp begins ").or_else(|| line.strip_prefix("wtmpdb begins ")) {
            report.sessions_since = utc(rest, zone, now);
        } else if let Some(session) = session(line, zone, now) {
            report.sessions.push(session);
        }
    }
    report.log = match s.first("logsrc").map(str::trim) {
        Some("journal") => LogSource::Journal,
        Some("file") => LogSource::File,
        Some("btmp") => LogSource::Btmp,
        _ => LogSource::None,
    };
    for line in s.get("sshlog") {
        let cells: Vec<&str> = line.split('\t').collect();
        let count = || cells.get(2).and_then(|count| count.parse::<u64>().ok());
        match cells[..] {
            ["N", _, _, earliest] => report.log_since = utc(earliest, zone, now),
            [tag @ ("A" | "F"), user, _, from, method, first, last] => {
                let (Some(count), Some(first), Some(last)) = (count(), utc(first, zone, now), utc(last, zone, now)) else { continue };
                let row = LoginSource { user: user.into(), from: address(from), method: if method == "-" { String::new() } else { method.into() }, count, first, last };
                if tag == "A" { report.accepted.push(row) } else { report.failed.push(row) }
            }
            ["G", user, _, sources, invalid, first, last] => {
                let (Some(count), Some(first), Some(last)) = (count(), utc(first, zone, now), utc(last, zone, now)) else { continue };
                report.fail_totals.push(FailTotal { user: user.into(), count, sources: sources.parse().unwrap_or(0), invalid: invalid == "1", first, last });
            }
            _ => {}
        }
    }
    for rows in [&mut report.accepted, &mut report.failed] { rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| b.last.cmp(&a.last))) }
    report.fail_totals.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| b.last.cmp(&a.last)));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sections::parse_sections;

    #[test]
    fn times_are_read_in_any_of_the_hosts_forms() {
        let zone = offset("+0800").unwrap();
        let now = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        assert_eq!(utc("2026-01-01T12:00:00+08:00", zone, now).as_deref(), Some("2026-01-01T04:00:00Z"));
        assert_eq!(utc("2026-01-01T12:00:00+0800", zone, now).as_deref(), Some("2026-01-01T04:00:00Z"));
        assert_eq!(utc("2026-01-01T12:00:00.123456+08:00", zone, now).as_deref(), Some("2026-01-01T04:00:00Z"));
        // Syslog names no year: the last day of December is last year's.
        assert_eq!(utc("Dec 31 23:00:00", zone, now).as_deref(), Some("2025-12-31T15:00:00Z"));
        assert_eq!(utc("Jan  1 08:00:00", zone, now).as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(offset("-0330"), FixedOffset::west_opt(3 * 3600 + 1800));
        assert_eq!(utc("yesterday", zone, now), None);
    }

    #[test]
    fn sessions_are_read_from_last() {
        let output = "@@tz\n+0800\n1795000000\n@@sessions\nalice    pts/1        10.0.0.5         2026-11-16T14:00:00+08:00   still logged in\nalice    pts/0        10.0.0.5         2026-11-16T12:32:00+08:00 - 2026-11-16T13:00:00+08:00  (00:27)\nreboot   system boot  0.0.0.0          2026-11-10T08:00:00+08:00   still running\nbob      tty1         0.0.0.0          2026-11-15T10:00:00+08:00 - crash                      (1+02:00)\n\nwtmp begins 2026-11-01T00:00:01+08:00\n@@logsrc\nnone\n@@sshlog\n\n@@end\n";
        let report = parse_logins(&parse_sections(output));
        assert!(report.sessions_read);
        assert_eq!(report.sessions.len(), 3);
        assert_eq!((report.sessions[0].from.as_str(), &report.sessions[0].end), ("10.0.0.5", &SessionEnd::Open));
        assert_eq!(report.sessions[1].end, SessionEnd::At("2026-11-16T05:00:00Z".into()));
        assert_eq!((report.sessions[2].from.as_str(), &report.sessions[2].end), ("", &SessionEnd::Crash));
        assert_eq!(report.sessions_since.as_deref(), Some("2026-10-31T16:00:01Z"));
        assert_eq!(report.last_login("alice"), Some(("2026-11-16T06:00:00Z", "10.0.0.5")));
        assert_eq!(report.log, LogSource::None);
        assert!(!parse_logins(&parse_sections("@@tz\n+0000\n@@end\n")).sessions_read);
    }

    // The log lines sshd writes, oldest first, as the journal prints them (`-o short-iso`) and as
    // an older auth log does (syslog times).
    #[cfg(unix)]
    const SSHD: &str = "2026-11-16T09:59:01+0800 web sshd[1]: Invalid user admin from 203.0.113.7 port 4000
2026-11-16T09:59:03+0800 web sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 4000 ssh2
2026-11-16T10:00:10+0800 web sshd[2]: Failed password for root from 203.0.113.7 port 4001 ssh2
2026-11-16T10:00:12+0800 web sshd[3]: Failed password for root from 203.0.113.8 port 4001 ssh2
2026-11-16T10:01:00+0800 web sshd[3]: Failed password for root from 203.0.113.7 port 4002 ssh2
2026-11-16T12:32:00+0800 web sshd-session[6]: Accepted publickey for alice from 10.0.0.5 port 7000 ssh2: ED25519 SHA256:abc
Nov 16 13:00:00 web sshd[7]: Accepted password for alice from 10.0.0.9 port 7001 ssh2
Nov 16 13:05:00 web sshd[8]: Failed password for alice from 10.0.0.9 port 7002 ssh2
Nov 16 13:06:00 web sshd[8]: Failed password for invalid user a b from 203.0.113.7 port 4003 ssh2
Nov 16 13:07:00 web sshd[9]: Accepted publickey for alice from 10.0.0.5 port 7003 ssh2";

    /// The script's own function, run by the real shell, awk and sort over the lines above.
    #[cfg(unix)]
    fn reduce(input: &str, rev: u8) -> String {
        let script = include_str!("scripts/logins.sh");
        let start = script.find("T=$(printf").unwrap();
        let end = script.find("src=none").unwrap();
        let program = format!("{}cat <<'DATA' | sshreduce {rev}\n{input}\nDATA\n", &script[start..end]);
        let output = std::process::Command::new("sh").arg("-c").arg(&program).env("PATH", "/usr/bin:/bin").output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_counted_by_account_address_and_method_on_the_host() {
        let reduced = reduce(SSHD, 0);
        let output = format!("@@tz\n+0800\n1795000000\n@@logsrc\njournal\n@@sshlog\n{reduced}@@end\n");
        let report = parse_logins(&parse_sections(&output));
        assert_eq!((report.log, report.log_since.as_deref()), (LogSource::Journal, Some("2026-11-16T01:59:03Z")), "{reduced}");
        let alice = report.of("alice");
        let accepted: Vec<(&str, &str, u64)> = alice.accepted.iter().map(|row| (row.from.as_str(), row.method.as_str(), row.count)).collect();
        assert_eq!(accepted, [("10.0.0.5", "publickey", 2), ("10.0.0.9", "password", 1)]);
        assert_eq!(alice.accepted[0].first, "2026-11-16T04:32:00Z");
        assert_eq!(alice.accepted[0].last, "2026-11-16T05:07:00Z");
        assert_eq!(report.last_login("alice"), Some(("2026-11-16T05:07:00Z", "10.0.0.5")));
        let root = report.of("root");
        assert_eq!(root.failed.iter().map(|row| (row.from.as_str(), row.count)).collect::<Vec<_>>(), [("203.0.113.7", 2), ("203.0.113.8", 1)]);
        let total = root.failures.unwrap();
        assert_eq!((total.count, total.sources, total.invalid, total.last.as_str()), (3, 2, false, "2026-11-16T02:01:00Z"));
        // A name that does not exist is counted, not listed address by address; one with a space is skipped.
        assert!(report.failed.iter().all(|row| row.user != "admin"));
        let (unknown, names) = report.unknown_names(&|name| matches!(name, "root" | "alice"));
        assert_eq!((unknown, names.iter().map(|row| row.user.as_str()).collect::<Vec<_>>()), (1, vec!["admin"]));
        assert_eq!(report.of("alice").failures.map(|row| row.count), Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn btmp_is_read_newest_first() {
        let lastb = "root     ssh:notty    203.0.113.7      2026-11-16T10:01:00+08:00 - 2026-11-16T10:01:00+08:00  (00:00)\nroot     ssh:notty    203.0.113.7      2026-11-16T10:00:10+08:00 - 2026-11-16T10:00:10+08:00  (00:00)\n\nbtmp begins 2026-11-01T00:00:00+08:00";
        let reduced = reduce(lastb, 1);
        let report = parse_logins(&parse_sections(&format!("@@tz\n+0800\n1795000000\n@@logsrc\nbtmp\n@@sshlog\n{reduced}@@end\n")));
        let row = &report.of("root").failed[0];
        assert_eq!((row.count, row.method.as_str(), row.first.as_str(), row.last.as_str()), (2, "", "2026-11-16T02:00:10Z", "2026-11-16T02:01:00Z"), "{reduced}");
        assert_eq!(report.log_since.as_deref(), Some("2026-11-16T02:00:10Z"));
    }
}
