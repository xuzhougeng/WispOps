//! Login attacks on a host, read-only, as the security page draws them: how many SSH logins
//! failed in the window, from which addresses, with which account names, hour by hour, and what
//! fail2ban has banned. The script is a tail for the security triage's: it reads the `sshd` lines
//! that script already took from the journal or the auth log, so both run in one connection.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::sections::{num, parse_sections};
use crate::security::{SecurityOptions, SecurityReport, SourceCount, security_script};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HourCount {
    /// `MM-DD HH`, in the server's own time.
    pub hour: String,
    pub count: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackReport {
    /// Failed login attempts in the window; one per attempt, not per log line.
    pub failed: f64,
    /// Distinct addresses they came from.
    pub sources: f64,
    /// The addresses that tried most, most first.
    pub by_source: Vec<SourceCount>,
    /// The account names tried most; `source` holds the name.
    pub by_user: Vec<SourceCount>,
    /// Every hour from the first attempt to the last, quiet hours included.
    pub hours: Vec<HourCount>,
    pub banned: Vec<String>,
}

/// One stored triage; the security page draws the latest per host.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySnapshot {
    pub at: String,
    pub hours: u32,
    pub report: SecurityReport,
    pub attacks: AttackReport,
}

/// The security triage followed by the attack counts, in one script.
pub fn attack_script(o: &SecurityOptions) -> String {
    let triage = security_script(o);
    format!("{}{}", triage.strip_suffix("echo @@end\n").unwrap_or(&triage), include_str!("scripts/attacks.sh"))
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/// The most hours a chart is given: a week and a day.
const MAX_HOURS: i64 = 24 * 8;

/// Hours since the epoch of a log line's hour: `2026-11-16T10` (ISO) or `Nov 16 10` (syslog, no year).
fn hour_ordinal(key: &str, now: DateTime<Utc>) -> Option<i64> {
    let (date, hour) = if let Some((date, hour)) = key.split_once('T') {
        (NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?, hour)
    } else {
        let mut words = key.split_whitespace();
        let month = MONTHS.iter().position(|name| Some(*name) == words.clone().next())? as u32 + 1;
        words.next();
        let (day, hour) = (words.next()?.parse::<u32>().ok()?, words.next()?);
        // A syslog date names no year: it is this year's unless that would be in the future.
        let this_year = NaiveDate::from_ymd_opt(now.year(), month, day);
        let date = this_year.filter(|date| *date <= now.date_naive().succ_opt().unwrap_or(now.date_naive())).or_else(|| NaiveDate::from_ymd_opt(now.year() - 1, month, day))?;
        (date, hour)
    };
    let hour = hour.parse::<i64>().ok().filter(|hour| (0..24).contains(hour))?;
    Some(date.and_hms_opt(0, 0, 0)?.and_utc().timestamp() / 3600 + hour)
}

pub fn parse_attacks(output: &str, now: DateTime<Utc>) -> AttackReport {
    let s = parse_sections(output);
    let mut report = AttackReport::default();
    let mut hours: Vec<(i64, f64)> = vec![];
    for line in s.get("attacks") {
        let mut cells = line.splitn(3, '\t');
        let (Some(tag), Some(count), Some(what)) = (cells.next(), cells.next().and_then(num), cells.next()) else { continue };
        match tag {
            "T" => (report.failed, report.sources) = (count, num(what).unwrap_or(0.0)),
            "S" => report.by_source.push(SourceCount { source: what.to_string(), count }),
            "U" => report.by_user.push(SourceCount { source: what.to_string(), count }),
            "H" => hours.extend(hour_ordinal(what, now).map(|at| (at, count))),
            _ => {}
        }
    }
    hours.sort_by_key(|(at, _)| *at);
    if let (Some((first, _)), Some((last, _))) = (hours.first().copied(), hours.last().copied()) {
        for at in first.max(last - MAX_HOURS + 1)..=last {
            let count = hours.iter().filter(|(hour, _)| *hour == at).map(|(_, count)| count).sum();
            let label = DateTime::from_timestamp(at * 3600, 0).map(|time| time.format("%m-%d %H").to_string()).unwrap_or_default();
            report.hours.push(HourCount { hour: label, count });
        }
    }
    report.banned = s.get("banned").iter().map(|line| line.trim().to_string()).filter(|line| !line.is_empty()).collect();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // Only the test that runs the real shell reads these.
    #[cfg(unix)]
    const LINES: &str = "Nov 16 09:59:01 web sshd[1]: Invalid user admin from 203.0.113.7 port 4000
Nov 16 09:59:03 web sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 4000 ssh2
Nov 16 10:00:10 web sshd[2]: Failed password for root from 203.0.113.7 port 4001 ssh2
Nov 16 10:00:12 web sshd[3]: Failed publickey for root from 2001:db8::9 port 5000 ssh2
Nov 16 12:30:00 web sshd[4]: Connection closed by invalid user oracle 198.51.100.4 port 6000 [preauth]
Nov 16 12:31:00 web sshd[5]: Connection closed by authenticating user root 198.51.100.4 port 6001 [preauth]
Nov 16 12:32:00 web sshd[6]: Accepted publickey for alice from 10.0.0.5 port 7000 ssh2
2026-11-16T13:05:00.120+08:00 web sshd[7]: Failed password for invalid user test from 203.0.113.7 port 4002 ssh2
Nov 16 13:06:00 web sshd[8]: Failed password for invalid user a b from 203.0.113.7 port 4003 ssh2";

    #[test]
    fn appends_to_the_triage_script_once() {
        let script = attack_script(&SecurityOptions { hours: 24 });
        assert_eq!(script.matches("echo @@end").count(), 1);
        assert!(script.ends_with("echo @@end\n") && script.contains("echo @@failed\n") && script.contains("echo @@attacks\n"));
    }

    /// The counting runs through the real shell's awk and sort.
    #[cfg(unix)]
    #[test]
    fn counts_attempts_sources_names_and_hours() {
        let script = format!("lines=$(cat <<'DATA'\n{LINES}\nDATA\n)\n{}", include_str!("scripts/attacks.sh"));
        let output = std::process::Command::new("sh").arg("-c").arg(&script).env("PATH", "/usr/bin:/bin").output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report = parse_attacks(&stdout, Utc.with_ymd_and_hms(2026, 11, 16, 14, 0, 0).unwrap());
        // "Invalid user … from" announces the attempt the next line counts; a name with a space is skipped.
        assert_eq!((report.failed, report.sources), (6.0, 3.0), "{stdout}");
        let pairs = |rows: &[SourceCount]| rows.iter().map(|row| (row.source.clone(), row.count)).collect::<Vec<_>>();
        assert_eq!(pairs(&report.by_source)[0], ("203.0.113.7".to_string(), 3.0));
        assert_eq!(pairs(&report.by_user)[0], ("root".to_string(), 3.0));
        assert!(pairs(&report.by_source).contains(&("2001:db8::9".to_string(), 1.0)) && pairs(&report.by_user).contains(&("oracle".to_string(), 1.0)));
        assert_eq!(report.hours.iter().map(|hour| (hour.hour.as_str(), hour.count)).collect::<Vec<_>>(), [("11-16 09", 1.0), ("11-16 10", 2.0), ("11-16 11", 0.0), ("11-16 12", 2.0), ("11-16 13", 1.0)]);
    }

    #[test]
    fn dates_without_a_year_never_land_in_the_future() {
        let now = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        let (december, january) = (hour_ordinal("Dec 31 23", now).unwrap(), hour_ordinal("Jan  1 00", now).unwrap());
        assert_eq!(january - december, 1);
        assert_eq!(hour_ordinal("2026-01-01T00", now), Some(january));
        assert_eq!(hour_ordinal("Foo 1 00", now), None);
        let report = parse_attacks("@@attacks\nH\t2\tDec 31 23\nH\t1\tJan  1 01\nT\t3\t1\n@@banned\n203.0.113.7\n\n@@end\n", now);
        assert_eq!(report.hours.len(), 3);
        assert_eq!((report.failed, report.banned), (3.0, vec!["203.0.113.7".to_string()]));
    }
}
