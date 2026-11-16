//! Fleet overview for the management panel: the recent inspection history of every inventory
//! host, reduced to what a status matrix and sparklines need. Pure and bounded: at most
//! `MAX_OVERVIEW_ROWS` inspections per host, a few non-informational findings per inspection, and
//! no command output or credentials.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::inspect::{Finding, Severity, worst_severity};
use crate::mutes::{Mute, finding_subject, mute_for};
use crate::trends::{ForecastPoint, forecast_full, reachability};
use crate::types::HistoryRecord;
use crate::util::{OrderedMap, date_parse, js_round, millis, take_chars, to_iso};

/// Overall state of one inspection as the panel colors it; `Never` is only the latest state of a
/// host nothing was recorded for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverviewState {
    Ok,
    Warn,
    Crit,
    Unreachable,
    Never,
}

/// A non-informational finding of one inspection; a muted one carries the mute covering it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewFinding {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mute: Option<Mute>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewRow {
    pub at: String,
    pub state: OverviewState,
    /// Why an unreachable inspection failed: the runner status such as `timeout`, `auth-failed` or `blocked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub disk_pct: OrderedMap<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_avail_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load1: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_bps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_bps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_established: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_retrans_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_util_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_mem_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_temp_c: Option<f64>,
    #[serde(rename = "sshFailures1h", default, skip_serializing_if = "Option::is_none")]
    pub ssh_failures_1h: Option<f64>,
    /// Live problems first, critical before warning, muted ones last; at most six.
    pub findings: Vec<OverviewFinding>,
}

/// Share of inspections that connected and the 95th-percentile login time over the last day and week.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewReach {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub week: Option<f64>,
    #[serde(rename = "loginP95", default, skip_serializing_if = "Option::is_none")]
    pub login_p95: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewHost {
    pub name: String,
    pub groups: Vec<String>,
    /// Oldest first, so the panel draws time left to right.
    pub rows: Vec<OverviewRow>,
    /// State of the newest inspection, or `never` when nothing was recorded.
    pub latest: OverviewState,
    /// Days until each mount of the newest successful inspection fills at its recent growth rate, when it is growing.
    pub forecast: OrderedMap<f64>,
    pub reach: OverviewReach,
}

/// Hosts per latest state, for the summary strip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct OverviewSummary {
    pub ok: u32,
    pub warn: u32,
    pub crit: u32,
    pub unreachable: u32,
    pub never: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub generated_at: String,
    pub limit: usize,
    pub hosts: Vec<OverviewHost>,
    pub summary: OverviewSummary,
}

/// One inventory host and its stored inspections, oldest first.
#[derive(Clone, Copy, Debug)]
pub struct OverviewInput<'a> {
    pub name: &'a str,
    pub groups: &'a [String],
    pub history: &'a [HistoryRecord],
    pub mutes: &'a [Mute],
}

pub const DEFAULT_OVERVIEW_ROWS: usize = 30;
pub const MAX_OVERVIEW_ROWS: usize = 200;
const MAX_FINDINGS: usize = 6;
const MAX_MESSAGE: usize = 240;

/// Clamp a client-supplied row count; anything that is not a finite number is the default.
pub fn overview_limit(value: Option<f64>) -> usize {
    match value {
        Some(value) if value.is_finite() => value.floor().clamp(1.0, MAX_OVERVIEW_ROWS as f64) as usize,
        _ => DEFAULT_OVERVIEW_ROWS,
    }
}

/// State of one stored inspection under the owner's current mutes, at `now_ms` (epoch milliseconds).
pub fn record_state(record: &HistoryRecord, mutes: &[Mute], now_ms: f64) -> OverviewState {
    if !record.is_ok() {
        return OverviewState::Unreachable;
    }
    match worst_severity(record.findings.iter().filter(|f| mute_for(f, mutes, now_ms).is_none())) {
        Some(Severity::Crit) => OverviewState::Crit,
        Some(Severity::Warn) => OverviewState::Warn,
        _ => OverviewState::Ok,
    }
}

/// Reduce one host's stored inspections (oldest first) to overview rows, applying the owner's current mutes.
pub fn overview_rows(records: &[HistoryRecord], mutes: &[Mute], now_ms: f64) -> Vec<OverviewRow> {
    records
        .iter()
        .map(|record| {
            let m = &record.metrics;
            let mut live: Vec<(&Finding, Option<&Mute>)> = record.findings.iter().filter(|f| f.severity != Severity::Info).map(|f| (f, mute_for(f, mutes, now_ms))).collect();
            // Live problems first, critical before warning; muted ones last.
            live.sort_by_key(|(f, mute)| (mute.is_some(), f.severity != Severity::Crit));
            OverviewRow {
                at: m.at.clone(),
                state: record_state(record, mutes, now_ms),
                status: (!record.is_ok()).then(|| record.status.clone()),
                disk_pct: m.disk_pct.iter().filter(|(_, pct)| pct.is_finite()).map(|(mount, pct)| (mount, *pct)).collect(),
                mem_avail_pct: m.mem_avail_pct,
                load1: m.load1,
                cpu_pct: m.cpu_pct,
                login_ms: m.login_ms.filter(|v| v.is_finite()),
                rx_bps: m.rx_bps.filter(|v| v.is_finite()),
                tx_bps: m.tx_bps.filter(|v| v.is_finite()),
                tcp_established: m.tcp_established.filter(|v| v.is_finite()),
                tcp_retrans_pct: m.tcp_retrans_pct.filter(|v| v.is_finite()),
                gpu_util_pct: m.gpu_util_pct.filter(|v| v.is_finite()),
                gpu_mem_pct: m.gpu_mem_pct.filter(|v| v.is_finite()),
                gpu_temp_c: m.gpu_temp_c.filter(|v| v.is_finite()),
                ssh_failures_1h: m.ssh_failures_1h.filter(|v| v.is_finite()),
                findings: live
                    .into_iter()
                    .take(MAX_FINDINGS)
                    .map(|(f, mute)| OverviewFinding {
                        severity: f.severity,
                        code: f.code.clone(),
                        message: if f.message.chars().count() > MAX_MESSAGE { format!("{}…", take_chars(&f.message, MAX_MESSAGE)) } else { f.message.clone() },
                        subject: finding_subject(f).map(str::to_string),
                        mute: mute.cloned(),
                    })
                    .collect(),
            }
        })
        .collect()
}

/// Days to full per mount of the newest successful inspection, rounded to a tenth.
pub fn host_forecast(history: &[HistoryRecord]) -> OrderedMap<f64> {
    let ok: Vec<&HistoryRecord> = history.iter().filter(|r| r.is_ok()).collect();
    let Some(latest) = ok.last() else { return OrderedMap::new() };
    latest
        .metrics
        .disk_pct
        .keys()
        .filter_map(|mount| {
            let points: Vec<ForecastPoint> = ok.iter().filter_map(|r| r.metrics.disk_pct.get(mount).map(|pct| ForecastPoint { at: date_parse(&r.metrics.at), pct: *pct })).collect();
            forecast_full(&points).map(|forecast| (mount, js_round(forecast.days * 10.0) / 10.0))
        })
        .collect()
}

/// Assemble the overview from per-host histories, keeping inventory order. Rows are the newest
/// `limit` inspections; forecasts and reachability use the whole history passed in.
pub fn build_overview(hosts: &[OverviewInput], limit: usize, now: DateTime<Utc>) -> Overview {
    let now_ms = millis(now);
    let mut summary = OverviewSummary::default();
    let hosts = hosts
        .iter()
        .map(|host| {
            let newest = if limit == 0 { host.history } else { &host.history[host.history.len().saturating_sub(limit)..] };
            let rows = overview_rows(newest, host.mutes, now_ms);
            let latest = rows.last().map_or(OverviewState::Never, |row| row.state);
            match latest {
                OverviewState::Ok => summary.ok += 1,
                OverviewState::Warn => summary.warn += 1,
                OverviewState::Crit => summary.crit += 1,
                OverviewState::Unreachable => summary.unreachable += 1,
                OverviewState::Never => summary.never += 1,
            }
            let day = reachability(host.history, now_ms - 86_400_000.0);
            let week = reachability(host.history, now_ms - 7.0 * 86_400_000.0);
            OverviewHost {
                name: host.name.to_string(),
                groups: host.groups.to_vec(),
                rows,
                latest,
                forecast: host_forecast(host.history),
                reach: OverviewReach { day: day.pct, week: week.pct, login_p95: day.login_p95 },
            }
        })
        .collect();
    Overview { generated_at: to_iso(now), limit, hosts, summary }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::InspectionMetrics;
    use crate::trends::reachability;
    use crate::util::testing::assert_golden;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().to_utc()
    }

    fn ok(at: &str, findings: Vec<Finding>) -> HistoryRecord {
        HistoryRecord { metrics: InspectionMetrics { at: at.into(), disk_pct: [("/", 40.0)].into_iter().collect(), mem_avail_pct: Some(60.0), ..Default::default() }, status: "ok".into(), findings }
    }

    fn failed(at: &str, status: &str, findings: Vec<Finding>) -> HistoryRecord {
        HistoryRecord { metrics: InspectionMetrics { at: at.into(), ..Default::default() }, status: status.into(), findings }
    }

    fn input<'a>(name: &'a str, groups: &'a [String], history: &'a [HistoryRecord]) -> OverviewInput<'a> {
        OverviewInput { name, groups, history, mutes: &[] }
    }

    #[test]
    fn clamps_the_requested_row_count_and_falls_back_to_the_default() {
        assert_eq!(overview_limit(None), DEFAULT_OVERVIEW_ROWS);
        assert_eq!(overview_limit(Some(f64::NAN)), DEFAULT_OVERVIEW_ROWS);
        assert_eq!(overview_limit(Some(0.0)), 1);
        assert_eq!(overview_limit(Some(12.9)), 12);
        assert_eq!(overview_limit(Some(10_000.0)), MAX_OVERVIEW_ROWS);
    }

    #[test]
    fn colors_each_inspection_by_its_worst_finding_and_marks_failed_runs_unreachable() {
        let rows = overview_rows(
            &[
                ok("2026-10-01T00:00:00Z", vec![Finding::new(Severity::Info, "note", "fine")]),
                ok("2026-10-02T00:00:00Z", vec![Finding::new(Severity::Warn, "disk-high", "/ 85%")]),
                ok("2026-10-03T00:00:00Z", vec![Finding::new(Severity::Warn, "disk-high", "/ 91%"), Finding::new(Severity::Crit, "disk-full", "/data 97%")]),
                failed("2026-10-04T00:00:00Z", "unreachable", vec![Finding::new(Severity::Crit, "unreachable", "ssh: connect timed out")]),
            ],
            &[],
            0.0,
        );
        assert_eq!(rows.iter().map(|r| r.state).collect::<Vec<_>>(), [OverviewState::Ok, OverviewState::Warn, OverviewState::Crit, OverviewState::Unreachable]);
        // Informational findings are dropped; critical ones come first.
        assert!(rows[0].findings.is_empty());
        assert_eq!(rows[2].findings.iter().map(|f| f.code.as_str()).collect::<Vec<_>>(), ["disk-full", "disk-high"]);
        assert_eq!((rows[0].status.as_deref(), rows[3].status.as_deref()), (None, Some("unreachable")));
    }

    #[test]
    fn bounds_findings_per_inspection_and_truncates_long_messages() {
        let findings: Vec<Finding> = (0..9).map(|i| Finding::new(Severity::Warn, format!("w{i}"), "x".repeat(500))).collect();
        let rows = overview_rows(&[ok("2026-10-01T00:00:00Z", findings)], &[], 0.0);
        assert_eq!(rows[0].findings.len(), 6);
        assert_eq!(rows[0].findings[0].message.chars().count(), 241);
        assert!(rows[0].findings[0].message.ends_with('…'));
    }

    #[test]
    fn carries_network_metrics_and_drops_values_a_damaged_file_made_non_numeric() {
        let record: HistoryRecord =
            serde_json::from_str(r#"{"at":"2026-10-01T00:00:00Z","status":"ok","diskPct":{"/":40,"/bad":null,"/str":"n/a"},"memAvailPct":60,"findings":[],"loginMs":640,"rxBps":2048,"txBps":512,"tcpEstablished":37,"tcpRetransPct":null}"#).unwrap();
        let row = &overview_rows(&[record], &[], 0.0)[0];
        assert_eq!((row.login_ms, row.rx_bps, row.tx_bps, row.tcp_established, row.tcp_retrans_pct), (Some(640.0), Some(2048.0), Some(512.0), Some(37.0), None));
        assert_eq!(row.disk_pct.keys().collect::<Vec<_>>(), ["/"]);
        assert!(serde_json::to_value(row).unwrap().get("tcpRetransPct").is_none());
        let old: HistoryRecord = serde_json::from_str(r#"{"at":"2026-10-01T00:00:00Z","status":"ok","diskPct":{"/":40},"findings":[],"loginMs":"640"}"#).unwrap();
        let row = &overview_rows(&[old], &[], 0.0)[0];
        assert_eq!((row.login_ms, row.rx_bps), (None, None));
    }

    #[test]
    fn keeps_inventory_order_applies_the_limit_per_host_and_summarizes_the_latest_state() {
        let history: Vec<HistoryRecord> = (0..5)
            .map(|i| {
                let mut record = ok(&format!("2026-10-0{}T00:00:00Z", i + 1), vec![]);
                record.metrics.disk_pct.insert("/", 40.0 + f64::from(i));
                record
            })
            .collect();
        let crit = [ok("2026-10-01T00:00:00Z", vec![Finding::new(Severity::Crit, "disk-full", "x")])];
        let gpu = ["gpu".to_string()];
        let view = build_overview(&[input("b", &gpu, &history), input("a", &[], &[]), input("c", &[], &crit)], 3, at("2026-10-27T00:00:00Z"));
        assert_eq!(view.hosts.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), ["b", "a", "c"]);
        assert_eq!(view.hosts[0].rows.iter().map(|r| r.disk_pct.get("/").copied()).collect::<Vec<_>>(), [Some(42.0), Some(43.0), Some(44.0)]);
        assert_eq!(view.hosts.iter().map(|h| h.latest).collect::<Vec<_>>(), [OverviewState::Ok, OverviewState::Never, OverviewState::Crit]);
        assert_eq!(view.summary, OverviewSummary { ok: 1, warn: 0, crit: 1, unreachable: 0, never: 1 });
        assert_eq!((view.limit, view.generated_at.as_str()), (3, "2026-10-27T00:00:00.000Z"));
    }

    #[test]
    fn reports_reachability_login_p95_and_forecasts_from_the_whole_history() {
        let now = at("2026-10-29T12:00:00Z");
        let hour = |h: i64| to_iso(now - chrono::Duration::hours(h));
        let with = |h: i64, pct: f64, login: Option<f64>| {
            let mut record = ok(&hour(h), vec![]);
            record.metrics.disk_pct.insert("/", pct);
            record.metrics.login_ms = login;
            record
        };
        let mut history = vec![with(72, 80.0, None), with(48, 82.0, None), failed(&hour(20), "timeout", vec![])];
        history.extend([10, 8, 6, 4, 2].iter().enumerate().map(|(i, h)| with(*h, 84.0 + i as f64 * 0.1, Some(100.0 * (i as f64 + 1.0)))));
        let view = build_overview(&[input("a", &[], &history)], 2, now);
        let host = &view.hosts[0];
        assert_eq!(host.rows.len(), 2);
        assert_eq!(host.reach, OverviewReach { day: Some(83.3), week: Some(87.5), login_p95: Some(500.0) });
        assert!(host.forecast.get("/").is_some_and(|days| *days > 1.0));
        assert_eq!(reachability(&history, millis(now) + 1.0), Default::default());
    }

    #[test]
    fn stops_a_muted_problem_from_coloring_the_server_and_lists_it_last_with_its_mute() {
        let mut disk = ok("2026-10-29T00:00:00Z", vec![Finding::new(Severity::Crit, "disk-full", "/data5 99% used").about("/data5"), Finding::new(Severity::Warn, "memory-low", "memory available 9%")]);
        disk.metrics.disk_pct = [("/data5", 99.0)].into_iter().collect();
        let now = date_parse("2026-10-29T12:00:00Z");
        let mute = |code: &str, subject: Option<&str>, until: Option<&str>| Mute { code: code.into(), subject: subject.map(Into::into), until: until.map(Into::into) };
        assert_eq!(record_state(&disk, &[], now), OverviewState::Crit);
        assert_eq!(record_state(&disk, &[mute("disk-full", Some("/data5"), None)], now), OverviewState::Warn);
        assert_eq!(record_state(&disk, &[mute("disk-full", None, None), mute("memory-low", None, None)], now), OverviewState::Ok);
        let rows = overview_rows(std::slice::from_ref(&disk), &[mute("disk-full", Some("/data5"), Some("2026-11-05T00:00:00Z"))], now);
        assert_eq!(rows[0].state, OverviewState::Warn);
        let listed: Vec<(&str, Option<&str>, Option<&str>)> = rows[0].findings.iter().map(|f| (f.code.as_str(), f.subject.as_deref(), f.mute.as_ref().and_then(|m| m.until.as_deref()))).collect();
        assert_eq!(listed, [("memory-low", None, None), ("disk-full", Some("/data5"), Some("2026-11-05T00:00:00Z"))]);
    }

    #[test]
    fn matches_the_plugin_overview() {
        let history: Vec<HistoryRecord> = serde_json::from_str(include_str!("testdata/history.json")).unwrap();
        let groups = ["gpu".to_string()];
        let mutes = [Mute { code: "disk-full".into(), subject: Some("/".into()), until: None }];
        let view = build_overview(&[OverviewInput { name: "gpu-01", groups: &groups, history: &history, mutes: &mutes }, input("none", &[], &[])], 3, at("2026-10-29T06:00:00Z"));
        assert_golden(&view, include_str!("testdata/overview.json"));
    }
}
