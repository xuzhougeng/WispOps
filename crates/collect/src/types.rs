//! Types shared by the collectors and their callers: inspection thresholds, stored history
//! records, and the result of inspecting a fleet.

use serde::{Deserialize, Serialize};

use crate::inspect::{Finding, HostInspection, InspectionMetrics};

/// Limits that turn an inspection into findings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Thresholds {
    pub disk_warn_pct: f64,
    pub disk_crit_pct: f64,
    pub inode_warn_pct: f64,
    pub inode_crit_pct: f64,
    pub mem_avail_warn_pct: f64,
    pub mem_avail_crit_pct: f64,
    pub swap_warn_pct: f64,
    pub load_per_core_warn: f64,
    pub load_per_core_crit: f64,
    pub gpu_temp_warn_c: f64,
    pub zombie_warn: f64,
    /// Disk growth since the previous inspection that is reported, in percentage points.
    pub disk_growth_warn_pts: f64,
    /// A mount forecast to fill within this many days at its recent growth rate is a warning; 0 disables the check.
    pub disk_full_forecast_days: f64,
    /// SSH login slower than this is a warning; 0 disables the check.
    pub login_warn_ms: f64,
    /// TCP retransmit share during the inspection sample that is a warning; 0 disables the check.
    pub tcp_retrans_warn_pct: f64,
    /// Failed SSH logins in the last hour that are a warning, when the sshd journal is readable; 0 disables the check.
    pub ssh_fail_warn_per_hour: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            disk_warn_pct: 80.0,
            disk_crit_pct: 90.0,
            inode_warn_pct: 80.0,
            inode_crit_pct: 90.0,
            mem_avail_warn_pct: 10.0,
            mem_avail_crit_pct: 5.0,
            swap_warn_pct: 50.0,
            load_per_core_warn: 1.5,
            load_per_core_crit: 3.0,
            gpu_temp_warn_c: 85.0,
            zombie_warn: 10.0,
            disk_growth_warn_pts: 5.0,
            disk_full_forecast_days: 7.0,
            login_warn_ms: 3000.0,
            tcp_retrans_warn_pct: 5.0,
            ssh_fail_warn_per_hour: 100.0,
        }
    }
}

/// One stored inspection: its metrics, how the run ended, and what it found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRecord {
    #[serde(flatten)]
    pub metrics: InspectionMetrics,
    /// The run status: `ok`, `failed`, `unreachable`, `auth-failed`, `blocked`, `sudo-required`, `timeout` or `cancelled`.
    pub status: String,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl HistoryRecord {
    pub fn is_ok(&self) -> bool {
        self.status == "ok"
    }
}

/// The inspection of one host.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInspectionResult {
    pub host: String,
    /// The run status, as in [`HistoryRecord::status`].
    pub status: String,
    /// `crit`, `warn`, `info`, `ok` or `unreachable`.
    pub severity: String,
    /// `muted` marks a finding the owner acknowledged; it does not count toward `severity`.
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<HostInspection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Hosts per severity of one fleet inspection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FleetCounts {
    pub ok: u32,
    pub info: u32,
    pub warn: u32,
    pub crit: u32,
    pub unreachable: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetInspection {
    pub at: String,
    pub hosts: Vec<HostInspectionResult>,
    pub counts: FleetCounts,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_default_and_merge_partial_json() {
        let t: Thresholds = serde_json::from_str(r#"{"diskWarnPct":70,"zombieWarn":3}"#).unwrap();
        assert_eq!(t, Thresholds { disk_warn_pct: 70.0, zombie_warn: 3.0, ..Thresholds::default() });
        assert_eq!(serde_json::to_value(Thresholds::default()).unwrap()["sshFailWarnPerHour"], 100.0);
    }

    #[test]
    fn reads_records_the_plugin_wrote_and_tolerates_damaged_numbers() {
        let rows: Vec<HistoryRecord> = serde_json::from_str(include_str!("testdata/history.json")).unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[3].status, "timeout");
        assert_eq!(rows[4].metrics.disk_pct.keys().collect::<Vec<_>>(), ["/", "/data"]);
        assert_eq!(rows[4].metrics.login_ms, Some(4200.0));
        crate::util::testing::assert_golden(&rows, include_str!("testdata/history.json"));
        let damaged: HistoryRecord = serde_json::from_str(r#"{"at":"2026-10-01T00:00:00Z","status":"ok","diskPct":{"/":40,"/bad":null,"/str":"n/a"},"loginMs":"640","tcpRetransPct":null,"findings":[]}"#).unwrap();
        assert_eq!(damaged.metrics.disk_pct.keys().collect::<Vec<_>>(), ["/"]);
        assert_eq!((damaged.metrics.login_ms, damaged.metrics.tcp_retrans_pct), (None, None));
    }
}
