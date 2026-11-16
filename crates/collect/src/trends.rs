//! Trends over the inspection history: rendered changes, the disk-full forecast, and reachability.

use crate::types::HistoryRecord;
use crate::util::{date_parse, js_round, to_fixed};

fn describe(label: &str, values: &[(&str, f64)]) -> Option<String> {
    if values.len() < 2 {
        return None;
    }
    let (first, last) = (values[0], values[values.len() - 1]);
    let delta = last.1 - first.1;
    let steps: Vec<String> = values.iter().map(|v| format!("{}%", to_fixed(v.1, 1))).collect();
    Some(format!("{label}: {} ({}{} percentage points; {} → {})", steps.join(" → "), if delta >= 0.0 { "+" } else { "" }, to_fixed(delta, 1), first.0, last.0))
}

/// Lines describing how memory and each mount changed over the successful inspections in `rows`.
pub fn render_trends(rows: &[HistoryRecord]) -> Vec<String> {
    let good: Vec<&HistoryRecord> = rows.iter().filter(|row| row.is_ok()).collect();
    if good.len() < 2 {
        return vec!["Trend: at least two successful inspections are required.".to_string()];
    }
    let memory: Vec<(&str, f64)> = good.iter().filter_map(|r| r.metrics.mem_avail_pct.map(|v| (r.metrics.at.as_str(), v))).collect();
    let mut lines: Vec<String> = describe("Memory available", &memory).into_iter().collect();
    let mut mounts: Vec<&str> = Vec::new();
    for mount in good.iter().flat_map(|row| row.metrics.disk_pct.keys()) {
        if !mounts.contains(&mount) {
            mounts.push(mount);
        }
    }
    for mount in mounts {
        let values: Vec<(&str, f64)> = good.iter().filter_map(|r| r.metrics.disk_pct.get(mount).map(|v| (r.metrics.at.as_str(), *v))).collect();
        lines.extend(describe(&format!("Disk {mount}"), &values));
    }
    lines
}

const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 24.0 * HOUR;
/// Inspections read for forecasts and availability: a week at five-minute intervals, bounded by retention anyway.
pub const STATS_ROWS: usize = 2016;
/// How far back a disk-full forecast looks.
pub const FORECAST_WINDOW_DAYS: f64 = 7.0;

/// Used percentage of a mount at a time in epoch milliseconds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ForecastPoint {
    pub at: f64,
    pub pct: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Forecast {
    /// Days until the mount is full.
    pub days: f64,
    /// Growth in percentage points a day.
    pub per_day: f64,
}

/// When a mount fills at its recent growth rate: a least-squares line through its used % over the
/// last week, from at least three points spanning six hours, extended from the newest value. `None`
/// when it is not growing (under 0.05 points a day), the data is too thin, or full is more than a
/// year away.
pub fn forecast_full(points: &[ForecastPoint]) -> Option<Forecast> {
    let last = *points.last()?;
    let recent: Vec<ForecastPoint> = points.iter().copied().filter(|p| p.at.is_finite() && p.pct.is_finite() && p.at >= last.at - FORECAST_WINDOW_DAYS * DAY && p.at <= last.at).collect();
    let first = *recent.first()?;
    if recent.len() < 3 || last.at - first.at < 6.0 * HOUR {
        return None;
    }
    let count = recent.len() as f64;
    let xs: Vec<f64> = recent.iter().map(|p| (p.at - last.at) / DAY).collect();
    let mx = xs.iter().sum::<f64>() / count;
    let my = recent.iter().map(|p| p.pct).sum::<f64>() / count;
    let (mut sxx, mut sxy) = (0.0, 0.0);
    for (p, x) in recent.iter().zip(&xs) {
        let dx = x - mx;
        sxx += dx * dx;
        sxy += dx * (p.pct - my);
    }
    let per_day = if sxx == 0.0 { 0.0 } else { sxy / sxx };
    if per_day.is_nan() || per_day < 0.05 {
        return None;
    }
    let days = ((100.0 - last.pct) / per_day).max(0.0);
    (days <= 365.0).then_some(Forecast { days, per_day })
}

/// Share of inspections that connected, and the 95th-percentile login time.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Reachability {
    pub pct: Option<f64>,
    pub login_p95: Option<f64>,
}

/// Share of inspections that connected and the 95th-percentile login time, over the history since
/// `since_ms` (epoch milliseconds).
pub fn reachability(rows: &[HistoryRecord], since_ms: f64) -> Reachability {
    let window: Vec<&HistoryRecord> = rows.iter().filter(|r| date_parse(&r.metrics.at) >= since_ms).collect();
    if window.is_empty() {
        return Reachability::default();
    }
    let ok: Vec<&&HistoryRecord> = window.iter().filter(|r| r.is_ok()).collect();
    let mut logins: Vec<f64> = ok.iter().filter_map(|r| r.metrics.login_ms.filter(|ms| ms.is_finite())).collect();
    logins.sort_by(|a, b| a.total_cmp(b));
    let p95 = (!logins.is_empty()).then(|| logins[(logins.len() - 1).min(((logins.len() as f64) * 0.95).ceil() as usize - 1)]);
    Reachability { pct: Some(js_round((ok.len() as f64 / window.len() as f64) * 1000.0) / 10.0), login_p95: p95 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forecasts_when_a_growing_mount_fills_and_not_from_thin_or_flat_data() {
        let t0 = date_parse("2026-10-20T00:00:00Z");
        let at = |d: f64, pct: f64| ForecastPoint { at: t0 + d * DAY, pct };
        let growing: Vec<ForecastPoint> = (0..4).map(|d| at(f64::from(d), 80.0 + f64::from(d) * 2.0)).collect();
        assert_eq!(forecast_full(&growing), Some(Forecast { days: 7.0, per_day: 2.0 }));
        assert_eq!(forecast_full(&growing[..2]), None);
        assert_eq!(forecast_full(&[ForecastPoint { at: t0, pct: 50.0 }, ForecastPoint { at: t0 + 3_600_000.0, pct: 60.0 }, ForecastPoint { at: t0 + 7_200_000.0, pct: 70.0 }]), None);
        let flat: Vec<ForecastPoint> = (0..3).map(|d| at(f64::from(d), 70.0)).collect();
        assert_eq!(forecast_full(&flat), None);
        // Points older than the week no longer steer the line.
        let mut old = vec![at(-30.0, 10.0)];
        old.extend(flat);
        assert_eq!(forecast_full(&old), None);
        assert_eq!(forecast_full(&[]), None);
    }

    #[test]
    fn renders_trends_like_the_plugin() {
        let rows: Vec<HistoryRecord> = serde_json::from_str(include_str!("testdata/history.json")).unwrap();
        assert_eq!(render_trends(&rows).join("\n"), include_str!("testdata/trends.txt"));
        assert_eq!(render_trends(&rows[..1]), ["Trend: at least two successful inspections are required."]);
    }
}
