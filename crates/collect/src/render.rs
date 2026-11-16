//! Model-facing renderings shared by tools, tasks, and commands: fleet command output and the
//! fleet inspection.

use serde::{Deserialize, Serialize};

use crate::sections::format_kb;
use crate::types::FleetInspection;
use crate::util::{js_round, n, n_or, take_chars, to_fixed};

/// One finished remote command, as far as rendering needs it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub host: String,
    /// `ok`, `failed`, `unreachable`, `auth-failed`, `blocked`, `sudo-required`, `timeout` or `cancelled`.
    pub status: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub duration_ms: u64,
}

fn format_rate(bps: f64) -> String {
    if bps < 1024.0 { format!("{}B/s", n(js_round(bps))) } else { format!("{}/s", format_kb(bps / 1024.0)) }
}

fn status_line(r: &Run) -> String {
    let exit = r.exit_code.map_or_else(String::new, |code| format!(" exit {code}"));
    format!("{}{exit}, {}s{}", r.status, to_fixed(r.duration_ms as f64 / 1000.0, 1), if r.truncated { ", output truncated" } else { "" })
}

/// Render fleet output, folding hosts whose output and exit code are identical. Each host's stdout
/// and stderr are clipped to `per_host_chars` characters.
pub fn render_runs(results: &[Run], per_host_chars: usize) -> String {
    let mut groups: Vec<Vec<&Run>> = Vec::new();
    for r in results {
        match groups.iter_mut().find(|members| {
            let first = members[0];
            first.status == r.status && first.exit_code == r.exit_code && first.stdout == r.stdout && first.stderr == r.stderr
        }) {
            Some(members) => members.push(r),
            None => groups.push(vec![r]),
        }
    }
    let clip = |text: &str| {
        let length = text.chars().count();
        if length > per_host_chars { format!("{}\n… [{} more characters]", take_chars(text, per_host_chars), length - per_host_chars) } else { text.to_string() }
    };
    let mut blocks: Vec<String> = Vec::new();
    for members in &groups {
        let first = members[0];
        let names = members.iter().map(|m| m.host.as_str()).collect::<Vec<_>>().join(", ");
        let mut lines = vec![format!("### {names} — {}", status_line(first))];
        if !first.stdout.trim().is_empty() {
            lines.push(clip(first.stdout.trim_end()));
        }
        if !first.stderr.trim().is_empty() {
            lines.push(format!("[stderr]\n{}", clip(first.stderr.trim_end())));
        }
        if first.status == "sudo-required" {
            lines.push("Hint: sudo needs a password on this host. Configure sudoSecret to a Password Store entry, a NOPASSWD rule, or ask the user to run it.".to_string());
        }
        if first.status == "timeout" {
            lines.push("Hint: the local ssh was stopped; the remote command may still be running. Check before retrying.".to_string());
        }
        blocks.push(lines.join("\n"));
    }
    let counts: Vec<String> = ["ok", "failed", "unreachable", "auth-failed", "blocked", "sudo-required", "timeout", "cancelled"]
        .iter()
        .filter_map(|status| {
            let count = results.iter().filter(|r| r.status == *status).count();
            (count > 0).then(|| format!("{count} {status}"))
        })
        .collect();
    let mut parts = vec![format!("{} host(s): {}", results.len(), counts.join(", "))];
    parts.extend(blocks);
    parts.join("\n\n")
}

/// Render a fleet inspection; `detail` adds informational findings, processes, GPUs and disks.
pub fn render_inspection(fleet: &FleetInspection, detail: bool) -> String {
    let c = &fleet.counts;
    let mut lines = vec![format!("Fleet inspection {}: {} hosts — {} critical, {} warning, {} unreachable, {} healthy", fleet.at, fleet.hosts.len(), c.crit, c.warn, c.unreachable, c.ok + c.info)];
    for h in &fleet.hosts {
        let facts = match &h.report {
            None => h.error.clone().unwrap_or_else(|| h.status.clone()),
            Some(r) => [
                r.load.as_ref().map(|load| format!("load {}{}", n(load.m1), r.cores.map_or_else(String::new, |cores| format!("/{}c", n(cores))))),
                r.cpu_pct.map(|pct| format!("cpu {}%", n(pct))),
                r.mem.as_ref().map(|mem| format!("mem avail {}%", n(mem.avail_pct))),
                r.disks.iter().map(|d| d.use_pct).reduce(f64::max).map(|max| format!("disk max {}%", n(max))),
                (!r.gpus.is_empty()).then(|| format!("gpu {}", r.gpus.iter().map(|g| format!("{}%", n_or(g.util_pct, "?"))).collect::<Vec<_>>().join("/"))),
                r.slurm.as_ref().map(|slurm| format!("slurm {}", slurm.node_states.iter().map(|(state, count)| format!("{} {state}", n(*count))).collect::<Vec<_>>().join(", "))),
                r.login_ms.map(|ms| format!("login {} ms", n(ms))),
                r.ssh_failures_1h.map(|count| format!("{} failed ssh logins/h", n(count))),
                r.net.as_ref().map(|net| {
                    format!(
                        "net rx {} tx {}{}{}",
                        format_rate(net.rx_bps),
                        format_rate(net.tx_bps),
                        net.tcp_established.map_or_else(String::new, |tcp| format!(", {} tcp", n(tcp))),
                        net.tcp_retrans_pct.map_or_else(String::new, |pct| format!(" ({}% retrans)", n(pct)))
                    )
                }),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", "),
        };
        lines.push(format!("- {} [{}] {facts}", h.host, h.severity.to_uppercase()));
        for f in h.findings.iter().filter(|f| detail || f.severity != crate::inspect::Severity::Info) {
            lines.push(format!("    {}: {}{}", f.severity.as_str(), f.message, if f.muted { " (muted by the owner as known)" } else { "" }));
        }
        let Some(r) = h.report.as_ref().filter(|_| detail) else { continue };
        if !r.top_cpu.is_empty() {
            lines.push(format!("    top cpu: {}", r.top_cpu.iter().take(3).map(|p| format!("{}[{} {}] {}%", p.command, p.pid, p.user, n(p.cpu_pct))).collect::<Vec<_>>().join(", ")));
        }
        if !r.top_mem.is_empty() {
            lines.push(format!("    top mem: {}", r.top_mem.iter().take(3).map(|p| format!("{}[{} {}] {}%", p.command, p.pid, p.user, n(p.mem_pct))).collect::<Vec<_>>().join(", ")));
        }
        for g in &r.gpus {
            let pids = if g.processes.is_empty() { String::new() } else { format!(", pids {}", g.processes.iter().map(|p| p.pid.to_string()).collect::<Vec<_>>().join(" ")) };
            lines.push(format!("    gpu {} {}: {}% util, {}/{} MiB, {}°C{pids}", g.index, g.name, n_or(g.util_pct, "?"), n_or(g.mem_used_mb, "?"), n_or(g.mem_total_mb, "?"), n_or(g.temp_c, "?")));
        }
        if !r.kernel_error_samples.is_empty() {
            lines.push(format!("    recent kernel errors:\n{}", r.kernel_error_samples.iter().map(|l| format!("      {l}")).collect::<Vec<_>>().join("\n")));
        }
        for d in &r.disks {
            lines.push(format!("    {}: {}% of {}", d.mount, n(d.use_pct), format_kb(d.size_kb)));
        }
        if let Some(listeners) = r.listeners.as_ref().filter(|l| !l.is_empty()) {
            lines.push(format!("    listening: {}", listeners.join(", ")));
        }
        if let Some(sources) = r.login_sources.as_ref().filter(|l| !l.is_empty()) {
            lines.push(format!("    recent login sources: {}", sources.join(", ")));
        }
        if let Some(net) = r.net.as_ref().filter(|net| !net.interfaces.is_empty()) {
            lines.push(format!("    interfaces: {}", net.interfaces.iter().map(|i| format!("{} rx {} tx {}", i.name, format_rate(i.rx_bps), format_rate(i.tx_bps))).collect::<Vec<_>>().join(", ")));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_fleet_inspection_like_the_plugin() {
        let fleet: FleetInspection = serde_json::from_str(include_str!("testdata/fleet.json")).unwrap();
        assert_eq!(render_inspection(&fleet, true), include_str!("testdata/fleet.detail.txt"));
        assert_eq!(render_inspection(&fleet, false), include_str!("testdata/fleet.brief.txt"));
        crate::util::testing::assert_golden(&fleet, include_str!("testdata/fleet.json"));
    }

    #[test]
    fn folds_identical_runs_and_clips_output() {
        // The plugin writes a missing exit code as `null`.
        let runs: Vec<Run> = serde_json::from_str(include_str!("testdata/runs.json")).unwrap();
        assert_eq!(runs[3].exit_code, None);
        assert_eq!(render_runs(&runs, 20), include_str!("testdata/runs.txt"));
        assert_eq!(render_runs(&[], 20), "0 host(s): ");
    }
}
