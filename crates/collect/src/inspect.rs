//! Fleet inspection (巡检): one read-only round trip per host collects load, CPU, memory, disks,
//! inodes, failed units, top processes, GPUs, Slurm state, kernel errors, OOM kills and network
//! traffic; the runner adds the login latency. Thresholds turn them into findings, and the
//! previous inspection supplies growth trends.

use std::collections::{BTreeSet, HashSet};
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::sections::{FsUsage, InodeUsage, Sections, format_kb, num, num_opt, parse_df, parse_df_inodes, parse_sections};
use crate::service_checks::{ServiceKind, ServiceResult, parse_service_results};
use crate::trends::{ForecastPoint, forecast_full};
use crate::types::Thresholds;
use crate::util::{OrderedMap, date_parse, desc, fields, js_number, js_round, lenient_number, lenient_number_map, millis, n, split_ws, to_fixed, to_iso};

/// The inspection script; one run prints every section [`parse_inspection`] reads.
pub const INSPECT_SCRIPT: &str = include_str!("scripts/inspect.sh");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Crit,
    Warn,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Crit => "crit",
            Severity::Warn => "warn",
            Severity::Info => "info",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Severity::Crit => 2,
            Severity::Warn => 1,
            Severity::Info => 0,
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    /// What the finding is about when a server can have several: a mount or a checked service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Set on a fleet inspection's findings the owner muted; never stored in the history.
    #[serde(default, skip_serializing_if = "is_false")]
    pub muted: bool,
}

impl Finding {
    pub fn new(severity: Severity, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { severity, code: code.into(), message: message.into(), subject: None, muted: false }
    }

    /// The same finding about `subject`.
    pub fn about(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessSample {
    pub pid: i64,
    pub user: String,
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub elapsed_sec: f64,
    pub command: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuProcess {
    pub pid: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_mb: Option<f64>,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuSample {
    pub index: i64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub util_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_used_mb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_c: Option<f64>,
    #[serde(default)]
    pub processes: Vec<GpuProcess>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlurmNode {
    pub node: String,
    pub state: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlurmState {
    pub node_states: OrderedMap<f64>,
    pub problem_nodes: Vec<SlurmNode>,
    pub jobs: OrderedMap<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceRate {
    pub name: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

/// Traffic over the one-second sample; rates are bytes per second.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSample {
    /// Totals over interfaces backed by a device, or every interface but `lo` when none is.
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub interfaces: Vec<InterfaceRate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_established: Option<f64>,
    /// Retransmitted share of TCP segments sent during the sample; absent when too few were sent to tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_retrans_pct: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Load {
    pub m1: f64,
    pub m5: f64,
    pub m15: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_core: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Memory {
    pub total_kb: f64,
    pub avail_kb: f64,
    pub avail_pct: f64,
    pub swap_total_kb: f64,
    pub swap_used_pct: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInspection {
    /// Milliseconds from starting ssh until the remote shell answered, measured locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cores: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_sec: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<Load>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem: Option<Memory>,
    #[serde(default)]
    pub disks: Vec<FsUsage>,
    #[serde(default)]
    pub inodes: Vec<InodeUsage>,
    #[serde(default)]
    pub failed_units: Vec<String>,
    #[serde(default)]
    pub top_cpu: Vec<ProcessSample>,
    #[serde(default)]
    pub top_mem: Vec<ProcessSample>,
    #[serde(default)]
    pub gpus: Vec<GpuSample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slurm: Option<SlurmState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zombies: Option<f64>,
    #[serde(rename = "oom24h", default, skip_serializing_if = "Option::is_none")]
    pub oom_24h: Option<f64>,
    #[serde(rename = "kernelErrors24h", default, skip_serializing_if = "Option::is_none")]
    pub kernel_errors_24h: Option<f64>,
    #[serde(default)]
    pub kernel_error_samples: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reboot_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp_synced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetworkSample>,
    /// Non-loopback TCP listeners as `address:port`, `*` for every address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listeners: Option<Vec<String>>,
    /// Distinct `user@address` of recent logins with a pty, from wtmp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_sources: Option<Vec<String>>,
    /// Failed SSH logins in the last hour, when the login user may read the sshd journal.
    #[serde(rename = "sshFailures1h", default, skip_serializing_if = "Option::is_none")]
    pub ssh_failures_1h: Option<f64>,
    /// Owner-listed service checks, when the host has any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ServiceResult>>,
}

/// Compact metrics kept per inspection for trends. Numbers a damaged file turned into something
/// else read as absent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectionMetrics {
    pub at: String,
    #[serde(default, deserialize_with = "lenient_number_map")]
    pub disk_pct: OrderedMap<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub mem_avail_pct: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub load1: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub login_ms: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub rx_bps: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub tx_bps: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub tcp_established: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub tcp_retrans_pct: Option<f64>,
    /// Mean utilization, memory used across all GPUs, and the hottest GPU.
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub gpu_util_pct: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub gpu_mem_pct: Option<f64>,
    #[serde(default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub gpu_temp_c: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listeners: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_sources: Option<Vec<String>>,
    #[serde(rename = "sshFailures1h", default, deserialize_with = "lenient_number", skip_serializing_if = "Option::is_none")]
    pub ssh_failures_1h: Option<f64>,
}

/// Earlier inspections whose listeners and login sources count as already seen.
const SEEN_WINDOW: usize = 50;
/// Fewer TCP segments sent in the sample than this make a retransmit share meaningless.
const MIN_RETRANS_SAMPLE: f64 = 100.0;

static IGNORED_MOUNT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/(?:proc|sys|dev|run|snap)(?:/|$)|^/boot/efi$").unwrap());
const IGNORED_FS_TYPE: [&str; 9] = ["tmpfs", "devtmpfs", "overlay", "squashfs", "efivarfs", "proc", "sysfs", "nsfs", "autofs"];
static NET_COUNTER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*([^\s:|]+):\s*(.*)$").unwrap());
static INTEGER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-?[0-9]+$").unwrap());
static LISTENER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.*):([0-9]+)$").unwrap());
static MEMINFO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\w+):\s+([0-9]+)").unwrap());
static SQUEUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*([0-9]+)\s+(\S+)").unwrap());

fn parse_processes(lines: &[String]) -> Vec<ProcessSample> {
    lines
        .iter()
        .filter_map(|line| {
            let f = fields(line);
            let pid = num(f[0])?;
            let user = f.get(1)?;
            let field = |index: usize| num_opt(f.get(index).copied()).unwrap_or(0.0);
            Some(ProcessSample { pid: pid as i64, user: user.to_string(), cpu_pct: field(2), mem_pct: field(3), elapsed_sec: field(4), command: f.get(5..).unwrap_or(&[]).join(" ") })
        })
        .collect()
}

fn cpu_busy_pct(lines: &[String]) -> Option<f64> {
    let parse = |line: Option<&String>| line.map(|l| fields(l).into_iter().skip(1).map(js_number).collect::<Vec<f64>>());
    let (a, b) = (parse(lines.first())?, parse(lines.get(1))?);
    if a.len() < 4 || b.len() < 4 {
        return None;
    }
    let idle = |v: &[f64]| v[3] + v.get(4).copied().unwrap_or(0.0);
    let total = |v: &[f64]| v.iter().filter(|x| x.is_finite()).sum::<f64>();
    let dt = total(&b) - total(&a);
    if dt.is_nan() || dt <= 0.0 {
        return None;
    }
    let pct = js_round(((dt - (idle(&b) - idle(&a))) / dt) * 1000.0) / 10.0;
    pct.is_finite().then_some(pct)
}

/// Receive and transmit byte counters per interface from /proc/net/dev, in file order.
fn net_counters(lines: &[String]) -> Vec<(String, f64, f64)> {
    let mut counters: Vec<(String, f64, f64)> = Vec::new();
    for line in lines {
        let Some(m) = NET_COUNTER.captures(line) else { continue };
        let f: Vec<f64> = fields(&m[2]).into_iter().map(js_number).collect();
        if f.len() >= 9 && f[0].is_finite() && f[8].is_finite() {
            match counters.iter_mut().find(|(name, ..)| name == &m[1]) {
                Some(entry) => (entry.1, entry.2) = (f[0], f[8]),
                None => counters.push((m[1].to_string(), f[0], f[8])),
            }
        }
    }
    counters
}

/// The `Tcp:` header/value line pairs of /proc/net/snmp, in sample order.
fn tcp_samples(lines: &[String]) -> Vec<Vec<(String, f64)>> {
    let mut samples = Vec::new();
    let mut i = 0;
    while i + 1 < lines.len() {
        let names: Vec<&str> = split_ws(&lines[i]).into_iter().skip(1).collect();
        let values: Vec<&str> = split_ws(&lines[i + 1]).into_iter().skip(1).collect();
        if names.is_empty() || names.iter().any(|name| INTEGER.is_match(name)) || values.iter().any(|value| !INTEGER.is_match(value)) {
            i += 1;
            continue;
        }
        samples.push(names.iter().enumerate().map(|(j, name)| (name.to_string(), values.get(j).map_or(f64::NAN, |v| js_number(v)))).collect());
        i += 2;
    }
    samples
}

fn tcp_value(sample: &[(String, f64)], name: &str) -> Option<f64> {
    // A repeated column keeps its last value, as a JavaScript Map does.
    sample.iter().rev().find(|(key, _)| key == name).map(|(_, value)| *value)
}

fn parse_network(dev: &[String], physical: &[String], tcp: &[String]) -> Option<NetworkSample> {
    let split = dev.iter().position(|line| line == "--");
    let before = net_counters(split.map_or(&[], |at| &dev[..at]));
    let after = net_counters(split.map_or(&[], |at| &dev[at + 1..]));
    let rate = |a: f64, b: f64| (b - a).max(0.0);
    let interfaces: Vec<InterfaceRate> = after
        .iter()
        .filter_map(|(name, rx, tx)| before.iter().find(|(earlier, ..)| earlier == name).map(|(_, rx0, tx0)| InterfaceRate { name: name.clone(), rx_bps: rate(*rx0, *rx), tx_bps: rate(*tx0, *tx) }))
        .collect();
    let samples = tcp_samples(tcp);
    let (t0, t1) = (samples.first(), samples.get(1));
    if interfaces.is_empty() && t1.is_none() {
        return None;
    }
    let devices: HashSet<&str> = physical.iter().map(|path| path.rsplit('/').next().unwrap_or(path)).collect();
    let backed = interfaces.iter().any(|i| devices.contains(i.name.as_str()));
    let counted: Vec<&InterfaceRate> = interfaces.iter().filter(|i| if backed { devices.contains(i.name.as_str()) } else { i.name != "lo" }).collect();
    let established = t1.and_then(|t| tcp_value(t, "CurrEstab")).filter(|v| v.is_finite());
    let delta = |name: &str| match (t0, t1) {
        (Some(t0), Some(t1)) => tcp_value(t1, name).unwrap_or(0.0) - tcp_value(t0, name).unwrap_or(0.0),
        _ => 0.0,
    };
    let (sent, retrans) = (delta("OutSegs"), delta("RetransSegs"));
    let mut listed: Vec<InterfaceRate> = interfaces.iter().filter(|i| i.name != "lo").cloned().collect();
    listed.sort_by(|a, b| desc(a.rx_bps + a.tx_bps, b.rx_bps + b.tx_bps));
    listed.truncate(8);
    Some(NetworkSample {
        rx_bps: counted.iter().map(|i| i.rx_bps).sum(),
        tx_bps: counted.iter().map(|i| i.tx_bps).sum(),
        interfaces: listed,
        tcp_established: established,
        tcp_retrans_pct: (sent >= MIN_RETRANS_SAMPLE && retrans >= 0.0).then(|| js_round((retrans / sent) * 1000.0) / 10.0),
    })
}

/// `address:port` of non-loopback TCP listeners from `ss`/`netstat` local addresses.
fn parse_listeners(lines: &[String]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for line in lines {
        let Some(m) = LISTENER.captures(line.trim()) else { continue };
        let raw = &m[1];
        let raw = raw.strip_prefix('[').unwrap_or(raw);
        let raw = raw.strip_suffix(']').unwrap_or(raw);
        let mut address = raw.split('%').next().unwrap_or(raw);
        if matches!(address, "" | "*" | "0.0.0.0" | "::") {
            address = "*";
        }
        if address.starts_with("127.") || matches!(address, "::1" | "localhost" | "::ffff:127.0.0.1") {
            continue;
        }
        out.insert(format!("{address}:{}", &m[2]));
    }
    out.into_iter().take(64).collect()
}

fn count_states(lines: &[String]) -> OrderedMap<f64> {
    let mut states: OrderedMap<f64> = OrderedMap::new();
    for line in lines {
        let mut cells = line.split('|');
        let state = cells.next().unwrap_or("");
        if !state.is_empty() {
            let total = states.get(state).copied().unwrap_or(0.0) + num_opt(cells.next()).unwrap_or(0.0);
            states.insert(state, total);
        }
    }
    states
}

fn parse_gpus(s: &Sections) -> Vec<GpuSample> {
    let apps: Vec<Vec<&str>> = s.get("gpuapps").iter().map(|line| line.split(',').map(str::trim).collect()).collect();
    s.get("gpu")
        .iter()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(',').map(str::trim).collect();
            let index = num(f[0])?;
            let name = f.get(2)?;
            let uuid = f[1];
            let pick = |at: usize| num_opt(f.get(at).copied());
            Some(GpuSample {
                index: index as i64,
                name: name.to_string(),
                util_pct: pick(3),
                mem_used_mb: pick(4),
                mem_total_mb: pick(5),
                temp_c: pick(6),
                processes: apps
                    .iter()
                    .filter(|app| app[0] == uuid)
                    .filter_map(|app| Some(GpuProcess { pid: num_opt(app.get(1).copied())? as i64, mem_mb: num_opt(app.get(2).copied()), name: app.get(3).copied().unwrap_or("").to_string() }))
                    .collect(),
            })
        })
        .collect()
}

/// Parse the inspection script's output.
pub fn parse_inspection(output: &str) -> HostInspection {
    let s = parse_sections(output);
    let mut kv: OrderedMap<String> = OrderedMap::new();
    for line in s.get("kv") {
        if let Some(eq) = line.find('=').filter(|eq| *eq > 0) {
            kv.insert(&line[..eq], line[eq + 1..].trim().to_string());
        }
    }
    let value = |key: &str| kv.get(key).map(String::as_str);
    let non_empty = |key: &str| value(key).filter(|v| !v.is_empty()).map(str::to_string);
    let number = |key: &str| num_opt(value(key));
    let cores = number("cores");
    let load_fields: Vec<f64> = split_ws(value("loadavg").unwrap_or("")).into_iter().map(js_number).collect();
    let load = (load_fields.len() >= 3 && load_fields[..3].iter().all(|v| v.is_finite())).then(|| Load {
        m1: load_fields[0],
        m5: load_fields[1],
        m15: load_fields[2],
        per_core: cores.filter(|c| *c != 0.0).map(|c| js_round((load_fields[0] / c) * 100.0) / 100.0),
    });

    let mut meminfo: OrderedMap<f64> = OrderedMap::new();
    for line in s.get("meminfo") {
        if let Some(m) = MEMINFO.captures(line) {
            meminfo.insert(&m[1], js_number(&m[2]));
        }
    }
    let swap_total_kb = meminfo.get("SwapTotal").copied().unwrap_or(0.0);
    let swap_free_kb = meminfo.get("SwapFree").copied().unwrap_or(0.0);
    let mem = match (meminfo.get("MemTotal").copied(), meminfo.get("MemAvailable").copied()) {
        (Some(total_kb), Some(avail_kb)) if total_kb > 0.0 => Some(Memory {
            total_kb,
            avail_kb,
            avail_pct: js_round((avail_kb / total_kb) * 1000.0) / 10.0,
            swap_total_kb,
            swap_used_pct: if swap_total_kb > 0.0 { js_round(((swap_total_kb - swap_free_kb) / swap_total_kb) * 1000.0) / 10.0 } else { 0.0 },
        }),
        _ => None,
    };

    let disks = parse_df(s.get("df")).into_iter().filter(|fs| !IGNORED_MOUNT.is_match(&fs.mount) && !IGNORED_FS_TYPE.contains(&fs.fs_type.as_deref().unwrap_or("")) && fs.size_kb > 0.0).collect();
    let inodes = parse_df_inodes(s.get("dfi")).into_iter().filter(|fs| !IGNORED_MOUNT.is_match(&fs.mount)).collect();

    let slurm_lines = s.get("slurm");
    let slurm = (!slurm_lines.is_empty() || !s.get("squeue").is_empty()).then(|| SlurmState {
        node_states: count_states(slurm_lines),
        problem_nodes: s
            .get("slurmbad")
            .iter()
            .filter_map(|line| {
                let mut cells = line.split('|');
                let (node, state) = (cells.next()?, cells.next()?);
                Some(SlurmNode { node: node.to_string(), state: state.to_string(), reason: cells.collect::<Vec<_>>().join("|") })
            })
            .collect(),
        jobs: s.get("squeue").iter().filter_map(|line| SQUEUE.captures(line).map(|m| (m[2].to_string(), js_number(&m[1])))).collect(),
    });

    let ntp = value("ntp");
    let login_sources = s.has("logins").then(|| {
        let sources: BTreeSet<String> = s
            .get("logins")
            .iter()
            .filter_map(|line| {
                let f = fields(line);
                let (user, address) = (f.first().filter(|u| !u.is_empty())?, f.get(1).filter(|a| !a.is_empty())?);
                Some(format!("{user}@{address}"))
            })
            .collect();
        sources.into_iter().collect::<Vec<String>>()
    });
    HostInspection {
        login_ms: None,
        hostname: non_empty("hostname"),
        os: non_empty("os"),
        kernel: non_empty("kernel"),
        cores,
        uptime_sec: number("uptime").map(js_round),
        load,
        cpu_pct: cpu_busy_pct(s.get("cpu")),
        mem,
        disks,
        inodes,
        failed_units: s.get("failed").to_vec(),
        top_cpu: parse_processes(s.get("topcpu")),
        top_mem: parse_processes(s.get("topmem")),
        gpus: parse_gpus(&s),
        slurm,
        zombies: number("zombies"),
        oom_24h: number("oom_24h"),
        kernel_errors_24h: number("kerr_24h"),
        kernel_error_samples: s.get("kerr").to_vec(),
        reboot_required: value("reboot_required").map(|v| v == "yes"),
        ntp_synced: matches!(ntp, Some("yes" | "no")).then(|| ntp == Some("yes")),
        net: parse_network(s.get("netdev"), s.get("netphys"), s.get("tcp")),
        listeners: s.has("listen").then(|| parse_listeners(s.get("listen"))),
        login_sources,
        ssh_failures_1h: number("sshfail_1h"),
        services: s.has("svc").then(|| parse_service_results(s.get("svc"))),
    }
}

/// Compact metrics for the trend history; GPU figures are rounded fleet-level values.
pub fn metrics_of(report: &HostInspection, at: DateTime<Utc>) -> InspectionMetrics {
    let gpus = &report.gpus;
    let util: Vec<f64> = gpus.iter().filter_map(|g| g.util_pct).collect();
    let sized: Vec<(f64, f64)> = gpus.iter().filter_map(|g| Some((g.mem_used_mb?, g.mem_total_mb.filter(|total| *total > 0.0)?))).collect();
    let temps: Vec<f64> = gpus.iter().filter_map(|g| g.temp_c).collect();
    let total: f64 = sized.iter().map(|(_, total)| total).sum();
    InspectionMetrics {
        at: to_iso(at),
        disk_pct: report.disks.iter().map(|d| (d.mount.as_str(), d.use_pct)).collect(),
        mem_avail_pct: report.mem.as_ref().map(|m| m.avail_pct),
        load1: report.load.as_ref().map(|l| l.m1),
        cpu_pct: report.cpu_pct,
        login_ms: report.login_ms,
        rx_bps: report.net.as_ref().map(|net| net.rx_bps),
        tx_bps: report.net.as_ref().map(|net| net.tx_bps),
        tcp_established: report.net.as_ref().and_then(|net| net.tcp_established),
        tcp_retrans_pct: report.net.as_ref().and_then(|net| net.tcp_retrans_pct),
        gpu_util_pct: (!util.is_empty()).then(|| js_round((util.iter().sum::<f64>() / util.len() as f64) * 10.0) / 10.0),
        gpu_mem_pct: (total != 0.0).then(|| js_round((sized.iter().map(|(used, _)| used).sum::<f64>() / total) * 1000.0) / 10.0),
        gpu_temp_c: temps.iter().copied().reduce(f64::max),
        listeners: report.listeners.clone(),
        login_sources: report.login_sources.clone(),
        ssh_failures_1h: report.ssh_failures_1h,
    }
}

/// What earlier inspections saw, or `None` before any of them recorded the field (the first run is a baseline).
fn seen<'a>(history: &[&'a InspectionMetrics], read: impl Fn(&'a InspectionMetrics) -> Option<&'a Vec<String>>) -> Option<HashSet<&'a str>> {
    let rows: Vec<&Vec<String>> = history.iter().filter_map(|row| read(row)).collect();
    if rows.is_empty() {
        return None;
    }
    Some(rows[rows.len().saturating_sub(SEEN_WINDOW)..].iter().flat_map(|row| row.iter().map(String::as_str)).collect())
}

fn listed(items: &[String], more: bool) -> String {
    format!("{}{}", items.join(", "), if more { " …" } else { "" })
}

/// Turn an inspection into findings, comparing against the previous one when present. `history`
/// (successful inspections, oldest first; empty when there is none) and `at` feed the disk-full
/// forecast, and the history says which listeners and login sources are new.
pub fn evaluate(report: &HostInspection, t: &Thresholds, previous: Option<&InspectionMetrics>, history: &[&InspectionMetrics], at: DateTime<Utc>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut add = |severity: Severity, code: &str, message: String, subject: Option<&str>| {
        let finding = Finding::new(severity, code, message);
        findings.push(match subject {
            Some(subject) => finding.about(subject),
            None => finding,
        });
    };

    for disk in &report.disks {
        let mount = disk.mount.as_str();
        let detail = format!("{mount} {}% used ({} free of {})", n(disk.use_pct), format_kb(disk.avail_kb), format_kb(disk.size_kb));
        if disk.use_pct >= t.disk_crit_pct {
            add(Severity::Crit, "disk-full", detail, Some(mount));
        } else if disk.use_pct >= t.disk_warn_pct {
            add(Severity::Warn, "disk-high", detail, Some(mount));
        }
        if let Some(previous) = previous
            && let Some(before) = previous.disk_pct.get(mount)
            && disk.use_pct - before >= t.disk_growth_warn_pts
        {
            add(Severity::Warn, "disk-growth", format!("{mount} grew {}% → {}% since {}", n(*before), n(disk.use_pct), previous.at), Some(mount));
        }
        if t.disk_full_forecast_days > 0.0 && !history.is_empty() {
            let mut points: Vec<ForecastPoint> = history.iter().filter_map(|r| r.disk_pct.get(mount).map(|pct| ForecastPoint { at: date_parse(&r.at), pct: *pct })).collect();
            points.push(ForecastPoint { at: millis(at), pct: disk.use_pct });
            if let Some(forecast) = forecast_full(&points).filter(|f| f.days <= t.disk_full_forecast_days) {
                let when = if forecast.days < 1.0 { "less than a day".to_string() } else { format!("about {} days", n(js_round(forecast.days))) };
                add(Severity::Warn, "disk-forecast", format!("{mount} grows {} points a day and fills in {when}", to_fixed(forecast.per_day, 1)), Some(mount));
            }
        }
    }
    for inode in &report.inodes {
        let detail = format!("{} inodes {}% used", inode.mount, n(inode.use_pct));
        if inode.use_pct >= t.inode_crit_pct {
            add(Severity::Crit, "inodes-full", detail, Some(&inode.mount));
        } else if inode.use_pct >= t.inode_warn_pct {
            add(Severity::Warn, "inodes-high", detail, Some(&inode.mount));
        }
    }
    if let Some(m) = &report.mem {
        let detail = format!("memory available {}% ({} of {})", n(m.avail_pct), format_kb(m.avail_kb), format_kb(m.total_kb));
        if m.avail_pct <= t.mem_avail_crit_pct {
            add(Severity::Crit, "memory-low", detail, None);
        } else if m.avail_pct <= t.mem_avail_warn_pct {
            add(Severity::Warn, "memory-low", detail, None);
        }
        if m.swap_used_pct >= t.swap_warn_pct {
            add(Severity::Warn, "swap-high", format!("swap {}% used", n(m.swap_used_pct)), None);
        }
    }
    if let Some(load) = &report.load
        && let Some(per_core) = load.per_core
    {
        let detail = format!("load {}/{}/{} on {} cores ({} per core)", n(load.m1), n(load.m5), n(load.m15), report.cores.map_or_else(|| "undefined".to_string(), n), n(per_core));
        if per_core >= t.load_per_core_crit {
            add(Severity::Crit, "load-high", detail, None);
        } else if per_core >= t.load_per_core_warn {
            add(Severity::Warn, "load-high", detail, None);
        }
    }
    if !report.failed_units.is_empty() {
        add(Severity::Warn, "units-failed", format!("failed systemd units: {}", report.failed_units.join(", ")), None);
    }
    if report.zombies.unwrap_or(0.0) >= t.zombie_warn {
        add(Severity::Warn, "zombies", format!("{} zombie processes", report.zombies.map_or_else(|| "undefined".to_string(), n)), None);
    }
    if let Some(count) = report.oom_24h.filter(|count| *count > 0.0) {
        add(Severity::Warn, "oom-kills", format!("{} OOM-killer messages in the last 24h", n(count)), None);
    }
    if let Some(count) = report.kernel_errors_24h.filter(|count| *count > 0.0) {
        add(Severity::Info, "kernel-errors", format!("{} kernel error lines in the last 24h", n(count)), None);
    }
    for gpu in &report.gpus {
        if let Some(temp) = gpu.temp_c.filter(|temp| *temp >= t.gpu_temp_warn_c) {
            add(Severity::Warn, "gpu-hot", format!("GPU {} at {}°C", gpu.index, n(temp)), None);
        }
        if let (Some(util), Some(used), Some(total)) = (gpu.util_pct, gpu.mem_used_mb, gpu.mem_total_mb)
            && util == 0.0
            && total > 0.0
            && used / total > 0.5
        {
            let pids: Vec<String> = gpu.processes.iter().map(|p| p.pid.to_string()).collect();
            let pids = if pids.is_empty() { "unknown".to_string() } else { pids.join(", ") };
            add(Severity::Info, "gpu-idle-held", format!("GPU {} holds {}/{} MiB at 0% utilization (pids {pids})", gpu.index, n(used), n(total)), None);
        }
    }
    if let Some(slurm) = report.slurm.as_ref().filter(|slurm| !slurm.problem_nodes.is_empty()) {
        let nodes: Vec<String> = slurm.problem_nodes.iter().take(10).map(|node| format!("{} {}{}", node.node, node.state, if node.reason.is_empty() { String::new() } else { format!(" ({})", node.reason) })).collect();
        add(Severity::Warn, "slurm-nodes", format!("Slurm nodes need attention: {}{}", nodes.join("; "), if slurm.problem_nodes.len() > 10 { " …" } else { "" }), None);
    }
    if t.login_warn_ms > 0.0
        && let Some(login_ms) = report.login_ms.filter(|ms| *ms >= t.login_warn_ms)
    {
        add(Severity::Warn, "login-slow", format!("SSH login took {} s", to_fixed(login_ms / 1000.0, 1)), None);
    }
    if t.tcp_retrans_warn_pct > 0.0
        && let Some(pct) = report.net.as_ref().and_then(|net| net.tcp_retrans_pct).filter(|pct| *pct >= t.tcp_retrans_warn_pct)
    {
        add(Severity::Warn, "tcp-retrans", format!("{}% of TCP segments were retransmitted during the sample", n(pct)), None);
    }
    if let Some(known) = seen(history, |row| row.listeners.as_ref()) {
        let opened: Vec<String> = report.listeners.iter().flatten().filter(|l| !known.contains(l.as_str())).cloned().collect();
        if !opened.is_empty() {
            add(Severity::Warn, "port-new", format!("new listening TCP ports: {}", listed(&opened[..opened.len().min(10)], opened.len() > 10)), None);
        }
    }
    if let Some(familiar) = seen(history, |row| row.login_sources.as_ref()) {
        let arrived: Vec<String> = report.login_sources.iter().flatten().filter(|l| !familiar.contains(l.as_str())).map(|l| l.replacen('@', " from ", 1)).collect();
        if !arrived.is_empty() {
            add(Severity::Warn, "login-new-source", format!("new login sources: {}", listed(&arrived[..arrived.len().min(10)], arrived.len() > 10)), None);
        }
    }
    if t.ssh_fail_warn_per_hour > 0.0
        && let Some(count) = report.ssh_failures_1h.filter(|count| *count >= t.ssh_fail_warn_per_hour)
    {
        add(Severity::Warn, "ssh-failures", format!("{} failed SSH logins in the last hour", n(count)), None);
    }
    for service in report.services.iter().flatten().filter(|service| !service.ok) {
        let detail = match service.kind {
            ServiceKind::Unit => format!("{} is {}", service.target, if service.result.is_empty() { "unknown" } else { &service.result }),
            ServiceKind::Port => format!("port {} is not listening", service.target),
            ServiceKind::Http => format!("{} answered {}", service.target, if service.result == "000" || service.result.is_empty() { "nothing" } else { &service.result }),
        };
        add(Severity::Crit, "service-down", detail, Some(&service.target));
    }
    if report.ntp_synced == Some(false) {
        add(Severity::Warn, "ntp-unsynced", "system clock is not NTP-synchronized".to_string(), None);
    }
    if report.reboot_required == Some(true) {
        add(Severity::Info, "reboot-required", "a package update requires a reboot".to_string(), None);
    }
    findings
}

/// The most severe finding level, or `None` ("ok") when there are none above info.
pub fn worst_severity<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> Option<Severity> {
    findings.into_iter().map(|f| f.severity).filter(|s| *s != Severity::Info).max_by_key(|s| s.rank())
}

/// The name of a [`worst_severity`] result: `crit`, `warn` or `ok`.
pub fn severity_label(worst: Option<Severity>) -> &'static str {
    worst.map_or("ok", Severity::as_str)
}

/// Findings ordered critical first, keeping their order within a level.
pub fn sort_findings(findings: &[Finding]) -> Vec<Finding> {
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testing::assert_golden;

    const INSPECT: &str = include_str!("testdata/inspect.txt");

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().to_utc()
    }

    fn now() -> DateTime<Utc> {
        at("2026-10-29T00:00:00Z")
    }

    fn codes(findings: &[Finding]) -> Vec<String> {
        findings.iter().map(|f| format!("{}:{}", f.severity.as_str(), f.code)).collect()
    }

    fn metrics(at: &str, disks: &[(&str, f64)]) -> InspectionMetrics {
        InspectionMetrics { at: at.into(), disk_pct: disks.iter().copied().collect(), ..Default::default() }
    }

    #[test]
    fn carries_the_script_over_unchanged() {
        assert!(INSPECT_SCRIPT.starts_with("export LC_ALL=C\necho @@kv\n"));
        assert!(INSPECT_SCRIPT.ends_with("echo @@end\n"));
        assert!(INSPECT_SCRIPT.contains(r#"last -i -w -n 100 2>/dev/null | awk 'NF>=3 && $1!="reboot" && $1!="shutdown" && $1!="wtmp" && $3!="0.0.0.0" {print $1" "$3}' | sort -u | head -n 32"#));
    }

    #[test]
    fn parses_through_banners_and_probes() {
        let report = parse_inspection(INSPECT);
        assert_eq!(report.hostname.as_deref(), Some("gpu-01"));
        assert_eq!(report.load, Some(Load { m1: 60.1, m5: 55.0, m15: 40.0, per_core: Some(1.88) }));
        assert_eq!(report.cpu_pct, Some(90.0));
        assert_eq!(report.mem.as_ref().map(|m| (m.avail_pct, m.swap_used_pct)), Some((4.0, 75.0)));
        assert_eq!(report.disks.iter().map(|d| d.mount.as_str()).collect::<Vec<_>>(), ["/", "/data"]);
        assert_eq!(report.inodes, [InodeUsage { mount: "/".into(), use_pct: 2.0 }]);
        let gpu = &report.gpus[0];
        assert_eq!((gpu.index, gpu.util_pct, gpu.temp_c), (0, Some(98.0), Some(87.0)));
        assert_eq!(gpu.processes, [GpuProcess { pid: 4242, mem_mb: Some(79000.0), name: "python".into() }]);
        let slurm = report.slurm.as_ref().unwrap();
        assert_eq!(slurm.node_states.iter().collect::<Vec<_>>(), [("mixed", &3.0), ("drained", &1.0)]);
        assert_eq!(slurm.problem_nodes, [SlurmNode { node: "gpu-02".into(), state: "drained".into(), reason: "Kill task failed".into() }]);
        assert_eq!(slurm.jobs.iter().collect::<Vec<_>>(), [("RUNNING", &12.0), ("PENDING", &3.0)]);
        assert_eq!(report.ntp_synced, Some(false));
    }

    #[test]
    fn matches_the_plugin_report_findings_and_metrics() {
        let mut report = parse_inspection(&format!("{INSPECT}@@svc\nunit\tredis\tfailed\nport\t8080\tclosed\nhttp\thttps://h/x\t000\nhttp\thttps://h/ok\t204\n"));
        report.login_ms = Some(4200.0);
        assert_golden(&report, include_str!("testdata/inspect.report.json"));
        assert_eq!(serde_json::from_str::<HostInspection>(include_str!("testdata/inspect.report.json")).unwrap(), report);
        let history: Vec<InspectionMetrics> = [3.0, 2.0, 1.0]
            .iter()
            .map(|d| InspectionMetrics {
                at: to_iso(now() - chrono::Duration::days(*d as i64)),
                disk_pct: [("/", 95.0 - d * 0.5), ("/data", 74.0)].into_iter().collect(),
                mem_avail_pct: Some(10.0 + d),
                listeners: Some(vec!["*:22".into(), "10.0.0.5:9100".into()]),
                login_sources: Some(vec!["alice@10.0.0.9".into()]),
                ..Default::default()
            })
            .collect();
        let refs: Vec<&InspectionMetrics> = history.iter().collect();
        let thresholds = Thresholds { disk_full_forecast_days: 14.0, ..Thresholds::default() };
        let findings = sort_findings(&evaluate(&report, &thresholds, history.last(), &refs, now()));
        assert_golden(&findings, include_str!("testdata/inspect.findings.json"));
        assert_golden(&metrics_of(&report, now()), include_str!("testdata/inspect.metrics.json"));
    }

    #[test]
    fn turns_thresholds_and_trends_into_findings() {
        let report = parse_inspection(INSPECT);
        let previous = metrics("2026-10-25T00:00:00.000Z", &[("/", 85.0), ("/data", 80.0)]);
        let findings = evaluate(&report, &Thresholds::default(), Some(&previous), &[], now());
        let codes = codes(&findings);
        for expected in [
            "crit:disk-full", "warn:disk-high", "warn:disk-growth", "crit:memory-low", "warn:swap-high", "warn:load-high", "warn:units-failed", "warn:zombies", "warn:oom-kills", "info:kernel-errors",
            "warn:gpu-hot", "info:gpu-idle-held", "warn:slurm-nodes", "warn:ntp-unsynced", "info:reboot-required",
        ] {
            assert!(codes.iter().any(|c| c == expected), "{expected} missing from {codes:?}");
        }
        assert_eq!(findings.iter().filter(|f| f.code == "disk-growth").map(|f| f.subject.as_deref()).collect::<Vec<_>>(), [Some("/")]);
        assert_eq!(worst_severity(&findings), Some(Severity::Crit));
        assert_eq!(severity_label(worst_severity(&[Finding::new(Severity::Info, "x", "y")])), "ok");
    }

    #[test]
    fn measures_traffic_on_device_backed_interfaces_and_tcp_over_the_sample() {
        let report = parse_inspection(INSPECT);
        // Bridges, veths and bonds have no backing device, so container traffic is not counted twice.
        let rate = |name: &str, rx_bps: f64, tx_bps: f64| InterfaceRate { name: name.into(), rx_bps, tx_bps };
        assert_eq!(
            report.net,
            Some(NetworkSample {
                rx_bps: 524_288.0 + 100_000.0,
                tx_bps: 1024.0 + 100.0,
                interfaces: vec![rate("docker0", 5_000_000.0, 5_000_000.0), rate("eth0", 524_288.0, 1024.0), rate("eth1", 100_000.0, 100.0)],
                tcp_established: Some(42.0),
                tcp_retrans_pct: Some(10.0),
            })
        );
        // Without device information every interface but loopback counts; too few segments give no retransmit share.
        let bare = parse_inspection(&INSPECT.replace("@@netphys\n/sys/class/net/eth0\n/sys/class/net/eth1\n", "").replace("10300 20400 140", "10300 20050 101"));
        let net = bare.net.unwrap();
        assert_eq!((net.rx_bps, net.tcp_established, net.tcp_retrans_pct), (5_000_000.0 + 524_288.0 + 100_000.0, Some(42.0), None));
        assert_eq!(parse_inspection("@@kv\nhostname=x\n@@end\n").net, None);
    }

    #[test]
    fn records_public_listeners_login_sources_and_failed_logins_and_flags_what_is_new() {
        let report = parse_inspection(INSPECT);
        assert_eq!(report.listeners.as_deref().unwrap(), ["*:22", "*:6379", "*:8888", "10.0.0.5:9100"]);
        assert_eq!(report.login_sources.as_deref().unwrap(), ["alice@10.0.0.9", "root@203.0.113.7"]);
        assert_eq!(report.ssh_failures_1h, Some(240.0));
        let message = |code: &str, history: &[InspectionMetrics]| {
            let refs: Vec<&InspectionMetrics> = history.iter().collect();
            evaluate(&report, &Thresholds::default(), None, &refs, now()).into_iter().find(|f| f.code == code).map(|f| f.message)
        };
        // Without earlier data the first inspection is the baseline.
        assert_eq!(message("port-new", &[]), None);
        assert_eq!(message("port-new", &[metrics("2026-10-28T00:00:00Z", &[])]), None);
        let seen = |at: &str, listeners: &[&str], sources: &[&str]| InspectionMetrics {
            listeners: Some(listeners.iter().map(|s| s.to_string()).collect()),
            login_sources: Some(sources.iter().map(|s| s.to_string()).collect()),
            ..metrics(at, &[])
        };
        let before = [seen("2026-10-28T00:00:00Z", &["*:22", "10.0.0.5:9100"], &["alice@10.0.0.9"]), seen("2026-10-28T01:00:00Z", &["*:22", "*:8888"], &[])];
        assert_eq!(message("port-new", &before).as_deref(), Some("new listening TCP ports: *:6379"));
        assert_eq!(message("login-new-source", &before).as_deref(), Some("new login sources: root from 203.0.113.7"));
        assert_eq!(message("ssh-failures", &[]).as_deref(), Some("240 failed SSH logins in the last hour"));
        let quiet = Thresholds { ssh_fail_warn_per_hour: 0.0, ..Thresholds::default() };
        assert!(!evaluate(&report, &quiet, None, &[], now()).iter().any(|f| f.code == "ssh-failures"));
        let m = metrics_of(&report, now());
        assert_eq!((m.listeners, m.login_sources, m.ssh_failures_1h), (report.listeners.clone(), report.login_sources.clone(), Some(240.0)));
        // A host without the sections records nothing, rather than an empty set that would make everything look new later.
        let empty = parse_inspection("@@kv\n@@end\n");
        assert_eq!(empty.listeners, None);
        assert!(serde_json::to_value(&empty).unwrap().get("listeners").is_none());
    }

    #[test]
    fn warns_when_a_disk_will_fill_within_the_forecast_window() {
        let report = parse_inspection(INSPECT);
        let history: Vec<InspectionMetrics> = [3.0, 2.0, 1.0].iter().map(|d| metrics(&to_iso(now() - chrono::Duration::days(*d as i64)), &[("/", 95.0 - d * 0.5), ("/data", 80.0)])).collect();
        let refs: Vec<&InspectionMetrics> = history.iter().collect();
        let messages = |t: Thresholds| evaluate(&report, &t, history.last(), &refs, now()).into_iter().filter(|f| f.code == "disk-forecast").map(|f| f.message).collect::<Vec<_>>();
        // Ten days away is outside the default seven-day window.
        assert!(messages(Thresholds::default()).is_empty());
        assert_eq!(messages(Thresholds { disk_full_forecast_days: 14.0, ..Thresholds::default() }), ["/ grows 0.5 points a day and fills in about 10 days"]);
        assert!(messages(Thresholds { disk_full_forecast_days: 0.0, ..Thresholds::default() }).is_empty());
    }

    #[test]
    fn warns_about_a_slow_login_and_retransmits_and_keeps_network_metrics() {
        let report = parse_inspection(INSPECT);
        let slow = HostInspection { login_ms: Some(4200.0), ..report.clone() };
        let found = codes(&evaluate(&slow, &Thresholds::default(), None, &[], now()));
        assert!(found.contains(&"warn:login-slow".to_string()) && found.contains(&"warn:tcp-retrans".to_string()));
        let fast = HostInspection { login_ms: Some(800.0), ..report.clone() };
        assert!(!evaluate(&fast, &Thresholds::default(), None, &[], now()).iter().any(|f| f.code == "login-slow"));
        let off = Thresholds { login_warn_ms: 0.0, tcp_retrans_warn_pct: 0.0, ..Thresholds::default() };
        assert!(!evaluate(&slow, &off, None, &[], now()).iter().any(|f| f.code == "login-slow" || f.code == "tcp-retrans"));
        let m = metrics_of(&slow, now());
        assert_eq!((m.login_ms, m.rx_bps, m.tx_bps, m.tcp_established, m.tcp_retrans_pct), (Some(4200.0), Some(624_288.0), Some(1124.0), Some(42.0), Some(10.0)));
        // Two A100s: mean utilization, memory used across both, and the hotter one.
        assert_eq!((m.gpu_util_pct, m.gpu_mem_pct, m.gpu_temp_c), (Some(49.0), Some(90.9), Some(87.0)));
    }

    #[test]
    fn turns_failing_checks_into_critical_findings_about_each_service() {
        let report = parse_inspection("@@kv\n@@svc\nunit\tredis\tfailed\nport\t8080\tclosed\nhttp\thttps://h/x\t000\n@@end\n");
        let down: Vec<(Severity, Option<String>, String)> = evaluate(&report, &Thresholds::default(), None, &[], now()).into_iter().filter(|f| f.code == "service-down").map(|f| (f.severity, f.subject, f.message)).collect();
        assert_eq!(down, [
            (Severity::Crit, Some("redis".to_string()), "redis is failed".to_string()),
            (Severity::Crit, Some("8080".to_string()), "port 8080 is not listening".to_string()),
            (Severity::Crit, Some("https://h/x".to_string()), "https://h/x answered nothing".to_string()),
        ]);
    }
}
