//! The fleet as the window and the assistant use it: the engine
//! (`wisp_ops_engine`: inventory, SSH, permissions, vault, audit) and the
//! collectors (`wisp_ops_collect`) put together. Everything that reaches a
//! server blocks, so the window calls it from the background executor.
//!
//! Authorization is settled before this layer (`tools::gate`, or a task's
//! own definition); what is here executes and records. Every remote command,
//! whoever asked for it, goes through `Fleet::execute` and so into the audit.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use wisp_ops_collect::inspect::{self, Finding, Severity};
use wisp_ops_collect::mutes::{self, Mute};
use wisp_ops_collect::probe::HostProbe;
use wisp_ops_collect::render::{self, Run};
use wisp_ops_collect::service_checks::{self, ServiceCheck};
use wisp_ops_collect::{FleetCounts, FleetInspection, HistoryRecord, HostInspectionResult, Thresholds, attacks, disk, files, security, space, trends, util};
use wisp_ops_engine::config::{self, AuthMethod, Capability, Config, HostSpec, Permission, Playbook, PolicySpec, TaskSchedule, TaskSpec};
use wisp_ops_engine::inventory::{Host, Inventory};
use wisp_ops_engine::managed::{CredentialBinding, ManagedState, managed_store};
use wisp_ops_engine::policy::{DenyList, GrantStore, NewGrant};
use wisp_ops_engine::risk::{self, RiskLevel};
use wisp_ops_engine::ssh::{RunRequest, RunResult, RunStatus, SshRunner};
use wisp_ops_engine::store::{AuditEntry, AuditFilter, Authorization, OpsStore};
use wisp_ops_engine::vault::{CredentialInput, FileKey, LocalVault};
use wisp_ops_engine::{schedule, ssh_config, time};

// ---- what the pages draw

#[derive(Clone, Debug, Default)]
pub struct FindingView {
    pub severity: String,
    pub message: String,
    pub muted: bool,
}

/// One inspection of a server, as the overview's square and the detail panel show it.
#[derive(Clone, Debug, Default)]
pub struct RunView {
    pub at: String,
    /// `ok`, `info`, `warn`, `crit` or `unreachable`.
    pub state: String,
    pub findings: Vec<FindingView>,
    pub disk_max: Option<(String, f64)>,
    /// Every mount and how full it was, as inspected.
    pub disks: Vec<(String, f64)>,
    pub cpu_pct: Option<f64>,
    /// Mean utilisation, memory used across all GPUs, and the hottest GPU.
    pub gpu_util_pct: Option<f64>,
    pub gpu_mem_pct: Option<f64>,
    pub gpu_temp_c: Option<f64>,
    pub mem_avail_pct: Option<f64>,
    pub load1: Option<f64>,
    pub login_ms: Option<f64>,
}

impl RunView {
    /// The fullest mount, the memory left, the load and the login time, in a line.
    pub fn metrics_line(&self) -> Option<String> {
        let mut parts = vec![];
        if let Some((mount, pct)) = &self.disk_max { parts.push(format!("{mount} {pct:.0}%")) }
        if let Some(pct) = self.mem_avail_pct { parts.push(tf!("可用内存 {pct:.0}%", "mem free {pct:.0}%")) }
        if let Some(load) = self.load1 { parts.push(tf!("负载 {load:.2}", "load {load:.2}")) }
        if let Some(ms) = self.login_ms { parts.push(tf!("登录 {ms:.0} ms", "login {ms:.0} ms")) }
        (!parts.is_empty()).then(|| parts.join(" · "))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProbeView {
    pub os: String,
    pub arch: String,
    pub cores: String,
    pub gpus: u32,
    pub scheduler: String,
    pub privilege: String,
    pub docker: String,
    pub at: String,
}

impl ProbeView {
    pub fn line(&self) -> String {
        let mut parts = vec![self.os.clone(), tf!("{} 核", "{} cores", self.cores)];
        if self.gpus > 0 { parts.push(format!("{} GPU", self.gpus)) }
        if self.scheduler != "none" { parts.push(self.scheduler.clone()) }
        parts.join(" · ")
    }
}

#[derive(Clone, Debug, Default)]
pub struct HostView {
    pub name: String,
    /// `user@host:port` as shown.
    pub address: String,
    pub ssh: String,
    pub user: String,
    pub port: Option<u16>,
    pub groups: Vec<String>,
    pub description: String,
    pub jump: String,
    pub identity: String,
    /// Added in the window (or taken from ssh_config): it can be edited and removed here.
    pub managed: bool,
    /// The effective permission of change, sudo, destructive.
    pub policy: [String; 3],
    /// What the window set for this host; empty inherits.
    pub policy_own: [String; 3],
    pub policy_inherited: [String; 3],
    pub login_secret: String,
    pub sudo_secret: String,
    pub probe: Option<ProbeView>,
    pub blocked_until: Option<String>,
    /// The latest inspections, the oldest first.
    pub runs: Vec<RunView>,
}

impl HostView {
    /// The state of the latest inspection; `none` without one.
    pub fn state(&self) -> &str {
        self.runs.last().map_or("none", |run| run.state.as_str())
    }

    pub fn source_label(&self) -> &'static str {
        if self.managed { "在这里添加" } else { "inventory.yml" }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CredentialView {
    pub name: String,
    pub username: String,
    pub note: String,
    pub agent: bool,
}

/// A task as its form holds it.
#[derive(Clone, Debug, Default)]
pub struct TaskDraft {
    pub name: String,
    pub description: String,
    pub targets: String,
    pub playbook: String,
    pub paths: Vec<String>,
    pub instruction: String,
    pub commands: Vec<String>,
    /// `manual`, `daily` or `every`.
    pub schedule: String,
    pub daily: String,
    pub every_minutes: u32,
    pub sudo: bool,
}

#[derive(Clone, Debug, Default)]
pub struct TaskLast {
    pub at: String,
    pub problems: bool,
    pub summary: String,
}

#[derive(Clone, Debug, Default)]
pub struct TaskView {
    pub name: String,
    pub draft: TaskDraft,
    pub managed: bool,
    /// It has a time the timer can keep (daily or an interval; cron is not kept).
    pub scheduled: bool,
    pub enabled: bool,
    pub when: String,
    pub next: Option<String>,
    pub last: Option<TaskLast>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct AuditRow {
    pub at: String,
    pub host: String,
    pub tool: String,
    pub risk: String,
    pub sudo: bool,
    pub authorization: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub command: String,
    pub reason: String,
    pub duration_ms: u64,
}

impl AuditRow {
    /// The whole record, for the dialog a row opens.
    pub fn detail(&self) -> String {
        format!("time      {}\nhost      {}\nsource    {}\nrisk      {}{}\nauthorized {}\nresult    {}{}\nduration  {} ms{}\n\n{}", self.at, self.host, self.tool, self.risk, if self.sudo { " + sudo" } else { "" }, self.authorization, self.status, self.exit_code.map(|code| format!(" (exit {code})")).unwrap_or_default(), self.duration_ms, if self.reason.is_empty() { String::new() } else { format!("\nreason    {}", self.reason) }, self.command)
    }
}

#[derive(Clone, Debug, Default)]
pub struct HostDraft {
    pub name: String,
    pub ssh: String,
    pub user: String,
    pub port: Option<u16>,
    pub groups: Vec<String>,
    pub jump: String,
    pub identity: String,
    pub description: String,
}

#[derive(Default)]
pub struct View {
    pub hosts: Vec<HostView>,
    pub credentials: Vec<CredentialView>,
    pub tasks: Vec<TaskView>,
    pub audit: Vec<AuditRow>,
    /// The latest check for long-running tasks of each server that has one.
    pub long_runs: BTreeMap<String, wisp_ops_collect::longrun::LongRunSnapshot>,
    /// The latest security triage of each server that has one.
    pub attacks: BTreeMap<String, attacks::SecuritySnapshot>,
    pub inventory_error: Option<String>,
    pub vault_error: Option<String>,
    pub vault_key_place: &'static str,
    pub limits: Limits,
}

/// The thresholds the meters and charts are coloured by: (warning, critical).
#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    pub disk: (f64, f64),
    pub gpu_temp: f64,
    /// Of the memory still available: lower is worse.
    pub mem_avail: (f64, f64),
    pub load_per_core: (f64, f64),
}

/// The inspections of a server the pages keep at hand.
const RUNS_KEPT: usize = 30;

/// A serde word of an enum (`sudo-nopasswd`, `read-only`).
fn word<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value).ok().and_then(|value| value.as_str().map(String::from)).unwrap_or_default()
}

// ---- the fleet

/// How one execution is recorded.
#[derive(Clone)]
pub struct Exec {
    pub sudo: bool,
    pub timeout_ms: u64,
    pub max_output_bytes: Option<usize>,
    pub tool: String,
    pub session: Option<String>,
    pub risk: RiskLevel,
    pub authorization: Authorization,
    pub reason: Option<String>,
    /// What the audit says in place of the script: a built-in collector's name, a change's plan.
    pub audit_command: Option<String>,
    pub time_login: bool,
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Exec {
    pub fn read(tool: &str, authorization: Authorization) -> Exec {
        Exec { sudo: false, timeout_ms: 60_000, max_output_bytes: None, tool: tool.to_string(), session: None, risk: RiskLevel::Read, authorization, reason: None, audit_command: None, time_login: false, cancel: None }
    }
}

/// The options the built-in collectors share.
#[derive(Clone)]
pub struct Collect {
    pub sudo: bool,
    pub tool: String,
    pub session: Option<String>,
    pub authorization: Authorization,
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Collect {
    fn exec(&self, timeout_ms: u64, command: &str) -> Exec {
        Exec { sudo: self.sudo, timeout_ms, max_output_bytes: None, tool: self.tool.clone(), session: self.session.clone(), risk: RiskLevel::Read, authorization: self.authorization, reason: None, audit_command: Some(command.to_string()), time_login: false, cancel: self.cancel.clone() }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskRunRecord {
    pub at: String,
    pub hosts: Vec<String>,
    pub playbook: String,
    /// Problems found, by kind.
    pub counts: BTreeMap<String, f64>,
    /// Head of the collected data, for "what changed since last time".
    pub excerpt: String,
}

const PROBLEM_KEYS: [&str; 5] = ["warn", "crit", "unreachable", "incomplete", "commandFailed"];

impl TaskRunRecord {
    pub fn has_problems(&self) -> bool {
        PROBLEM_KEYS.iter().any(|key| self.counts.get(*key).is_some_and(|count| *count > 0.))
    }

    pub fn summary(&self) -> String {
        let counts: Vec<String> = self.counts.iter().map(|(key, value)| format!("{key}={value}")).collect();
        if counts.is_empty() { "no findings".into() } else { counts.join(", ") }
    }
}

/// Which tasks the window's timer runs, and since when.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct TimerState {
    tasks: BTreeMap<String, TimerEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimerEntry {
    enabled_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

struct Loaded {
    inventory: Inventory,
    /// Why the files could not be read the last time; the inventory is then the one before.
    error: Option<String>,
    stamp: String,
    managed_names: HashSet<String>,
    managed_tasks: HashSet<String>,
}

pub struct Fleet {
    root: PathBuf,
    pub config: Config,
    loaded: RwLock<Loaded>,
    pub runner: SshRunner,
    pub store: OpsStore,
    vault: LocalVault,
    grants: GrantStore,
    pub deny: DenyList,
    pub thresholds: Thresholds,
    pub extra_read: HashSet<String>,
    /// The hosts a managed change is running on.
    changing: Mutex<HashSet<String>>,
    timer: Mutex<()>,
}

const REPORT_GUIDE: &str = "Report format (use the user's language):\n1. One status line: overall healthy / needs attention / urgent, with the count of affected hosts.\n2. What changed since the previous run (new problems, resolved problems, growth), if a previous run exists.\n3. Findings by severity, each with host, evidence (numbers, paths, processes), and likely cause.\n4. Recommended actions, ordered by urgency, each marked read-only check / change needing approval.\nKeep it short; put long lists in an appendix.";

impl Fleet {
    /// Open the data folder: `config.json` (optional overrides), `inventory.yml`, `managed.json`, the vault and the stores.
    pub fn open(root: &Path) -> Fleet {
        let _ = std::fs::create_dir_all(root);
        let mut overrides = std::fs::read_to_string(root.join("config.json")).ok().and_then(|text| serde_json::from_str::<Value>(&text).ok()).filter(Value::is_object).unwrap_or_else(|| serde_json::json!({}));
        overrides["dataDir"] = Value::String(root.to_string_lossy().into_owned());
        let config = Config::resolve(overrides).unwrap_or_else(|_| Config::resolve(serde_json::json!({"dataDir": root.to_string_lossy()})).unwrap_or_default());
        let thresholds: Thresholds = serde_json::from_value(config.thresholds.clone()).unwrap_or_default();
        let runner = SshRunner::new(config.ssh.clone(), config.limits.max_output_bytes as usize, root);
        let store = OpsStore::new(root, (&config.retention).into());
        // `WISP_OPS_VAULT_KEY=file` keeps the vault's key beside it instead of in the system's key store: for tests and scripted runs.
        let vault = if std::env::var("WISP_OPS_VAULT_KEY").as_deref() == Ok("file") { LocalVault::with_key_provider(root, Box::new(FileKey::default())) } else { LocalVault::new(root) };
        let deny = DenyList::compile(&config.deny_patterns).unwrap_or_else(|_| DenyList::compile(&config::default_deny_patterns()).expect("built-in deny list"));
        let extra_read = config.extra_read_programs.iter().cloned().collect();
        let empty = Inventory::from_specs(vec![], BTreeMap::new(), config.default_policy).expect("empty inventory");
        let fleet = Fleet { root: root.to_path_buf(), config, loaded: RwLock::new(Loaded { inventory: empty, error: None, stamp: String::new(), managed_names: HashSet::new(), managed_tasks: HashSet::new() }), runner, store, vault, grants: GrantStore::new(), deny, thresholds, extra_read, changing: Mutex::new(HashSet::new()), timer: Mutex::new(()) };
        fleet.refresh();
        fleet
    }

    pub fn data_dir(&self) -> &Path {
        &self.root
    }

    fn stamp(&self) -> String {
        let of = |path: PathBuf| std::fs::metadata(&path).ok().map(|meta| format!("{:?}:{}", meta.modified().ok(), meta.len())).unwrap_or_else(|| "missing".into());
        format!("{}|{}", of(self.root.join("managed.json")), self.config.inventory_file.as_ref().map(|file| of(PathBuf::from(wisp_ops_engine::fsutil::expand_home(file)))).unwrap_or_default())
    }

    /// Read the inventory again when its files changed; true when it did. A
    /// broken edit keeps the inventory as it was and is said on the servers' page.
    pub fn refresh(&self) -> bool {
        let stamp = self.stamp();
        if self.loaded.read().unwrap().stamp == stamp { return false }
        self.reload_inventory();
        true
    }

    fn reload_inventory(&self) {
        let stamp = self.stamp();
        let managed = managed_store(&self.root).read().map(|read| read.value);
        let loaded = managed.and_then(|state| Inventory::load(&self.config, &[], Some(&state)).map(|inventory| (inventory, state)));
        let mut now = self.loaded.write().unwrap();
        now.stamp = stamp;
        match loaded {
            Ok((inventory, state)) => {
                now.inventory = inventory;
                now.error = None;
                now.managed_names = state.hosts.iter().map(|host| host.name.clone()).collect();
                now.managed_tasks = state.tasks.iter().map(|task| task.name.clone()).collect();
            }
            Err(error) => now.error = Some(error),
        }
    }

    pub fn inventory(&self) -> Inventory {
        self.loaded.read().unwrap().inventory.clone()
    }

    /// Resolve a selector and keep to the largest fleet one call may address.
    pub fn select(&self, selector: &str) -> Result<Vec<Host>, String> {
        let inventory = self.inventory();
        if inventory.hosts().is_empty() { return Err("the inventory is empty; the user adds servers on the Servers page".into()) }
        let hosts = inventory.select(selector)?;
        if hosts.is_empty() { return Err(format!("selector \"{selector}\" matches no hosts")) }
        let limit = self.config.limits.max_targets as usize;
        if hosts.len() > limit { return Err(format!("selector \"{selector}\" matches {} hosts; the limit is {limit} (limits.maxTargets)", hosts.len())) }
        Ok(hosts)
    }

    pub fn select_names(&self, selector: &str) -> Result<Vec<String>, String> {
        Ok(self.select(selector)?.into_iter().map(|host| host.name).collect())
    }

    pub fn clamp_timeout(&self, timeout_ms: Option<u64>) -> u64 {
        timeout_ms.unwrap_or(self.config.limits.default_timeout_ms).clamp(1000, self.config.limits.max_timeout_ms)
    }

    fn mutes_of(host: &Host) -> Vec<Mute> {
        host.mutes.as_ref().and_then(|value| mutes::validate_mutes(value).ok()).unwrap_or_default()
    }

    fn checks_of(&self, host: &Host) -> (Vec<ServiceCheck>, Vec<ServiceCheck>) {
        let all = host.service_checks.as_ref().and_then(|value| service_checks::validate_checks(value).ok()).unwrap_or_default();
        // The deny list has the last word over owner-listed checks too.
        all.into_iter().partition(|check| self.deny.matches(&service_checks::check_line(check)).is_none())
    }

    // ---- executing

    /// Run one script on each host (or one built per host), recording every attempt in the audit.
    pub fn execute(&self, hosts: &[Host], script: &(dyn Fn(&Host) -> String + Sync), exec: &Exec) -> Vec<RunResult> {
        let results = self.runner.run_many_with(hosts, |host| {
            let sudo_credential = if exec.sudo { self.vault.sudo_credential(host)? } else { None };
            let sudo_password = sudo_credential.as_ref().map(|credential| credential.password.clone());
            let sudo_account = sudo_credential.as_ref().map(|credential| credential.username.trim().to_string()).filter(|name| !name.is_empty());
            if let Some(account) = &sudo_account && !account.chars().enumerate().all(|(n, c)| c.is_ascii_alphanumeric() || c == '_' || (n > 0 && matches!(c, '.' | '-'))) {
                return Err("sudo 凭据的用户名格式不正确，请在密码库中填写实际系统账号，或留空沿用 SSH 登录账号。".into());
            }
            // A sudo credential of another account logs in as that account for this run only: the inventory name and permissions stay.
            let alternate = match &sudo_account {
                Some(account) => Some(account).filter(|account| self.runner.login_user(host).ok().as_ref() != Some(*account)),
                None => None,
            };
            let connection = match alternate {
                Some(account) => Host { user: Some(account.clone()), auth: Some(AuthMethod::Password), ..host.clone() },
                None => host.clone(),
            };
            let login_password = if alternate.is_some() { sudo_password.clone() } else if host.uses_password() { self.vault.login_password(host)? } else { None };
            let mut request = RunRequest::new(connection, script(host)).sudo(exec.sudo).sudo_password(sudo_password).login_password(login_password).timeout_ms(exec.timeout_ms).time_login(exec.time_login);
            if let Some(cancel) = &exec.cancel { request = request.cancel(cancel.clone()) }
            if let Some(limit) = exec.max_output_bytes { request = request.max_output_bytes(limit) }
            Ok(request)
        });
        let at = time::to_iso(time::now_ms());
        for (host, result) in hosts.iter().zip(&results) {
            let command = exec.audit_command.clone().unwrap_or_else(|| {
                let text = script(host);
                if text.chars().count() > 4000 { format!("{}…", text.chars().take(4000).collect::<String>()) } else { text }
            });
            let _ = self.store.audit(&AuditEntry { at: at.clone(), session: exec.session.clone(), tool: exec.tool.clone(), host: result.host.clone(), risk: exec.risk, sudo: exec.sudo, authorization: exec.authorization, command, reason: exec.reason.clone(), status: result.status, exit_code: result.exit_code, duration_ms: result.duration_ms });
        }
        results
    }

    /// The same command on every host.
    pub fn execute_one(&self, hosts: &[Host], script: &str, exec: &Exec) -> Vec<RunResult> {
        self.execute(hosts, &|_| script.to_string(), exec)
    }

    /// Inspect a fleet, turn thresholds and trends into findings, and write the history.
    pub fn inspect_hosts(&self, hosts: &[Host], options: &Collect, audit_command: &str) -> FleetInspection {
        let script = |host: &Host| service_checks::with_service_checks(inspect::INSPECT_SCRIPT, &self.checks_of(host).0);
        let mut exec = options.exec(self.clamp_timeout(Some(self.config.ssh.connect_timeout_sec * 1000 + 45_000)), audit_command);
        exec.time_login = true;
        let results = self.execute(hosts, &script, &exec);
        let now = Utc::now();
        let at = time::to_iso(time::now_ms());
        let mut counts = FleetCounts::default();
        let mut out = vec![];
        for (host, result) in hosts.iter().zip(results) {
            // The collector tolerates individual probe failures, so a non-zero exit with output is still usable.
            let usable = matches!(result.status, RunStatus::Ok | RunStatus::Failed) && result.stdout.contains("@@end");
            if !usable {
                let ran = matches!(result.status, RunStatus::Ok | RunStatus::Failed);
                let error: String = if !result.stderr.trim().is_empty() { result.stderr.trim().chars().take(500).collect() } else if ran { "connected but the inspection produced no result: a restricted shell, a forced command, or a login script that exits early".into() } else { format!("inspection {}", result.status.as_str()) };
                let status = if result.status == RunStatus::Ok { "failed" } else { result.status.as_str() };
                let record = serde_json::json!({"at": at, "diskPct": {}, "status": status, "findings": [{"severity": "crit", "code": "unreachable", "message": error}]});
                let _ = self.store.append_history(&host.name, &record);
                counts.unreachable += 1;
                out.push(HostInspectionResult { host: host.name.clone(), status: result.status.as_str().into(), severity: "unreachable".into(), findings: vec![Finding::new(Severity::Crit, if ran { "no-output" } else { result.status.as_str() }, error.clone())], report: None, error: Some(error), duration_ms: result.duration_ms });
                continue;
            }
            let mut report = inspect::parse_inspection(&result.stdout);
            if let Some(ms) = result.first_output_ms { report.login_ms = Some(ms as f64) }
            let history: Vec<HistoryRecord> = self.store.read_history::<HistoryRecord>(&host.name, trends::STATS_ROWS).unwrap_or_default().into_iter().filter(HistoryRecord::is_ok).collect();
            let metrics: Vec<&inspect::InspectionMetrics> = history.iter().map(|record| &record.metrics).collect();
            let mut thresholds = self.thresholds.clone();
            if let Some(Value::Object(overrides)) = &host.threshold_override && let Ok(Value::Object(mut merged)) = serde_json::to_value(&thresholds) {
                merged.extend(overrides.clone());
                thresholds = serde_json::from_value(Value::Object(merged)).unwrap_or(thresholds);
            }
            let mut found = inspect::evaluate(&report, &thresholds, metrics.last().copied(), &metrics, now);
            found.extend(self.checks_of(host).1.iter().map(|check| Finding::new(Severity::Warn, "service-check-refused", format!("service check {} was not run: the deny list refuses it", service_checks::describe_check(check))).about(service_checks::describe_check(check))));
            let findings = inspect::sort_findings(&found);
            let _ = self.store.append_history(&host.name, &HistoryRecord { metrics: inspect::metrics_of(&report, now), status: "ok".into(), findings: findings.clone() });
            // The history keeps every finding; what the owner muted is marked for the reader and does not set the severity.
            let muted = Self::mutes_of(host);
            let now_ms = util::millis(now);
            let marked: Vec<Finding> = findings.into_iter().map(|mut finding| { finding.muted = mutes::mute_for(&finding, &muted, now_ms).is_some(); finding }).collect();
            let severity = inspect::worst_severity(marked.iter().filter(|finding| !finding.muted));
            match severity {
                Some(Severity::Crit) => counts.crit += 1,
                Some(Severity::Warn) => counts.warn += 1,
                Some(Severity::Info) => counts.info += 1,
                None => counts.ok += 1,
            }
            out.push(HostInspectionResult { host: host.name.clone(), status: "ok".into(), severity: severity.map_or("ok", Severity::as_str).into(), findings: marked, report: Some(report), error: None, duration_ms: result.duration_ms });
        }
        FleetInspection { at, hosts: out, counts }
    }

    /// Probe what the hosts are and remember it. Key hosts never prompt, so this is safe fleet-wide.
    pub fn probe_hosts(&self, hosts: &[Host], tool: &str, session: Option<String>, cancel: Option<Arc<AtomicBool>>) -> Vec<(String, Result<HostProbe, String>)> {
        let mut exec = Exec::read(tool, Authorization::ReadOnly);
        exec.timeout_ms = self.clamp_timeout(Some(self.config.ssh.connect_timeout_sec * 1000 + 20_000));
        exec.session = session;
        exec.cancel = cancel;
        exec.audit_command = Some("(built-in read-only capability probe)".into());
        let results = self.execute_one(hosts, wisp_ops_collect::probe::PROBE_SCRIPT, &exec);
        let now = Utc::now();
        let mut update = BTreeMap::new();
        let out = results.into_iter().map(|result| {
            let probe = if result.status == RunStatus::Ok { wisp_ops_collect::probe::parse_probe(&result.stdout, now) } else { None };
            match probe {
                Some(probe) => {
                    update.insert(result.host.clone(), probe.clone());
                    (result.host, Ok(probe))
                }
                None => {
                    let error: String = if result.stderr.trim().is_empty() { format!("{}: connected but the probe produced no result (restricted shell or forced command?)", result.status.as_str()) } else { result.stderr.trim().chars().take(300).collect() };
                    (result.host, Err(error))
                }
            }
        }).collect();
        if !update.is_empty() { let _ = self.store.save_probes(&update); }
        out
    }

    /// Diagnose one filesystem and keep a snapshot for the next comparison.
    pub fn disk(&self, host: &Host, options: &disk::DiskOptions, collect: &Collect) -> (Option<disk::DiskReport>, RunResult) {
        let path = if options.path.len() > 1 { options.path.trim_end_matches('/').to_string() } else { options.path.clone() };
        let previous: Option<disk::DiskSnapshot> = self.store.disk_snapshot(&host.name, &path).ok().flatten();
        let exec = collect.exec(self.clamp_timeout(Some((options.walk_timeout_sec * 3 + 30) * 1000 + self.config.ssh.connect_timeout_sec * 1000)), &format!("(built-in read-only disk diagnosis of {})", options.path));
        let result = self.execute_one(std::slice::from_ref(host), &disk::disk_script(options), &exec).remove(0);
        if !result.stdout.contains("@@end") { return (None, result) }
        let diagnosis = disk::parse_disk(&result.stdout, options, previous.as_ref(), Utc::now());
        if let Some(snapshot) = &diagnosis.snapshot { let _ = self.store.save_disk_snapshot(&host.name, snapshot); }
        (Some(diagnosis.report), result)
    }

    /// Recent-file analysis on one host, compared with the previous scan of the same roots and window.
    pub fn files(&self, host: &Host, options: &files::FilesOptions, collect: &Collect) -> (Option<files::FilesReport>, RunResult) {
        let key = format!("{}|{}", options.paths.join(","), options.days);
        let previous = self.store.read_bounded::<Value>("files", &host.name).unwrap_or_default().into_iter().rev().find(|row| row["key"] == key.as_str()).and_then(|row| serde_json::from_value::<files::FilesSnapshot>(row).ok());
        let mut exec = collect.exec(self.clamp_timeout(Some((options.walk_timeout_sec * (options.paths.len() as u64 + 1) + 60) * 1000)), &format!("(built-in read-only recent-file analysis of {})", options.paths.join(",")));
        exec.max_output_bytes = Some(8 << 20);
        let result = self.execute_one(std::slice::from_ref(host), &files::files_script(options), &exec).remove(0);
        if !result.stdout.contains("@@end") { return (None, result) }
        let scan = files::parse_files(&result.stdout, options, previous.as_ref(), Utc::now());
        if let Ok(mut row) = serde_json::to_value(&scan.snapshot) {
            row["key"] = Value::String(key);
            let _ = self.store.append_bounded("files", &host.name, &row, 60);
        }
        (Some(scan.report), result)
    }

    /// Directory sizes under one path, kept with the previous scan of the same path for growth.
    pub fn space(&self, host: &Host, options: &space::SpaceOptions, collect: &Collect) -> (Option<(space::SpaceReport, Option<space::SpaceSnapshot>)>, RunResult) {
        let options = space::SpaceOptions { path: space::normalize_root(&options.path).to_string(), ..options.clone() };
        let previous = self.store.read_bounded::<space::SpaceSnapshot>("space", &host.name).unwrap_or_default().into_iter().rev().find(|snapshot| snapshot.report.path == options.path);
        let mut exec = collect.exec(self.clamp_timeout(Some((options.walk_timeout_sec + 60) * 1000 + self.config.ssh.connect_timeout_sec * 1000)), &format!("(built-in read-only directory sizes of {})", options.path));
        exec.max_output_bytes = Some(2 << 20);
        let result = self.execute_one(std::slice::from_ref(host), &space::space_script(&options), &exec).remove(0);
        if !result.stdout.contains("@@end") { return (None, result) }
        let report = space::parse_space(&result.stdout, &options);
        let _ = self.store.append_bounded("space", &host.name, &space::SpaceSnapshot { report: report.clone(), at: time::to_iso(time::now_ms()) }, 24);
        (Some((report, previous)), result)
    }

    /// Security triage on a set of hosts, with the login attacks counted in the same run; what
    /// was found is kept for the security page, whoever asked.
    pub fn security(&self, hosts: &[Host], hours: u32, collect: &Collect) -> Vec<(String, Option<security::SecurityReport>, RunResult)> {
        let options = security::SecurityOptions { hours };
        let mut exec = collect.exec(self.clamp_timeout(Some(90_000 + self.config.ssh.connect_timeout_sec * 1000)), "(built-in read-only security triage)");
        exec.max_output_bytes = Some(2 << 20);
        let at = time::to_iso(time::now_ms());
        self.execute_one(hosts, &attacks::attack_script(&options), &exec).into_iter().map(|result| {
            let report = result.stdout.contains("@@end").then(|| security::parse_security(&result.stdout, &options));
            if let Some(report) = &report { let _ = self.store.append_bounded("security", &result.host, &attacks::SecuritySnapshot { at: at.clone(), hours, report: report.clone(), attacks: attacks::parse_attacks(&result.stdout, Utc::now()) }, 5); }
            (result.host.clone(), report, result)
        }).collect()
    }

    // ---- what the window does itself (read-only, no sudo)

    /// Probe the selected servers and say what came of it.
    pub fn probe(&self, selector: &str) -> Result<String, String> {
        let hosts = self.select(selector)?;
        let results = self.probe_hosts(&hosts, "window:probe", None, None);
        let failed: Vec<String> = results.iter().filter_map(|(host, result)| result.as_ref().err().map(|error| format!("{host}: {error}"))).collect();
        if failed.is_empty() { Ok(tf!("已探测 {} 台服务器", "Probed {} servers", results.len())) } else { Err(tf!("探测失败：{}", "Probe failed: {}", failed.join("；"))) }
    }

    /// Inspect the selected servers into the history. `origin` is `window` or `auto`.
    pub fn inspect(&self, selector: &str, origin: &str) -> Result<String, String> {
        let hosts = self.select(selector)?;
        let collect = Collect { sudo: false, tool: format!("window:{origin}"), session: None, authorization: Authorization::ReadOnly, cancel: None };
        let fleet = self.inspect_hosts(&hosts, &collect, "(built-in read-only inspection)");
        let c = &fleet.counts;
        Ok(tf!("巡检完成：正常 {}，警告 {}，严重 {}，不可达 {}", "Inspected: {} ok, {} warning, {} critical, {} unreachable", c.ok + c.info, c.warn, c.crit, c.unreachable))
    }

    /// The servers whose last inspection is older than `minutes` (or that have none).
    pub fn inspection_due(&self, minutes: u32) -> Vec<String> {
        let cutoff = time::now_ms() - i64::from(minutes) * 60_000;
        self.inventory().hosts().iter().filter(|host| {
            let last = self.store.read_history::<Value>(&host.name, 1).ok().and_then(|rows| rows.last().and_then(|row| row["at"].as_str().map(|at| util::date_parse(at) as i64)));
            last.is_none_or(|at| at < cutoff)
        }).map(|host| host.name.clone()).collect()
    }

    pub fn unblock(&self, host: &str) {
        self.runner.guard().clear(host);
    }

    // ---- grants

    pub fn grant_store(&self) -> &GrantStore {
        &self.grants
    }

    pub fn grant_minutes(&self) -> u32 {
        self.config.grants.default_ttl_minutes as u32
    }

    /// Give what a card asked for, for a while: the capabilities on the hosts, never the destructive one.
    pub fn grant(&self, session: &str, ask: &crate::tools::Ask) {
        let expires_at = time::now_ms() + i64::from(self.grant_minutes()) * 60_000;
        for need in &ask.needs {
            let capability = match need.as_str() { "change" => Capability::Change, "sudo" => Capability::Sudo, _ => continue };
            self.grants.add(NewGrant { session: session.to_string(), capability, hosts: ask.hosts.clone(), selector: ask.hosts.join(","), expires_at });
        }
    }

    /// Full permission for one conversation: nothing a host's policy asks about is asked again.
    pub fn grant_full(&self, session: &str) {
        self.grants.add_full(session);
    }

    pub fn revoke_grants(&self, session: &str) {
        self.grants.revoke(session, "all");
    }

    /// The grants of a conversation, each in a few words.
    pub fn grants(&self, session: &str) -> Vec<String> {
        self.grants.active(session).iter().map(|grant| format!("{} @ {} → {}", grant.capability, wisp_ops_engine::policy::host_list(&grant.hosts), wisp_ops_core::time::short_time(&time::to_iso(grant.expires_at)).split(' ').next_back().unwrap_or(""))).collect()
    }

    // ---- the view

    pub fn view(&self) -> View {
        // Read before the inventory is held: both look the hosts up themselves.
        let (long_runs, attacks) = (self.long_runs(), self.attacks());
        let loaded = self.loaded.read().unwrap();
        let probes: BTreeMap<String, HostProbe> = self.store.probes().unwrap_or_default();
        let blocks = self.runner.guard().list();
        let now_ms = time::now_ms() as f64;
        let hosts = loaded.inventory.hosts().iter().map(|host| {
            let muted = Self::mutes_of(host);
            let runs = self.store.read_history::<HistoryRecord>(&host.name, RUNS_KEPT).unwrap_or_default().into_iter().map(|record| {
                let findings: Vec<FindingView> = record.findings.iter().map(|finding| FindingView { severity: finding.severity.as_str().into(), message: finding.message.clone(), muted: mutes::mute_for(finding, &muted, now_ms).is_some() }).collect();
                let state = if !record.is_ok() { "unreachable" } else { inspect::worst_severity(record.findings.iter().filter(|finding| mutes::mute_for(finding, &muted, now_ms).is_none())).map_or("ok", Severity::as_str) };
                let disk_max = record.metrics.disk_pct.iter().max_by(|a, b| a.1.total_cmp(b.1)).map(|(mount, pct)| (mount.to_string(), *pct));
                let disks = record.metrics.disk_pct.iter().map(|(mount, pct)| (mount.to_string(), *pct)).collect();
                RunView { at: record.metrics.at.clone(), state: state.into(), findings, disk_max, disks, cpu_pct: record.metrics.cpu_pct, gpu_util_pct: record.metrics.gpu_util_pct, gpu_mem_pct: record.metrics.gpu_mem_pct, gpu_temp_c: record.metrics.gpu_temp_c, mem_avail_pct: record.metrics.mem_avail_pct, load1: record.metrics.load1, login_ms: record.metrics.login_ms }
            }).collect();
            let policy = |policy: &config::Policy| [policy.change.as_str().to_string(), policy.sudo.as_str().to_string(), policy.destructive.as_str().to_string()];
            let own = host.policy_override.clone().unwrap_or_default();
            let secret = |reference: &Option<String>| reference.as_deref().map(|name| name.strip_prefix("local:").unwrap_or(name).to_string()).unwrap_or_default();
            HostView {
                name: host.name.clone(),
                address: format!("{}{}{}", host.user.as_ref().map(|user| format!("{user}@")).unwrap_or_default(), host.destination(), host.port.map(|port| format!(":{port}")).unwrap_or_default()),
                ssh: host.ssh.clone().unwrap_or_default(),
                user: host.user.clone().unwrap_or_default(),
                port: host.port.map(|port| port as u16),
                groups: host.groups.clone(),
                description: host.description.clone().unwrap_or_default(),
                jump: host.proxy_jump.clone().unwrap_or_default(),
                identity: host.identity_file.clone().unwrap_or_default(),
                managed: loaded.managed_names.contains(&host.name),
                policy: policy(&host.policy),
                policy_own: [own.change, own.sudo, own.destructive].map(|permission| permission.map(|p| p.as_str().to_string()).unwrap_or_default()),
                policy_inherited: policy(&host.inherited_policy),
                login_secret: if host.uses_password() { secret(&host.login_secret) } else { String::new() },
                sudo_secret: secret(&host.sudo_secret),
                probe: probes.get(&host.name).map(|probe| ProbeView { os: probe.os.clone().unwrap_or_else(|| "?".into()), arch: probe.arch.clone().unwrap_or_default(), cores: probe.cores.map(|cores| cores.to_string()).unwrap_or_else(|| "?".into()), gpus: probe.gpus, scheduler: word(&probe.scheduler), privilege: word(&probe.privilege), docker: word(&probe.docker), at: probe.at.clone() }),
                blocked_until: blocks.iter().find(|block| block.host == host.name).map(|block| block.until.clone()),
                runs,
            }
        }).collect();
        let (credentials, vault_error) = match self.vault.list() {
            Ok(listing) => (listing.entries.into_iter().map(|entry| CredentialView { name: entry.name, username: entry.username, note: entry.note, agent: entry.agent }).collect(), None),
            Err(error) => (vec![], Some(error)),
        };
        let timer = self.timer_state();
        let now = time::now_ms();
        let zone = &self.config.time_zone;
        let tasks = loaded.inventory.tasks().iter().map(|task| {
            let records: Vec<TaskRunRecord> = self.store.read_bounded("tasks", &task.name).unwrap_or_default();
            let last = records.last();
            let entry = timer.tasks.get(&task.name);
            let timed = task.schedule.as_ref().filter(|schedule| schedule.cron.is_none() && schedule.is_timed());
            let next = match (timed, entry) {
                (Some(schedule), Some(entry)) => schedule::next_due(schedule, zone, last.map(|record| record.at.as_str()), &entry.enabled_at, now).ok().flatten().map(time::to_iso),
                _ => None,
            };
            TaskView { name: task.name.clone(), draft: draft_of(task), managed: loaded.managed_tasks.contains(&task.name), scheduled: timed.is_some(), enabled: entry.is_some(), when: describe_when(task.schedule.as_ref()), next, last: last.map(|record| TaskLast { at: record.at.clone(), problems: record.has_problems(), summary: record.summary() }), error: entry.and_then(|entry| entry.last_error.clone()) }
        }).collect();
        let limits = Limits { gpu_temp: self.thresholds.gpu_temp_warn_c, disk: (self.thresholds.disk_warn_pct, self.thresholds.disk_crit_pct), mem_avail: (self.thresholds.mem_avail_warn_pct, self.thresholds.mem_avail_crit_pct), load_per_core: (self.thresholds.load_per_core_warn, self.thresholds.load_per_core_crit) };
        View { limits, hosts, credentials, tasks, audit: vec![], long_runs, attacks, inventory_error: loaded.error.clone(), vault_error, vault_key_place: if std::env::var("WISP_OPS_VAULT_KEY").as_deref() == Ok("file") || !cfg!(target_os = "macos") { "数据文件夹的 vault.key 里" } else { "系统钥匙串里" } }
    }

    pub fn audit(&self, host: Option<&str>, hours: u32, limit: usize) -> Vec<AuditRow> {
        let filter = AuditFilter { hosts: host.map(|host| HashSet::from([host.to_string()])), since_ms: Some(time::now_ms() - i64::from(hours) * 3_600_000), limit };
        self.store.read_audit(&filter).unwrap_or_default().into_iter().map(|entry| AuditRow { at: entry.at, host: entry.host, tool: entry.tool, risk: entry.risk.as_str().into(), sudo: entry.sudo, authorization: word(&entry.authorization), status: entry.status.as_str().into(), exit_code: entry.exit_code, command: entry.command, reason: entry.reason.unwrap_or_default(), duration_ms: entry.duration_ms }).collect()
    }

    // ---- the inventory the window keeps (managed.json)

    /// Change `managed.json`, having checked that the inventory still loads with the change.
    fn edit_managed(&self, update: impl FnOnce(&mut ManagedState) -> Result<(), String>) -> Result<(), String> {
        let store = managed_store(&self.root);
        let read = store.read()?;
        let mut state = read.value;
        update(&mut state)?;
        Inventory::load(&self.config, &[], Some(&state))?;
        store.change(&read.revision, |_| Ok(state))?;
        self.reload_inventory();
        Ok(())
    }

    pub fn save_host(&self, editing: Option<&str>, draft: HostDraft) -> Result<(), String> {
        let some = |text: String| Some(text).filter(|text| !text.is_empty());
        let spec = HostSpec { name: draft.name.clone(), ssh: some(draft.ssh), port: draft.port.map(u32::from), user: some(draft.user), groups: draft.groups, description: some(draft.description), proxy_jump: some(draft.jump), identity_file: some(draft.identity), ..Default::default() };
        config::validate_host(&spec)?;
        let exists = self.inventory().has_host(&spec.name);
        self.edit_managed(|state| {
            match editing {
                Some(name) => {
                    if name != spec.name { return Err("名称关联着凭据、权限和任务，不能修改。".into()) }
                    let slot = state.hosts.iter_mut().find(|host| host.name == name).ok_or("这台服务器不是在这里添加的，请在 inventory.yml 里修改。")?;
                    // What the form does not hold stays: tags, the sudo user.
                    *slot = HostSpec { tags: slot.tags.clone(), sudo_user: slot.sudo_user.clone(), ..spec };
                }
                None => {
                    if exists { return Err(format!("清单里已经有一台叫 {} 的服务器。", spec.name)) }
                    state.hosts.push(spec);
                }
            }
            Ok(())
        })
    }

    pub fn remove_host(&self, name: &str) -> Result<(), String> {
        self.edit_managed(|state| {
            state.hosts.retain(|host| host.name != name);
            state.bindings.remove(name);
            state.policies.remove(name);
            state.checks.remove(name);
            state.thresholds.remove(name);
            state.mutes.remove(name);
            Ok(())
        })
    }

    /// The Host aliases of `~/.ssh/config` not yet in the inventory, each with what it connects to.
    pub fn import_candidates(&self) -> Vec<(String, String)> {
        let inventory = self.inventory();
        ssh_config::load_ssh_config_hosts(&self.config.ssh_config_file).map(|found| found.hosts).unwrap_or_default().into_iter().filter(|host| !inventory.has_host(&ssh_config::inventory_name_for(&host.alias))).map(|host| (host.alias.clone(), ssh_config::describe_ssh_config_host(&host))).collect()
    }

    pub fn import_hosts(&self, aliases: &[String]) -> Result<(), String> {
        let found = ssh_config::load_ssh_config_hosts(&self.config.ssh_config_file)?.hosts;
        self.edit_managed(|state| {
            for host in found.iter().filter(|host| aliases.contains(&host.alias)) {
                let mut spec = ssh_config::ssh_config_host_spec(host);
                if !spec.groups.iter().any(|group| group == "ssh-config") { spec.groups.push("ssh-config".into()) }
                state.hosts.retain(|known| known.name != spec.name);
                state.hosts.push(spec);
            }
            Ok(())
        })
    }

    /// What the window says of a host's three permissions; empty inherits.
    pub fn set_policy(&self, host: &str, values: &[String; 3]) -> Result<(), String> {
        let read = |value: &str| match value { "allow" => Some(Permission::Allow), "ask" => Some(Permission::Ask), "deny" => Some(Permission::Deny), _ => None };
        let policy = PolicySpec { change: read(&values[0]), sudo: read(&values[1]), destructive: read(&values[2]) };
        self.edit_managed(|state| {
            if policy.is_empty() { state.policies.remove(host); } else { state.policies.insert(host.to_string(), policy); }
            Ok(())
        })
    }

    /// Link a vault entry to a host's SSH login or its sudo; empty unlinks.
    pub fn bind_credential(&self, host: &str, sudo: bool, credential: &str) -> Result<(), String> {
        let current = self.inventory().host(host).cloned().ok_or_else(|| format!("清单里没有 {host}。"))?;
        self.edit_managed(|state| {
            let mut binding = state.bindings.get(host).cloned().unwrap_or(CredentialBinding { auth: current.auth.unwrap_or(AuthMethod::Key), login_secret: current.login_secret.clone(), sudo_secret: current.sudo_secret.clone() });
            let reference = (!credential.is_empty()).then(|| format!("local:{credential}"));
            if sudo {
                binding.sudo_secret = reference;
            } else {
                // Linking a login credential is logging in with a password.
                binding.auth = if reference.is_some() { AuthMethod::Password } else { AuthMethod::Key };
                binding.login_secret = reference;
            }
            state.bindings.insert(host.to_string(), binding);
            Ok(())
        })
    }

    /// Log in with the credential picked (and for sudo, validate it), without saving the link.
    pub fn test_credential(&self, host: &str, sudo: bool, credential: &str) -> Result<String, String> {
        let mut host = self.inventory().host(host).cloned().ok_or_else(|| format!("清单里没有 {host}。"))?;
        let reference = (!credential.is_empty()).then(|| format!("local:{credential}"));
        if sudo {
            host.sudo_secret = reference;
        } else {
            host.auth = Some(if reference.is_some() { AuthMethod::Password } else { AuthMethod::Key });
            host.login_secret = reference;
        }
        let mut exec = Exec::read(if sudo { "window:test-sudo" } else { "window:test-login" }, Authorization::ReadOnly);
        exec.sudo = sudo;
        exec.timeout_ms = self.config.ssh.connect_timeout_sec * 1000 + 15_000;
        let result = self.execute_one(std::slice::from_ref(&host), "id -un", &exec).remove(0);
        let who = result.stdout.lines().next().unwrap_or("").trim().to_string();
        match result.status {
            RunStatus::Ok if sudo => Ok(tf!("sudo 可用，执行身份是 {who}", "sudo works; commands run as {who}")),
            RunStatus::Ok => Ok(tf!("登录成功，身份是 {who}", "Logged in as {who}")),
            status => Err(format!("{}：{}", status.as_str(), result.stderr.trim().chars().take(240).collect::<String>())),
        }
    }

    // ---- the vault

    pub fn save_credential(&self, editing: Option<&str>, name: &str, username: &str, password: &str, note: &str, agent: bool) -> Result<(), String> {
        let listing = self.vault.list()?;
        if let Some(old) = editing && old != name { return Err("凭据的名称关联着服务器，不能修改；需要换名时新建一条。".into()) }
        if editing.is_none() && listing.entries.iter().any(|entry| entry.name == name) { return Err(format!("已经有一条叫 {name} 的凭据。")) }
        self.vault.save(&CredentialInput { name: name.to_string(), username: username.to_string(), note: note.to_string(), agent, password: Some(password.to_string()).filter(|password| !password.is_empty()) }, &listing.revision, None)
    }

    /// Delete a credential; the servers that used it go back to keys and to no sudo password.
    pub fn delete_credential(&self, name: &str) -> Result<(), String> {
        let reference = format!("local:{name}");
        let uses = |secret: &Option<String>| secret.as_deref() == Some(reference.as_str()) || secret.as_deref() == Some(name);
        self.edit_managed(|state| {
            for binding in state.bindings.values_mut() {
                if uses(&binding.login_secret) {
                    binding.login_secret = None;
                    binding.auth = AuthMethod::Key;
                }
                if uses(&binding.sudo_secret) { binding.sudo_secret = None }
            }
            Ok(())
        })?;
        let listing = self.vault.list()?;
        self.vault.remove(name, &listing.revision, None)
    }

    // ---- tasks

    fn timer_file(&self) -> PathBuf {
        self.root.join("task-timer.json")
    }

    fn timer_state(&self) -> TimerState {
        std::fs::read_to_string(self.timer_file()).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    fn edit_timer(&self, update: impl FnOnce(&mut TimerState)) {
        let _held = self.timer.lock().unwrap();
        let mut state = self.timer_state();
        update(&mut state);
        let _ = std::fs::write(self.timer_file(), serde_json::to_string_pretty(&state).unwrap_or_default());
    }

    pub fn save_task(&self, editing: Option<&str>, draft: TaskDraft) -> Result<(), String> {
        let some = |text: String| Some(text).filter(|text| !text.is_empty());
        let playbook: Playbook = serde_json::from_value(Value::String(draft.playbook.clone())).map_err(|_| "不认识这种检查内容。".to_string())?;
        let schedule = match draft.schedule.as_str() {
            "daily" => Some(TaskSchedule { daily: Some(draft.daily.clone()), ..Default::default() }),
            "every" => Some(TaskSchedule { every_minutes: Some(u64::from(draft.every_minutes)), ..Default::default() }),
            _ => None,
        };
        if playbook == Playbook::Custom && draft.commands.is_empty() { return Err("自定义任务至少写一条只读命令。".into()) }
        if matches!(playbook, Playbook::Disk | Playbook::Space | Playbook::NewFiles) && draft.paths.is_empty() { return Err("这种检查需要填写路径。".into()) }
        for command in &draft.commands {
            let risk = risk::classify_command(command, &self.extra_read);
            if risk.level != RiskLevel::Read || risk.elevates { return Err(format!("这条命令不是只读的，任务里不能用：{command}{}", if risk.reasons.is_empty() { String::new() } else { format!("（{}）", risk.reasons.join("; ")) })) }
            if let Some(pattern) = self.deny.matches(command) { return Err(format!("这条命令被拒绝清单拦下（{pattern}）：{command}")) }
        }
        // A timed task of the window runs on its timer and the assistant reports when asked.
        let spec = TaskSpec { name: draft.name.clone(), description: some(draft.description), targets: draft.targets, playbook, instruction: some(draft.instruction), schedule, paths: draft.paths, commands: draft.commands, sudo: draft.sudo.then_some(true), report: Some(config::ReportMode::Problems), ..Default::default() };
        config::validate_task(&spec)?;
        let exists = self.inventory().task(&spec.name).is_some();
        let (name, timed) = (spec.name.clone(), spec.schedule.is_some());
        self.edit_managed(|state| {
            match editing {
                Some(old) => {
                    if old != spec.name { return Err("任务的标识关联着运行记录，不能修改。".into()) }
                    let slot = state.tasks.iter_mut().find(|task| task.name == old).ok_or("这个任务写在 inventory.yml 里，请在那里修改。")?;
                    *slot = spec;
                }
                None => {
                    if exists { return Err(format!("已经有一个叫 {} 的任务。", spec.name)) }
                    state.tasks.push(spec);
                }
            }
            Ok(())
        })?;
        // A new task with a time is kept by the timer from now on; one that lost its time is let go.
        self.edit_timer(|state| {
            if !timed { state.tasks.remove(&name); } else if editing.is_none() { state.tasks.insert(name.clone(), TimerEntry { enabled_at: time::to_iso(time::now_ms()), last_error: None }); }
        });
        Ok(())
    }

    pub fn delete_task(&self, name: &str) -> Result<(), String> {
        self.edit_managed(|state| {
            state.tasks.retain(|task| task.name != name);
            Ok(())
        })?;
        self.edit_timer(|state| { state.tasks.remove(name); });
        Ok(())
    }

    /// Switch the timer of a task on or off.
    pub fn toggle_task(&self, name: &str) -> Result<(), String> {
        if self.inventory().task(name).is_none() { return Err(format!("没有叫 {name} 的任务。")) }
        self.edit_timer(|state| {
            if state.tasks.remove(name).is_none() { state.tasks.insert(name.to_string(), TimerEntry { enabled_at: time::to_iso(time::now_ms()), last_error: None }); }
        });
        Ok(())
    }

    /// The tasks whose time has come.
    pub fn due_tasks(&self) -> Vec<String> {
        let inventory = self.inventory();
        let now = time::now_ms();
        self.timer_state().tasks.iter().filter_map(|(name, entry)| {
            let task = inventory.task(name)?;
            let schedule = task.schedule.as_ref().filter(|schedule| schedule.cron.is_none())?;
            let last: Option<TaskRunRecord> = self.store.read_bounded("tasks", name).ok().and_then(|mut rows: Vec<TaskRunRecord>| rows.pop());
            schedule::due_now(schedule, &self.config.time_zone, last.as_ref().map(|record| record.at.as_str()), &entry.enabled_at, now).ok().filter(|due| *due).map(|_| name.clone())
        }).collect()
    }

    /// Run a task from the window or its timer: the task's own definition is the authorization
    /// (it only reads; its sudo was written by the person), a policy that denies sudo still wins.
    /// Gives whether it found problems, and its summary.
    pub fn run_task(&self, name: &str, timed: bool) -> Result<(bool, String), String> {
        let task = self.inventory().task(name).cloned().ok_or_else(|| format!("没有叫 {name} 的任务。"))?;
        let result = self.run_task_as(&task, task.sudo == Some(true), Authorization::Task, None, None).map(|(_, record)| (record.has_problems(), record.summary()));
        if timed || result.is_err() { self.edit_timer(|state| if let Some(entry) = state.tasks.get_mut(name) { entry.last_error = result.as_ref().err().cloned() }) }
        result
    }

    /// Run one task's playbook: the text for the model, and the record that is kept.
    pub fn run_task_as(&self, task: &TaskSpec, sudo: bool, authorization: Authorization, session: Option<String>, cancel: Option<Arc<AtomicBool>>) -> Result<(String, TaskRunRecord), String> {
        let hosts = self.select(&task.targets)?;
        if task.sudo == Some(true) {
            let refused: Vec<&str> = hosts.iter().filter(|host| host.policy.sudo == Permission::Deny).map(|host| host.name.as_str()).collect();
            if !refused.is_empty() { return Err(format!("host policy denies sudo on {}", refused.join(", "))) }
        }
        if let Some(pattern) = task.commands.iter().find_map(|command| self.deny.matches(command)) { return Err(format!("Refused by the deny list ({pattern}).")) }
        let collect = Collect { sudo, tool: format!("ops_task:{}", task.name), session, authorization, cancel };
        let mut counts: BTreeMap<String, f64> = BTreeMap::new();
        let mut bump = |key: &str, n: f64| *counts.entry(key.to_string()).or_default() += n;
        let (warn, crit) = (self.thresholds.disk_warn_pct, self.thresholds.disk_crit_pct);
        let usage = |fs: Option<&wisp_ops_collect::sections::FsUsage>| fs.and_then(|fs| if fs.use_pct >= crit { Some("crit") } else if fs.use_pct >= warn { Some("warn") } else { None });
        let runs = |result: &RunResult, chars: usize| render::render_runs(&[as_run(result)], chars);
        let paths = if task.paths.is_empty() { vec!["/".to_string()] } else { task.paths.clone() };
        let mut body = match task.playbook {
            Playbook::Inspect => {
                let fleet = self.inspect_hosts(&hosts, &collect, &format!("(task {}: built-in read-only inspection)", task.name));
                let c = &fleet.counts;
                for (key, count) in [("ok", c.ok), ("info", c.info), ("warn", c.warn), ("crit", c.crit), ("unreachable", c.unreachable)] {
                    if count > 0 { bump(key, f64::from(count)) }
                }
                render::render_inspection(&fleet, true)
            }
            Playbook::Disk => {
                let mut parts = vec![];
                for host in &hosts {
                    for path in &paths {
                        let (report, result) = self.disk(host, &disk::DiskOptions { path: path.clone(), depth: 2, top: 15, min_file_mb: 100, recent_min_file_mb: 10, recent_minutes: 1440, walk_timeout_sec: 120 }, &collect);
                        match &report {
                            None => bump("unreachable", 1.),
                            Some(report) if report.walk_incomplete || report.filesystem.is_none() => bump("incomplete", 1.),
                            _ => {}
                        }
                        if let Some(key) = usage(report.as_ref().and_then(|report| report.filesystem.as_ref())) { bump(key, 1.) }
                        parts.push(match report { Some(report) => disk::render_disk(&host.name, &report), None => runs(&result, 2000) });
                    }
                }
                parts.join("\n\n")
            }
            Playbook::Space => {
                let mut parts = vec![];
                for host in &hosts {
                    for path in &paths {
                        let (found, result) = self.space(host, &space::SpaceOptions { path: path.clone(), depth: 5, max_dirs: 2000, min_kb: 1024, walk_timeout_sec: 300 }, &collect);
                        match &found {
                            None => bump("unreachable", 1.),
                            Some((report, _)) if report.walk_incomplete || report.filesystem.is_none() => bump("incomplete", 1.),
                            _ => {}
                        }
                        if let Some(key) = usage(found.as_ref().and_then(|(report, _)| report.filesystem.as_ref())) { bump(key, 1.) }
                        parts.push(match found { Some((report, previous)) => space::render_space(&host.name, &report, previous.as_ref()), None => runs(&result, 2000) });
                    }
                }
                parts.join("\n\n")
            }
            Playbook::NewFiles => {
                let mut parts = vec![];
                for host in &hosts {
                    let (report, result) = self.files(host, &files::FilesOptions { paths: paths.clone(), days: task.days.unwrap_or(1) as u32, depth: 3, list_min_mb: 10, max_files: 5000, top: 20, walk_timeout_sec: 300 }, &collect);
                    let Some(report) = report else {
                        bump("unreachable", 1.);
                        parts.push(runs(&result, 2000));
                        continue;
                    };
                    bump("newBytes", report.total_bytes);
                    if !report.incomplete_roots.is_empty() { bump("incomplete", 1.) }
                    bump("reclaimableBytes", report.plan.iter().map(|item| item.reclaim_bytes).sum());
                    parts.push(files::render_files(&host.name, &report));
                }
                parts.join("\n\n")
            }
            Playbook::Security => {
                let hours = task.hours.unwrap_or(24) as u32;
                self.security(&hosts, hours, &collect).into_iter().map(|(host, report, result)| match report {
                    None => {
                        bump("unreachable", 1.);
                        runs(&result, 2000)
                    }
                    Some(report) => {
                        for finding in &report.findings { bump(&word(&finding.severity), 1.) }
                        security::render_security(&host, &report, hours)
                    }
                }).collect::<Vec<_>>().join("\n\n")
            }
            Playbook::Custom if !task.commands.is_empty() => String::new(),
            Playbook::Custom => {
                bump("incomplete", 1.);
                format!("No built-in collector: gather the evidence yourself with read-only ops_exec / ops_inspect calls on {}.", hosts.iter().map(|host| host.name.as_str()).collect::<Vec<_>>().join(", "))
            }
            Playbook::Script => {
                bump("incomplete", 1.);
                "Check scripts are not supported in this build; nothing ran.".to_string()
            }
        };
        // The task's own read-only commands, checked when the task was saved, run after the collector.
        if !task.commands.is_empty() {
            let mut unreachable: HashSet<String> = HashSet::new();
            let mut parts = vec![];
            for (index, command) in task.commands.iter().enumerate() {
                let mut exec = collect.exec(self.config.limits.default_timeout_ms, command);
                exec.reason = Some(format!("task {} command {}", task.name, index + 1));
                let results = self.execute_one(&hosts, command, &exec);
                for result in &results {
                    if result.status == RunStatus::Failed { bump("commandFailed", 1.) } else if result.status != RunStatus::Ok { unreachable.insert(result.host.clone()); }
                }
                parts.push(format!("### Command {}: {command}\n{}", index + 1, render::render_runs(&results.iter().map(as_run).collect::<Vec<_>>(), 4000)));
            }
            if !unreachable.is_empty() && task.playbook == Playbook::Custom { bump("unreachable", unreachable.len() as f64) }
            body = format!("{}## Read-only commands ({})\nExit status other than 0 counts as commandFailed; interpret it against the user's instruction.\n\n{}", if body.is_empty() { String::new() } else { format!("{body}\n\n") }, task.commands.len(), parts.join("\n\n"));
        }
        let previous: Option<TaskRunRecord> = self.store.read_bounded("tasks", &task.name).ok().and_then(|mut rows: Vec<TaskRunRecord>| rows.pop());
        let record = TaskRunRecord { at: time::to_iso(time::now_ms()), hosts: hosts.iter().map(|host| host.name.clone()).collect(), playbook: task.playbook.as_str().into(), counts, excerpt: body.chars().take(6000).collect() };
        let _ = self.store.append_bounded("tasks", &task.name, &record, 90);
        Ok((task_text(task, &record, &body, previous.as_ref()), record))
    }

    /// The last recorded run as the assistant would have seen it, without running anything.
    pub fn last_task_text(&self, task: &TaskSpec) -> String {
        let mut rows: Vec<TaskRunRecord> = self.store.read_bounded("tasks", &task.name).unwrap_or_default();
        let Some(record) = rows.pop() else { return format!("Task \"{}\" has no recorded run yet; call ops_task with mode=\"run\" to run it.", task.name) };
        task_text(task, &record, &format!("{}\n\n(Recorded run; evidence above is the stored excerpt of what WispOps collected at {}.)", record.excerpt, record.at), rows.last())
    }

    /// Hold the hosts of a managed change; `Err` names those one is already running on.
    pub fn begin_change(&self, hosts: &[Host]) -> Result<(), String> {
        let mut changing = self.changing.lock().unwrap();
        let busy: Vec<&str> = hosts.iter().filter(|host| changing.contains(&host.name)).map(|host| host.name.as_str()).collect();
        if !busy.is_empty() { return Err(format!("A managed change is already running on {}", busy.join(", "))) }
        changing.extend(hosts.iter().map(|host| host.name.clone()));
        Ok(())
    }

    pub fn end_change(&self, hosts: &[Host]) {
        let mut changing = self.changing.lock().unwrap();
        for host in hosts { changing.remove(&host.name); }
    }
}

/// The model-facing text of a task's run: header, the person's instruction, the data, and the previous run to compare with.
fn task_text(task: &TaskSpec, record: &TaskRunRecord, body: &str, previous: Option<&TaskRunRecord>) -> String {
    let mut header = vec![format!("# WispOps task \"{}\" ({}) on {} — {}", task.name, record.playbook, record.hosts.join(", "), record.at)];
    if let Some(description) = &task.description { header.push(format!("Description: {description}")) }
    if let Some(instruction) = &task.instruction { header.push(format!("What the user wants from this task: {instruction}")) }
    header.push(match previous {
        None => "No previous run recorded.".to_string(),
        Some(previous) => format!("Previous run {}: {}. Its excerpt follows the current data for comparison.", previous.at, previous.summary()),
    });
    header.push(REPORT_GUIDE.to_string());
    let tail = previous.map(|previous| format!("\n\n---\nPrevious run excerpt ({}):\n{}", previous.at, previous.excerpt.chars().take(2500).collect::<String>())).unwrap_or_default();
    format!("{}\n\n{body}{tail}", header.join("\n"))
}

pub fn as_run(result: &RunResult) -> Run {
    Run { host: result.host.clone(), status: result.status.as_str().into(), exit_code: result.exit_code, stdout: result.stdout.clone(), stderr: result.stderr.clone(), truncated: result.truncated, duration_ms: result.duration_ms }
}

fn draft_of(task: &TaskSpec) -> TaskDraft {
    let schedule = task.schedule.as_ref();
    TaskDraft {
        name: task.name.clone(),
        description: task.description.clone().unwrap_or_default(),
        targets: task.targets.clone(),
        playbook: task.playbook.as_str().into(),
        paths: task.paths.clone(),
        instruction: task.instruction.clone().unwrap_or_default(),
        commands: task.commands.clone(),
        schedule: match schedule { Some(schedule) if schedule.daily.is_some() => "daily", Some(schedule) if schedule.every_minutes.is_some() => "every", _ => "manual" }.into(),
        daily: schedule.and_then(|schedule| schedule.daily.clone()).unwrap_or_else(|| "08:30".into()),
        every_minutes: schedule.and_then(|schedule| schedule.every_minutes).unwrap_or(60) as u32,
        sudo: task.sudo == Some(true),
    }
}

/// When a task runs, in the interface's words.
fn describe_when(schedule: Option<&TaskSchedule>) -> String {
    match schedule {
        None => crate::i18n::t("仅手动").to_string(),
        Some(schedule) => match (&schedule.daily, &schedule.cron, schedule.every_minutes) {
            (Some(daily), ..) if schedule.weekdays.is_empty() => tf!("每天 {daily}", "Daily at {daily}"),
            (Some(daily), ..) => tf!("每周 {} 的 {daily}", "Weekdays {} at {daily}", schedule.weekdays.iter().map(u32::to_string).collect::<Vec<_>>().join(",")),
            (_, Some(cron), _) => tf!("cron {cron}（定时器不支持，仅手动）", "cron {cron} (not kept by the timer; manual only)"),
            (_, _, Some(minutes)) => tf!("每 {minutes} 分钟", "Every {minutes} min"),
            _ => crate::i18n::t("仅手动").to_string(),
        },
    }
}

/// The skills on offer: those shipped with the app (written into the folder beside the settings on first run) and the person's own.
pub fn skills(settings_file: &Path) -> Vec<wisp_ops_core::skill::Skill> {
    let folder = wisp_ops_core::skill::folder(settings_file);
    for (path, bytes) in crate::assets::FILES.iter().filter(|(path, _)| path.starts_with("skills/")) {
        let target = folder.join(path.trim_start_matches("skills/"));
        if target.exists() { continue }
        if let Some(dir) = target.parent() { let _ = std::fs::create_dir_all(dir); }
        let _ = std::fs::write(target, bytes);
    }
    wisp_ops_core::skill::list(&folder)
}
