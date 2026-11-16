//! Configuration: inventory entries, permission policy, transport limits and retention.
//!
//! Every deployment-varying value lives here. [`Config::resolve`] fills defaults and validates,
//! as the plugin's schema did; the serde field names are the plugin's, so its files stay readable.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fsutil::home_dir;
use crate::jsre::js_re;

/// How a capability is handled for a host: run, ask the human, or refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Allow,
    Ask,
    Deny,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Allow => "allow",
            Permission::Ask => "ask",
            Permission::Deny => "deny",
        }
    }

    fn strictness(self) -> u8 {
        match self {
            Permission::Allow => 0,
            Permission::Ask => 1,
            Permission::Deny => 2,
        }
    }
}

/// The stricter of two permissions.
pub fn stricter(a: Permission, b: Permission) -> Permission {
    if a.strictness() >= b.strictness() { a } else { b }
}

/// Capabilities a remote action may require. Reading is always allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Change,
    Sudo,
    Destructive,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Change => "change",
            Capability::Sudo => "sudo",
            Capability::Destructive => "destructive",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const CAPABILITIES: [Capability; 3] = [Capability::Change, Capability::Sudo, Capability::Destructive];

/// Partial per-capability permission table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicySpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change: Option<Permission>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sudo: Option<Permission>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive: Option<Permission>,
}

impl PolicySpec {
    pub fn get(&self, capability: Capability) -> Option<Permission> {
        match capability {
            Capability::Change => self.change,
            Capability::Sudo => self.sudo,
            Capability::Destructive => self.destructive,
        }
    }

    pub fn set(&mut self, capability: Capability, permission: Option<Permission>) {
        match capability {
            Capability::Change => self.change = permission,
            Capability::Sudo => self.sudo = permission,
            Capability::Destructive => self.destructive = permission,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.change.is_none() && self.sudo.is_none() && self.destructive.is_none()
    }
}

/// A complete permission table: the default policy, or a host's effective policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Policy {
    pub change: Permission,
    pub sudo: Permission,
    pub destructive: Permission,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { change: Permission::Ask, sudo: Permission::Ask, destructive: Permission::Ask }
    }
}

impl Policy {
    pub fn get(&self, capability: Capability) -> Permission {
        match capability {
            Capability::Change => self.change,
            Capability::Sudo => self.sudo,
            Capability::Destructive => self.destructive,
        }
    }

    pub fn set(&mut self, capability: Capability, permission: Permission) {
        match capability {
            Capability::Change => self.change = permission,
            Capability::Sudo => self.sudo = permission,
            Capability::Destructive => self.destructive = permission,
        }
    }
}

/// `key` (default) uses BatchMode; `password` logs in with the password of `loginSecret`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Key,
    Password,
}

/// One managed host.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HostSpec {
    /// Stable name used by tools and commands.
    pub name: String,
    /// OpenSSH destination: an ssh_config alias or `user@host`; defaults to `name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Group memberships.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Free-form labels, selectable as `tag:key=value`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Per-host overrides; win over every group and the default policy.
    #[serde(skip_serializing_if = "PolicySpec::is_empty")]
    pub policy: PolicySpec,
    /// Run sudo as this user instead of root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sudo_user: Option<String>,
    /// `ssh -J`; otherwise put ProxyJump in ~/.ssh/config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_jump: Option<String>,
    /// `ssh -i` with IdentitiesOnly=yes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthMethod>,
    /// Vault entry holding the login password (auth: password).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_secret: Option<String>,
    /// Vault entry holding the sudo password; without one sudo runs `sudo -n`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sudo_secret: Option<String>,
}

impl HostSpec {
    pub fn named(name: &str) -> Self {
        HostSpec { name: name.to_string(), ..HostSpec::default() }
    }
}

/// Built-in read-only analyses a task can run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Playbook {
    #[default]
    Inspect,
    Disk,
    Space,
    NewFiles,
    Security,
    Custom,
    Script,
}

impl Playbook {
    pub fn as_str(self) -> &'static str {
        match self {
            Playbook::Inspect => "inspect",
            Playbook::Disk => "disk",
            Playbook::Space => "space",
            Playbook::NewFiles => "new-files",
            Playbook::Security => "security",
            Playbook::Custom => "custom",
            Playbook::Script => "script",
        }
    }
}

pub const PLAYBOOKS: [Playbook; 7] =
    [Playbook::Inspect, Playbook::Disk, Playbook::Space, Playbook::NewFiles, Playbook::Security, Playbook::Custom, Playbook::Script];

/// Who writes the report after a run: `always` wakes the agent every time; `problems` and `never`
/// run on the application's own timer, and `problems` queues the agent only when a run found something.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportMode {
    Always,
    Problems,
    Never,
}

impl ReportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ReportMode::Always => "always",
            ReportMode::Problems => "problems",
            ReportMode::Never => "never",
        }
    }
}

/// When a task runs; one of daily, weekly (daily + weekdays), cron, or everyMinutes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TaskSchedule {
    /// Local time `HH:MM`; with `weekdays` it runs weekly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily: Option<String>,
    /// ISO weekdays, Monday 1 … Sunday 7.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub weekdays: Vec<u32>,
    /// Five-field cron expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub every_minutes: Option<u64>,
    /// IANA zone; defaults to the configured `timeZone`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
}

impl TaskSchedule {
    /// Whether any of daily, cron, everyMinutes is set.
    pub fn is_timed(&self) -> bool {
        self.daily.is_some() || self.cron.is_some() || self.every_minutes.is_some()
    }
}

/// Local wall-clock window during which a task's external notifications are not sent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QuietHours {
    /// `HH:MM`; a window that crosses midnight (22:00 → 07:00) is allowed.
    pub start: String,
    pub end: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
}

/// A recurring job for some servers, e.g. a morning report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskSpec {
    pub name: String,
    /// Human-configured channel names; credentials never enter task records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notify: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_only_problems: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_on_change: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_hours: Option<QuietHours>,
    /// Origin template; execution uses the saved copy, never a live template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Host selector.
    pub targets: String,
    pub playbook: Playbook,
    /// What the report should cover, in the user's words; required for `custom`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<TaskSchedule>,
    /// Roots for `new-files`, `disk` and `space`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Window for `new-files`, in days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<u64>,
    /// Window for `security`, in hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hours: Option<u64>,
    /// Read-only shell commands the task runs on every target after its collector. Each must
    /// classify as read-only at load time; anything else is rejected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    /// Check script from the owner-reviewed script library; required by the `script` playbook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// Default `always`: the agent writes a report after every run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<ReportMode>,
    /// Run the built-in collector as root. Written by a human, this pre-authorizes sudo for the
    /// task's read-only collector; a host policy `sudo: deny` still wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GroupSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "PolicySpec::is_empty")]
    pub policy: PolicySpec,
}

pub const DEFAULT_EXTRA_PATH: [&str; 7] =
    ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/sbin", "/usr/local/cuda/bin", "/opt/slurm/bin", "/usr/lpp/mmfs/bin"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshSpec {
    /// OpenSSH client executable.
    pub binary: String,
    pub connect_timeout_sec: u64,
    /// Reuse one master connection per host for this many seconds; 0 disables multiplexing.
    pub control_persist_sec: u64,
    /// Extra `ssh` arguments, inserted before the destination.
    pub extra_args: Vec<String>,
    /// Parallel hosts per fleet operation.
    pub concurrency: u64,
    /// Source /etc/profile and ~/.profile (output discarded) so non-login sessions find site tools.
    pub load_profile: bool,
    /// Directories appended to the remote PATH, for tools such as nvidia-smi or sinfo outside it.
    pub extra_path: Vec<String>,
    /// After an authentication or host-key failure, refuse new logins to that host for this long.
    pub auth_failure_block_minutes: u64,
}

impl Default for SshSpec {
    fn default() -> Self {
        SshSpec {
            binary: "ssh".to_string(),
            connect_timeout_sec: 10,
            // Win32-OpenSSH has no ControlMaster.
            control_persist_sec: if cfg!(windows) { 0 } else { 60 },
            extra_args: Vec::new(),
            concurrency: 8,
            load_profile: true,
            extra_path: DEFAULT_EXTRA_PATH.iter().map(|s| s.to_string()).collect(),
            auth_failure_block_minutes: 15,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LimitsSpec {
    pub default_timeout_ms: u64,
    pub max_timeout_ms: u64,
    /// Captured bytes per stream per host; the remainder is dropped and reported.
    pub max_output_bytes: u64,
    /// Largest fleet one call may address.
    pub max_targets: u64,
}

impl Default for LimitsSpec {
    fn default() -> Self {
        LimitsSpec { default_timeout_ms: 60_000, max_timeout_ms: 30 * 60_000, max_output_bytes: 64 * 1024, max_targets: 64 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ChangeSpec {
    /// Directory on each host where managed changes keep `wispops-change.*` backups.
    pub backup_root: String,
    /// Backups older than this many days are pruned at the start of the next change on that host; 0 keeps them.
    pub backup_retention_days: u64,
}

impl Default for ChangeSpec {
    fn default() -> Self {
        ChangeSpec { backup_root: "/var/tmp".to_string(), backup_retention_days: 14 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrantsSpec {
    pub default_ttl_minutes: u64,
    pub max_ttl_minutes: u64,
    /// Whether a destructive grant is accepted at all.
    pub allow_destructive: bool,
}

impl Default for GrantsSpec {
    fn default() -> Self {
        GrantsSpec { default_ttl_minutes: 30, max_ttl_minutes: 8 * 60, allow_destructive: false }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RetentionSpec {
    /// Inspection records kept per host; older ones are dropped when a new one is written.
    pub inspection_records: u64,
    /// Monthly audit partitions kept, counting the current month; 0 keeps every month.
    pub audit_months: u64,
}

impl Default for RetentionSpec {
    fn default() -> Self {
        RetentionSpec { inspection_records: 1000, audit_months: 12 }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub hosts: Vec<HostSpec>,
    pub groups: BTreeMap<String, GroupSpec>,
    pub tasks: Vec<TaskSpec>,
    /// Default IANA zone for task schedules.
    pub time_zone: String,
    /// YAML or JSON file with `hosts`, `groups` and `tasks`, merged after the inline inventory.
    /// A missing file is an empty inventory; `None` reads no file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_file: Option<String>,
    /// OpenSSH client configuration the application offers to import hosts from.
    pub ssh_config_file: String,
    /// Policy for capabilities no host or group sets.
    pub default_policy: Policy,
    /// Regular expressions that are refused on every host, regardless of approval or grants.
    pub deny_patterns: Vec<String>,
    /// Programs a deployment trusts as read-only in addition to the built-in list.
    pub extra_read_programs: Vec<String>,
    pub ssh: SshSpec,
    pub limits: LimitsSpec,
    pub change: ChangeSpec,
    pub grants: GrantsSpec,
    /// Inspection thresholds; their type lives with the collectors.
    pub thresholds: Value,
    pub retention: RetentionSpec,
    /// Audit log, inspection history, disk snapshots, managed state and the vault.
    pub data_dir: String,
}

/// The data directory: `$WISP_OPS_HOME` when set, otherwise `~/.wisp-ops`.
pub fn default_data_dir() -> PathBuf {
    match std::env::var_os("WISP_OPS_HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home),
        _ => home_dir().join(".wisp-ops"),
    }
}

/// The deny list every deployment starts with: `rm -rf /`, a fork bomb, `chmod 777 /`.
pub fn default_deny_patterns() -> Vec<String> {
    vec![
        r"\brm\s+(?:-\S+\s+)*(?:--no-preserve-root\b|/\*?(?:\s|$))".to_string(),
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:".to_string(),
        r"\bchmod\s+(?:-\S+\s+)*[0-7]*777\s+/(?:\s|$)".to_string(),
    ]
}

fn inventory_file_in(data_dir: &str) -> String {
    PathBuf::from(data_dir).join("inventory.yml").to_string_lossy().into_owned()
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = default_data_dir().to_string_lossy().into_owned();
        Config {
            hosts: Vec::new(),
            groups: BTreeMap::new(),
            tasks: Vec::new(),
            time_zone: iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".to_string()),
            inventory_file: Some(inventory_file_in(&data_dir)),
            ssh_config_file: "~/.ssh/config".to_string(),
            default_policy: Policy::default(),
            deny_patterns: default_deny_patterns(),
            extra_read_programs: Vec::new(),
            ssh: SshSpec::default(),
            limits: LimitsSpec::default(),
            change: ChangeSpec::default(),
            grants: GrantsSpec::default(),
            thresholds: Value::Object(serde_json::Map::new()),
            retention: RetentionSpec::default(),
            data_dir,
        }
    }
}

impl Config {
    /// Resolve a partial configuration (a JSON object) into a full one: defaults filled, then validated.
    ///
    /// An absent `inventoryFile` becomes `<dataDir>/inventory.yml`; an explicit `null` reads no file.
    pub fn resolve(input: Value) -> Result<Config, String> {
        let input = if input.is_null() { Value::Object(serde_json::Map::new()) } else { input };
        let explicit_inventory = input.get("inventoryFile").is_some();
        let mut config: Config = serde_json::from_value(input).map_err(|error| format!("invalid configuration: {error}"))?;
        if !explicit_inventory {
            config.inventory_file = Some(inventory_file_in(&config.data_dir));
        }
        config.validate()?;
        Ok(config)
    }

    /// The data directory with a leading `~/` expanded.
    pub fn data_path(&self) -> PathBuf {
        PathBuf::from(crate::fsutil::expand_home(&self.data_dir))
    }

    /// Check every value the schema constrains: names, destinations, ranges.
    pub fn validate(&self) -> Result<(), String> {
        validate_hosts(&self.hosts)?;
        validate_groups(&self.groups)?;
        validate_tasks(&self.tasks)?;
        let ssh = &self.ssh;
        if ssh.connect_timeout_sec < 1 { return Err("ssh.connectTimeoutSec must be at least 1".to_string()) }
        if ssh.concurrency < 1 { return Err("ssh.concurrency must be at least 1".to_string()) }
        for path in &ssh.extra_path {
            if !js_re!(r#"^/[^:\s'"]*$"#).is_match(path) {
                return Err(format!("ssh.extraPath entry \"{path}\" must be an absolute path without colons, quotes or spaces"));
            }
        }
        let limits = &self.limits;
        if limits.default_timeout_ms < 1000 { return Err("limits.defaultTimeoutMs must be at least 1000".to_string()) }
        if limits.max_timeout_ms < 1000 { return Err("limits.maxTimeoutMs must be at least 1000".to_string()) }
        if limits.max_output_bytes < 1024 { return Err("limits.maxOutputBytes must be at least 1024".to_string()) }
        if limits.max_targets < 1 { return Err("limits.maxTargets must be at least 1".to_string()) }
        if !js_re!(r"^/[^\0\r\n]*[^/\0\r\n]$").is_match(&self.change.backup_root) {
            return Err("change.backupRoot must be an absolute path without a trailing slash".to_string());
        }
        if self.grants.default_ttl_minutes < 1 { return Err("grants.defaultTtlMinutes must be at least 1".to_string()) }
        if self.grants.max_ttl_minutes < 1 { return Err("grants.maxTtlMinutes must be at least 1".to_string()) }
        if self.retention.inspection_records < 10 { return Err("retention.inspectionRecords must be at least 10".to_string()) }
        if !self.thresholds.is_object() && !self.thresholds.is_null() { return Err("thresholds must be an object".to_string()) }
        Ok(())
    }
}

/// Upper bound on `commands` per task, so one task cannot turn into a fleet-wide batch job.
pub const MAX_TASK_COMMANDS: usize = 20;

/// Whether `name` is a valid host, group, task or channel name.
pub fn is_valid_name(name: &str) -> bool {
    js_re!(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").is_match(name)
}

fn is_destination(value: &str) -> bool {
    js_re!(r"^[^-\s][^\s]*$").is_match(value)
}

fn is_hhmm(value: &str) -> bool {
    js_re!(r"^(?:[01]\d|2[0-3]):[0-5]\d$").is_match(value)
}

/// Validate one host entry against the schema.
pub fn validate_host(host: &HostSpec) -> Result<(), String> {
    if !is_valid_name(&host.name) {
        return Err(format!("invalid host name \"{}\"; use letters, digits, dot, underscore and dash, starting with a letter or digit", host.name));
    }
    let name = &host.name;
    if let Some(ssh) = &host.ssh
        && !is_destination(ssh)
    {
        return Err(format!("host \"{name}\": ssh destination must not start with a dash or contain whitespace"));
    }
    if let Some(port) = host.port
        && port > 65535
    {
        return Err(format!("host \"{name}\": port must be at most 65535"));
    }
    if let Some(user) = &host.user
        && !is_destination(user)
    {
        return Err(format!("host \"{name}\": user must not start with a dash or contain whitespace"));
    }
    for group in &host.groups {
        if !is_valid_name(group) {
            return Err(format!("host \"{name}\": invalid group name \"{group}\""));
        }
    }
    if let Some(sudo_user) = &host.sudo_user
        && !js_re!(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$").is_match(sudo_user)
    {
        return Err(format!("host \"{name}\": invalid sudoUser"));
    }
    if let Some(jump) = &host.proxy_jump
        && !is_destination(jump)
    {
        return Err(format!("host \"{name}\": proxyJump must not start with a dash or contain whitespace"));
    }
    Ok(())
}

pub fn validate_hosts(hosts: &[HostSpec]) -> Result<(), String> {
    hosts.iter().try_for_each(validate_host)
}

/// Group keys are free-form in the plugin's schema; only their shape is checked.
pub fn validate_groups(_groups: &BTreeMap<String, GroupSpec>) -> Result<(), String> {
    Ok(())
}

/// Validate one task entry against the schema (cross-field rules live in the inventory).
pub fn validate_task(task: &TaskSpec) -> Result<(), String> {
    if !is_valid_name(&task.name) {
        return Err(format!("invalid task name \"{}\"", task.name));
    }
    let name = &task.name;
    if let Some(channel) = task.notify.iter().find(|channel| !is_valid_name(channel)) {
        return Err(format!("task \"{name}\": invalid notification channel \"{channel}\""));
    }
    if let Some(quiet) = &task.quiet_hours {
        for value in [&quiet.start, &quiet.end] {
            if !value.is_empty() && !is_hhmm(value) {
                return Err(format!("task \"{name}\": quietHours times must be HH:MM"));
            }
        }
    }
    if let Some(template) = &task.template
        && !is_valid_name(template)
    {
        return Err(format!("task \"{name}\": invalid template name"));
    }
    if let Some(schedule) = &task.schedule {
        if let Some(daily) = &schedule.daily
            && !is_hhmm(daily)
        {
            return Err(format!("task \"{name}\": schedule.daily must be HH:MM"));
        }
        if schedule.weekdays.iter().any(|day| !(1..=7).contains(day)) {
            return Err(format!("task \"{name}\": schedule.weekdays must be ISO weekdays 1-7"));
        }
        if let Some(cron) = &schedule.cron
            && let Err(error) = crate::cron::parse(cron)
        {
            return Err(format!("task \"{name}\": schedule.cron \"{cron}\" {error}"));
        }
        if schedule.every_minutes == Some(0) {
            return Err(format!("task \"{name}\": schedule.everyMinutes must be at least 1"));
        }
    }
    if task.paths.iter().any(|path| !path.starts_with('/')) {
        return Err(format!("task \"{name}\": paths must be absolute"));
    }
    if task.days == Some(0) { return Err(format!("task \"{name}\": days must be at least 1")) }
    if task.hours == Some(0) { return Err(format!("task \"{name}\": hours must be at least 1")) }
    if task.commands.len() > MAX_TASK_COMMANDS {
        return Err(format!("task \"{name}\": at most {MAX_TASK_COMMANDS} commands"));
    }
    if task.commands.iter().any(|command| command.chars().count() > 2000) {
        return Err(format!("task \"{name}\": a command is longer than 2000 characters"));
    }
    if let Some(script) = &task.script
        && !is_valid_name(script)
    {
        return Err(format!("task \"{name}\": invalid script id"));
    }
    Ok(())
}

pub fn validate_tasks(tasks: &[TaskSpec]) -> Result<(), String> {
    tasks.iter().try_for_each(validate_task)
}
