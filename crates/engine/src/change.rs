//! Managed changes: back up → apply → verify → restore on failure, as one remote shell
//! transaction per host. A plan names every path it touches: existing regular files (copied),
//! new files (must not exist; rollback deletes them) and existing directories (tar archive;
//! rollback replaces the directory).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jsre::js_trim;
use crate::risk::{RiskAssessment, RiskLevel, classify_command};
use crate::ssh::shell_quote;
pub use crate::store::ChangeOutcome;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePlan {
    /// Inventory selector; `host` is accepted as an alias when validating.
    pub targets: String,
    /// Existing regular files, backed up with `cp -a`.
    pub files: Vec<String>,
    /// Paths that must not exist yet; rollback removes them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_files: Vec<String>,
    /// Existing directories, backed up as tar archives; rollback replaces them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directories: Vec<String>,
    pub command: String,
    pub verify: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_rollback: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

pub const MAX_PATHS_PER_KIND: usize = 30;

fn valid_path(value: &Value) -> bool {
    let Some(path) = value.as_str() else { return false };
    path.encode_utf16().count() <= 4096
        && path.starts_with('/')
        && path != "/"
        && !path.contains(['\0', '\r', '\n'])
        && !path.ends_with('/')
        && !path.split('/').any(|segment| segment == ".." || segment == ".")
}

fn path_list(value: Option<&Value>, key: &str) -> Result<Vec<String>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else { return Ok(Vec::new()) };
    let list = value.as_array().filter(|list| list.len() <= MAX_PATHS_PER_KIND).ok_or_else(|| format!("{key} must list at most {MAX_PATHS_PER_KIND} paths"))?;
    if list.iter().any(|path| !valid_path(path)) { return Err(format!("{key} entries must be absolute normalized paths")) }
    Ok(list.iter().filter_map(|path| path.as_str().map(str::to_string)).collect())
}

/// Validate the arguments of a managed change.
pub fn validate_change(value: &Value) -> Result<ChangePlan, String> {
    let text = |key: &str| value.get(key).and_then(Value::as_str);
    let present = |key: &str| value.get(key).filter(|v| !v.is_null());
    let targets = text("targets")
        .filter(|targets| !js_trim(targets).is_empty())
        .or_else(|| text("host").filter(|host| !js_trim(host).is_empty()))
        .ok_or_else(|| "ops_change requires targets (a host selector)".to_string())?;
    let files = path_list(value.get("files"), "files")?;
    let new_files = path_list(value.get("newFiles"), "newFiles")?;
    let directories = path_list(value.get("directories"), "directories")?;
    let all: Vec<&String> = files.iter().chain(&new_files).chain(&directories).collect();
    if all.is_empty() { return Err("ops_change requires at least one path in files, newFiles or directories".to_string()) }
    if all.iter().collect::<HashSet<_>>().len() != all.len() { return Err("duplicate paths across files, newFiles and directories".to_string()) }
    let within = |text: &str| text.encode_utf16().count() <= 8000 && !text.contains('\0');
    let mut required = Vec::new();
    for key in ["command", "verify", "reason"] {
        match text(key) {
            Some(text) if !js_trim(text).is_empty() && within(text) => required.push(text.to_string()),
            _ => return Err(format!("{key} is required and must be at most 8000 characters")),
        }
    }
    let after_rollback = match present("afterRollback") {
        None => None,
        Some(Value::String(text)) if within(text) => Some(text.clone()),
        Some(_) => return Err("invalid afterRollback command".to_string()),
    };
    let sudo = match present("sudo") {
        None => None,
        Some(Value::Bool(sudo)) => Some(*sudo),
        Some(_) => return Err("sudo must be boolean".to_string()),
    };
    let timeout_ms = match present("timeoutMs") {
        None => None,
        Some(number) => match number.as_f64() {
            Some(ms) if ms.is_finite() && ms >= 1000.0 => Some(ms as u64),
            _ => return Err("timeoutMs must be a number of milliseconds (at least 1000)".to_string()),
        },
    };
    let mut required = required.into_iter();
    Ok(ChangePlan {
        targets: targets.to_string(),
        files,
        new_files,
        directories,
        command: required.next().unwrap_or_default(),
        verify: required.next().unwrap_or_default(),
        after_rollback,
        reason: required.next().unwrap_or_default(),
        sudo,
        timeout_ms,
    })
}

/// Every command text the transaction runs verbatim: apply, verify, after-rollback.
pub fn change_commands(plan: &ChangePlan) -> Vec<String> {
    vec![plan.command.clone(), plan.verify.clone(), plan.after_rollback.clone().unwrap_or_else(|| "true".to_string())]
}

/// A managed change is at least `change`; destructive when any of its phases is.
pub fn change_risk(plan: &ChangePlan, extra_read: &HashSet<String>) -> RiskAssessment {
    let risks: Vec<RiskAssessment> = change_commands(plan).iter().map(|command| classify_command(command, extra_read)).collect();
    let mut reasons = vec!["managed change with automatic backup and rollback".to_string()];
    if !plan.directories.is_empty() {
        let count = plan.directories.len();
        reasons.push(format!("replaces {count} listed director{} from a tar backup on failure", if count == 1 { "y" } else { "ies" }));
    }
    if !plan.new_files.is_empty() { reasons.push(format!("deletes {} listed new file(s) on failure", plan.new_files.len())) }
    reasons.extend(risks.iter().flat_map(|risk| risk.reasons.iter().cloned()));
    RiskAssessment {
        level: if risks.iter().any(|risk| risk.level == RiskLevel::Destructive) { RiskLevel::Destructive } else { RiskLevel::Change },
        elevates: risks.iter().any(|risk| risk.elevates),
        reasons,
    }
}

fn after_rollback_or_true(plan: &ChangePlan) -> &str {
    plan.after_rollback.as_deref().filter(|command| !command.is_empty()).unwrap_or("true")
}

/// The whole plan in words, for the approval prompt and the audit log.
pub fn describe_change(plan: &ChangePlan) -> String {
    let mut lines = Vec::new();
    if !plan.files.is_empty() { lines.push(format!("Backup existing regular files: {}", plan.files.join(", "))) }
    if !plan.new_files.is_empty() { lines.push(format!("New files (must not exist; deleted on failure): {}", plan.new_files.join(", "))) }
    if !plan.directories.is_empty() { lines.push(format!("Backup directories as tar (replaced on failure): {}", plan.directories.join(", "))) }
    lines.push(format!("Apply:\n{}", plan.command));
    lines.push(format!("Verify:\n{}", plan.verify));
    lines.push(format!("On failure: restore every backup, then run:\n{}", after_rollback_or_true(plan)));
    lines.push(format!("Reason: {}", plan.reason));
    lines.join("\n")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeScriptOptions {
    /// Where `wispops-change.*` backup directories are created.
    pub backup_root: String,
    /// Backup directories older than this are pruned at the start of each run; 0 keeps them forever.
    pub retention_days: u64,
}

impl Default for ChangeScriptOptions {
    fn default() -> Self {
        ChangeScriptOptions { backup_root: "/var/tmp".to_string(), retention_days: 0 }
    }
}

/// POSIX `dirname` and `basename` of a validated absolute path.
fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(slash) => (&path[..slash], &path[slash + 1..]),
        None => (".", path),
    }
}

/// One remote transaction: no second SSH connection is needed to start rollback.
/// Backups are stored as `f<i>` (files) and `d<i>.tar` (directories) with a manifest.
/// Each stage is limited to `seconds` by GNU timeout.
pub fn change_script(plan: &ChangePlan, seconds: u64, options: &ChangeScriptOptions) -> String {
    let q = shell_quote;
    let backup_root = options.backup_root.as_str();
    let retention_days = options.retention_days;
    let stage = |script: &str| format!("timeout --signal=TERM --kill-after=2s {seconds}s sh -ec {}", q(script));
    let lines = |items: Vec<String>| items.join("\n");
    let mut out = String::new();
    out.push_str("umask 077\n");
    out.push_str("command -v timeout >/dev/null 2>&1 || { echo 'GNU timeout is required'; exit 20; }\n");
    if !plan.directories.is_empty() { out.push_str("command -v tar >/dev/null 2>&1 || { echo 'tar is required for directory backups'; exit 20; }\n") }
    if retention_days > 0 {
        out.push_str(&format!("find {} -maxdepth 1 -name 'wispops-change.*' -type d -mtime +{retention_days} -exec rm -rf -- {{}} + 2>/dev/null\n", q(backup_root)));
    }
    out.push_str(&lines(
        plan.files.iter().map(|f| format!("[ -f {0} ] && [ ! -L {0} ] || {{ echo {1}; exit 20; }}", q(f), q(&format!("Backup requires an existing regular non-symlink file: {f}")))).collect(),
    ));
    out.push('\n');
    out.push_str(&lines(
        plan.new_files
            .iter()
            .map(|f| {
                format!(
                    "[ ! -e {0} ] && [ ! -L {0} ] && [ -d {1} ] || {{ echo {2}; exit 20; }}",
                    q(f),
                    q(split_path(f).0),
                    q(&format!("New file must not exist yet and its directory must exist: {f}"))
                )
            })
            .collect(),
    ));
    out.push('\n');
    out.push_str(&lines(
        plan.directories.iter().map(|d| format!("[ -d {0} ] && [ ! -L {0} ] || {{ echo {1}; exit 20; }}", q(d), q(&format!("Backup requires an existing non-symlink directory: {d}")))).collect(),
    ));
    out.push('\n');
    out.push_str(&format!("B=$(mktemp -d {}) || exit 20\n", q(&format!("{backup_root}/wispops-change.XXXXXXXX"))));
    out.push_str("echo \"Backup directory: $B\"\n");
    out.push_str(&lines(plan.files.iter().enumerate().map(|(i, f)| format!("cp -a -- {} \"$B/f{i}\" || exit 21", q(f))).collect()));
    out.push('\n');
    out.push_str(&lines(
        plan.directories
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let (parent, name) = split_path(d);
                format!("tar -C {} -cf \"$B/d{i}.tar\" -- {} || exit 21", q(parent), q(name))
            })
            .collect(),
    ));
    out.push('\n');
    let manifest: Vec<String> = plan
        .files
        .iter()
        .map(|f| format!("printf 'file\\t%s\\n' {}", q(f)))
        .chain(plan.new_files.iter().map(|f| format!("printf 'new\\t%s\\n' {}", q(f))))
        .chain(plan.directories.iter().map(|d| format!("printf 'dir\\t%s\\n' {}", q(d))))
        .collect();
    out.push_str(&format!("{{ {}; }} > \"$B/manifest\"\n", manifest.join("; ")));
    out.push_str("started=0\nrollback() {\n  failed=0\n");
    out.push_str(&lines(
        plan.directories
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let name = split_path(d).1;
                format!(
                    "  if [ -L {path} ]; then failed=1\n  else\n    T=$(mktemp -d {template}) && tar -C \"$T\" -xpf \"$B/d{i}.tar\" && rm -rf -- {path} && mv -- \"$T/\"{name} {path} && rmdir -- \"$T\" || failed=1\n  fi",
                    path = q(d),
                    template = q(&format!("{d}.wispops-restore.XXXXXXXX")),
                    name = q(name),
                )
            })
            .collect(),
    ));
    out.push('\n');
    out.push_str(&lines(
        plan.files
            .iter()
            .enumerate()
            .map(|(i, f)| {
                format!(
                    "  if [ -L {path} ] || [ -d {path} ]; then failed=1\n  else\n    T=$(mktemp {template}) && cp -a -- \"$B/f{i}\" \"$T\" && mv -f -- \"$T\" {path} || failed=1\n  fi",
                    path = q(f),
                    template = q(&format!("{f}.wispops-restore.XXXXXXXX")),
                )
            })
            .collect(),
    ));
    out.push('\n');
    out.push_str(&lines(
        plan.new_files
            .iter()
            .map(|f| format!("  if [ -L {path} ] || [ -f {path} ]; then rm -f -- {path} || failed=1\n  elif [ -e {path} ]; then failed=1\n  fi", path = q(f)))
            .collect(),
    ));
    out.push('\n');
    out.push_str(&format!("  {} || failed=1\n", stage(after_rollback_or_true(plan))));
    out.push_str(
        "  if [ \"$failed\" = 0 ]; then echo 'WISPOPS_CHANGE=rolled-back'; else echo 'WISPOPS_CHANGE=rollback-failed'; fi\n  return \"$failed\"\n}\nfinish() {\n  rc=$?\n  trap - EXIT HUP INT TERM\n  if [ \"$started\" = 1 ]; then rollback || rc=24; fi\n  exit \"$rc\"\n}\ntrap finish EXIT\ntrap 'exit 25' HUP INT TERM\nstarted=1\necho 'WISPOPS_STAGE=apply'\n",
    );
    out.push_str(&format!("{} || exit 22\n", stage(&plan.command)));
    out.push_str("echo 'WISPOPS_STAGE=verify'\n");
    out.push_str(&format!("{} || exit 23\n", stage(&plan.verify)));
    out.push_str("started=0\necho 'WISPOPS_CHANGE=verified'\n");
    out
}

/// What the transaction markers in a host's output say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeResult {
    pub outcome: ChangeOutcome,
    pub backup_dir: Option<String>,
}

/// Read the transaction markers out of a host's output.
pub fn parse_change_output(stdout: &str, exit_code: Option<i32>) -> ChangeResult {
    // Lines end at `\n` or `\r`, as multi-line anchors do in the original patterns.
    let lines = || stdout.split(['\n', '\r', '\u{2028}', '\u{2029}']);
    let backup_dir = lines()
        .find_map(|line| line.strip_prefix("Backup directory: ").filter(|rest| !rest.is_empty()))
        .map(|rest| js_trim(rest).to_string());
    let mut marker = lines().filter_map(|line| line.strip_prefix("WISPOPS_CHANGE=")).filter_map(|value| match value {
        "verified" => Some(ChangeOutcome::Verified),
        "rolled-back" => Some(ChangeOutcome::RolledBack),
        "rollback-failed" => Some(ChangeOutcome::RollbackFailed),
        _ => None,
    });
    let outcome = match marker.next_back() {
        Some(outcome) => outcome,
        None if exit_code == Some(20) || exit_code == Some(21) => ChangeOutcome::Refused,
        None => ChangeOutcome::Unknown,
    };
    ChangeResult { outcome, backup_dir }
}
