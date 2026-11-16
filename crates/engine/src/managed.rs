//! Application-managed state: private atomic JSON files with optimistic revisions, and
//! `managed.json` (hosts added in the app, credential bindings, per-host policies, exclusions).

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::{AuthMethod, CAPABILITIES, HostSpec, Permission, PolicySpec, TaskSpec, is_valid_name, validate_hosts, validate_tasks};
use crate::fsutil::{create_private_dir, hex, random_hex, set_mode, with_suffix, write_new_private};

/// What a write says when another holds the lock, and when the file changed since it was read.
const BUSY: &str = "另一个保存操作正在进行，请稍后刷新重试。";
const STALE: &str = "数据已更新，请刷新后再保存，避免覆盖其他修改。";

/// What [`LocalState::read`] returns: the value and the revision a later change must name.
#[derive(Clone, Debug)]
pub struct Revisioned<T> {
    pub revision: String,
    pub value: T,
}

/// A private atomic JSON file with optimistic revisions and cross-process write exclusion.
pub struct LocalState<T> {
    path: PathBuf,
    empty: fn() -> T,
    validate: fn(Value) -> Result<T, String>,
}

fn revision_of(raw: &str) -> String {
    hex(&Sha256::digest(raw.as_bytes()))
}

impl<T: Serialize> LocalState<T> {
    pub fn new(path: PathBuf, empty: fn() -> T, validate: fn(Value) -> Result<T, String>) -> Self {
        LocalState { path, empty, validate }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn raw(&self) -> Result<String, String> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Ok(text),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(format!("cannot read {}: {error}", self.path.display())),
        }
    }

    fn parse(&self, raw: &str) -> Result<T, String> {
        if raw.is_empty() { return Ok((self.empty)()) }
        let value: Value = serde_json::from_str(raw).map_err(|error| format!("{} is not valid JSON: {error}", self.path.display()))?;
        (self.validate)(value)
    }

    /// The current value (the empty value when the file is missing) and its revision.
    pub fn read(&self) -> Result<Revisioned<T>, String> {
        let raw = self.raw()?;
        Ok(Revisioned { revision: revision_of(&raw), value: self.parse(&raw)? })
    }

    /// Replace the value if the file still has `revision`.
    /// Read and change in one go, waiting its turn: for a writer that has no person behind it to
    /// refresh and try again (the assistant queueing two drafts in one turn). The update is
    /// applied to whatever is there when the lock is had, so nothing another writer saved is lost.
    pub fn update(&self, update: impl Fn(T) -> Result<T, String>) -> Result<(), String> {
        let mut tries = 0;
        loop {
            let read = self.read()?;
            match self.change(&read.revision, &update) {
                Err(error) if (error == BUSY || error == STALE) && tries < 40 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                other => return other,
            }
        }
    }

    pub fn change(&self, revision: &str, update: impl FnOnce(T) -> Result<T, String>) -> Result<(), String> {
        self.change_with(revision, update, |commit| commit())
    }

    /// Stage under the write lock; `participate` receives the commit and may commit another file
    /// first. If the participant fails after committing this file, its exact preimage is restored.
    /// This handles write errors, not process crashes between two file renames.
    pub fn change_with(
        &self,
        revision: &str,
        update: impl FnOnce(T) -> Result<T, String>,
        participate: impl FnOnce(&mut dyn FnMut() -> Result<(), String>) -> Result<(), String>,
    ) -> Result<(), String> {
        let io = |error: std::io::Error| format!("cannot write {}: {error}", self.path.display());
        if let Some(parent) = self.path.parent() { create_private_dir(parent).map_err(io)? }
        let lock = with_suffix(&self.path, ".lock");
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&lock) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => return Err(BUSY.to_string()),
            Err(error) => return Err(io(error)),
        }
        let temp = with_suffix(&self.path, &format!(".{}.tmp", random_hex::<16>().unwrap_or_else(|_| std::process::id().to_string())));
        let mut previous = String::new();
        let mut committed = false;
        let result = (|| -> Result<(), String> {
            previous = self.raw()?;
            if revision_of(&previous) != revision { return Err(STALE.to_string()) }
            let current = self.parse(&previous)?;
            let updated = update(current)?;
            let next = (self.validate)(serde_json::to_value(&updated).map_err(|error| error.to_string())?)?;
            let text = format!("{}\n", serde_json::to_string_pretty(&next).map_err(|error| error.to_string())?);
            write_new_private(&temp, text.as_bytes()).map_err(io)?;
            set_mode(&temp, 0o600).map_err(io)?;
            let mut commit = || -> Result<(), String> {
                if committed { return Err("保存操作不能重复提交。".to_string()) }
                fs::rename(&temp, &self.path).map_err(io)?;
                committed = true;
                Ok(())
            };
            participate(&mut commit)?;
            if !committed { return Err("保存操作未完成提交。".to_string()) }
            Ok(())
        })();
        let result = match result {
            Err(error) if committed => {
                let restored = if previous.is_empty() {
                    match fs::remove_file(&self.path) {
                        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
                        _ => Ok(()),
                    }
                } else {
                    write_new_private(&temp, previous.as_bytes()).and_then(|()| fs::rename(&temp, &self.path))
                };
                match restored {
                    Ok(()) => Err(error),
                    Err(_) => Err("保存未完成，且无法恢复原数据。请刷新检查凭据及服务器关联后重试。".to_string()),
                }
            }
            other => other,
        };
        let _ = fs::remove_file(&temp);
        let _ = fs::remove_dir_all(&lock);
        result
    }
}

/// How a host logs in and which vault entries it uses; replaces the host's own three fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialBinding {
    pub auth: AuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo_secret: Option<String>,
}

/// The application's own inventory additions and per-host settings. Overrides apply to
/// same-named hosts from the YAML inventory too; external source files are never changed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedState {
    pub version: u32,
    pub hosts: Vec<HostSpec>,
    pub bindings: BTreeMap<String, CredentialBinding>,
    pub tasks: Vec<TaskSpec>,
    /// Per-host permission overrides.
    #[serde(default)]
    pub policies: BTreeMap<String, PolicySpec>,
    /// Owner-excluded inventory names.
    #[serde(default)]
    pub excluded_hosts: Vec<String>,
    /// Per-host service checks, threshold overrides and muted findings. Their types live with the
    /// collectors; here they are carried as-is and surfaced on [`crate::inventory::Host`].
    #[serde(default)]
    pub checks: BTreeMap<String, Value>,
    #[serde(default)]
    pub thresholds: BTreeMap<String, Value>,
    #[serde(default)]
    pub mutes: BTreeMap<String, Value>,
}

impl Default for ManagedState {
    fn default() -> Self {
        ManagedState {
            version: 1,
            hosts: Vec::new(),
            bindings: BTreeMap::new(),
            tasks: Vec::new(),
            policies: BTreeMap::new(),
            excluded_hosts: Vec::new(),
            checks: BTreeMap::new(),
            thresholds: BTreeMap::new(),
            mutes: BTreeMap::new(),
        }
    }
}

/// The store behind `<dataDir>/managed.json`.
pub fn managed_store(data_dir: &Path) -> LocalState<ManagedState> {
    LocalState::new(data_dir.join("managed.json"), ManagedState::default, validate_managed)
}

/// Validate the content of `managed.json`; files written before a field existed are accepted.
pub fn validate_managed(value: Value) -> Result<ManagedState, String> {
    let invalid = || "Invalid WispOps management file".to_string();
    let raw = value.as_object().ok_or_else(invalid)?;
    if raw.get("version").and_then(Value::as_u64) != Some(1) { return Err(invalid()) }
    let hosts = raw.get("hosts").filter(|v| v.is_array()).ok_or_else(invalid)?;
    let tasks = raw.get("tasks").filter(|v| v.is_array()).ok_or_else(invalid)?;
    let raw_bindings = raw.get("bindings").and_then(Value::as_object).ok_or_else(invalid)?;
    let hosts: Vec<HostSpec> = serde_json::from_value(hosts.clone()).map_err(|error| format!("Invalid managed host: {error}"))?;
    validate_hosts(&hosts)?;
    let tasks: Vec<TaskSpec> = serde_json::from_value(tasks.clone()).map_err(|error| format!("Invalid managed task: {error}"))?;
    validate_tasks(&tasks)?;
    let mut bindings = BTreeMap::new();
    for (name, binding) in raw_bindings {
        let auth = match binding.get("auth").and_then(Value::as_str) {
            Some("key") => AuthMethod::Key,
            Some("password") => AuthMethod::Password,
            _ => return Err("Invalid credential binding".to_string()),
        };
        let reference = |key: &str| -> Result<Option<String>, String> {
            match binding.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(text)) => Ok(Some(text.clone())),
                Some(_) => Err("Invalid credential reference".to_string()),
            }
        };
        bindings.insert(name.clone(), CredentialBinding { auth, login_secret: reference("loginSecret")?, sudo_secret: reference("sudoSecret")? });
    }
    let mut policies = BTreeMap::new();
    // Older files have no policies; an absent map means no overrides.
    if let Some(raw_policies) = raw.get("policies") {
        let map = raw_policies.as_object().ok_or_else(|| "Invalid policy overrides".to_string())?;
        for (name, policy) in map {
            policies.insert(name.clone(), validate_policy(policy)?);
        }
    }
    // Absent in older files. Reject malformed exclusions instead of re-enabling hosts.
    let mut excluded_hosts: Vec<String> = Vec::new();
    if let Some(raw_excluded) = raw.get("excludedHosts") {
        let list = raw_excluded.as_array().ok_or_else(|| "Invalid excluded hosts".to_string())?;
        for name in list {
            match name.as_str() {
                Some(name) if is_valid_name(name) => {
                    if !excluded_hosts.iter().any(|known| known == name) { excluded_hosts.push(name.to_string()) }
                }
                _ => return Err("Invalid excluded hosts".to_string()),
            }
        }
    }
    Ok(ManagedState {
        version: 1,
        hosts,
        tasks,
        bindings,
        policies,
        excluded_hosts,
        checks: per_host(raw.get("checks"), "service checks")?,
        thresholds: per_host(raw.get("thresholds"), "threshold overrides")?,
        mutes: per_host(raw.get("mutes"), "mutes")?,
    })
}

/// A per-host map from an optional field; empty lists and objects are dropped.
fn per_host(value: Option<&Value>, what: &str) -> Result<BTreeMap<String, Value>, String> {
    let mut out = BTreeMap::new();
    let Some(value) = value else { return Ok(out) };
    let map = value.as_object().ok_or_else(|| format!("Invalid {what}"))?;
    for (name, entry) in map {
        let keep = match entry {
            Value::Array(items) => !items.is_empty(),
            Value::Object(fields) => !fields.is_empty(),
            _ => return Err(format!("Invalid {what}")),
        };
        if keep { out.insert(name.clone(), entry.clone()); }
    }
    Ok(out)
}

/// A partial capability table with only allow / ask / deny values and no unknown keys.
pub fn validate_policy(value: &Value) -> Result<PolicySpec, String> {
    let map = value.as_object().ok_or_else(|| "Invalid policy".to_string())?;
    let mut policy = PolicySpec::default();
    for (key, permission) in map {
        let capability = CAPABILITIES.iter().copied().find(|c| c.as_str() == key).ok_or_else(|| format!("Unknown capability \"{key}\""))?;
        let permission: Permission = serde_json::from_value(permission.clone()).map_err(|_| format!("Invalid permission for {key}"))?;
        policy.set(capability, Some(permission));
    }
    Ok(policy)
}
