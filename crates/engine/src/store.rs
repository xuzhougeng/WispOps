//! Local durable state: the operation audit log, inspection history, disk snapshots, probes and
//! change records, as JSON Lines under the data directory. Host names are validated by the
//! configuration, so they are safe file names.
//!
//! Inspection, snapshot and probe payloads belong to the collectors; those methods are generic and
//! only the file names and line layout are fixed here.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fsutil::{append_private, create_private_dir, write_private};
use crate::jsre::js_re;
use crate::risk::RiskLevel;
use crate::ssh::RunStatus;
use crate::time::{now_ms, parse_iso, utc_month};

/// How an action was authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authorization {
    ReadOnly,
    Policy,
    Grant,
    Approval,
    Task,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub tool: String,
    pub host: String,
    pub risk: RiskLevel,
    pub sudo: bool,
    pub authorization: Authorization,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub status: RunStatus,
    /// Remote exit status; written as `null` when the command never reported one.
    #[serde(default)]
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
}

/// What a managed change came to on one host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeOutcome {
    Verified,
    RolledBack,
    RollbackFailed,
    Refused,
    Unknown,
}

/// One host's outcome of a managed change, kept so retained backups can be listed later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRecord {
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub host: String,
    pub outcome: ChangeOutcome,
    pub status: RunStatus,
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Remote backup directory, when the transaction got far enough to create one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub new_files: Vec<String>,
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub sudo: bool,
}

/// One mutex per file path, shared by every store in the process, for read-modify-write cycles.
fn file_lock(path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
    let mut locks = LOCKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    locks.entry(path.to_path_buf()).or_default().clone()
}

fn hold(lock: &Mutex<()>) -> MutexGuard<'_, ()> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn io_error(path: &Path, error: std::io::Error) -> String {
    format!("{}: {error}", path.display())
}

/// The lines of a JSON Lines file that hold valid JSON, verbatim. A torn final line from an
/// interrupted append is skipped, not fatal; a missing file is empty.
fn read_raw_lines(path: &Path) -> Result<Vec<String>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(path, error)),
    };
    let text = String::from_utf8_lossy(&bytes);
    Ok(text
        .split('\n')
        .filter(|line| !line.trim().is_empty() && serde_json::from_str::<IgnoredAny>(line).is_ok())
        .map(str::to_string)
        .collect())
}

fn read_json_lines<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, String> {
    Ok(read_raw_lines(path)?.iter().filter_map(|line| serde_json::from_str(line).ok()).collect())
}

/// Reads a JSON Lines file newest first in fixed-size chunks. Malformed and torn lines, lines
/// that do not deserialize as `T`, and lines over 1 MiB are skipped; a missing file is empty.
pub struct ReverseJsonLines<T> {
    file: Option<File>,
    pos: u64,
    tail: Vec<u8>,
    oversized: bool,
    pending: VecDeque<Vec<u8>>,
    marker: PhantomData<T>,
}

const REVERSE_CHUNK: u64 = 64 * 1024;
const MAX_LINE: usize = 1024 * 1024;

/// Iterate a JSON Lines file from its last line to its first.
pub fn reverse_json_lines<T: DeserializeOwned>(path: &Path) -> Result<ReverseJsonLines<T>, String> {
    let (file, pos) = match File::open(path) {
        Ok(file) => {
            let size = file.metadata().map_err(|error| io_error(path, error))?.len();
            (Some(file), size)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => (None, 0),
        Err(error) => return Err(io_error(path, error)),
    };
    Ok(ReverseJsonLines { file, pos, tail: Vec::new(), oversized: false, pending: VecDeque::new(), marker: PhantomData })
}

impl<T> ReverseJsonLines<T> {
    /// Read the next block towards the start of the file and queue its complete lines.
    fn fill(&mut self) -> bool {
        let Some(file) = self.file.as_mut() else { return false };
        if self.pos == 0 {
            if !self.oversized && !self.tail.is_empty() { self.pending.push_back(std::mem::take(&mut self.tail)) }
            self.file = None;
            return !self.pending.is_empty();
        }
        let size = REVERSE_CHUNK.min(self.pos);
        self.pos -= size;
        let mut data = vec![0u8; size as usize];
        if file.seek(SeekFrom::Start(self.pos)).is_err() || file.read_exact(&mut data).is_err() {
            self.file = None;
            return false;
        }
        // The split point may fall inside a UTF-8 character; joining bytes before decoding keeps it whole.
        data.extend_from_slice(&self.tail);
        let mut end = data.len();
        for i in (0..data.len()).rev() {
            if data[i] != b'\n' { continue }
            if !self.oversized { self.pending.push_back(data[i + 1..end].to_vec()) }
            self.oversized = false;
            end = i;
        }
        data.truncate(end);
        self.tail = data;
        if self.tail.len() > MAX_LINE {
            self.tail.clear();
            self.oversized = true;
        }
        true
    }
}

impl<T: DeserializeOwned> Iterator for ReverseJsonLines<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        loop {
            while let Some(line) = self.pending.pop_front() {
                if let Ok(value) = serde_json::from_slice::<T>(&line) { return Some(value) }
            }
            if !self.fill() && self.pending.is_empty() { return None }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreRetention {
    /// Inspection records kept per host.
    pub inspection_records: usize,
    /// Monthly audit partitions kept, counting the current one; 0 keeps all.
    pub audit_months: u32,
}

impl Default for StoreRetention {
    fn default() -> Self {
        StoreRetention { inspection_records: 1000, audit_months: 12 }
    }
}

impl From<&crate::config::RetentionSpec> for StoreRetention {
    fn from(spec: &crate::config::RetentionSpec) -> Self {
        StoreRetention { inspection_records: spec.inspection_records as usize, audit_months: spec.audit_months.min(u64::from(u32::MAX)) as u32 }
    }
}

/// First month that `audit_months` retention keeps, as `YYYY-MM`.
pub fn audit_cutoff_month(audit_months: u32, now_ms: i64) -> String {
    let month = utc_month(now_ms);
    let year: i64 = month[..4].parse().unwrap_or(1970);
    let month_index: i64 = month[5..7].parse::<i64>().unwrap_or(1) - 1;
    let total = year * 12 + month_index - (i64::from(audit_months) - 1);
    format!("{:04}-{:02}", total.div_euclid(12), total.rem_euclid(12) + 1)
}

/// Which audit rows to read.
#[derive(Clone, Debug, Default)]
pub struct AuditFilter {
    pub hosts: Option<HashSet<String>>,
    pub since_ms: Option<i64>,
    pub limit: usize,
}

fn is_audit_partition(name: &str) -> bool {
    js_re!(r"^\d{4}-\d{2}\.jsonl$").is_match(name)
}

pub struct OpsStore {
    dir: PathBuf,
    retention: StoreRetention,
    pruned_for: Mutex<Option<String>>,
}

impl OpsStore {
    pub fn new(dir: impl Into<PathBuf>, retention: StoreRetention) -> Self {
        OpsStore { dir: dir.into(), retention, pruned_for: Mutex::new(None) }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure(&self, sub: &str) -> Result<PathBuf, String> {
        let path = if sub.is_empty() { self.dir.clone() } else { self.dir.join(sub) };
        create_private_dir(&path).map_err(|error| io_error(&path, error))?;
        Ok(path)
    }

    /// Replace a JSON Lines file with the newest `keep - 1` rows plus `row`, through a rename so readers never see a torn file.
    fn write_bounded(&self, file: &Path, rows: &[String], row: &str, keep: usize) -> Result<(), String> {
        let older = keep.max(1) - 1;
        let mut kept: Vec<&str> = rows[rows.len().saturating_sub(older)..].iter().map(String::as_str).collect();
        kept.push(row);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let tmp = crate::fsutil::with_suffix(file, &format!(".{}.{nanos:x}.tmp", std::process::id()));
        write_private(&tmp, format!("{}\n", kept.join("\n")).as_bytes()).map_err(|error| io_error(&tmp, error))?;
        fs::rename(&tmp, file).map_err(|error| io_error(file, error))
    }

    /// Append one audit row to the month it happened in, pruning old months once per month.
    pub fn audit(&self, entry: &AuditEntry) -> Result<(), String> {
        let at = parse_iso(&entry.at).ok_or_else(|| format!("audit entry has an invalid time \"{}\"", entry.at))?;
        let month = utc_month(at);
        let dir = self.ensure("audit")?;
        let file = dir.join(format!("{month}.jsonl"));
        let line = format!("{}\n", serde_json::to_string(entry).map_err(|error| error.to_string())?);
        {
            let lock = file_lock(&file);
            let _guard = hold(&lock);
            append_private(&file, line.as_bytes()).map_err(|error| io_error(&file, error))?;
        }
        if self.retention.audit_months > 0 {
            let mut pruned = self.pruned_for.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if pruned.as_deref() != Some(month.as_str()) {
                *pruned = Some(month);
                drop(pruned);
                self.prune_audit_at(at)?;
            }
        }
        Ok(())
    }

    fn audit_partitions(&self) -> Result<Vec<String>, String> {
        let dir = self.dir.join("audit");
        match fs::read_dir(&dir) {
            Ok(entries) => Ok(entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| is_audit_partition(name))
                .collect()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(io_error(&dir, error)),
        }
    }

    /// Delete monthly audit partitions older than the retention window; the legacy `audit.jsonl` is left alone.
    pub fn prune_audit_at(&self, now_ms: i64) -> Result<Vec<String>, String> {
        if self.retention.audit_months == 0 { return Ok(Vec::new()) }
        let cutoff = audit_cutoff_month(self.retention.audit_months, now_ms);
        let mut names: Vec<String> = self.audit_partitions()?.into_iter().filter(|name| name[..7] < *cutoff).collect();
        names.sort();
        for name in &names {
            let path = self.dir.join("audit").join(name);
            match fs::remove_file(&path) {
                Err(error) if error.kind() != ErrorKind::NotFound => return Err(io_error(&path, error)),
                _ => {}
            }
        }
        Ok(names)
    }

    pub fn prune_audit(&self) -> Result<Vec<String>, String> {
        self.prune_audit_at(now_ms())
    }

    /// The newest `limit` matching audit rows, oldest first, across monthly partitions and the legacy single file.
    pub fn read_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, String> {
        if filter.limit == 0 { return Ok(Vec::new()) }
        let mut names = self.audit_partitions()?;
        names.sort();
        names.reverse();
        let month = filter.since_ms.map(utc_month);
        let mut paths: Vec<PathBuf> =
            names.iter().filter(|name| month.as_deref().is_none_or(|month| &name[..7] >= month)).map(|name| self.dir.join("audit").join(name)).collect();
        paths.push(self.dir.join("audit.jsonl"));
        let mut rows: Vec<AuditEntry> = Vec::new();
        'files: for path in paths {
            for row in reverse_json_lines::<AuditEntry>(&path)? {
                let Some(at) = parse_iso(&row.at) else { continue };
                if filter.hosts.as_ref().is_none_or(|hosts| hosts.contains(&row.host)) && filter.since_ms.is_none_or(|since| at >= since) { rows.push(row) }
                if rows.len() >= filter.limit { break 'files }
            }
        }
        rows.reverse();
        Ok(rows)
    }

    /// Append one inspection, keeping only the newest `retention.inspection_records` per host.
    pub fn append_history<T: Serialize>(&self, host: &str, record: &T) -> Result<(), String> {
        let file = self.ensure("inspections")?.join(format!("{host}.jsonl"));
        let line = serde_json::to_string(record).map_err(|error| error.to_string())?;
        let lock = file_lock(&file);
        let _guard = hold(&lock);
        let rows = read_raw_lines(&file)?;
        if rows.len() < self.retention.inspection_records {
            return append_private(&file, format!("{line}\n").as_bytes()).map_err(|error| io_error(&file, error));
        }
        self.write_bounded(&file, &rows, &line, self.retention.inspection_records)
    }

    fn history_rows(&self, host: &str, limit: usize) -> Result<Vec<Value>, String> {
        let mut rows: Vec<Value> = Vec::new();
        if limit == 0 { return Ok(rows) }
        for row in reverse_json_lines::<Value>(&self.dir.join("inspections").join(format!("{host}.jsonl")))? {
            if !row.get("diskPct").is_some_and(|disk| disk.is_object()) || !row.get("findings").is_some_and(Value::is_array) { continue }
            rows.push(row);
            if rows.len() >= limit { break }
        }
        rows.reverse();
        Ok(rows)
    }

    /// The newest `limit` inspections of a host, oldest first. Rows without `diskPct` or a `findings` list are skipped.
    pub fn read_history<T: DeserializeOwned>(&self, host: &str, limit: usize) -> Result<Vec<T>, String> {
        Ok(self.history_rows(host, limit)?.into_iter().filter_map(|row| serde_json::from_value(row).ok()).collect())
    }

    /// The latest successful inspection among the newest 50, used as the trend baseline.
    pub fn last_healthy<T: DeserializeOwned>(&self, host: &str) -> Result<Option<T>, String> {
        let rows = self.history_rows(host, 50)?;
        Ok(rows.into_iter().rev().find(|row| row.get("status").and_then(Value::as_str) == Some("ok")).and_then(|row| serde_json::from_value(row).ok()))
    }

    /// The latest saved snapshot of one path on a host.
    pub fn disk_snapshot<T: DeserializeOwned>(&self, host: &str, path: &str) -> Result<Option<T>, String> {
        let rows: Vec<Value> = read_json_lines(&self.dir.join("disk").join(format!("{host}.jsonl")))?;
        Ok(rows.into_iter().rev().find(|row| row.get("path").and_then(Value::as_str) == Some(path)).and_then(|row| serde_json::from_value(row).ok()))
    }

    /// Save a disk snapshot (an object with a `path`), keeping a bounded tail of 50 per host.
    pub fn save_disk_snapshot<T: Serialize>(&self, host: &str, snapshot: &T) -> Result<(), String> {
        self.append_bounded("disk", host, snapshot, 50)
    }

    /// Capability probes by host name; a missing or unreadable file is empty, and entries that do not fit `T` are left out.
    pub fn probes<T: DeserializeOwned>(&self) -> Result<BTreeMap<String, T>, String> {
        Ok(self.raw_probes()?.into_iter().filter_map(|(host, probe)| serde_json::from_value(probe).ok().map(|probe| (host, probe))).collect())
    }

    fn raw_probes(&self) -> Result<serde_json::Map<String, Value>, String> {
        let path = self.dir.join("probes.json");
        match fs::read_to_string(&path) {
            Ok(text) => Ok(serde_json::from_str(&text).unwrap_or_default()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(serde_json::Map::new()),
            Err(error) => Err(io_error(&path, error)),
        }
    }

    /// Merge probes into `probes.json`.
    pub fn save_probes<T: Serialize>(&self, update: &BTreeMap<String, T>) -> Result<(), String> {
        let file = self.ensure("")?.join("probes.json");
        let lock = file_lock(&file);
        let _guard = hold(&lock);
        let mut merged = self.raw_probes()?;
        for (host, probe) in update {
            merged.insert(host.clone(), serde_json::to_value(probe).map_err(|error| error.to_string())?);
        }
        let tmp = crate::fsutil::with_suffix(&file, &format!(".{}.tmp", std::process::id()));
        write_private(&tmp, serde_json::to_string_pretty(&merged).map_err(|error| error.to_string())?.as_bytes()).map_err(|error| io_error(&tmp, error))?;
        fs::rename(&tmp, &file).map_err(|error| io_error(&file, error))
    }

    pub fn record_change(&self, record: &ChangeRecord) -> Result<(), String> {
        self.append_bounded("changes", &record.host, record, 200)
    }

    /// The newest `limit` change records of a host, oldest first.
    pub fn read_changes(&self, host: &str, limit: usize) -> Result<Vec<ChangeRecord>, String> {
        let rows: Vec<ChangeRecord> = self.read_bounded("changes", host)?;
        let skip = rows.len().saturating_sub(limit);
        Ok(rows.into_iter().skip(skip).collect())
    }

    /// Append to a bounded per-key JSON Lines log at `<sub>/<key>.jsonl`, keeping the newest `keep` rows.
    pub fn append_bounded<T: Serialize>(&self, sub: &str, key: &str, row: &T, keep: usize) -> Result<(), String> {
        let file = self.ensure(sub)?.join(format!("{key}.jsonl"));
        let line = serde_json::to_string(row).map_err(|error| error.to_string())?;
        let lock = file_lock(&file);
        let _guard = hold(&lock);
        let rows = read_raw_lines(&file)?;
        self.write_bounded(&file, &rows, &line, keep)
    }

    /// Every row of `<sub>/<key>.jsonl` that fits `T`, oldest first.
    pub fn read_bounded<T: DeserializeOwned>(&self, sub: &str, key: &str) -> Result<Vec<T>, String> {
        read_json_lines(&self.dir.join(sub).join(format!("{key}.jsonl")))
    }
}
