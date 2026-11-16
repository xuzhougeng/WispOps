//! Disk-full diagnosis on one host: where the space is, what grew, which large files are still
//! held open by processes or sit in running job directories, how much space deleted-but-open
//! files pin, and which caches are usually reclaimable. Everything here is read-only; a later
//! diagnosis of the same path verifies a cleanup against the stored snapshot.

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::jobs::{JOBS_SCRIPT, SchedulerJob, parse_scheduler_jobs};
use crate::sections::{FsUsage, Sections, format_kb, num, num_opt, parse_df, parse_df_inodes, parse_sections};
use crate::util::{OrderedMap, desc, fields, fill, iso_from_millis, millis, n, n_or, pad_start, shell_quote, to_iso};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskOptions {
    /// Absolute path whose filesystem is diagnosed.
    pub path: String,
    /// `du` depth below the path.
    pub depth: u32,
    /// Rows kept per list.
    pub top: usize,
    /// Files at least this large are listed as large files.
    pub min_file_mb: u64,
    /// Files at least this large and modified within `recent_minutes` are growth suspects.
    pub recent_min_file_mb: u64,
    pub recent_minutes: u64,
    /// Deadline for each `du`/`find` walk.
    pub walk_timeout_sec: u64,
}

/// Directories that commonly hold reclaimable data.
const KNOWN_DIRS: [&str; 18] = [
    "/var/log",
    "/var/log/journal",
    "/var/cache/apt/archives",
    "/var/cache/yum",
    "/var/cache/dnf",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/crash",
    "/var/lib/systemd/coredump",
    "/tmp",
    "/var/tmp",
    "$HOME/.cache/pip",
    "$HOME/.cache/huggingface",
    "$HOME/.conda/pkgs",
    "$HOME/miniconda3/pkgs",
    "$HOME/anaconda3/pkgs",
    "/opt/conda/pkgs",
    "/root/.cache",
];

/// Shell lines that print `@@open` (pid, size-if-deleted, target for every open fd whose target is
/// listed in `$<list_var>` field 4 or is deleted), `@@procs` for those pids, and `@@jobs` (running
/// scheduler jobs and their working directories). Shared by the disk and new-file collectors; the
/// caller defines `TAB`.
pub fn holders_script(list_var: &str) -> String {
    fill(include_str!("scripts/holders.sh.tpl"), &[("listVar", list_var), ("JOBS_SCRIPT", JOBS_SCRIPT)])
}

/// Build the diagnosis script; every user value is single-quoted.
pub fn disk_script(o: &DiskOptions) -> String {
    let known: Vec<String> = KNOWN_DIRS.iter().map(|d| if d.starts_with("$HOME") { format!("\"{d}\"") } else { shell_quote(d) }).collect();
    let known_timeout = (o.walk_timeout_sec / 4).clamp(5, 15);
    fill(
        include_str!("scripts/disk.sh.tpl"),
        &[
            ("shellQuote(o.path)", &shell_quote(&o.path)),
            ("o.depth", &o.depth.to_string()),
            ("o.top", &o.top.to_string()),
            ("o.minFileMb", &o.min_file_mb.to_string()),
            ("o.recentMinFileMb", &o.recent_min_file_mb.to_string()),
            ("o.recentMinutes", &o.recent_minutes.to_string()),
            ("o.walkTimeoutSec", &o.walk_timeout_sec.to_string()),
            ("knownTimeout", &known_timeout.to_string()),
            ("holdersScript('files')", &holders_script("files")),
            ("known", &known.join(" ")),
        ],
    )
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Holder {
    pub pid: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_sec: Option<f64>,
}

/// Why a large file is or is not a cleanup candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileVerdict {
    InUse,
    JobDirectory,
    RotatedLog,
    CoreDump,
    RecentlyWritten,
    Review,
}

/// A running scheduler job whose working directory protects the files under it.
pub type RunningJob = SchedulerJob;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub path: String,
    pub bytes: f64,
    pub modified: String,
    pub owner: String,
    pub holders: Vec<Holder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<RunningJob>,
    pub verdict: FileVerdict,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedOpen {
    pub pid: i64,
    pub bytes: f64,
    pub path: String,
    pub holder: Holder,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownDir {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount: Option<String>,
    pub same_filesystem: bool,
    pub hint: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirUsage {
    pub path: String,
    pub kb: f64,
    /// Change since the previous snapshot of the same path, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_kb: Option<f64>,
}

/// Stored per host and path to compute growth and verify cleanups.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskSnapshot {
    pub at: String,
    pub path: String,
    pub used_kb: f64,
    pub avail_kb: f64,
    pub use_pct: f64,
    pub dirs: OrderedMap<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotatedLogs {
    pub bytes: f64,
    pub count: f64,
}

/// Comparison against the previous diagnosis of the same path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SincePrevious {
    pub at: String,
    pub used_delta_kb: f64,
    pub use_pct_before: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskReport {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FsUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode_use_pct: Option<f64>,
    /// Whether /proc of other users was visible (root); without it holders are partial.
    pub full_visibility: bool,
    pub walk_incomplete: bool,
    pub top_dirs: Vec<DirUsage>,
    pub large_files: Vec<FileEntry>,
    pub recent_files: Vec<FileEntry>,
    pub deleted_open: Vec<DeletedOpen>,
    pub deleted_open_bytes: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal: Option<String>,
    pub docker: Vec<String>,
    pub known_dirs: Vec<KnownDir>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_logs: Option<RotatedLogs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_previous: Option<SincePrevious>,
    pub notes: Vec<String>,
}

/// A parsed diagnosis and the snapshot to store for the next one; no snapshot when `df` said nothing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskDiagnosis {
    pub report: DiskReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<DiskSnapshot>,
}

static KNOWN_HINTS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r"/var/log/journal$", "systemd journal: `journalctl --vacuum-size=<size>` or `--vacuum-time=<days>d` (sudo)"),
        (r"/var/log$", "logs: check rotation (logrotate), compress or remove rotated *.gz files"),
        (r"/var/cache/apt/archives$", "package cache: `apt-get clean` (sudo)"),
        (r"/var/cache/(?:yum|dnf)$", "package cache: `dnf clean all` / `yum clean all` (sudo)"),
        (r"/var/lib/(?:docker|containerd)$", "container storage: inspect `docker system df -v`; prune only unused images/volumes after confirming"),
        (r"/var/crash$|/coredump$", "crash dumps: inspect, then delete old dumps"),
        (r"^/(?:var/)?tmp$", "temporary files: remove files older than a few days that no process holds"),
        (r"\.cache/pip$", "pip cache: `pip cache purge` as the owning user"),
        (r"\.cache/huggingface$", "model cache: weights may be in use by jobs; `huggingface-cli scan-cache` before deleting"),
        (r"(?:conda|miniconda3|anaconda3)/pkgs$", "conda package cache: `conda clean --all` as the owning user"),
        (r"/root/\.cache$", "root user cache: review contents"),
    ]
    .into_iter()
    .map(|(pattern, hint)| (Regex::new(pattern).unwrap(), hint))
    .collect()
});
static CORE_DUMP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/core(?:\.[0-9]+)?$|\.core$").unwrap());
static ROTATED_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(?:log\.[0-9]+|[0-9]+\.gz|gz|xz|bz2|old)$").unwrap());
static LOG_DIR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/log(?:s)?/").unwrap());

fn hint_for(path: &str) -> &'static str {
    KNOWN_HINTS.iter().find(|(re, _)| re.is_match(path)).map_or("review contents", |(_, hint)| hint)
}

/// Who holds which file open, which deleted files are still pinned, and which jobs are running.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Holders {
    /// Holders per open path.
    pub open_by: HashMap<String, Vec<Holder>>,
    /// Deleted but still open files, largest first.
    pub deleted: Vec<DeletedOpen>,
    pub jobs: Vec<RunningJob>,
}

/// Parse the sections printed by [`holders_script`].
pub fn parse_holders(s: &Sections) -> Holders {
    let mut procs: HashMap<i64, Holder> = HashMap::new();
    for line in s.get("procs") {
        let f = fields(line);
        if let Some(pid) = num(f[0]) {
            let pid = pid as i64;
            procs.insert(pid, Holder { pid, user: f.get(1).map(|u| u.to_string()), elapsed_sec: num_opt(f.get(2).copied()), command: Some(f.get(3..).unwrap_or(&[]).join(" ")) });
        }
    }
    let holder_of = |pid: i64| procs.get(&pid).cloned().unwrap_or(Holder { pid, user: None, command: None, elapsed_sec: None });
    let mut open_by: HashMap<String, Vec<Holder>> = HashMap::new();
    let mut deleted: Vec<DeletedOpen> = Vec::new();
    for line in s.get("open") {
        let mut cells = line.split('\t');
        let Some(pid) = num_opt(cells.next()) else { continue };
        let pid = pid as i64;
        let size = cells.next();
        let target = cells.collect::<Vec<_>>().join("\t");
        if let Some(path) = target.strip_suffix(" (deleted)") {
            let bytes = num_opt(size).unwrap_or(0.0);
            if bytes > 0.0 {
                deleted.push(DeletedOpen { pid, bytes, path: path.to_string(), holder: holder_of(pid) });
            }
            continue;
        }
        let holders = open_by.entry(target).or_default();
        if !holders.iter().any(|h| h.pid == pid) {
            holders.push(holder_of(pid));
        }
    }
    deleted.sort_by(|a, b| desc(a.bytes, b.bytes));
    Holders { open_by, deleted, jobs: parse_scheduler_jobs(s) }
}

/// Whether `path` is `dir` or lies below it.
pub fn is_under(path: &str, dir: &str) -> bool {
    path == dir || if dir.ends_with('/') { path.starts_with(dir) } else { path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/')) }
}

/// The text before the first tab and the text after it.
pub(crate) fn split_tab(line: &str) -> Option<(&str, &str)> {
    line.split_once('\t')
}

/// Parse the diagnosis script's output, comparing against the previous snapshot. `now` stamps the
/// snapshot and stands in for the host's clock when the output lacks it.
pub fn parse_disk(output: &str, options: &DiskOptions, previous: Option<&DiskSnapshot>, now: DateTime<Utc>) -> DiskDiagnosis {
    let s = parse_sections(output);
    let mut notes = vec!["Job-directory checks cover visible Slurm/PBS/LSF jobs, up to 500 per scheduler. Missing tools, permissions or scheduler failures can hide active jobs; verify with the owner before cleanup.".to_string()];
    let filesystem = parse_df(s.get("df")).into_iter().next();
    let inode_use_pct = parse_df_inodes(s.get("dfi")).first().map(|i| i.use_pct);
    let full_visibility = s.first("whoami") == Some("0");
    let host_now = num_opt(s.first("now")).unwrap_or(millis(now) / 1000.0);

    let du_rc = num_opt(s.first("du_rc"));
    let find_rc = num_opt(s.first("find_rc"));
    let walk_incomplete = du_rc == Some(124.0) || find_rc == Some(124.0);
    if walk_incomplete {
        notes.push(format!("a directory walk hit the {}s deadline; lists are partial — narrow the path or raise walkTimeoutSec", options.walk_timeout_sec));
    }
    if du_rc.is_some_and(|rc| rc != 0.0 && rc != 124.0) {
        notes.push("du could not read some directories (permission denied); sizes are lower bounds — rerun with sudo for full totals".to_string());
    }
    if !full_visibility {
        notes.push("not running as root: only your own processes are visible as file holders, and deleted-open totals cover only them".to_string());
    }
    if s.first("gnufind") != Some("ok") {
        notes.push("this host has no GNU find (-printf); large-file lists are empty — the diagnosis supports GNU/Linux targets".to_string());
    }

    let dirs: Vec<(String, f64)> = s.get("du").iter().filter_map(|line| split_tab(line).and_then(|(kb, path)| Some((path.to_string(), num(kb)?)))).collect();
    let normalized_path = if options.path.chars().count() > 1 { options.path.trim_end_matches('/').to_string() } else { options.path.clone() };
    let top_dirs: Vec<DirUsage> = dirs
        .iter()
        .filter(|(path, _)| *path != normalized_path)
        .take(options.top)
        .map(|(path, kb)| DirUsage { path: path.clone(), kb: *kb, delta_kb: previous.and_then(|p| p.dirs.get(path)).map(|before| kb - before) })
        .collect();

    let Holders { open_by, deleted, jobs } = parse_holders(&s);
    // A deleted file no longer has a path on disk; attribute it by mount prefix.
    let deleted_open: Vec<DeletedOpen> = deleted.into_iter().filter(|d| filesystem.as_ref().is_none_or(|fs| is_under(&d.path, &fs.mount))).collect();

    let to_entry = |line: &String| -> Option<FileEntry> {
        let mut cells = line.split('\t');
        let bytes = num_opt(cells.next())?;
        let modified = num_opt(cells.next())?;
        let owner = cells.next()?;
        let file = cells.collect::<Vec<_>>().join("\t");
        let holders = open_by.get(&file).cloned().unwrap_or_default();
        let job = jobs.iter().find(|j| is_under(&file, &j.workdir)).cloned();
        let verdict = if !holders.is_empty() {
            FileVerdict::InUse
        } else if job.is_some() {
            FileVerdict::JobDirectory
        } else if CORE_DUMP.is_match(&file) {
            FileVerdict::CoreDump
        } else if ROTATED_NAME.is_match(&file) && LOG_DIR.is_match(&file) {
            FileVerdict::RotatedLog
        } else if host_now - modified < 3600.0 {
            FileVerdict::RecentlyWritten
        } else {
            FileVerdict::Review
        };
        Some(FileEntry { path: file, bytes, modified: iso_from_millis(modified * 1000.0), owner: owner.to_string(), holders, job, verdict })
    };
    let large_files: Vec<FileEntry> = s.get("big").iter().filter_map(to_entry).collect();
    let recent_files: Vec<FileEntry> = s.get("recent").iter().filter_map(to_entry).collect();

    let mut known_dirs: Vec<KnownDir> = s
        .get("known")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let (kb, mount) = (cells.next(), cells.next());
            let dir = cells.collect::<Vec<_>>().join("\t");
            if dir.is_empty() {
                return None;
            }
            Some(KnownDir {
                hint: hint_for(&dir).to_string(),
                path: dir,
                kb: num_opt(kb),
                mount: mount.filter(|m| !m.is_empty()).map(str::to_string),
                same_filesystem: filesystem.as_ref().is_some_and(|fs| mount == Some(fs.mount.as_str())),
            })
        })
        .collect();
    known_dirs.sort_by(|a, b| desc(a.kb.unwrap_or(0.0), b.kb.unwrap_or(0.0)));

    let rotated_logs = s.first("rotated").map(|line| {
        let mut cells = line.split('\t');
        RotatedLogs { bytes: num_opt(cells.next()).unwrap_or(0.0), count: num_opt(cells.next()).unwrap_or(0.0) }
    });

    if filesystem.is_none() {
        notes.push(format!("df returned nothing for {}; the path may not exist", options.path));
    }
    let snapshot = filesystem.as_ref().map(|fs| DiskSnapshot {
        at: to_iso(now),
        path: normalized_path.clone(),
        used_kb: fs.used_kb,
        avail_kb: fs.avail_kb,
        use_pct: fs.use_pct,
        dirs: dirs.iter().map(|(path, kb)| (path.as_str(), *kb)).collect(),
    });
    let since_previous = previous.zip(filesystem.as_ref()).map(|(p, fs)| SincePrevious { at: p.at.clone(), used_delta_kb: fs.used_kb - p.used_kb, use_pct_before: p.use_pct });

    let report = DiskReport {
        path: normalized_path,
        inode_use_pct,
        full_visibility,
        walk_incomplete,
        top_dirs,
        large_files,
        recent_files,
        deleted_open_bytes: deleted_open.iter().map(|d| d.bytes).sum(),
        deleted_open: deleted_open.into_iter().take(options.top).collect(),
        journal: (!s.get("journal").is_empty()).then(|| s.get("journal").join(" ")),
        docker: s.get("docker").to_vec(),
        known_dirs,
        rotated_logs,
        since_previous,
        filesystem,
        notes,
    };
    DiskDiagnosis { report, snapshot }
}

fn verdict_text(verdict: FileVerdict) -> &'static str {
    match verdict {
        FileVerdict::InUse => "IN USE — do not delete; truncate or rotate only after checking the holder",
        FileVerdict::JobDirectory => "inside a running Slurm job directory — ask the job owner",
        FileVerdict::RotatedLog => "rotated log — usually safe to remove",
        FileVerdict::CoreDump => "core dump — inspect, then usually safe to remove",
        FileVerdict::RecentlyWritten => "written within the last hour — likely still growing",
        FileVerdict::Review => "not held open — review before removing",
    }
}

/// Human-readable size from bytes.
pub fn bytes(count: f64) -> String {
    format_kb(count / 1024.0)
}

/// The first three holders as `command[pid user]`.
pub fn holder_text(holders: &[Holder]) -> String {
    holders.iter().take(3).map(|h| format!("{}[{}{}]", h.command.as_deref().unwrap_or("?"), h.pid, h.user.as_ref().map_or_else(String::new, |user| format!(" {user}")))).collect::<Vec<_>>().join(", ")
}

fn sign(delta: f64) -> &'static str {
    if delta >= 0.0 { "+" } else { "-" }
}

/// Model-facing rendering of one diagnosis.
pub fn render_disk(host: &str, r: &DiskReport) -> String {
    let mut lines: Vec<String> = Vec::new();
    let fs = r.filesystem.as_ref();
    lines.push(match fs {
        None => format!("## {host}:{}", r.path),
        Some(fs) => format!(
            "## {host}:{} — {} ({}) {}% used, {} free of {}{}",
            r.path,
            fs.mount,
            fs.filesystem,
            n(fs.use_pct),
            format_kb(fs.avail_kb),
            format_kb(fs.size_kb),
            r.inode_use_pct.map_or_else(String::new, |pct| format!(", inodes {}%", n(pct)))
        ),
    });
    if let Some(since) = &r.since_previous {
        let d = since.used_delta_kb;
        lines.push(format!("Since previous diagnosis ({}): used {}{} ({}% → {}%)", since.at, sign(d), format_kb(d.abs()), n(since.use_pct_before), n_or(fs.map(|fs| fs.use_pct), "undefined")));
    }
    lines.extend(r.notes.iter().map(|note| format!("Note: {note}")));
    if !r.top_dirs.is_empty() {
        lines.extend([String::new(), "Largest directories:".to_string()]);
        for d in &r.top_dirs {
            let delta = match d.delta_kb {
                Some(delta) if delta != 0.0 => format!("  ({}{} since previous)", if delta > 0.0 { "+" } else { "-" }, format_kb(delta.abs())),
                _ => String::new(),
            };
            lines.push(format!("  {}  {}{delta}", pad_start(&format_kb(d.kb), 7), d.path));
        }
    }
    let mut growing: Vec<&DirUsage> = r.top_dirs.iter().filter(|d| d.delta_kb.unwrap_or(0.0) > 0.0).collect();
    growing.sort_by(|a, b| desc(a.delta_kb.unwrap_or(0.0), b.delta_kb.unwrap_or(0.0)));
    if !growing.is_empty() {
        let listed: Vec<String> = growing.iter().take(5).map(|d| format!("{} +{}", d.path, format_kb(d.delta_kb.unwrap_or(0.0)))).collect();
        lines.extend([String::new(), format!("Growth since previous diagnosis: {}", listed.join(", "))]);
    }
    let file_line = |f: &FileEntry| {
        format!(
            "  {}  {}  [{}, modified {}] — {}{}{}",
            pad_start(&bytes(f.bytes), 7),
            f.path,
            f.owner,
            f.modified,
            verdict_text(f.verdict),
            if f.holders.is_empty() { String::new() } else { format!(" (held by {})", holder_text(&f.holders)) },
            f.job.as_ref().map_or_else(String::new, |job| format!(" (job {} of {})", job.id, job.user))
        )
    };
    if !r.recent_files.is_empty() {
        lines.extend([String::new(), "Large files modified recently (growth suspects):".to_string()]);
        lines.extend(r.recent_files.iter().map(file_line));
    }
    if !r.large_files.is_empty() {
        lines.extend([String::new(), "Largest files:".to_string()]);
        lines.extend(r.large_files.iter().map(file_line));
    }
    if r.deleted_open_bytes > 0.0 {
        lines.extend([
            String::new(),
            format!("Deleted but still open: {} is pinned by processes; deleting more files will not free it. Restart/reload the holder, or truncate through /proc/<pid>/fd after confirming:", bytes(r.deleted_open_bytes)),
        ]);
        lines.extend(r.deleted_open.iter().map(|d| format!("  {}  {}  held by {}", pad_start(&bytes(d.bytes), 7), d.path, holder_text(std::slice::from_ref(&d.holder)))));
    }
    let known: Vec<&KnownDir> = r.known_dirs.iter().filter(|k| k.kb.unwrap_or(0.0) >= 100.0 * 1024.0).collect();
    if !known.is_empty() {
        lines.extend([String::new(), "Common reclaimable locations:".to_string()]);
        for k in known {
            let place = if k.same_filesystem { String::new() } else { format!(" (on {})", k.mount.as_deref().unwrap_or("another filesystem")) };
            lines.push(format!("  {}  {}{place} — {}", pad_start(&format_kb(k.kb.unwrap_or(0.0)), 7), k.path, k.hint));
        }
    }
    if let Some(rotated) = r.rotated_logs.as_ref().filter(|rotated| rotated.count > 0.0) {
        lines.push(format!("Rotated logs under /var/log: {} files, {}", n(rotated.count), bytes(rotated.bytes)));
    }
    if let Some(journal) = &r.journal {
        lines.push(format!("Journal: {journal}"));
    }
    if !r.docker.is_empty() {
        lines.extend([String::new(), "docker system df:".to_string()]);
        lines.extend(r.docker.iter().map(|l| format!("  {l}")));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::Scheduler;
    use crate::util::testing::assert_golden;

    const DISK: &str = include_str!("testdata/disk.txt");

    fn options() -> DiskOptions {
        DiskOptions { path: "/data".into(), depth: 2, top: 10, min_file_mb: 100, recent_min_file_mb: 10, recent_minutes: 1440, walk_timeout_sec: 60 }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-29T00:00:00Z").unwrap().to_utc()
    }

    fn previous() -> DiskSnapshot {
        DiskSnapshot { at: "2026-10-20T00:00:00.000Z".into(), path: "/data".into(), used_kb: 900_000_000.0, avail_kb: 100_000_000.0, use_pct: 90.0, dirs: [("/data/projects", 550_000_000.0), ("/data/scratch", 40_000_000.0)].into_iter().collect() }
    }

    #[test]
    fn builds_the_script_the_plugin_built() {
        let o = DiskOptions { path: "/da'ta/x y".into(), ..options() };
        assert_eq!(disk_script(&o), include_str!("testdata/disk.golden.sh"));
        // A path that looks like a placeholder stays quoted text.
        let tricky = disk_script(&DiskOptions { path: "{{known}}".into(), ..options() });
        assert!(tricky.contains("P='{{known}}'; D=2;"));
    }

    #[test]
    fn classifies_files_by_who_still_needs_them() {
        let DiskDiagnosis { report, .. } = parse_disk(DISK, &options(), Some(&previous()), now());
        let verdicts: Vec<(&str, FileVerdict)> = report.large_files.iter().map(|f| (f.path.as_str(), f.verdict)).collect();
        assert_eq!(verdicts, [
            ("/data/projects/alice/train.log", FileVerdict::InUse),
            ("/data/projects/bob/model.ckpt", FileVerdict::JobDirectory),
            ("/data/logs/app.log.1.gz", FileVerdict::RotatedLog),
            ("/data/scratch/core.1234", FileVerdict::CoreDump),
        ]);
        assert_eq!(report.large_files[0].holders, [Holder { pid: 4242, user: Some("alice".into()), elapsed_sec: Some(86400.0), command: Some("python".into()) }]);
        assert_eq!(report.large_files[1].job, Some(RunningJob { id: "1001".into(), user: "bob".into(), workdir: "/data/projects/bob".into(), scheduler: Some(Scheduler::Slurm) }));
    }

    #[test]
    fn finds_pinned_space_and_growth_against_the_previous_snapshot() {
        let DiskDiagnosis { report, snapshot } = parse_disk(DISK, &options(), Some(&previous()), now());
        assert_eq!(report.deleted_open_bytes, 8_000_000_000.0);
        assert_eq!(report.deleted_open[0].holder.command.as_deref(), Some("rsyslogd"));
        assert_eq!(report.top_dirs.iter().find(|d| d.path == "/data/projects").unwrap().delta_kb, Some(50_000_000.0));
        assert_eq!(report.since_previous, Some(SincePrevious { at: previous().at, used_delta_kb: 50_000_000.0, use_pct_before: 90.0 }));
        assert_eq!((report.known_dirs[0].path.as_str(), report.known_dirs[0].same_filesystem), ("/var/log", false));
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.dirs.get("/data/scratch"), Some(&40_000_000.0));
        assert_eq!(snapshot.at, "2026-10-29T00:00:00.000Z");
        assert!(report.full_visibility);
    }

    #[test]
    fn matches_the_plugin_report_and_rendering() {
        let diagnosis = parse_disk(DISK, &options(), Some(&previous()), now());
        assert_golden(&diagnosis, include_str!("testdata/disk.report.json"));
        assert_eq!(serde_json::from_str::<DiskDiagnosis>(include_str!("testdata/disk.report.json")).unwrap(), diagnosis);
        let text = render_disk("nas-01", &diagnosis.report);
        assert_eq!(text, include_str!("testdata/disk.render.txt"));
        for expected in ["nas-01:/data — /data (/dev/sdb1) 95% used", "IN USE", "python[4242 alice]", "job 1001 of bob", "Deleted but still open", "/data/projects +47.7G", "conda clean"] {
            assert!(text.contains(expected), "{expected}");
        }
    }

    #[test]
    fn reports_partial_walks() {
        let output = DISK.replace("@@du_rc\n0", "@@du_rc\n124").replace("@@whoami\n0", "@@whoami\n1000");
        let DiskDiagnosis { report, .. } = parse_disk(&output, &options(), None, now());
        assert!(report.walk_incomplete);
        let notes = report.notes.join(" ");
        assert!(notes.contains("deadline") && notes.contains("not running as root"));
        let DiskDiagnosis { report, snapshot } = parse_disk("@@end\n", &options(), Some(&previous()), now());
        assert!(snapshot.is_none() && report.since_previous.is_none());
        assert_eq!(render_disk("h", &report).lines().next(), Some("## h:/data"));
    }

    #[test]
    fn protects_pbs_and_lsf_directories() {
        let data = "@@pbs_jobs\n123|alice|/data/pbs\n@@lsf_jobs\n456|RUN|bob|/data/lsf|/tmp\n@@big\n1000\t1700000000\talice\t/data/pbs/sample.sam\n@@files\n1000\t1700000000\talice\t/data/pbs/sample.sam\n200\t1700000000\talice\t/data/pbs/sample.bam\n2000\t1700000000\tbob\t/data/lsf/_STARtmp/tmp\n@@now\n1800000000\n@@gnufind\nok";
        let o = DiskOptions { path: "/data".into(), depth: 2, top: 15, min_file_mb: 1, recent_min_file_mb: 1, recent_minutes: 1440, walk_timeout_sec: 10 };
        assert_eq!(parse_disk(data, &o, None, now()).report.large_files[0].verdict, FileVerdict::JobDirectory);
    }

    #[test]
    fn knows_what_lies_under_a_directory() {
        assert!(is_under("/data/a", "/data") && is_under("/data", "/data") && is_under("/data/a", "/data/") && is_under("/x", "/"));
        assert!(!is_under("/database", "/data") && !is_under("/dat", "/data"));
    }
}
