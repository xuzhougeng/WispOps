//! Recent-file analysis (近期新增文件分析): what appeared or changed under some paths in the last N
//! days, where it landed, who wrote it, what kind of data it is (with sequencing and
//! analysis-pipeline knowledge), which of it is still in use, which files a sibling makes
//! redundant, which pipeline work directories belong to finished runs, and a cleanup plan ordered
//! by reclaimable space. Read-only.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::disk::{Holder, RunningJob, bytes, holder_text, holders_script, is_under, parse_holders};
use crate::omics::{FileKind, RETENTION_ORDER, Redundancy, Retention, classify_path, find_redundant, kind_by_id, retention_label};
use crate::sections::{format_kb, num_opt, parse_sections};
use crate::util::{OrderedMap, desc, fill, iso_from_millis, js_round, n, pad_start, shell_quote, to_iso};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesOptions {
    /// Absolute roots to scan.
    pub paths: Vec<String>,
    /// Window: files modified within this many days.
    pub days: u32,
    /// Directory aggregation depth below each root.
    pub depth: u32,
    /// Files at least this large are listed and classified individually.
    pub list_min_mb: u64,
    /// Most individually listed files.
    pub max_files: u64,
    pub top: u64,
    pub walk_timeout_sec: u64,
}

/// Build the scan script; every root is single-quoted.
pub fn files_script(o: &FilesOptions) -> String {
    let roots = o.paths.iter().map(|path| shell_quote(path)).collect::<Vec<_>>().join(" ");
    let pipeline_timeout = (o.walk_timeout_sec / 4).clamp(5, 30);
    fill(
        include_str!("scripts/files.sh.tpl"),
        &[
            ("o.days", &o.days.to_string()),
            ("o.depth", &o.depth.to_string()),
            ("o.top", &o.top.to_string()),
            ("o.listMinMb", &o.list_min_mb.to_string()),
            ("o.maxFiles", &o.max_files.to_string()),
            ("o.walkTimeoutSec", &o.walk_timeout_sec.to_string()),
            ("pipelineTimeout", &pipeline_timeout.to_string()),
            ("roots", &roots),
            ("holdersScript('flist')", &holders_script("flist")),
        ],
    )
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentFile {
    pub path: String,
    pub bytes: f64,
    pub modified: String,
    pub owner: String,
    pub kind: FileKind,
    pub holders: Vec<Holder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<RunningJob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redundant_with: Option<Redundancy>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PipelineKind {
    Nextflow,
    Snakemake,
    Star,
    Cellranger,
    Tmp,
}

impl PipelineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PipelineKind::Nextflow => "nextflow",
            PipelineKind::Snakemake => "snakemake",
            PipelineKind::Star => "star",
            PipelineKind::Cellranger => "cellranger",
            PipelineKind::Tmp => "tmp",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineDir {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kb: Option<f64>,
    pub modified: String,
    /// Run state as far as markers tell (complete, failed, incomplete-jobs, locked-running, ...).
    pub state: String,
    pub kind: PipelineKind,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupItem {
    pub title: String,
    pub reclaim_bytes: f64,
    pub paths: Vec<String>,
    pub why: String,
    /// Checks to run before acting.
    pub verify: String,
    pub retention: Retention,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesSnapshot {
    pub at: String,
    pub roots: Vec<String>,
    pub days: u32,
    pub total_bytes: f64,
    pub total_files: f64,
    pub dirs: OrderedMap<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirBytes {
    pub path: String,
    pub bytes: f64,
    pub files: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_bytes: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserBytes {
    pub user: String,
    pub bytes: f64,
    pub files: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KindBytes {
    pub kind: FileKind,
    pub bytes: f64,
    pub files: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDelta {
    pub at: String,
    pub delta_bytes: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesReport {
    pub roots: Vec<String>,
    pub days: u32,
    pub total_bytes: f64,
    pub total_files: f64,
    /// Share of the window's bytes that the individually classified files cover.
    pub classified_share: f64,
    pub incomplete_roots: Vec<String>,
    pub full_visibility: bool,
    pub dirs: Vec<DirBytes>,
    pub users: Vec<UserBytes>,
    pub by_kind: Vec<KindBytes>,
    pub files: Vec<RecentFile>,
    pub pipelines: Vec<PipelineDir>,
    pub plan: Vec<CleanupItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_previous: Option<ScanDelta>,
    pub notes: Vec<String>,
}

/// A parsed scan and the snapshot to store for the next one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesScan {
    pub report: FilesReport,
    pub snapshot: FilesSnapshot,
}

fn pipeline_kind(path: &str) -> PipelineKind {
    let base = path.rsplit('/').next().unwrap_or(path);
    match base {
        "work" => PipelineKind::Nextflow,
        ".snakemake" => PipelineKind::Snakemake,
        "_STARtmp" => PipelineKind::Star,
        _ if base.len() >= 6 && base.starts_with("SC_") && base.ends_with("_CS") && !base.contains('\n') => PipelineKind::Cellranger,
        _ => PipelineKind::Tmp,
    }
}

/// Parse the scan output and build the cleanup plan; `now` stamps the snapshot.
pub fn parse_files(output: &str, options: &FilesOptions, previous: Option<&FilesSnapshot>, now: DateTime<Utc>) -> FilesScan {
    let s = parse_sections(output);
    let mut notes = vec!["Job-directory checks cover visible Slurm/PBS/LSF jobs, up to 500 per scheduler. Missing tools, permissions or scheduler failures can hide active jobs; verify with the owner before cleanup.".to_string()];
    let full_visibility = s.first("whoami") == Some("0");
    let mut totals = s.first("total").map(|line| line.split('\t')).into_iter().flatten();
    let total_bytes = num_opt(totals.next()).unwrap_or(0.0);
    let total_files = num_opt(totals.next()).unwrap_or(0.0);
    let incomplete_roots: Vec<String> = s
        .get("rc")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            (cells.next() == Some("124")).then(|| cells.next().map(str::to_string)).flatten()
        })
        .collect();
    if !incomplete_roots.is_empty() {
        notes.push(format!("the scan of {} hit the {}s deadline; totals are partial — narrow the paths or raise walkTimeoutSec", incomplete_roots.join(", "), options.walk_timeout_sec));
    }
    if !full_visibility {
        notes.push("not running as root: unreadable directories are skipped and only your own processes show up as file holders".to_string());
    }
    if s.first("gnufind") != Some("ok") {
        notes.push("this host has no GNU find (-printf); file lists are empty — the analysis supports GNU/Linux targets".to_string());
    }

    let dirs: Vec<DirBytes> = s
        .get("dirs")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let (b, f) = (cells.next(), cells.next());
            let path = cells.collect::<Vec<_>>().join("\t");
            let size = num_opt(b)?;
            if path.is_empty() {
                return None;
            }
            let delta_bytes = previous.and_then(|p| p.dirs.get(&path)).map(|before| size - before);
            Some(DirBytes { path, bytes: size, files: num_opt(f).unwrap_or(0.0), delta_bytes })
        })
        .collect();
    let users: Vec<UserBytes> = s
        .get("users")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let (b, f, user) = (cells.next(), cells.next(), cells.next()?);
            Some(UserBytes { user: user.to_string(), bytes: num_opt(b)?, files: num_opt(f).unwrap_or(0.0) })
        })
        .collect();

    let holders = parse_holders(&s);
    let (open_by, jobs) = (&holders.open_by, &holders.jobs);
    let raw: Vec<(String, f64, f64, &str)> = s
        .get("files")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let (size, modified, owner) = (num_opt(cells.next())?, num_opt(cells.next())?, cells.next()?);
            let path = cells.collect::<Vec<_>>().join("\t");
            (!path.is_empty()).then_some((path, size, modified, owner))
        })
        .collect();
    let raw_paths: Vec<&str> = raw.iter().map(|(path, ..)| path.as_str()).collect();
    let redundant: HashMap<String, Redundancy> = find_redundant(&raw_paths).into_iter().map(|r| (r.path.clone(), r)).collect();
    let files: Vec<RecentFile> = raw
        .iter()
        .map(|(path, size, modified, owner)| RecentFile {
            path: path.clone(),
            bytes: *size,
            modified: iso_from_millis(modified * 1000.0),
            owner: owner.to_string(),
            kind: classify_path(path),
            holders: open_by.get(path).cloned().unwrap_or_default(),
            job: jobs.iter().find(|j| is_under(path, &j.workdir)).cloned(),
            redundant_with: redundant.get(path).cloned(),
        })
        .collect();
    let classified_bytes: f64 = files.iter().map(|f| f.bytes).sum();
    let classified_share = if total_bytes > 0.0 { (classified_bytes / total_bytes).min(1.0) } else { 1.0 };

    let mut by_kind: Vec<KindBytes> = Vec::new();
    for f in &files {
        match by_kind.iter_mut().find(|entry| entry.kind.id == f.kind.id) {
            Some(entry) => {
                entry.bytes += f.bytes;
                entry.files += 1.0;
            }
            None => by_kind.push(KindBytes { kind: f.kind.clone(), bytes: f.bytes, files: 1.0 }),
        }
    }
    by_kind.sort_by(|a, b| desc(a.bytes, b.bytes));

    let mut pipelines: Vec<PipelineDir> = s
        .get("pipelines")
        .iter()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            let (kb, mtime, state) = (cells.next(), cells.next(), cells.next());
            let path = cells.collect::<Vec<_>>().join("\t");
            if path.is_empty() {
                return None;
            }
            Some(PipelineDir { kind: pipeline_kind(&path), path, kb: num_opt(kb), modified: iso_from_millis(num_opt(mtime).unwrap_or(0.0) * 1000.0), state: state.unwrap_or("-").to_string() })
        })
        .collect();
    pipelines.sort_by(|a, b| desc(a.kb.unwrap_or(0.0), b.kb.unwrap_or(0.0)));

    let plan = build_plan(&files, &pipelines, jobs);
    let snapshot = FilesSnapshot { at: to_iso(now), roots: options.paths.clone(), days: options.days, total_bytes, total_files, dirs: dirs.iter().map(|d| (d.path.as_str(), d.bytes)).collect() };
    let report = FilesReport {
        roots: options.paths.clone(),
        days: options.days,
        total_bytes,
        total_files,
        classified_share,
        incomplete_roots,
        full_visibility,
        dirs,
        users,
        by_kind,
        files,
        pipelines,
        plan,
        since_previous: previous.map(|p| ScanDelta { at: p.at.clone(), delta_bytes: total_bytes - p.total_bytes }),
        notes,
    };
    FilesScan { report, snapshot }
}

/// Never offered for cleanup: in use, inside a running job, or kept by policy.
fn blocked(f: &RecentFile) -> bool {
    !f.holders.is_empty() || f.job.is_some()
}

fn build_plan(files: &[RecentFile], pipelines: &[PipelineDir], jobs: &[RunningJob]) -> Vec<CleanupItem> {
    let mut plan: Vec<CleanupItem> = Vec::new();
    let redundant: Vec<&RecentFile> = files.iter().filter(|f| f.redundant_with.is_some() && !blocked(f)).collect();
    if !redundant.is_empty() {
        let mut reasons: Vec<&str> = Vec::new();
        for reason in redundant.iter().map(|f| f.redundant_with.as_ref().map_or("", |r| r.reason.as_str())) {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        plan.push(CleanupItem {
            title: "Duplicates superseded by a processed or compressed copy".to_string(),
            reclaim_bytes: redundant.iter().map(|f| f.bytes).sum(),
            paths: redundant.iter().map(|f| f.path.clone()).collect(),
            why: reasons.join("; "),
            verify: "For each pair, validate the kept file (`samtools quickcheck`, `gzip -t`, `zstd -t`, or record counts) before deleting the superseded one.".to_string(),
            retention: Retention::Intermediate,
        });
    }
    let mut grouped: Vec<(&str, Vec<&RecentFile>)> = Vec::new();
    for f in files {
        if blocked(f) || f.redundant_with.is_some() || !matches!(f.kind.retention, Retention::Intermediate | Retention::Temp | Retention::Reducible | Retention::Cache) {
            continue;
        }
        match grouped.iter_mut().find(|(id, _)| *id == f.kind.id) {
            Some((_, group)) => group.push(f),
            None => grouped.push((&f.kind.id, vec![f])),
        }
    }
    for (id, group) in grouped {
        let kind = kind_by_id(id);
        let size: f64 = group.iter().map(|f| f.bytes).sum();
        let reducible = kind.retention == Retention::Reducible;
        plan.push(CleanupItem {
            title: format!("{} ({})", kind.label, retention_label(kind.retention)),
            // Compression and conversion reclaim only part of the size.
            reclaim_bytes: if reducible { js_round(size * 0.5) } else { size },
            paths: group.iter().map(|f| f.path.clone()).collect(),
            why: kind.advice,
            verify: if reducible { "Convert, validate the new file, and only then remove the original." } else { "Confirm the producing run finished successfully and its outputs were checked; nothing holds these files open." }.to_string(),
            retention: kind.retention,
        });
    }
    for p in pipelines {
        if jobs.iter().any(|j| is_under(&p.path, &j.workdir) || is_under(&j.workdir, &p.path)) {
            continue;
        }
        let finished = matches!(p.kind, PipelineKind::Nextflow | PipelineKind::Cellranger) && p.state == "complete";
        let idle_snake = p.kind == PipelineKind::Snakemake && p.state == "idle";
        if !finished && !idle_snake && p.kind != PipelineKind::Star {
            continue;
        }
        plan.push(CleanupItem {
            title: format!("{} working directory of a {} run", p.kind.as_str(), if p.state == "-" { "finished" } else { &p.state }),
            reclaim_bytes: p.kb.unwrap_or(0.0) * 1024.0,
            paths: vec![p.path.clone()],
            why: match p.kind {
                PipelineKind::Nextflow => "The run log ends with \"Execution complete\"; task scratch is only needed to -resume. Use `nextflow clean -f` in the launch directory or remove work/.",
                PipelineKind::Cellranger => "outs/web_summary.html exists, so the stage directory is no longer needed.",
                PipelineKind::Snakemake => "No incomplete jobs or locks; shadow/ and conda/ can be rebuilt.",
                _ => "STAR temporary directory with no running alignment.",
            }
            .to_string(),
            verify: "Confirm results were published/copied and nobody plans to resume the run.".to_string(),
            retention: Retention::Intermediate,
        });
    }
    let order = |r: Retention| RETENTION_ORDER.iter().position(|o| *o == r).unwrap_or(usize::MAX);
    plan.sort_by(|a, b| desc(a.reclaim_bytes, b.reclaim_bytes).then(order(a.retention).cmp(&order(b.retention))));
    plan
}

/// Model-facing rendering.
pub fn render_files(host: &str, r: &FilesReport) -> String {
    let gb = bytes;
    let mut lines = vec![format!("## {host}: files modified in the last {} day(s) under {}", r.days, r.roots.join(", "))];
    let since = r.since_previous.as_ref().map_or_else(String::new, |p| format!(" (previous scan {}: {}{})", p.at, if p.delta_bytes >= 0.0 { "+" } else { "-" }, gb(p.delta_bytes.abs())));
    lines.push(format!("{} files, {}{since}; individually classified files cover {}% of the bytes.", n(r.total_files), gb(r.total_bytes), n(js_round(r.classified_share * 100.0))));
    lines.extend(r.notes.iter().map(|note| format!("Note: {note}")));
    if !r.dirs.is_empty() {
        lines.extend([String::new(), "Where it landed:".to_string()]);
        for d in &r.dirs {
            let delta = match d.delta_bytes {
                Some(delta) if delta != 0.0 => format!("  ({}{} vs previous scan)", if delta > 0.0 { "+" } else { "-" }, gb(delta.abs())),
                _ => String::new(),
            };
            lines.push(format!("  {}  {} files  {}{delta}", pad_start(&gb(d.bytes), 7), pad_start(&n(d.files), 7), d.path));
        }
    }
    if !r.users.is_empty() {
        lines.extend([String::new(), format!("By owner: {}", r.users.iter().take(8).map(|u| format!("{} {}", u.user, gb(u.bytes))).collect::<Vec<_>>().join(", "))]);
    }
    if !r.by_kind.is_empty() {
        lines.extend([String::new(), "By kind (large files):".to_string()]);
        lines.extend(r.by_kind.iter().map(|k| format!("  {}  {}×  {} — {}", pad_start(&gb(k.bytes), 7), pad_start(&n(k.files), 5), k.kind.label, retention_label(k.kind.retention))));
    }
    let in_use: Vec<&RecentFile> = r.files.iter().filter(|f| blocked(f)).collect();
    if !in_use.is_empty() {
        lines.extend([String::new(), "Still in use (excluded from the plan):".to_string()]);
        for f in in_use.iter().take(10) {
            let held = if f.holders.is_empty() { String::new() } else { format!(" held by {}", holder_text(&f.holders)) };
            let job = f.job.as_ref().map_or_else(String::new, |job| format!(" in running job {} ({})", job.id, job.user));
            lines.push(format!("  {}  {}{held}{job}", pad_start(&gb(f.bytes), 7), f.path));
        }
    }
    if !r.pipelines.is_empty() {
        lines.extend([String::new(), "Pipeline working directories:".to_string()]);
        lines.extend(r.pipelines.iter().take(15).map(|p| format!("  {}  {} [{}] {} (modified {})", pad_start(&format_kb(p.kb.unwrap_or(0.0)), 7), p.kind.as_str(), p.state, p.path, p.modified)));
    }
    if r.plan.is_empty() {
        lines.extend([String::new(), "No cleanup candidates among the large recent files.".to_string()]);
    } else {
        lines.extend([String::new(), "Cleanup suggestions (largest first; nothing has been changed):".to_string()]);
        for (i, item) in r.plan.iter().enumerate() {
            lines.push(format!("{}. {}: ~{} in {} path(s)", i + 1, item.title, gb(item.reclaim_bytes), item.paths.len()));
            lines.push(format!("   why: {}", item.why));
            lines.push(format!("   before acting: {}", item.verify));
            lines.extend(item.paths.iter().take(5).map(|p| format!("   - {p}")));
            if item.paths.len() > 5 {
                lines.push(format!("   - … {} more", item.paths.len() - 5));
            }
        }
    }
    let raw: Vec<&KindBytes> = r.by_kind.iter().filter(|k| k.kind.retention == Retention::Raw).collect();
    if !raw.is_empty() {
        lines.extend([String::new(), format!("Raw data ({}) is never a cleanup candidate; archive it to cold storage if space is tight.", raw.iter().map(|k| format!("{} {}", k.kind.label, gb(k.bytes))).collect::<Vec<_>>().join(", "))]);
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testing::assert_golden;

    const FILES: &str = include_str!("testdata/files.txt");
    const G: f64 = 1024.0 * 1024.0 * 1024.0;

    fn options() -> FilesOptions {
        FilesOptions { paths: vec!["/data".into()], days: 7, depth: 3, list_min_mb: 10, max_files: 5000, top: 20, walk_timeout_sec: 300 }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-29T00:00:00Z").unwrap().to_utc()
    }

    fn scan() -> FilesScan {
        let previous = FilesSnapshot { at: "2026-10-20T00:00:00.000Z".into(), roots: vec!["/data".into()], days: 7, total_bytes: 250.0 * G, total_files: 1000.0, dirs: [("/data/proj/alice", 150.0 * G)].into_iter().collect() };
        parse_files(FILES, &options(), Some(&previous), now())
    }

    #[test]
    fn builds_the_script_the_plugin_built() {
        let o = FilesOptions { paths: vec!["/data".into(), "/it's here".into()], ..options() };
        assert_eq!(files_script(&o), include_str!("testdata/files.golden.sh"));
    }

    #[test]
    fn aggregates_and_compares_with_the_previous_scan() {
        let FilesScan { report, snapshot } = scan();
        assert_eq!(report.total_bytes, 300.0 * G);
        assert_eq!(report.since_previous.as_ref().map(|p| p.delta_bytes), Some(50.0 * G));
        assert_eq!((report.dirs[0].path.as_str(), report.dirs[0].delta_bytes), ("/data/proj/alice", Some(50.0 * G)));
        assert!((report.classified_share - 175.0 / 300.0).abs() < 1e-9);
        assert_eq!(snapshot.dirs.get("/data/proj/bob/work"), Some(&(80.0 * G)));
    }

    #[test]
    fn plans_cleanup_without_touching_raw_data_open_files_or_running_pipelines() {
        let report = scan().report;
        let paths: Vec<&str> = report.plan.iter().flat_map(|p| p.paths.iter().map(String::as_str)).collect();
        for expected in ["/data/proj/alice/S1.sam", "/data/proj/bob/work", "/data/proj/bob/trimmed/S3_R1_val_1.fq.gz", "/data/proj/bob/S3.fastq"] {
            assert!(paths.contains(&expected), "{expected}");
        }
        for kept in ["/data/proj/alice/S2.sorted.bam", "/data/proj/alice/raw/S2_R1.fastq.gz", "/data/proj/carol/.snakemake"] {
            assert!(!paths.contains(&kept), "{kept}");
        }
        assert!(report.plan[0].reclaim_bytes >= report.plan.last().unwrap().reclaim_bytes);
        assert!(report.plan.iter().any(|p| p.title.contains("nextflow")));
    }

    #[test]
    fn matches_the_plugin_report_and_rendering() {
        let scan = scan();
        assert_golden(&scan, include_str!("testdata/files.report.json"));
        assert_eq!(serde_json::from_str::<FilesScan>(include_str!("testdata/files.report.json")).unwrap(), scan);
        let text = render_files("seq-01", &scan.report);
        assert_eq!(text, include_str!("testdata/files.render.txt"));
        for expected in ["held by samtools[4242 alice]", "Raw FASTQ", "never a cleanup candidate", "samtools quickcheck"] {
            assert!(text.contains(expected), "{expected}");
        }
    }

    #[test]
    fn protects_pbs_and_lsf_directories_in_cleanup_plans() {
        let data = "@@pbs_jobs\n123|alice|/data/pbs\n@@lsf_jobs\n456|RUN|bob|/data/lsf|/tmp\n@@big\n1000\t1700000000\talice\t/data/pbs/sample.sam\n@@files\n1000\t1700000000\talice\t/data/pbs/sample.sam\n200\t1700000000\talice\t/data/pbs/sample.bam\n2000\t1700000000\tbob\t/data/lsf/_STARtmp/tmp\n@@now\n1800000000\n@@gnufind\nok";
        let o = FilesOptions { paths: vec!["/data".into()], days: 1, depth: 2, list_min_mb: 1, max_files: 100, top: 10, walk_timeout_sec: 10 };
        let report = parse_files(data, &o, None, now()).report;
        assert!(report.files.iter().all(|f| f.job.is_some()));
        assert!(report.plan.is_empty());
        assert!(render_files("h", &report).contains("No cleanup candidates among the large recent files."));
    }
}
