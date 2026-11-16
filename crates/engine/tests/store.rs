//! Audit partitions, bounded histories and reverse reading (`store.spec.ts`).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wisp_ops_engine::risk::RiskLevel;
use wisp_ops_engine::ssh::RunStatus;
use wisp_ops_engine::store::{AuditEntry, AuditFilter, Authorization, ChangeOutcome, ChangeRecord, OpsStore, StoreRetention, audit_cutoff_month, reverse_json_lines};
use wisp_ops_engine::time::parse_iso;

fn row(at: &str, host: &str) -> AuditEntry {
    AuditEntry {
        at: at.to_string(),
        session: None,
        tool: "test".to_string(),
        host: host.to_string(),
        risk: RiskLevel::Read,
        sudo: false,
        authorization: Authorization::ReadOnly,
        command: "true".to_string(),
        reason: None,
        status: RunStatus::Ok,
        exit_code: Some(0),
        duration_ms: 1,
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

fn filter(limit: usize) -> AuditFilter {
    AuditFilter { limit, ..AuditFilter::default() }
}

#[test]
fn writes_audit_rows_in_the_layout_the_plugin_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpsStore::new(dir.path(), StoreRetention::default());
    store.audit(&row("2026-10-01T00:00:00Z", "a")).unwrap();
    let mut failed = row("2026-10-01T00:00:01Z", "a");
    failed.session = Some("s1".to_string());
    failed.reason = Some("why".to_string());
    failed.risk = RiskLevel::Destructive;
    failed.authorization = Authorization::Approval;
    failed.status = RunStatus::SudoRequired;
    failed.exit_code = None;
    store.audit(&failed).unwrap();
    let text = std::fs::read_to_string(dir.path().join("audit/2026-10.jsonl")).unwrap();
    assert_eq!(
        text,
        concat!(
            r#"{"at":"2026-10-01T00:00:00Z","tool":"test","host":"a","risk":"read","sudo":false,"authorization":"read-only","command":"true","status":"ok","exitCode":0,"durationMs":1}"#,
            "\n",
            r#"{"at":"2026-10-01T00:00:01Z","session":"s1","tool":"test","host":"a","risk":"destructive","sudo":false,"authorization":"approval","command":"true","reason":"why","status":"sudo-required","exitCode":null,"durationMs":1}"#,
            "\n"
        )
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.path().join("audit/2026-10.jsonl")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(dir.path().join("audit")).unwrap().permissions().mode() & 0o777, 0o700);
    }
    assert_eq!(store.read_audit(&filter(10)).unwrap(), [row("2026-10-01T00:00:00Z", "a"), failed]);
}

#[test]
fn partitions_audit_months_and_reads_filtered_tails_with_legacy_history() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpsStore::new(dir.path(), StoreRetention::default());
    std::fs::write(dir.path().join("audit.jsonl"), format!("{}\n", serde_json::to_string(&row("2026-08-01T00:00:00Z", "a")).unwrap())).unwrap();
    store.audit(&row("2026-09-30T23:59:00Z", "a")).unwrap();
    store.audit(&row("2026-10-01T00:00:00Z", "b")).unwrap();
    store.audit(&row("2026-10-01T01:00:00Z", "a")).unwrap();
    assert_eq!(names(&dir.path().join("audit")), ["2026-09.jsonl", "2026-10.jsonl"]);
    let only_a = AuditFilter { limit: 2, hosts: Some(HashSet::from(["a".to_string()])), since_ms: None };
    assert_eq!(store.read_audit(&only_a).unwrap().iter().map(|r| r.at.as_str()).collect::<Vec<_>>(), ["2026-09-30T23:59:00Z", "2026-10-01T01:00:00Z"]);
    assert_eq!(store.read_audit(&filter(10)).unwrap().len(), 4);
    assert_eq!(store.read_audit(&AuditFilter { limit: 10, hosts: None, since_ms: parse_iso("2026-10-01") }).unwrap().len(), 2);
    assert!(store.read_audit(&filter(0)).unwrap().is_empty());
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Line {
    i: usize,
    text: String,
}

#[test]
fn handles_split_utf8_missing_files_malformed_lines_and_unfinished_tails() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("utf8.jsonl");
    let mut values: Vec<Line> = (0..1000).map(|i| Line { i, text: "中文🙂".repeat(20) }).collect();
    let body = values.iter().map(|value| serde_json::to_string(value).unwrap()).collect::<Vec<_>>().join("\n");
    std::fs::write(&file, format!("{body}\nnot-json\n{{\"torn\":")).unwrap();
    let read: Vec<Line> = reverse_json_lines(&file).unwrap().collect();
    values.reverse();
    assert_eq!(read, values);
    assert_eq!(reverse_json_lines::<Value>(&dir.path().join("missing")).unwrap().count(), 0);
    // A line over 1 MiB is skipped; its neighbours survive.
    let big = dir.path().join("big.jsonl");
    std::fs::write(&big, format!("{{\"i\":1}}\n{{\"pad\":\"{}\"}}\n{{\"i\":3}}\n", "x".repeat(2 * 1024 * 1024))).unwrap();
    let kept: Vec<Value> = reverse_json_lines(&big).unwrap().collect();
    assert_eq!(kept, [json!({ "i": 3 }), json!({ "i": 1 })]);
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Inspection {
    at: String,
    status: String,
    disk_pct: BTreeMap<String, f64>,
    findings: Vec<Value>,
}

fn inspection(day: usize, status: &str) -> Inspection {
    Inspection { at: format!("2026-10-{:02}T00:00:00Z", day + 1), status: status.to_string(), disk_pct: BTreeMap::from([("/".to_string(), day as f64)]), findings: Vec::new() }
}

#[test]
fn keeps_only_the_newest_inspection_records_per_host_and_prunes_audit_months_past_retention() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpsStore::new(dir.path(), StoreRetention { inspection_records: 10, audit_months: 3 });
    for i in 0..25 {
        store.append_history("a", &inspection(i, if i == 24 { "failed" } else { "ok" })).unwrap();
    }
    let kept: Vec<Inspection> = store.read_history("a", 100).unwrap();
    assert_eq!(kept.len(), 10);
    assert_eq!(kept[0].disk_pct["/"], 15.0);
    assert_eq!(kept[9].disk_pct["/"], 24.0);
    assert_eq!(store.read_history::<Inspection>("a", 2).unwrap().iter().map(|r| r.disk_pct["/"]).collect::<Vec<_>>(), [23.0, 24.0]);
    assert_eq!(store.last_healthy::<Inspection>("a").unwrap().unwrap().disk_pct["/"], 23.0);
    assert!(store.last_healthy::<Inspection>("nobody").unwrap().is_none());
    assert!(names(&dir.path().join("inspections")).iter().all(|name| !name.ends_with(".tmp")));
    // Rows that are not inspections are skipped rather than counted.
    std::fs::write(dir.path().join("inspections/b.jsonl"), "{\"at\":\"x\"}\n{\"at\":\"y\",\"status\":\"ok\",\"diskPct\":{\"/\":1},\"findings\":[]}\n{\"torn\":").unwrap();
    assert_eq!(store.read_history::<Value>("b", 10).unwrap().len(), 1);

    std::fs::create_dir_all(dir.path().join("audit")).unwrap();
    for month in ["2026-02", "2026-07", "2026-08"] {
        std::fs::write(dir.path().join(format!("audit/{month}.jsonl")), format!("{}\n", serde_json::to_string(&row(&format!("{month}-15T00:00:00Z"), "a")).unwrap())).unwrap();
    }
    store.audit(&row("2026-10-01T00:00:00Z", "a")).unwrap();
    assert_eq!(names(&dir.path().join("audit")), ["2026-08.jsonl", "2026-10.jsonl"]);
    assert_eq!(audit_cutoff_month(3, parse_iso("2026-10-15T00:00:00Z").unwrap()), "2026-08");
    assert_eq!(audit_cutoff_month(12, parse_iso("2026-01-15T00:00:00Z").unwrap()), "2025-02");
    // Legacy single-file history and a zero retention are left alone.
    let forever = OpsStore::new(dir.path(), StoreRetention { inspection_records: 10, audit_months: 0 });
    std::fs::write(dir.path().join("audit/2020-01.jsonl"), format!("{}\n", serde_json::to_string(&row("2020-01-15T00:00:00Z", "a")).unwrap())).unwrap();
    forever.audit(&row("2026-10-02T00:00:00Z", "a")).unwrap();
    assert!(forever.prune_audit().unwrap().is_empty());
    assert_eq!(names(&dir.path().join("audit")), ["2020-01.jsonl", "2026-08.jsonl", "2026-10.jsonl"]);
    assert_eq!(store.prune_audit_at(parse_iso("2026-10-15T00:00:00Z").unwrap()).unwrap(), ["2020-01.jsonl"]);
}

#[test]
fn keeps_bounded_per_host_logs_snapshots_probes_and_change_records() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpsStore::new(dir.path(), StoreRetention::default());
    for i in 0..7 {
        store.append_bounded("task-runs", "web-01", &json!({ "i": i }), 5).unwrap();
    }
    let rows: Vec<Value> = store.read_bounded("task-runs", "web-01").unwrap();
    assert_eq!(rows.iter().map(|row| row["i"].as_i64().unwrap()).collect::<Vec<_>>(), [2, 3, 4, 5, 6]);
    assert_eq!(std::fs::read_to_string(dir.path().join("task-runs/web-01.jsonl")).unwrap().lines().count(), 5);
    assert!(store.read_bounded::<Value>("task-runs", "nobody").unwrap().is_empty());
    // Rows written by someone else are carried over verbatim when the file is rewritten.
    std::fs::write(dir.path().join("task-runs/raw.jsonl"), "{\"z\":1,  \"a\":2}\n{\"torn\":\n").unwrap();
    store.append_bounded("task-runs", "raw", &json!({ "b": 3 }), 5).unwrap();
    assert_eq!(std::fs::read_to_string(dir.path().join("task-runs/raw.jsonl")).unwrap(), "{\"z\":1,  \"a\":2}\n{\"b\":3}\n");

    for i in 0..60 {
        store.save_disk_snapshot("web-01", &json!({ "path": if i % 2 == 0 { "/" } else { "/data" }, "at": i })).unwrap();
    }
    assert_eq!(store.disk_snapshot::<Value>("web-01", "/").unwrap().unwrap()["at"], 58);
    assert_eq!(store.disk_snapshot::<Value>("web-01", "/data").unwrap().unwrap()["at"], 59);
    assert!(store.disk_snapshot::<Value>("web-01", "/nope").unwrap().is_none());
    assert_eq!(store.read_bounded::<Value>("disk", "web-01").unwrap().len(), 50);

    assert!(store.probes::<Value>().unwrap().is_empty());
    store.save_probes(&BTreeMap::from([("a".to_string(), json!({ "os": "linux" })), ("b".to_string(), json!({ "os": "bsd" }))])).unwrap();
    store.save_probes(&BTreeMap::from([("b".to_string(), json!({ "os": "darwin" }))])).unwrap();
    let probes = store.probes::<Value>().unwrap();
    assert_eq!((probes["a"]["os"].as_str(), probes["b"]["os"].as_str()), (Some("linux"), Some("darwin")));
    assert_eq!(std::fs::read_to_string(dir.path().join("probes.json")).unwrap(), "{\n  \"a\": {\n    \"os\": \"linux\"\n  },\n  \"b\": {\n    \"os\": \"darwin\"\n  }\n}");
    std::fs::write(dir.path().join("probes.json"), "{broken").unwrap();
    assert!(store.probes::<Value>().unwrap().is_empty());

    let record = ChangeRecord {
        at: "2026-10-01T00:00:00.000Z".to_string(),
        session: None,
        host: "web-01".to_string(),
        outcome: ChangeOutcome::RolledBack,
        status: RunStatus::Failed,
        exit_code: Some(23),
        backup_dir: Some("/var/tmp/wispops-change.abc".to_string()),
        files: vec!["/etc/app.conf".to_string()],
        new_files: Vec::new(),
        directories: Vec::new(),
        reason: "Update config".to_string(),
        sudo: true,
    };
    store.record_change(&record).unwrap();
    store.record_change(&ChangeRecord { outcome: ChangeOutcome::Verified, exit_code: Some(0), status: RunStatus::Ok, ..record.clone() }).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("changes/web-01.jsonl")).unwrap().lines().next().unwrap(),
        r#"{"at":"2026-10-01T00:00:00.000Z","host":"web-01","outcome":"rolled-back","status":"failed","exitCode":23,"backupDir":"/var/tmp/wispops-change.abc","files":["/etc/app.conf"],"newFiles":[],"directories":[],"reason":"Update config","sudo":true}"#
    );
    assert_eq!(store.read_changes("web-01", 10).unwrap().len(), 2);
    assert_eq!(store.read_changes("web-01", 1).unwrap()[0].outcome, ChangeOutcome::Verified);
    assert!(store.read_changes("web-01", 0).unwrap().is_empty());
}

#[test]
fn serialises_concurrent_appends_to_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpsStore::new(dir.path(), StoreRetention { inspection_records: 1000, audit_months: 12 });
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let store = &store;
            scope.spawn(move || {
                for i in 0..25 {
                    store.append_bounded("runs", "shared", &json!({ "worker": worker, "i": i }), 1000).unwrap();
                    store.append_history("shared", &json!({ "diskPct": {}, "findings": [], "worker": worker, "i": i })).unwrap();
                }
            });
        }
    });
    assert_eq!(store.read_bounded::<Value>("runs", "shared").unwrap().len(), 200);
    assert_eq!(store.read_history::<Value>("shared", 1000).unwrap().len(), 200);
}
