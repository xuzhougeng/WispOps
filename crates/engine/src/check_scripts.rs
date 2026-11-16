//! Owner-reviewed check scripts. A script travels to each linked server on stdin exactly like
//! the built-in collectors. The model can only propose drafts; a person accepts one in the window,
//! and only then can a routine task run it. Every script must also pass the command classifier as
//! read-only (no sudo inside) and the deploy-wide deny list, when it is drafted, accepted and run.
//!
//! Its output follows a small contract, so a run can be judged and recorded without the model:
//!
//! - exit 0 = ok, 1 = warning, 2 = critical, anything else = failed
//! - the first non-empty stdout line is a one-line summary; the rest is evidence
//! - an optional `WISPOPS-JSON: {"key": number, …}` line carries metrics

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::fsutil::{hex, random_hex};
use crate::jsre::js_re;
use crate::managed::LocalState;
use crate::policy::DenyList;
use crate::risk::{RiskAssessment, RiskLevel, classify_command};
use crate::ssh::{RunResult, RunStatus};
use crate::time::{now_ms, parse_iso, to_iso};

pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
pub const DEFAULT_SCRIPT_TIMEOUT_SEC: u64 = 120;
pub const MAX_SCRIPT_TIMEOUT_SEC: u64 = 3600;
pub const MAX_DRAFTS: usize = 10;
const MAX_SUMMARY_CHARS: usize = 300;
const MAX_EVIDENCE_CHARS: usize = 4000;

pub const SCRIPT_CONTRACT: &str = "Exit 0 = ok, 1 = warning, 2 = critical, other = failed. The first non-empty stdout line is the one-line summary; everything after it is evidence. An optional line \"WISPOPS-JSON: {\\\"key\\\": number}\" records metrics.";

/// Shell built-ins a check script needs for its contract, read-only by nature.
const SCRIPT_BUILTINS: &[&str] = &["exit", ":"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckScript {
    pub id: String,
    pub title: String,
    pub description: String,
    /// POSIX shell, run with `sh -s` on every linked server.
    pub content: String,
    /// Of `content`, recomputed on every save so a task record can name the exact script it ran.
    pub sha256: String,
    pub timeout_sec: u64,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptLibrary {
    pub version: u32,
    pub entries: Vec<CheckScript>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptDraft {
    pub id: String,
    pub created_at: String,
    pub script: CheckScript,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptDrafts {
    pub version: u32,
    pub entries: Vec<ScriptDraft>,
}

pub fn script_digest(content: &str) -> String {
    hex(&Sha256::digest(content.as_bytes()))
}

/// Read one script from JSON; the content's line endings are normalized and its digest recomputed.
pub fn validate_script(value: &Value) -> Result<CheckScript, String> {
    validate_script_at(value, now_ms())
}

pub fn validate_script_at(value: &Value, now: i64) -> Result<CheckScript, String> {
    let Some(raw) = value.as_object() else { return Err("脚本格式不正确。".into()) };
    let id = raw.get("id").and_then(Value::as_str).unwrap_or("");
    if !js_re!(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$").is_match(id) || id == "all" || id.starts_with("builtin.") { return Err("脚本标识无效：字母、数字、点、连字符或下划线，不能使用保留名称。".into()) }
    let title = raw.get("title").and_then(Value::as_str).unwrap_or("");
    if title.trim().is_empty() || title.chars().count() > 120 { return Err("请填写脚本标题，最多 120 个字符。".into()) }
    let description = match raw.get("description") {
        None | Some(Value::Null) => "",
        Some(Value::String(text)) if text.chars().count() <= 1000 => text.as_str(),
        Some(_) => return Err("脚本说明最多 1000 个字符。".into()),
    };
    let content = raw.get("content").and_then(Value::as_str).unwrap_or("");
    if content.trim().is_empty() { return Err("请填写脚本内容。".into()) }
    if content.contains('\0') { return Err("脚本内容包含无效字符。".into()) }
    if content.len() > MAX_SCRIPT_BYTES { return Err("脚本最多 64 KB。".into()) }
    let timeout_sec = match raw.get("timeoutSec") {
        None | Some(Value::Null) => DEFAULT_SCRIPT_TIMEOUT_SEC,
        Some(value) => value.as_u64().filter(|seconds| (5..=MAX_SCRIPT_TIMEOUT_SEC).contains(seconds)).ok_or("超时须为 5 到 3600 秒的整数。")?,
    };
    let content = content.replace("\r\n", "\n");
    let updated_at = raw.get("updatedAt").and_then(Value::as_str).filter(|at| parse_iso(at).is_some()).map_or_else(|| to_iso(now), String::from);
    Ok(CheckScript { id: id.to_string(), title: title.trim().to_string(), description: description.trim().to_string(), sha256: script_digest(&content), content, timeout_sec, updated_at })
}

/// The first script line the deploy-wide deny list refuses, and the pattern; the same last word commands get.
pub fn denied_script_line(content: &str, deny: &DenyList) -> Option<(String, String)> {
    content.split('\n').find_map(|line| deny.matches(line).map(|source| (line.chars().take(120).collect(), source.to_string())))
}

/// The classifier's view of the whole script, with the contract's `exit` counted as read-only.
pub fn script_risk(content: &str, extra_read_programs: &HashSet<String>) -> RiskAssessment {
    let mut extra = extra_read_programs.clone();
    extra.extend(SCRIPT_BUILTINS.iter().map(|word| word.to_string()));
    classify_command(content, &extra)
}

/// Why a script may not run unattended, or `None` when it reads only and no deny rule refuses it.
pub fn script_refusal(content: &str, extra_read_programs: &HashSet<String>, deny: &DenyList) -> Option<String> {
    if let Some((line, source)) = denied_script_line(content, deny) { return Some(format!("refused by the deny list ({source}): {line}")) }
    let risk = script_risk(content, extra_read_programs);
    if risk.elevates { return Some("the script escalates privilege itself; check scripts never use sudo or su (a task may run one as root instead)".into()) }
    if risk.level != RiskLevel::Read { return Some(format!("the script is not read-only ({}: {})", risk.level.as_str(), risk.reasons.join("; "))) }
    None
}

pub fn script_store(data_dir: &Path) -> LocalState<ScriptLibrary> {
    LocalState::new(data_dir.join("check-scripts.json"), || ScriptLibrary { version: 1, entries: vec![] }, |value| {
        if value["version"] != 1 || !value["entries"].is_array() { return Err("Invalid check script library".into()) }
        let entries = value["entries"].as_array().into_iter().flatten().map(validate_script).collect::<Result<Vec<_>, _>>()?;
        if entries.iter().map(|script| script.id.as_str()).collect::<HashSet<_>>().len() != entries.len() { return Err("脚本标识重复。".into()) }
        Ok(ScriptLibrary { version: 1, entries })
    })
}

/// Scripts the model proposed. Only a person moves one into the library, from the window.
pub fn script_draft_store(data_dir: &Path) -> LocalState<ScriptDrafts> {
    LocalState::new(data_dir.join("check-script-drafts.json"), || ScriptDrafts { version: 1, entries: vec![] }, |value| {
        if value["version"] != 1 || !value["entries"].is_array() { return Err("Invalid check script drafts".into()) }
        let entries = value["entries"].as_array().into_iter().flatten().map(|draft| {
            let (Some(id), Some(created_at)) = (draft["id"].as_str(), draft["createdAt"].as_str()) else { return Err("Invalid check script draft".to_string()) };
            Ok(ScriptDraft { id: id.to_string(), created_at: created_at.to_string(), script: validate_script(&draft["script"])? })
        }).collect::<Result<Vec<_>, _>>()?;
        Ok(ScriptDrafts { version: 1, entries })
    })
}

/// Keep a proposal for review: the newest draft per script id, at most [`MAX_DRAFTS`].
pub fn add_script_draft(data_dir: &Path, script: &Value) -> Result<ScriptDraft, String> {
    let draft = ScriptDraft { id: random_hex::<16>()?, created_at: to_iso(now_ms()), script: validate_script(script)? };
    let store = script_draft_store(data_dir);
    let current = store.read()?;
    store.change(&current.revision, |state| {
        let mut entries: Vec<ScriptDraft> = state.entries.into_iter().filter(|kept| kept.script.id != draft.script.id).collect();
        entries.push(draft.clone());
        let skip = entries.len().saturating_sub(MAX_DRAFTS);
        Ok(ScriptDrafts { version: 1, entries: entries.into_iter().skip(skip).collect() })
    })?;
    Ok(draft)
}

/// A person accepts a draft: it enters the library (replacing a script of the same id) and leaves the drafts.
pub fn accept_script_draft(data_dir: &Path, draft_id: &str, extra_read_programs: &HashSet<String>, deny: &DenyList) -> Result<CheckScript, String> {
    let drafts = script_draft_store(data_dir);
    let current = drafts.read()?;
    let draft = current.value.entries.iter().find(|draft| draft.id == draft_id).cloned().ok_or("这份草稿已经不在了。")?;
    if let Some(reason) = script_refusal(&draft.script.content, extra_read_programs, deny) { return Err(format!("这个脚本不能接受：{reason}")) }
    let script = CheckScript { updated_at: to_iso(now_ms()), ..draft.script };
    let library = script_store(data_dir);
    let known = library.read()?;
    library.change(&known.revision, |mut state| {
        state.entries.retain(|kept| kept.id != script.id);
        state.entries.push(script.clone());
        Ok(state)
    })?;
    drafts.change(&current.revision, |mut state| {
        state.entries.retain(|kept| kept.id != draft_id);
        Ok(state)
    })?;
    Ok(script)
}

pub fn delete_script_draft(data_dir: &Path, draft_id: &str) -> Result<(), String> {
    let store = script_draft_store(data_dir);
    let current = store.read()?;
    store.change(&current.revision, |mut state| {
        state.entries.retain(|kept| kept.id != draft_id);
        Ok(state)
    })
}

pub fn delete_script(data_dir: &Path, id: &str) -> Result<(), String> {
    let store = script_store(data_dir);
    let current = store.read()?;
    store.change(&current.revision, |mut state| {
        state.entries.retain(|kept| kept.id != id);
        Ok(state)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptVerdict {
    Ok,
    Warn,
    Crit,
    Failed,
    Unreachable,
}

impl ScriptVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            ScriptVerdict::Ok => "ok",
            ScriptVerdict::Warn => "warn",
            ScriptVerdict::Crit => "crit",
            ScriptVerdict::Failed => "failed",
            ScriptVerdict::Unreachable => "unreachable",
        }
    }

    /// How bad, for [`worst_verdict`]: a broken script or host is worse than a warning, a critical result is worst.
    fn rank(self) -> u8 {
        match self {
            ScriptVerdict::Ok => 0,
            ScriptVerdict::Warn => 1,
            ScriptVerdict::Failed => 2,
            ScriptVerdict::Unreachable => 3,
            ScriptVerdict::Crit => 4,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptOutcome {
    pub host: String,
    pub verdict: ScriptVerdict,
    pub exit_code: Option<i32>,
    /// First non-empty stdout line, bounded.
    pub summary: String,
    /// Remaining output, bounded; stored only in the run excerpt.
    pub evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<BTreeMap<String, f64>>,
}

fn bounded(text: &str, max: usize) -> String {
    if text.chars().count() > max { format!("{}… (truncated)", text.chars().take(max).collect::<String>()) } else { text.to_string() }
}

/// Judge one host's run by the output contract. Transport failures never count as script verdicts.
pub fn parse_script_result(result: &RunResult) -> ScriptOutcome {
    let stderr = result.stderr.trim();
    if result.status != RunStatus::Ok && result.status != RunStatus::Failed {
        let last = stderr.split('\n').next_back().unwrap_or("");
        let summary = if stderr.is_empty() { result.status.as_str().to_string() } else { format!("{}: {}", result.status.as_str(), bounded(last, MAX_SUMMARY_CHARS)) };
        return ScriptOutcome { host: result.host.clone(), verdict: ScriptVerdict::Unreachable, exit_code: result.exit_code, summary, evidence: String::new(), metrics: None };
    }
    let stdout = result.stdout.replace("\r\n", "\n");
    let mut metrics: Option<BTreeMap<String, f64>> = None;
    let mut kept: Vec<&str> = vec![];
    for line in stdout.split('\n') {
        let Some(captures) = js_re!(r"^WISPOPS-JSON:\s*(\{.*\})\s*$").captures(line) else {
            kept.push(line);
            continue;
        };
        match serde_json::from_str::<serde_json::Map<String, Value>>(&captures[1]) {
            Ok(parsed) => {
                let numbers: Vec<(String, f64)> = parsed.into_iter().filter(|(key, _)| js_re!(r"^[A-Za-z0-9_.-]{1,60}$").is_match(key)).filter_map(|(key, value)| value.as_f64().filter(|n| n.is_finite()).map(|n| (key, n))).take(50).collect();
                if !numbers.is_empty() { metrics.get_or_insert_with(BTreeMap::new).extend(numbers) }
            }
            Err(_) => kept.push(line),
        }
    }
    let first = kept.iter().position(|line| !line.trim().is_empty());
    let summary_line = first.map_or("", |at| kept[at].trim());
    let rest = first.map_or(String::new(), |at| kept[at + 1..].join("\n").trim().to_string());
    let verdict = match result.exit_code {
        Some(0) => ScriptVerdict::Ok,
        Some(1) => ScriptVerdict::Warn,
        Some(2) => ScriptVerdict::Crit,
        _ => ScriptVerdict::Failed,
    };
    let summary = if !summary_line.is_empty() {
        summary_line.to_string()
    } else if verdict == ScriptVerdict::Failed && !stderr.is_empty() {
        stderr.split('\n').next_back().unwrap_or("").to_string()
    } else if verdict == ScriptVerdict::Ok {
        "ok (no output)".to_string()
    } else {
        format!("exit {} (no output)", result.exit_code.map_or("?".to_string(), |code| code.to_string()))
    };
    let stderr_part = if !stderr.is_empty() && verdict != ScriptVerdict::Ok { format!("[stderr]\n{stderr}") } else { String::new() };
    let evidence = [rest, stderr_part].into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join("\n");
    let evidence = format!("{}{}", bounded(&evidence, MAX_EVIDENCE_CHARS), if result.truncated { "\n(output truncated by the capture limit)" } else { "" });
    ScriptOutcome { host: result.host.clone(), verdict, exit_code: result.exit_code, summary: bounded(&summary, MAX_SUMMARY_CHARS), evidence, metrics }
}

/// Model-facing body: summaries first so a bounded excerpt never loses them, evidence after.
pub fn render_script_outcomes(script: &CheckScript, outcomes: &[ScriptOutcome]) -> String {
    let mut lines = vec![
        format!("## Check script \"{}\" ({}, sha256 {}) on {} host(s)", script.title, script.id, script.sha256.chars().take(12).collect::<String>(), outcomes.len()),
        "Verdicts come from the script's exit status; failed = the script itself broke, unreachable = no result from the host.".to_string(),
        String::new(),
    ];
    for outcome in outcomes {
        let metrics = outcome.metrics.as_ref().map(|metrics| format!(" {{{}}}", metrics.iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join(", "))).unwrap_or_default();
        lines.push(format!("- {}: {} — {}{metrics}", outcome.host, outcome.verdict.as_str(), outcome.summary));
    }
    let detail: Vec<String> = outcomes.iter().filter(|outcome| !outcome.evidence.is_empty()).map(|outcome| format!("### {} ({}{})\n{}", outcome.host, outcome.verdict.as_str(), outcome.exit_code.map(|code| format!(", exit {code}")).unwrap_or_default(), outcome.evidence)).collect();
    if !detail.is_empty() {
        lines.push(String::new());
        lines.extend(detail);
    }
    lines.join("\n")
}

pub fn worst_verdict(verdicts: impl IntoIterator<Item = ScriptVerdict>) -> ScriptVerdict {
    verdicts.into_iter().fold(ScriptVerdict::Ok, |worst, verdict| if verdict.rank() > worst.rank() { verdict } else { worst })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(status: RunStatus, exit_code: Option<i32>, stdout: &str, stderr: &str) -> RunResult {
        RunResult { host: "a".into(), status, exit_code, stdout: stdout.into(), stderr: stderr.into(), truncated: false, duration_ms: 1, first_output_ms: None }
    }

    fn ok(stdout: &str) -> RunResult {
        run(RunStatus::Ok, Some(0), stdout, "")
    }

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wisp-scripts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn deny(patterns: &[&str]) -> DenyList {
        DenyList::compile(&patterns.iter().map(|p| p.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn validates_identifiers_sizes_and_timeouts_normalizes_line_endings_and_digests_the_content() {
        let script = validate_script(&json!({"id": "gpu-idle", "title": " GPU idle ", "description": "x", "content": "echo ok\r\nexit 0\r\n"})).unwrap();
        assert_eq!((script.id.as_str(), script.title.as_str(), script.content.as_str(), script.timeout_sec), ("gpu-idle", "GPU idle", "echo ok\nexit 0\n", 120));
        assert_eq!(script.sha256, script_digest("echo ok\nexit 0\n"));
        assert!(parse_iso(&script.updated_at).is_some());
        let big = "x".repeat(70 * 1024);
        for bad in [
            json!({"id": "builtin.x", "title": "t", "content": "x"}),
            json!({"id": "all", "title": "t", "content": "x"}),
            json!({"id": "bad id", "title": "t", "content": "x"}),
            json!({"id": "ok", "title": "", "content": "x"}),
            json!({"id": "ok", "title": "t", "content": "   "}),
            json!({"id": "ok", "title": "t", "content": "a\0b"}),
            json!({"id": "ok", "title": "t", "content": "x", "timeoutSec": 1}),
            json!({"id": "ok", "title": "t", "content": "x", "timeoutSec": 7200}),
            json!({"id": "ok", "title": "t", "content": "x", "timeoutSec": 30.5}),
            json!({"id": "ok", "title": "t", "content": big}),
            json!("not an object"),
        ] {
            assert!(validate_script(&bad).is_err(), "{}", bad.to_string().chars().take(60).collect::<String>());
        }
    }

    #[test]
    fn finds_deny_listed_lines_inside_a_script() {
        assert_eq!(denied_script_line("df -h\ncat /etc/secret-file\n", &deny(&["secret-file"])), Some(("cat /etc/secret-file".into(), "secret-file".into())));
        assert_eq!(denied_script_line("df -h\n", &deny(&["secret-file"])), None);
    }

    #[test]
    fn only_read_only_scripts_without_sudo_pass() {
        let none = HashSet::new();
        let list = deny(&["secret-file"]);
        let check = "used=$(df -P / | awk 'NR==2 {print $5}' | tr -d %)\nif [ \"$used\" -ge 90 ]; then\n  echo \"disk $used%\"\n  exit 2\nfi\necho \"disk ok $used%\"\necho \"WISPOPS-JSON: {\\\"used\\\": $used}\"\nexit 0\n";
        assert_eq!(script_refusal(check, &none, &list), None);
        assert!(script_refusal("df -h\nrm -rf /tmp/x\n", &none, &list).unwrap().contains("not read-only"));
        assert!(script_refusal("systemctl restart nginx\n", &none, &list).unwrap().contains("not read-only"));
        assert!(script_refusal("df -h > /tmp/out\n", &none, &list).unwrap().contains("not read-only"));
        assert!(script_refusal("sudo cat /etc/shadow\n", &none, &list).unwrap().contains("escalates"));
        assert!(script_refusal("cat /etc/secret-file\n", &none, &list).unwrap().contains("deny list"));
        // A program the deployment counts as read-only.
        assert!(script_refusal("mycheck --quiet\n", &none, &list).is_some());
        assert_eq!(script_refusal("mycheck --quiet\n", &HashSet::from(["mycheck".to_string()]), &list), None);
    }

    #[test]
    fn stores_scripts_and_drafts_with_unique_ids_newest_draft_per_id_bounded() {
        let dir = temp("store");
        let store = script_store(&dir);
        let revision = store.read().unwrap().revision;
        store.change(&revision, |mut state| {
            state.entries = vec![validate_script(&json!({"id": "s1", "title": "one", "content": "echo 1"})).unwrap()];
            Ok(state)
        }).unwrap();
        assert_eq!(store.read().unwrap().value.entries[0].id, "s1");
        let revision = store.read().unwrap().revision;
        let doubled = store.change(&revision, |mut state| {
            state.entries.extend(state.entries.clone());
            Ok(state)
        });
        assert!(doubled.unwrap_err().contains("重复"));
        for i in 0..12 { add_script_draft(&dir, &json!({"id": format!("d{}", i % 11), "title": "t", "content": format!("echo {i}")})).unwrap(); }
        let drafts = script_draft_store(&dir).read().unwrap().value.entries;
        assert_eq!(drafts.len(), 10);
        let last = &drafts.last().unwrap().script;
        assert_eq!((last.id.as_str(), last.content.as_str()), ("d0", "echo 11"));
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("check-script-drafts.json")).unwrap()).unwrap();
        assert_eq!(raw["entries"][9]["script"]["timeoutSec"], 120);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn accepting_moves_a_draft_into_the_library_and_refuses_one_that_is_not_read_only() {
        let dir = temp("accept");
        let list = deny(&["secret-file"]);
        let good = add_script_draft(&dir, &json!({"id": "load", "title": "Load", "content": "uptime\nexit 0", "timeoutSec": 30})).unwrap();
        let bad = add_script_draft(&dir, &json!({"id": "fix", "title": "Fix", "content": "systemctl restart nginx"})).unwrap();
        assert!(!dir.join("check-scripts.json").exists());
        assert!(accept_script_draft(&dir, &bad.id, &HashSet::new(), &list).is_err());
        let accepted = accept_script_draft(&dir, &good.id, &HashSet::new(), &list).unwrap();
        assert_eq!((accepted.id.as_str(), accepted.timeout_sec, accepted.sha256.as_str()), ("load", 30, script_digest("uptime\nexit 0").as_str()));
        assert_eq!(script_store(&dir).read().unwrap().value.entries, vec![accepted]);
        assert_eq!(script_draft_store(&dir).read().unwrap().value.entries.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), [bad.id.as_str()]);
        assert!(accept_script_draft(&dir, &good.id, &HashSet::new(), &list).is_err());
        delete_script_draft(&dir, &bad.id).unwrap();
        assert!(script_draft_store(&dir).read().unwrap().value.entries.is_empty());
        delete_script(&dir, "load").unwrap();
        assert!(script_store(&dir).read().unwrap().value.entries.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn maps_exit_codes_to_verdicts_and_splits_summary_evidence_and_metrics() {
        let parsed = parse_script_result(&ok("\n all good \nfree 80%\nWISPOPS-JSON: {\"free_pct\": 80, \"bad\": \"x\"}\n"));
        assert_eq!(parsed, ScriptOutcome { host: "a".into(), verdict: ScriptVerdict::Ok, exit_code: Some(0), summary: "all good".into(), evidence: "free 80%".into(), metrics: Some(BTreeMap::from([("free_pct".to_string(), 80.)])) });
        let warn = parse_script_result(&run(RunStatus::Failed, Some(1), "disk 91%\n", ""));
        assert_eq!((warn.verdict, warn.summary.as_str(), warn.evidence.as_str()), (ScriptVerdict::Warn, "disk 91%", ""));
        let crit = parse_script_result(&run(RunStatus::Failed, Some(2), "disk full\n/data 100%\n", "warning: slow"));
        assert_eq!((crit.verdict, crit.summary.as_str(), crit.evidence.as_str()), (ScriptVerdict::Crit, "disk full", "/data 100%\n[stderr]\nwarning: slow"));
        let failed = parse_script_result(&run(RunStatus::Failed, Some(127), "", "sh: nvidia-smi: not found"));
        assert_eq!((failed.verdict, failed.summary.as_str()), (ScriptVerdict::Failed, "sh: nvidia-smi: not found"));
        let silent = parse_script_result(&run(RunStatus::Failed, Some(1), "", ""));
        assert_eq!((silent.verdict, silent.summary.as_str()), (ScriptVerdict::Warn, "exit 1 (no output)"));
        assert_eq!(parse_script_result(&ok("")).summary, "ok (no output)");
        let down = parse_script_result(&run(RunStatus::Unreachable, None, "", "ssh: connect refused"));
        assert_eq!((down.verdict, down.summary.as_str(), down.exit_code), (ScriptVerdict::Unreachable, "unreachable: ssh: connect refused", None));
        assert_eq!(parse_script_result(&run(RunStatus::SudoRequired, Some(97), "", "")).verdict, ScriptVerdict::Unreachable);
        // A malformed metrics line stays in the evidence instead of being lost.
        assert!(parse_script_result(&ok("ok\nWISPOPS-JSON: {broken\n")).evidence.contains("WISPOPS-JSON: {broken"));
    }

    #[test]
    fn bounds_summaries_and_evidence_and_notes_capture_truncation() {
        let mut result = ok(&format!("{}\n{}", "s".repeat(400), "e".repeat(5000)));
        result.truncated = true;
        let out = parse_script_result(&result);
        assert!(out.summary.chars().count() < 320);
        assert!(out.evidence.contains("(truncated)"));
        assert!(out.evidence.contains("capture limit"));
    }

    #[test]
    fn renders_summaries_before_evidence_and_ranks_the_worst_verdict() {
        let mut second = run(RunStatus::Failed, Some(1), "load high\nload 12.0\n", "");
        second.host = "b".into();
        let outcomes = [parse_script_result(&ok("fine\n")), parse_script_result(&second)];
        let script = CheckScript { id: "load".into(), title: "Load".into(), description: String::new(), content: "uptime".into(), sha256: "abcdef0123456789".into(), timeout_sec: 120, updated_at: String::new() };
        let text = render_script_outcomes(&script, &outcomes);
        assert!(text.contains("sha256 abcdef012345)"));
        assert!(text.find("- a: ok — fine").unwrap() < text.find("### b (warn, exit 1)").unwrap());
        assert!(text.contains("- b: warn — load high"));
        assert!(text.contains("load 12.0"));
        assert_eq!(worst_verdict(outcomes.iter().map(|o| o.verdict)), ScriptVerdict::Warn);
        assert_eq!(worst_verdict([ScriptVerdict::Failed, ScriptVerdict::Crit, ScriptVerdict::Unreachable]), ScriptVerdict::Crit);
        assert_eq!(worst_verdict([ScriptVerdict::Failed, ScriptVerdict::Unreachable]), ScriptVerdict::Unreachable);
        assert_eq!(worst_verdict([]), ScriptVerdict::Ok);
    }
}
