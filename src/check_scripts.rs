//! The check-script library as the window and the tools use it (`impl Fleet`): what the 检查脚本
//! tab draws, a person accepting or deleting a draft, the model's `ops_script_draft`, and the
//! `script` playbook of a routine task. The model only ever writes drafts; a script runs only
//! once a person has accepted it, and every run checks it again (read-only, deny list).

use crate::ops::{Collect, Exec, Fleet};
use serde_json::{Value, json};
use wisp_ops_engine::check_scripts::{self as library, CheckScript, ScriptDraft, ScriptOutcome, ScriptVerdict};
use wisp_ops_engine::config::{Playbook, TaskSpec};
use wisp_ops_engine::inventory::Host;
use wisp_ops_engine::risk::RiskLevel;

/// A script of the library, with what stands against running it now and the tasks that run it.
#[derive(Clone, Debug)]
pub struct ScriptRow {
    pub script: CheckScript,
    pub refusal: Option<String>,
    pub used_by: Vec<String>,
}

/// A draft waiting for review, and whether accepting it would replace a script of the library.
#[derive(Clone, Debug)]
pub struct DraftRow {
    pub draft: ScriptDraft,
    pub refusal: Option<String>,
    pub replaces: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ScriptsView {
    pub scripts: Vec<ScriptRow>,
    pub drafts: Vec<DraftRow>,
    /// Why a file could not be read.
    pub error: Option<String>,
}

impl Fleet {
    pub fn scripts_view(&self) -> ScriptsView {
        let mut error = None;
        let scripts = library::script_store(self.data_dir()).read().map(|state| state.value.entries).unwrap_or_else(|e| { error = Some(e); vec![] });
        let drafts = library::script_draft_store(self.data_dir()).read().map(|state| state.value.entries).unwrap_or_else(|e| { error = Some(e); vec![] });
        let inventory = self.inventory();
        let tasks = inventory.tasks();
        let refusal = |content: &str| library::script_refusal(content, &self.extra_read, &self.deny);
        ScriptsView {
            drafts: drafts.into_iter().rev().map(|draft| DraftRow { refusal: refusal(&draft.script.content), replaces: scripts.iter().any(|script| script.id == draft.script.id), draft }).collect(),
            scripts: scripts.into_iter().map(|script| ScriptRow { refusal: refusal(&script.content), used_by: tasks.iter().filter(|task| task.script.as_deref() == Some(script.id.as_str())).map(|task| task.name.clone()).collect(), script }).collect(),
            error,
        }
    }

    pub fn library_script(&self, id: &str) -> Result<Option<CheckScript>, String> {
        Ok(library::script_store(self.data_dir()).read()?.value.entries.into_iter().find(|script| script.id == id))
    }

    /// A person accepts a draft in the window. Never reached from a tool.
    pub fn accept_script_draft(&self, draft_id: &str) -> Result<CheckScript, String> {
        library::accept_script_draft(self.data_dir(), draft_id, &self.extra_read, &self.deny)
    }

    pub fn delete_script_draft(&self, draft_id: &str) -> Result<(), String> {
        library::delete_script_draft(self.data_dir(), draft_id)
    }

    /// Take a script out of the library, unless a routine task still runs it.
    pub fn delete_script(&self, id: &str) -> Result<(), String> {
        let users: Vec<String> = self.inventory().tasks().iter().filter(|task| task.script.as_deref() == Some(id)).map(|task| task.name.clone()).collect();
        if !users.is_empty() { return Err(format!("例行任务 {} 还在用这个脚本，请先修改或删除任务。", users.join("、"))) }
        library::delete_script(self.data_dir(), id)
    }

    /// `ops_script_draft`: keep the model's proposal for review. Nothing is saved to the library, linked or run.
    pub fn draft_script(&self, args: &Value) -> Result<String, String> {
        let id = args["id"].as_str().unwrap_or("");
        if self.library_script(id)?.is_some() { return Err(format!("script id \"{id}\" is already in the script library; choose another id")) }
        let proposal = json!({"id": args["id"], "title": args["title"], "description": args["description"], "content": args["content"], "timeoutSec": args["timeoutSec"]});
        let script = library::validate_script(&proposal)?;
        // A draft that could never be accepted is sent back, so the model can rewrite it now.
        if let Some(reason) = library::script_refusal(&script.content, &self.extra_read, &self.deny) { return Err(format!("draft not kept: {reason}. Check scripts must be read-only POSIX sh without sudo; rewrite it.")) }
        let draft = library::add_script_draft(self.data_dir(), &proposal)?;
        Ok(format!("Draft script \"{}\" ({}, sha256 {}) is waiting for review. Nothing was saved or run: ask the user to open WispOps → Routine tasks → Check scripts, read the draft and accept it; they can then use it as the check of a routine task.", draft.script.title, draft.script.id, &draft.script.sha256[..12]))
    }

    /// The `script` playbook: run the accepted script on every host and judge each by the output contract.
    /// Gives the text for the record and the counts by verdict.
    pub fn run_script_task(&self, task: &TaskSpec, hosts: &[Host], collect: &Collect) -> Result<(String, Vec<(&'static str, f64)>), String> {
        debug_assert_eq!(task.playbook, Playbook::Script);
        let id = task.script.as_deref().unwrap_or("");
        let Some(script) = self.library_script(id)? else { return Ok((format!("Check script \"{id}\" is not in the script library (deleted, or never accepted); nothing ran."), vec![("incomplete", 1.)])) };
        if let Some(reason) = library::script_refusal(&script.content, &self.extra_read, &self.deny) { return Err(format!("check script {id} was not run: {reason}")) }
        let exec = Exec { sudo: collect.sudo, timeout_ms: script.timeout_sec * 1000, max_output_bytes: None, tool: collect.tool.clone(), session: collect.session.clone(), risk: RiskLevel::Read, authorization: collect.authorization, reason: Some(format!("task {} check script {}", task.name, script.id)), audit_command: Some(format!("(check script {} sha256:{})", script.id, &script.sha256[..12])), time_login: false, cancel: collect.cancel.clone() };
        let outcomes: Vec<ScriptOutcome> = self.execute_one(hosts, &script.content, &exec).iter().map(library::parse_script_result).collect();
        let counts = outcomes.iter().map(|outcome| (match outcome.verdict { ScriptVerdict::Ok => "ok", ScriptVerdict::Warn => "warn", ScriptVerdict::Crit => "crit", ScriptVerdict::Failed => "commandFailed", ScriptVerdict::Unreachable => "unreachable" }, 1.)).collect();
        Ok((library::render_script_outcomes(&script, &outcomes), counts))
    }
}

#[cfg(test)]
mod tests {
    use crate::ops::{Fleet, HostDraft, TaskDraft};
    use serde_json::json;

    const FAKE_SSH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/crates/engine/tests/fixtures/fake-ssh.sh");

    fn fleet(tag: &str) -> (Fleet, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("wisp-ops-scripts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("config.json"), json!({"ssh": {"binary": FAKE_SSH, "loadProfile": false}, "denyPatterns": ["secret-file"]}).to_string()).unwrap();
        let fleet = Fleet::open_keyed(&root, true);
        for name in ["web-01", "web-02"] {
            fleet.save_host(None, HostDraft { name: name.into(), ssh: name.into(), user: "ops".into(), ..Default::default() }).unwrap();
        }
        (fleet, root)
    }

    fn task(name: &str, script: &str) -> TaskDraft {
        TaskDraft { name: name.into(), targets: "web-01,web-02".into(), playbook: "script".into(), script: script.into(), schedule: "manual".into(), daily: "08:30".into(), every_minutes: 60, ..Default::default() }
    }

    #[test]
    fn a_drafted_script_runs_only_after_a_person_accepts_it() {
        let (fleet, root) = fleet("flow");
        let content = "echo \"load ok on $FAKE_HOST\"\necho \"procs 42\"\necho 'WISPOPS-JSON: {\"procs\": 42}'\n[ \"$FAKE_HOST\" = web-02 ] && exit 1\nexit 0\n";
        let said = fleet.draft_script(&json!({"id": "load", "title": "Load", "description": "warn on web-02", "content": content, "timeoutSec": 30})).unwrap();
        assert!(said.contains("waiting for review"));
        assert!(!root.join("check-scripts.json").exists());
        // The model cannot propose what could never be accepted, nor a bad id.
        assert!(fleet.draft_script(&json!({"id": "fix", "title": "Fix", "content": "systemctl restart nginx"})).unwrap_err().contains("not read-only"));
        assert!(fleet.draft_script(&json!({"id": "bad id", "title": "t", "content": "uptime"})).is_err());
        // A task cannot name a script that was not accepted.
        assert!(fleet.save_task(None, task("load-check", "load")).is_err());
        let view = fleet.scripts_view();
        assert_eq!((view.scripts.len(), view.drafts.len()), (0, 1));
        let accepted = fleet.accept_script_draft(&view.drafts[0].draft.id).unwrap();
        assert_eq!(accepted.timeout_sec, 30);
        // Proposing a script of the library again is refused: only a person replaces one.
        assert!(fleet.draft_script(&json!({"id": "load", "title": "Load", "content": "uptime"})).unwrap_err().contains("already in the script library"));
        fleet.save_task(None, task("load-check", "load")).unwrap();
        let (problems, summary) = fleet.run_task("load-check", false).unwrap();
        assert!(problems, "{summary}");
        assert_eq!(summary, "ok=1, warn=1");
        let text = fleet.last_task_text(fleet.inventory().task("load-check").unwrap());
        assert!(text.contains("- web-01: ok — load ok on web-01 {procs=42}"), "{text}");
        assert!(text.contains("- web-02: warn — load ok on web-02 {procs=42}"), "{text}");
        assert!(text.contains("### web-02 (warn, exit 1)\nprocs 42"), "{text}");
        // The audit names the script by its digest, never its text.
        let audit = fleet.audit(None, 1, 50);
        assert!(audit.iter().any(|row| row.command.contains("(check script load sha256:")));
        assert!(!audit.iter().any(|row| row.command.contains("echo")));
        // A script a task uses stays in the library.
        assert!(fleet.delete_script("load").is_err());
        fleet.delete_task("load-check").unwrap();
        fleet.delete_script("load").unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_library_script_that_became_refused_does_not_run() {
        let (fleet, root) = fleet("refused");
        // Written into the library by hand, past the window's checks.
        let store = wisp_ops_engine::check_scripts::script_store(&root);
        let revision = store.read().unwrap().revision;
        store.change(&revision, |mut state| {
            state.entries.push(wisp_ops_engine::check_scripts::validate_script(&json!({"id": "denied", "title": "Denied", "content": "cat /etc/secret-file"})).unwrap());
            Ok(state)
        }).unwrap();
        assert!(fleet.save_task(None, task("denied", "denied")).is_err());
        assert!(fleet.scripts_view().scripts[0].refusal.as_deref().unwrap_or("").contains("deny list"));
        let _ = std::fs::remove_dir_all(root);
    }
}
