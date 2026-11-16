//! Managed-change transactions run for real in a local shell (`change.spec.ts`), and the script
//! text compared byte for byte with what the plugin generated.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use wisp_ops_engine::change::{ChangeOutcome, ChangePlan, ChangeResult, ChangeScriptOptions, change_commands, change_script, describe_change, parse_change_output, validate_change};

struct Sandbox {
    dir: tempfile::TempDir,
    file: PathBuf,
}

/// A directory with one file to change and a stand-in `timeout` that just runs the stage.
/// Transaction tests exercise stage failures; GNU timeout itself is exercised on Linux only.
fn sandbox() -> Sandbox {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config with spaces");
    std::fs::write(&file, "before").unwrap();
    let timeout = dir.path().join("timeout");
    std::fs::write(&timeout, "#!/bin/sh\nshift; shift; shift; exec \"$@\"\n").unwrap();
    std::fs::set_permissions(&timeout, std::fs::Permissions::from_mode(0o700)).unwrap();
    Sandbox { dir, file }
}

impl Sandbox {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn plan(&self) -> Value {
        let file = self.file.display();
        json!({ "targets": "a", "files": [self.file], "command": format!("printf after > '{file}'"), "verify": format!("test \"$(cat '{file}')\" = after"), "reason": "Update config" })
    }

    fn plan_with(&self, extra: Value) -> ChangePlan {
        let mut plan = self.plan();
        plan.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        validate_change(&plan).unwrap()
    }

    fn run_with(&self, plan: &ChangePlan, retention_days: u64) -> (i32, String) {
        let script = change_script(plan, 2, &ChangeScriptOptions { backup_root: self.path().to_string_lossy().into_owned(), retention_days });
        let path = format!("{}:{}", self.path().display(), std::env::var("PATH").unwrap_or_default());
        let output = Command::new("sh").arg("-c").arg(script).env("PATH", path).output().unwrap();
        (output.status.code().unwrap_or(-1), String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn run(&self, plan: &ChangePlan) -> (i32, String) {
        self.run_with(plan, 0)
    }
}

fn backup_dir(stdout: &str) -> PathBuf {
    PathBuf::from(parse_change_output(stdout, None).backup_dir.expect("backup directory line"))
}

fn sorted_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

#[test]
fn generates_the_same_script_text_as_the_plugin() {
    let full = validate_change(&json!({
        "targets": "a",
        "files": ["/etc/app/config with spaces", "/etc/it's.conf"],
        "newFiles": ["/etc/app/new.conf"],
        "directories": ["/etc/nginx/conf.d", "/srv"],
        "command": "printf 'x' > /etc/app/new.conf; systemctl reload app",
        "verify": "test -s /etc/app/new.conf",
        "afterRollback": "systemctl reload app",
        "reason": "golden",
    }))
    .unwrap();
    assert_eq!(change_script(&full, 120, &ChangeScriptOptions { backup_root: "/var/tmp".to_string(), retention_days: 14 }), include_str!("fixtures/change-full.golden.sh"));
    assert_eq!(describe_change(&full), include_str!("fixtures/change-describe.golden.txt"));
    let minimal = validate_change(&json!({ "targets": "a", "files": ["/etc/motd"], "command": "echo hi > /etc/motd", "verify": "true", "reason": "r" })).unwrap();
    assert_eq!(change_script(&minimal, 30, &ChangeScriptOptions::default()), include_str!("fixtures/change-minimal.golden.sh"));
    assert_eq!(change_commands(&minimal), ["echo hi > /etc/motd", "true", "true"]);
    assert_eq!(change_commands(&full)[2], "systemctl reload app");
}

#[test]
fn backs_up_and_verifies_a_successful_change() {
    let sandbox = sandbox();
    let (code, stdout) = sandbox.run(&sandbox.plan_with(json!({})));
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains("WISPOPS_CHANGE=verified"));
    let backup = backup_dir(&stdout);
    assert_eq!(std::fs::read_to_string(backup.join("f0")).unwrap(), "before");
    assert_eq!(std::fs::read_to_string(backup.join("manifest")).unwrap(), format!("file\t{}\n", sandbox.file.display()));
    assert_eq!(std::fs::read_to_string(&sandbox.file).unwrap(), "after");
    assert_eq!(parse_change_output(&stdout, Some(code)).outcome, ChangeOutcome::Verified);
}

#[test]
fn restores_the_backup_when_apply_or_verify_fails() {
    for stage in ["apply", "verify"] {
        let sandbox = sandbox();
        let plan = if stage == "apply" {
            let command = format!("{}; false; echo must-not-run", sandbox.plan()["command"].as_str().unwrap());
            sandbox.plan_with(json!({ "command": command }))
        } else {
            sandbox.plan_with(json!({ "verify": "false" }))
        };
        let (code, stdout) = sandbox.run(&plan);
        assert_eq!(code, if stage == "apply" { 22 } else { 23 }, "{stdout}");
        assert!(stdout.contains("WISPOPS_CHANGE=rolled-back"));
        assert!(!stdout.contains("must-not-run"));
        assert_eq!(std::fs::read_to_string(&sandbox.file).unwrap(), "before");
        assert_eq!(parse_change_output(&stdout, Some(code)).outcome, ChangeOutcome::RolledBack);
    }
}

#[test]
fn refuses_missing_files_or_symlinks_before_executing_changes() {
    let sandbox = sandbox();
    std::os::unix::fs::symlink(&sandbox.file, sandbox.path().join("link")).unwrap();
    assert_eq!(sandbox.run(&sandbox.plan_with(json!({ "files": [sandbox.path().join("link")] }))).0, 20);
    let (code, stdout) = sandbox.run(&sandbox.plan_with(json!({ "files": [sandbox.path().join("missing")] })));
    assert_eq!(code, 20);
    assert_eq!(parse_change_output(&stdout, Some(code)), ChangeResult { outcome: ChangeOutcome::Refused, backup_dir: None });
    assert_eq!(std::fs::read_to_string(&sandbox.file).unwrap(), "before");
    let invalid = |extra: Value| {
        let mut plan = sandbox.plan();
        plan.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        validate_change(&plan).unwrap_err()
    };
    assert!(invalid(json!({ "files": ["/a/../b"] })).contains("absolute normalized paths"));
    assert!(invalid(json!({ "files": [], "newFiles": [] })).contains("at least one path"));
    assert!(invalid(json!({ "newFiles": [sandbox.file] })).contains("duplicate"));
    assert!(invalid(json!({ "directories": ["/etc/"] })).contains("absolute normalized paths"));
    assert!(invalid(json!({ "files": ["relative"] })).contains("absolute normalized paths"));
    assert!(invalid(json!({ "files": ["/"] })).contains("absolute normalized paths"));
    assert!(invalid(json!({ "files": (0..31).map(|i| format!("/f{i}")).collect::<Vec<_>>() })).contains("at most 30"));
    assert!(invalid(json!({ "verify": "  " })).contains("verify is required"));
    assert!(invalid(json!({ "command": "x".repeat(8001) })).contains("command is required"));
    assert!(invalid(json!({ "afterRollback": 5 })).contains("invalid afterRollback"));
    assert!(invalid(json!({ "sudo": "yes" })).contains("sudo must be boolean"));
    assert!(invalid(json!({ "timeoutMs": 10 })).contains("timeoutMs"));
    assert!(invalid(json!({ "targets": " " })).contains("requires targets"));
    // `host` keeps working as an alias of `targets`.
    let mut aliased = sandbox.plan();
    aliased.as_object_mut().unwrap().remove("targets");
    aliased["host"] = json!("b");
    aliased["sudo"] = json!(true);
    aliased["timeoutMs"] = json!(90_000);
    let plan = validate_change(&aliased).unwrap();
    assert_eq!((plan.targets.as_str(), plan.sudo, plan.timeout_ms), ("b", Some(true), Some(90_000)));
}

#[test]
fn deletes_listed_new_files_on_rollback_and_refuses_paths_that_already_exist() {
    let sandbox = sandbox();
    let created = sandbox.path().join("new.conf");
    let base = json!({ "files": [], "newFiles": [created], "command": format!("printf fresh > '{}'", created.display()), "verify": "false" });
    let (code, stdout) = sandbox.run(&sandbox.plan_with(base.clone()));
    assert_eq!(code, 23, "{stdout}");
    assert!(stdout.contains("WISPOPS_CHANGE=rolled-back"));
    assert!(!created.exists());
    let with = |extra: Value| {
        let mut plan = base.clone();
        plan.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        sandbox.plan_with(plan)
    };
    assert_eq!(sandbox.run(&with(json!({ "verify": "true" }))).0, 0);
    assert_eq!(std::fs::read_to_string(&created).unwrap(), "fresh");
    // Now it exists, so the same plan is refused before anything runs.
    assert_eq!(sandbox.run(&with(json!({ "command": "echo must-not-run" }))).0, 20);
    assert_eq!(sandbox.run(&with(json!({ "newFiles": [sandbox.path().join("missing-parent").join("x.conf")] }))).0, 20);
}

#[test]
fn archives_listed_directories_with_tar_and_replaces_them_from_the_archive_on_failure() {
    let sandbox = sandbox();
    let conf = sandbox.path().join("conf.d");
    std::fs::create_dir(&conf).unwrap();
    std::fs::write(conf.join("a.conf"), "A").unwrap();
    std::fs::write(conf.join("b.conf"), "B").unwrap();
    let command = format!("rm -f '{0}/a.conf'; printf C > '{0}/c.conf'; printf B2 > '{0}/b.conf'", conf.display());
    let plan = sandbox.plan_with(json!({ "files": [], "directories": [conf], "command": command, "verify": "false" }));
    let (code, stdout) = sandbox.run(&plan);
    assert_eq!(code, 23, "{stdout}");
    assert!(stdout.contains("WISPOPS_CHANGE=rolled-back"));
    assert_eq!(sorted_names(&conf), ["a.conf", "b.conf"]);
    assert_eq!(std::fs::read_to_string(conf.join("b.conf")).unwrap(), "B");
    assert!(sorted_names(sandbox.path()).iter().all(|name| !name.contains("wispops-restore")));
    assert_eq!(sorted_names(&backup_dir(&stdout)), ["d0.tar", "manifest"]);
    assert_eq!(sandbox.run(&sandbox.plan_with(json!({ "files": [], "directories": [sandbox.file], "command": "true", "verify": "true" }))).0, 20);
}

#[test]
fn prunes_expired_backup_directories_according_to_the_retention_and_keeps_them_with_retention_0() {
    let sandbox = sandbox();
    let old = sandbox.path().join("wispops-change.oldold");
    let recent = sandbox.path().join("wispops-change.recent");
    std::fs::create_dir(&old).unwrap();
    std::fs::create_dir(&recent).unwrap();
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(40 * 86_400);
    std::fs::File::open(&old).unwrap().set_modified(past).unwrap();
    sandbox.run_with(&sandbox.plan_with(json!({})), 0);
    assert!(old.exists());
    sandbox.run_with(&sandbox.plan_with(json!({})), 14);
    assert!(!old.exists());
    assert!(recent.exists());
}

#[test]
fn parses_transaction_markers_from_host_output() {
    let result = |outcome, backup_dir: Option<&str>| ChangeResult { outcome, backup_dir: backup_dir.map(str::to_string) };
    assert_eq!(
        parse_change_output("Backup directory: /var/tmp/wispops-change.abc\nWISPOPS_STAGE=apply\nWISPOPS_CHANGE=verified\n", Some(0)),
        result(ChangeOutcome::Verified, Some("/var/tmp/wispops-change.abc"))
    );
    assert_eq!(parse_change_output("Backup directory: /x\nWISPOPS_CHANGE=rollback-failed\n", Some(24)).outcome, ChangeOutcome::RollbackFailed);
    assert_eq!(parse_change_output("GNU timeout is required\n", Some(20)), result(ChangeOutcome::Refused, None));
    assert_eq!(parse_change_output("", None), result(ChangeOutcome::Unknown, None));
    // The last marker wins; a marker must be a whole line; CRLF output is understood.
    assert_eq!(parse_change_output("WISPOPS_CHANGE=verified\nWISPOPS_CHANGE=rolled-back\n", Some(1)).outcome, ChangeOutcome::RolledBack);
    assert_eq!(parse_change_output("echo WISPOPS_CHANGE=verified\nWISPOPS_CHANGE=verified!\n", Some(21)).outcome, ChangeOutcome::Refused);
    assert_eq!(parse_change_output("Backup directory: /x y \r\nWISPOPS_CHANGE=verified\r\n", Some(0)), result(ChangeOutcome::Verified, Some("/x y")));
}

#[test]
fn reports_a_failed_post_restore_check_instead_of_claiming_a_successful_rollback() {
    let sandbox = sandbox();
    let (code, stdout) = sandbox.run(&sandbox.plan_with(json!({ "verify": "false", "afterRollback": "false" })));
    assert_eq!(code, 24, "{stdout}");
    assert!(stdout.contains("WISPOPS_CHANGE=rollback-failed"));
    assert_eq!(std::fs::read_to_string(&sandbox.file).unwrap(), "before");
}

#[test]
#[cfg(target_os = "linux")]
fn rolls_back_when_gnu_timeout_terminates_an_apply_stage() {
    let sandbox = sandbox();
    let command = format!("printf after > '{}'; sleep 10", sandbox.file.display());
    let plan = sandbox.plan_with(json!({ "command": command }));
    let script = change_script(&plan, 1, &ChangeScriptOptions { backup_root: sandbox.path().to_string_lossy().into_owned(), retention_days: 0 });
    let output = Command::new("sh").arg("-c").arg(script).env("PATH", "/usr/bin:/bin").output().unwrap();
    assert_eq!(output.status.code(), Some(22));
    assert!(String::from_utf8_lossy(&output.stdout).contains("WISPOPS_CHANGE=rolled-back"));
    assert_eq!(std::fs::read_to_string(&sandbox.file).unwrap(), "before");
}
