//! Inventory selection, effective policy, grants, decisions and the gate (`policy.spec.ts`,
//! `config.spec.ts`, and the gate cases of `change.spec.ts`).

use std::collections::HashSet;

use serde_json::json;
use wisp_ops_engine::change::{change_commands, change_risk, describe_change, validate_change};
use wisp_ops_engine::config::{AuthMethod, Capability, Config, Permission, Policy};
use wisp_ops_engine::inventory::{Inventory, load_inventory_file};
use wisp_ops_engine::managed::ManagedState;
use wisp_ops_engine::policy::{
    Authorization, Decision, DenyList, GateOutcome, GrantStore, NewGrant, compact, decide_at, describe_rulings, gate_at, grant_capabilities, host_list,
    parse_duration, pending_needs, required_capabilities,
};
use wisp_ops_engine::risk::{RiskAssessment, RiskLevel, classify_command};

fn config() -> Config {
    Config::resolve(json!({
        "inventoryFile": null,
        "hosts": [
            { "name": "web-01", "groups": ["web", "prod"], "tags": { "env": "prod" } },
            { "name": "web-02", "groups": ["web"], "tags": { "env": "staging" } },
            { "name": "gpu-01", "groups": ["gpu"], "policy": { "sudo": "allow" } },
            { "name": "db-01", "groups": ["prod"], "ssh": "admin@10.0.0.9" },
        ],
        "groups": { "prod": { "policy": { "destructive": "deny", "change": "ask" } }, "web": { "policy": { "change": "allow" } } },
    }))
    .unwrap()
}

fn inventory() -> Inventory {
    let config = config();
    Inventory::from_specs(config.hosts, config.groups, config.default_policy).unwrap()
}

fn no_extra() -> HashSet<String> {
    HashSet::new()
}

fn grant(session: &str, capability: Capability, host: &str, expires_at: i64) -> NewGrant {
    NewGrant { session: session.to_string(), capability, hosts: vec![host.to_string()], selector: host.to_string(), expires_at }
}

#[test]
fn config_fills_defaults() {
    let config = Config::resolve(json!({})).unwrap();
    assert_eq!(config.default_policy, Policy { change: Permission::Ask, sudo: Permission::Ask, destructive: Permission::Ask });
    assert_eq!(config.ssh.binary, "ssh");
    assert_eq!(config.ssh.concurrency, 8);
    assert_eq!(config.limits.max_output_bytes, 64 * 1024);
    assert!(!config.grants.allow_destructive);
    assert_eq!(config.retention.inspection_records, 1000);
    assert_eq!(config.change.backup_root, "/var/tmp");
    assert_eq!(config.deny_patterns.len(), 3);
    // Joined as the system joins paths: a backslash on Windows.
    let inventory_in = |dir: &str| std::path::Path::new(dir).join("inventory.yml").to_string_lossy().into_owned();
    assert_eq!(config.inventory_file, Some(inventory_in(&config.data_dir)));
    assert!(config.thresholds.is_object());
    // A custom data directory moves the default inventory file with it; thresholds pass through untouched.
    let custom = Config::resolve(json!({ "dataDir": "/srv/ops", "thresholds": { "diskCritPct": 95 } })).unwrap();
    assert_eq!(custom.inventory_file, Some(inventory_in("/srv/ops")));
    assert_eq!(custom.thresholds["diskCritPct"], 95);
    assert_eq!(Config::resolve(json!({ "inventoryFile": null })).unwrap().inventory_file, None);
}

#[test]
fn config_accepts_a_host_inventory() {
    let config = Config::resolve(json!({
        "hosts": [{ "name": "gpu-01", "ssh": "alice@10.0.0.5", "groups": ["gpu"], "policy": { "sudo": "allow" } }],
        "groups": { "gpu": { "policy": { "destructive": "deny" } } },
    }))
    .unwrap();
    assert_eq!(config.hosts[0].policy.sudo, Some(Permission::Allow));
}

#[test]
fn config_rejects_option_injecting_destinations_and_bad_values() {
    assert!(Config::resolve(json!({ "hosts": [{ "name": "x", "ssh": "-oProxyCommand=evil" }] })).is_err());
    assert!(Config::resolve(json!({ "hosts": [{ "name": "x", "policy": { "sudo": "yes" } }] })).is_err());
    assert!(Config::resolve(json!({ "hosts": [{ "name": "-x" }] })).is_err());
    assert!(Config::resolve(json!({ "hosts": [{ "name": "x", "user": "-l root" }] })).is_err());
    assert!(Config::resolve(json!({ "hosts": [{ "name": "x", "proxyJump": "-J" }] })).is_err());
    assert!(Config::resolve(json!({ "hosts": [{ "name": "x", "port": 70000 }] })).is_err());
    assert!(Config::resolve(json!({ "hosts": [{ "name": "x", "sudoUser": "root; id" }] })).is_err());
    assert!(Config::resolve(json!({ "ssh": { "extraPath": ["/opt/bin:/tmp"] } })).is_err());
    assert!(Config::resolve(json!({ "ssh": { "concurrency": 0 } })).is_err());
    assert!(Config::resolve(json!({ "change": { "backupRoot": "/var/tmp/" } })).is_err());
    assert!(Config::resolve(json!({ "tasks": [{ "name": "t", "targets": "all", "playbook": "inspect", "schedule": { "daily": "25:00" } }] })).is_err());
    assert!(Config::resolve(json!({ "tasks": [{ "name": "t", "targets": "all", "playbook": "dance" }] })).is_err());
    assert!(Config::resolve(json!({ "tasks": [{ "name": "t", "playbook": "inspect" }] })).is_err());
}

#[test]
fn selects_by_name_group_tag_glob_and_exclusion() {
    let inventory = inventory();
    let names = |selector: &str| inventory.select_names(selector).unwrap();
    assert_eq!(names("@web"), ["web-01", "web-02"]);
    assert_eq!(names("tag:env=prod"), ["web-01"]);
    assert_eq!(names("tag:env"), ["web-01", "web-02"]);
    assert_eq!(names("web-*,!web-02"), ["web-01"]);
    assert_eq!(names("all !@prod"), ["web-02", "gpu-01"]);
    assert_eq!(names("???-01"), ["web-01", "gpu-01"]);
    assert_eq!(names("db-01, web-01"), ["web-01", "db-01"]);
    assert!(inventory.select("@nope").unwrap_err().contains("unknown group"));
    assert!(inventory.select("nope").unwrap_err().contains("unknown host"));
    assert!(inventory.select(" , ").unwrap_err().contains("empty host selector"));
    assert!(inventory.select("tag:=x").unwrap_err().contains("invalid tag selector"));
}

#[test]
fn resolves_policy_host_over_groups_and_the_strictest_group_wins() {
    let inventory = inventory();
    // web says change=allow, prod says change=ask: the stricter ask wins.
    assert_eq!(inventory.host("web-01").unwrap().policy, Policy { change: Permission::Ask, sudo: Permission::Ask, destructive: Permission::Deny });
    assert_eq!(inventory.host("web-02").unwrap().policy.change, Permission::Allow);
    assert_eq!(inventory.host("gpu-01").unwrap().policy.sudo, Permission::Allow);
    assert!(inventory.groups().contains_key("gpu"));
    assert!(inventory.address_tokens().contains("10.0.0.9"));
}

#[test]
fn example_inventory_is_valid_and_resolves_policy_as_documented() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/example-inventory.yml");
    let file = load_inventory_file(path).unwrap();
    let example = Inventory::new(file.hosts.into_iter().map(Into::into).collect(), file.groups, Policy::default(), file.tasks, &no_extra()).unwrap();
    assert_eq!(example.select_names("@gpu").unwrap(), ["gpu-01", "gpu-02"]);
    assert_eq!(example.host("web-01").unwrap().policy.destructive, Permission::Deny);
    let nas = example.host("nas").unwrap();
    assert_eq!(nas.auth, Some(AuthMethod::Password));
    assert_eq!(nas.policy, Policy { change: Permission::Allow, sudo: Permission::Allow, destructive: Permission::Ask });
    assert_eq!(example.tasks().len(), 4);
    let morning = example.task("a-mcp-morning").unwrap();
    assert_eq!(morning.commands.len(), 2);
    assert_eq!(morning.schedule.as_ref().unwrap().daily.as_deref(), Some("08:30"));
    assert_eq!(example.task("c-security").unwrap().schedule.as_ref().unwrap().weekdays, [1, 2, 3, 4, 5]);
}

#[test]
fn treats_a_missing_file_as_empty_and_rejects_invalid_entries() {
    let missing = load_inventory_file("/nonexistent/inventory.yml").unwrap();
    assert!(missing.hosts.is_empty() && missing.groups.is_empty() && missing.tasks.is_empty());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inventory.yml");
    std::fs::write(&path, "hosts:\n  - name: ok\n  - name: bad\n    ssh: \"-oProxyCommand=evil\"\n").unwrap();
    let error = load_inventory_file(path.to_str().unwrap()).unwrap_err();
    assert!(error.contains("invalid inventory file"), "{error}");
    std::fs::write(&path, "").unwrap();
    assert!(load_inventory_file(path.to_str().unwrap()).unwrap().hosts.is_empty());
}

#[test]
fn rejects_duplicate_hosts_and_tasks_that_are_not_read_only() {
    let load = |tasks: serde_json::Value| {
        let config = Config::resolve(json!({ "inventoryFile": null, "hosts": [{ "name": "a" }, { "name": "b" }], "tasks": tasks })).unwrap();
        Inventory::load(&config, &[], Some(&ManagedState::default()))
    };
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "commands": ["uptime", " df -h "] }])).unwrap().task("t").unwrap().commands == ["uptime", "df -h"]);
    let error = load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "commands": ["systemctl restart nginx"] }])).unwrap_err();
    assert!(error.contains("not read-only") && error.contains("systemctl changes service state"), "{error}");
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "commands": ["sudo uptime"] }])).unwrap_err().contains("privilege escalation"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "custom" }])).unwrap_err().contains("needs an instruction"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "script" }])).unwrap_err().contains("needs a script id"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "script": "x" }])).unwrap_err().contains("does not use the script playbook"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "new-files" }])).unwrap_err().contains("needs paths"));
    assert!(load(json!([{ "name": "t", "targets": "nope", "playbook": "inspect" }])).unwrap_err().contains("unknown host"));
    assert!(load(json!([{ "name": "t", "targets": "all !all", "playbook": "inspect" }])).unwrap_err().contains("matches no hosts"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "schedule": { "daily": "08:00", "everyMinutes": 5 } }])).unwrap_err().contains("exactly one of"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "schedule": { "everyMinutes": 5, "weekdays": [1] } }])).unwrap_err().contains("weekdays need daily"));
    // The timer keeps cron schedules, so a report that runs without the agent may use one.
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "report": "problems", "schedule": { "cron": "0 8 * * 1-5" } }])).unwrap().task("t").unwrap().schedule.as_ref().unwrap().cron.is_some());
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "custom", "instruction": "x", "report": "never" }])).unwrap_err().contains("needs read-only commands"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "quietHours": { "start": "22:00", "end": "22:00" } }])).unwrap_err().contains("different start and end"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "quietHours": { "start": "22:00", "end": "08:00", "timeZone": "Mars/Base" } }])).unwrap_err().contains("is invalid"));
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect" }, { "name": "t", "targets": "b", "playbook": "disk" }])).unwrap_err().contains("duplicate task"));
    // An empty schedule object is the same as none.
    assert!(load(json!([{ "name": "t", "targets": "a", "playbook": "inspect", "schedule": {} }])).unwrap().task("t").unwrap().schedule.is_none());
    let duplicate = Config::resolve(json!({ "inventoryFile": null, "hosts": [{ "name": "a" }, { "name": "a" }] })).unwrap();
    assert!(Inventory::load(&duplicate, &[], Some(&ManagedState::default())).unwrap_err().contains("duplicate inventory host"));
}

#[test]
fn denies_over_asks_over_allows_and_grants_only_lift_ask() {
    let inventory = inventory();
    let grants = GrantStore::new();
    let hosts = inventory.select("web-01,web-02").unwrap();
    let destructive = required_capabilities(&classify_command("rm -rf /tmp/x", &no_extra()), false);
    assert_eq!(destructive, [Capability::Change, Capability::Destructive]);
    let kind = |decision: Decision| match decision {
        Decision::Allow { .. } => "allow",
        Decision::Ask { .. } => "ask",
        Decision::Deny { .. } => "deny",
    };
    assert_eq!(kind(decide_at(&hosts, &destructive, Some("s"), &grants, 1000)), "deny");
    assert_eq!(kind(decide_at(&hosts, &[Capability::Change], Some("s"), &grants, 1000)), "ask");
    grants.add_at(grant("s", Capability::Change, "web-01", 5000), 1000);
    assert_eq!(kind(decide_at(&hosts, &[Capability::Change], Some("s"), &grants, 1000)), "allow");
    assert_eq!(kind(decide_at(&hosts, &[Capability::Change], Some("other-session"), &grants, 1000)), "ask");
    assert_eq!(kind(decide_at(&hosts, &[Capability::Change], None, &grants, 1000)), "ask");
    grants.add_at(grant("s", Capability::Destructive, "web-01", 5000), 1000);
    assert_eq!(kind(decide_at(&hosts, &destructive, Some("s"), &grants, 1000)), "deny");
    let Decision::Allow { rulings } = decide_at(&hosts, &[Capability::Change], Some("s"), &grants, 1000) else { panic!("expected allow") };
    assert!(describe_rulings(&rulings).starts_with("web-01: change (grant "));
    assert!(describe_rulings(&rulings).ends_with("; web-02: change"));
}

#[test]
fn expires_and_revokes_grants() {
    let grants = GrantStore::new();
    let first = grants.add_at(grant("s", Capability::Sudo, "web-02", 100), 0);
    assert_eq!(first.id.len(), 8);
    assert_eq!(first.created_at, 0);
    assert_eq!(grants.active_at("s", 0).len(), 1);
    assert!(grants.find_at("s", "web-02", Capability::Sudo, 99).is_some());
    assert!(grants.find_at("s", "web-02", Capability::Change, 99).is_none());
    assert!(grants.find_at("s", "web-01", Capability::Sudo, 99).is_none());
    assert_eq!(grants.active_at("s", 100).len(), 0);
    let kept = grants.add_at(grant("s", Capability::Sudo, "web-02", 1000), 0);
    grants.add_at(grant("s", Capability::Change, "web-02", 1000), 0);
    grants.add_at(grant("t", Capability::Change, "web-02", 1000), 0);
    assert_eq!(grants.revoke_at("s", &kept.id, 1).len(), 1);
    assert_eq!(grants.active_at("s", 1).len(), 1);
    assert_eq!(grants.revoke_at("s", "all", 1).len(), 1);
    assert_eq!(grants.active_at("t", 1).len(), 1);
    grants.clear();
    assert!(grants.active_at("t", 1).is_empty());
}

fn gate_exec(inventory: &Inventory, targets: &str, command: &str, sudo: bool, grants: &GrantStore) -> GateOutcome {
    let deny = DenyList::compile(&config().deny_patterns).unwrap();
    let hosts = inventory.select(targets).unwrap();
    gate_at(&hosts, &classify_command(command, &no_extra()), sudo, false, &[command.to_string()], Some("s"), grants, &deny, 42)
}

#[test]
fn gate_asks_with_the_pending_capabilities() {
    let inventory = inventory();
    let outcome = gate_exec(&inventory, "db-01", "systemctl restart postgresql", true, &GrantStore::new());
    let GateOutcome::Ask { voucher, pending } = outcome else { panic!("expected ask, got {outcome:?}") };
    assert_eq!(pending_needs(&pending), "change + sudo");
    assert_eq!(voucher.hosts, ["db-01"]);
    assert_eq!(voucher.authorization, Authorization::Approval);
    assert!(voucher.sudo);
    assert_eq!(voucher.issued_at, 42);
    assert_eq!(voucher.risk.level, RiskLevel::Change);
    // sudo inside the command counts as sudo.
    let GateOutcome::Ask { voucher, pending } = gate_exec(&inventory, "web-02", "sudo du -sh /root", false, &GrantStore::new()) else { panic!("expected ask") };
    assert_eq!(pending_needs(&pending), "sudo");
    assert!(voucher.sudo);
}

#[test]
fn gate_allows_read_only_policy_and_grants_and_refuses_denials() {
    let inventory = inventory();
    let grants = GrantStore::new();
    let deny = DenyList::compile(&config().deny_patterns).unwrap();
    let all = inventory.select("all").unwrap();
    let read = gate_at(&all, &RiskAssessment::read(), false, false, &["(built-in read-only inspection)".to_string()], Some("s"), &grants, &deny, 1);
    assert!(matches!(read, GateOutcome::Allow { ref voucher } if voucher.authorization == Authorization::ReadOnly && voucher.hosts.len() == 4));
    // web-02 allows change by group policy.
    assert!(matches!(gate_exec(&inventory, "web-02", "systemctl restart nginx", false, &grants), GateOutcome::Allow { ref voucher } if voucher.authorization == Authorization::Policy));
    // The deny list wins over everything, including an allowing policy.
    let GateOutcome::Deny { reason } = gate_exec(&inventory, "gpu-01", "rm -rf --no-preserve-root /", false, &grants) else { panic!("expected deny") };
    assert!(reason.contains("deployment deny list") && reason.contains("--no-preserve-root"), "{reason}");
    assert!(matches!(gate_exec(&inventory, "gpu-01", "rm -rf /", false, &grants), GateOutcome::Deny { .. }));
    assert!(matches!(gate_exec(&inventory, "gpu-01", ":(){ :|:& };:", false, &grants), GateOutcome::Deny { .. }));
    assert!(matches!(gate_exec(&inventory, "gpu-01", "chmod -R 777 /", false, &grants), GateOutcome::Deny { .. }));
    // Policy deny is absolute.
    let GateOutcome::Deny { reason } = gate_exec(&inventory, "web-01", "rm -rf /tmp/x", false, &grants) else { panic!("expected deny") };
    assert!(reason.contains("web-01: destructive is set to deny"), "{reason}");
    // A grant turns ask into allow, recorded as such.
    let db = inventory.select("db-01").unwrap();
    let change = classify_command("systemctl restart postgresql", &no_extra());
    grants.add_at(grant("s", Capability::Change, "db-01", 100), 0);
    let granted = gate_at(&db, &change, false, false, &[], Some("s"), &grants, &deny, 50);
    assert!(matches!(granted, GateOutcome::Allow { ref voucher } if voucher.authorization == Authorization::Grant));
    assert!(matches!(gate_at(&db, &change, true, false, &[], Some("s"), &grants, &deny, 50), GateOutcome::Ask { ref pending, .. } if pending_needs(pending) == "sudo"));
    // Once it expires the capability asks again.
    assert!(matches!(gate_at(&db, &change, false, false, &[], Some("s"), &grants, &deny, 100), GateOutcome::Ask { .. }));
}

#[test]
fn full_permission_lifts_every_ask_of_its_session_but_never_a_deny() {
    let config = Config::resolve(json!({ "inventoryFile": null, "hosts": [{ "name": "a" }, { "name": "b", "policy": { "destructive": "deny" } }] })).unwrap();
    let inventory = Inventory::load(&config, &[], Some(&ManagedState::default())).unwrap();
    let deny = DenyList::compile(&config.deny_patterns).unwrap();
    let grants = GrantStore::new();
    let a = inventory.select("a").unwrap();
    let destructive = classify_command("rm -rf /tmp/x", &no_extra());
    assert!(matches!(gate_at(&a, &destructive, true, false, &[], Some("s"), &grants, &deny, 0), GateOutcome::Ask { .. }));
    grants.add_full("s");
    assert!(grants.is_full("s") && !grants.is_full("other"));
    assert!(matches!(gate_at(&a, &destructive, true, false, &[], Some("s"), &grants, &deny, 0), GateOutcome::Allow { ref voucher } if voucher.authorization == Authorization::Full));
    assert!(matches!(gate_at(&a, &destructive, true, false, &[], Some("other"), &grants, &deny, 0), GateOutcome::Ask { .. }));
    assert!(matches!(gate_at(&a, &destructive, true, false, &[], None, &grants, &deny, 0), GateOutcome::Ask { .. }));
    // Policy deny and the deny list still refuse.
    let b = inventory.select("b").unwrap();
    assert!(matches!(gate_at(&b, &destructive, false, false, &[], Some("s"), &grants, &deny, 0), GateOutcome::Deny { .. }));
    let wipe = vec!["rm -rf /".to_string()];
    assert!(matches!(gate_at(&a, &classify_command("rm -rf /", &no_extra()), false, false, &wipe, Some("s"), &grants, &deny, 0), GateOutcome::Deny { .. }));
    // Revoking every grant of the session ends it.
    grants.revoke("s", "all");
    assert!(!grants.is_full("s"));
    assert!(matches!(gate_at(&a, &destructive, true, false, &[], Some("s"), &grants, &deny, 0), GateOutcome::Ask { .. }));
}

#[test]
fn gate_treats_task_sudo_as_pre_authorized_unless_policy_denies_it() {
    let config = Config::resolve(json!({ "inventoryFile": null, "hosts": [{ "name": "a" }, { "name": "b", "policy": { "sudo": "deny" } }] })).unwrap();
    let inventory = Inventory::load(&config, &[], Some(&ManagedState::default())).unwrap();
    let deny = DenyList::compile(&config.deny_patterns).unwrap();
    let grants = GrantStore::new();
    let commands = vec!["(task t: built-in inspect playbook)".to_string(), "journalctl -p err".to_string()];
    let a = inventory.select("a").unwrap();
    let allowed = gate_at(&a, &RiskAssessment::read(), true, true, &commands, None, &grants, &deny, 1);
    assert!(matches!(allowed, GateOutcome::Allow { ref voucher } if voucher.authorization == Authorization::Task && voucher.sudo));
    let all = inventory.select("all").unwrap();
    let GateOutcome::Deny { reason } = gate_at(&all, &RiskAssessment::read(), true, true, &commands, None, &grants, &deny, 1) else { panic!("expected deny") };
    assert_eq!(reason, "Task needs sudo, but host policy denies sudo on b.");
    // Without the task's pre-authorization the same sudo asks on `a`.
    assert!(matches!(gate_at(&a, &RiskAssessment::read(), true, false, &commands, None, &grants, &deny, 1), GateOutcome::Ask { .. }));
    // A deny-listed line among the task's commands refuses the whole run.
    let bad = vec!["uptime".to_string(), "rm -rf /".to_string()];
    assert!(matches!(gate_at(&a, &RiskAssessment::read(), false, false, &bad, None, &grants, &deny, 1), GateOutcome::Deny { .. }));
}

#[test]
fn gate_checks_every_phase_of_a_managed_change() {
    let config = Config::resolve(json!({ "inventoryFile": null, "hosts": [{ "name": "a" }, { "name": "b" }] })).unwrap();
    let inventory = Inventory::load(&config, &[], Some(&ManagedState::default())).unwrap();
    let grants = GrantStore::new();
    let deny = DenyList::compile(&["forbidden$".to_string()]).unwrap();
    let plan = |extra: serde_json::Value| {
        let mut base = json!({ "targets": "a", "files": ["/etc/app.conf"], "command": "printf after > /etc/app.conf", "verify": "test -s /etc/app.conf", "reason": "Update config" });
        base.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        validate_change(&base).unwrap()
    };
    let gate_plan = |plan: &wisp_ops_engine::change::ChangePlan| {
        let hosts = inventory.select(&plan.targets).unwrap();
        gate_at(&hosts, &change_risk(plan, &no_extra()), plan.sudo == Some(true), false, &change_commands(plan), Some("s"), &grants, &deny, 1)
    };
    assert!(matches!(gate_plan(&plan(json!({ "verify": "forbidden" }))), GateOutcome::Deny { .. }));
    let long = "echo x".repeat(500);
    let destructive = plan(json!({ "afterRollback": "rm -f /tmp/old", "command": long }));
    let GateOutcome::Ask { voucher, pending } = gate_plan(&destructive) else { panic!("expected ask") };
    assert_eq!(voucher.risk.level, RiskLevel::Destructive);
    assert_eq!(pending_needs(&pending), "change + destructive");
    // The approval text is the whole plan, never shortened.
    let text = describe_change(&destructive);
    assert!(text.contains("rm -f /tmp/old") && text.contains(&long));
    let fleet = plan(json!({ "targets": "a,b", "directories": ["/etc/nginx"] }));
    let GateOutcome::Ask { voucher, .. } = gate_plan(&fleet) else { panic!("expected ask") };
    assert_eq!(voucher.hosts, ["a", "b"]);
    assert!(describe_change(&fleet).contains("/etc/nginx"));
    assert!(voucher.risk.reasons.join(" ").contains("tar backup"));
}

#[test]
fn parses_durations_and_capability_words() {
    assert_eq!(parse_duration("1h30m"), Some(5_400_000));
    assert_eq!(parse_duration("2h"), Some(7_200_000));
    assert_eq!(parse_duration("30m"), Some(1_800_000));
    assert_eq!(parse_duration(" 45 "), Some(2_700_000));
    assert_eq!(parse_duration("2H"), Some(7_200_000));
    assert_eq!(parse_duration(""), None);
    assert_eq!(parse_duration("soon"), None);
    assert_eq!(parse_duration("30m1h"), None);
    assert_eq!(grant_capabilities("all"), Some(vec![Capability::Change, Capability::Sudo]));
    assert_eq!(grant_capabilities("destructive"), Some(vec![Capability::Destructive]));
    assert_eq!(grant_capabilities("root"), None);
    assert_eq!(compact("  a \n b\t c  ", 600), "a b c");
    assert_eq!(compact("abcdef", 3), "abc…");
    let names: Vec<String> = (1..=14).map(|i| format!("h{i}")).collect();
    assert_eq!(host_list(&names), "h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12 … (+2)");
    assert!(DenyList::compile(&["a(?=b)".to_string()]).unwrap_err().contains("invalid deny pattern"));
}
