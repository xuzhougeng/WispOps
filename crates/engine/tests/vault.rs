//! The encrypted vault and the application-managed state (the vault and `managed.json` parts of
//! `management.spec.ts`). Keys come from a closure or a key file, never from the real keychain.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use wisp_ops_engine::config::{AuthMethod, Config, HostSpec, Permission, PolicySpec};
use wisp_ops_engine::inventory::Inventory;
use wisp_ops_engine::managed::{CredentialBinding, ManagedState, managed_store, validate_managed, validate_policy};
use wisp_ops_engine::vault::{CredentialInput, FileKey, LocalVault};

const PASSWORD: &str = "test-only-secret";

/// A vault with a fixed key, recording every key request as `(create)`.
fn vault(dir: &Path) -> (LocalVault, Arc<Mutex<Vec<bool>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let key = move |_: &Path, create: bool| -> Result<[u8; 32], String> {
        recorded.lock().unwrap().push(create);
        Ok([7u8; 32])
    };
    (LocalVault::with_key_provider(dir, Box::new(key)), calls)
}

fn credential(name: &str, password: Option<&str>) -> CredentialInput {
    CredentialInput { name: name.to_string(), username: "tester".to_string(), note: "test".to_string(), agent: true, password: password.map(str::to_string) }
}

fn revision(vault: &LocalVault) -> String {
    vault.list().unwrap().revision
}

#[test]
fn encrypts_at_rest_lists_only_metadata_and_decrypts_for_the_execution_path() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, calls) = vault(dir.path());
    assert!(vault.list().unwrap().entries.is_empty());
    vault.save(&credential("login", Some(PASSWORD)), &revision(&vault), None).unwrap();
    assert_eq!(*calls.lock().unwrap(), [true]);
    let file = std::fs::read_to_string(dir.path().join("vault.json")).unwrap();
    assert!(!file.contains(PASSWORD));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.path().join("vault.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // The plugin's layout: version, then entries with name, username, note, agent, secret.
    let parsed: Value = serde_json::from_str(&file).unwrap();
    let secret = parsed["entries"][0]["secret"].as_str().unwrap().to_string();
    assert_eq!(parsed, json!({ "version": 1, "entries": [{ "name": "login", "username": "tester", "note": "test", "agent": true, "secret": secret }] }));
    assert!(file.starts_with("{\n  \"version\": 1,\n  \"entries\": [\n    {\n      \"name\": \"login\","));
    // base64(24-byte nonce ‖ ciphertext ‖ 16-byte tag)
    assert_eq!(secret.len(), (24 + PASSWORD.len() + 16).div_ceil(3) * 4);

    assert_eq!(vault.password(Some("local:login")).unwrap().as_deref(), Some(PASSWORD));
    assert_eq!(vault.password(Some("login")).unwrap().as_deref(), Some(PASSWORD));
    assert_eq!(vault.password(None).unwrap(), None);
    assert_eq!(vault.password(Some("")).unwrap(), None);
    assert!(vault.password(Some("local:nope")).unwrap_err().contains("找不到凭据 nope"));
    calls.lock().unwrap().clear();
    let listing = vault.list().unwrap();
    let view = format!("{listing:?}");
    assert!(!view.contains(PASSWORD) && !view.contains(&secret));
    assert_eq!((listing.entries.len(), listing.entries[0].name.as_str(), listing.entries[0].has_secret), (1, "login", true));
    assert!(calls.lock().unwrap().is_empty(), "listing must not touch the key");
    assert!(!format!("{:?}", vault.credential(Some("login")).unwrap()).contains(PASSWORD));
    assert!(!format!("{:?}", credential("x", Some(PASSWORD))).contains(PASSWORD));
}

#[test]
fn preserves_the_password_on_metadata_edits_and_enforces_the_automation_flag() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _) = vault(dir.path());
    vault.save(&credential("login", Some(PASSWORD)), &revision(&vault), None).unwrap();
    vault.save(&CredentialInput { note: "changed".to_string(), agent: false, ..credential("login", None) }, &revision(&vault), None).unwrap();
    assert!(vault.password(Some("local:login")).unwrap_err().contains("不允许自动化"));
    assert_eq!(vault.list().unwrap().entries[0].note, "changed");
    vault.save(&credential("login", Some("")), &revision(&vault), None).unwrap();
    assert_eq!(vault.password(Some("local:login")).unwrap().as_deref(), Some(PASSWORD));
    // A new entry needs a password; a replaced one decrypts to the new value.
    assert!(vault.save(&credential("fresh", None), &revision(&vault), None).unwrap_err().contains("需要填写密码"));
    vault.save(&credential("login", Some("rotated")), &revision(&vault), None).unwrap();
    assert_eq!(vault.password(Some("login")).unwrap().as_deref(), Some("rotated"));
    vault.remove("login", &revision(&vault), None).unwrap();
    assert!(vault.list().unwrap().entries.is_empty());
}

#[test]
fn detects_ciphertext_tampering_and_never_mints_a_key_for_existing_encrypted_entries() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, calls) = vault(dir.path());
    vault.save(&credential("login", Some(PASSWORD)), &revision(&vault), None).unwrap();
    let file = dir.path().join("vault.json");
    let mut raw: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    raw["entries"][0]["name"] = json!("swapped");
    std::fs::write(&file, raw.to_string()).unwrap();
    // The entry name is authenticated: a record moved under another name does not decrypt.
    assert!(vault.password(Some("local:swapped")).is_err());
    assert_eq!(calls.lock().unwrap().last(), Some(&false));
    // A second entry in a vault that already has one must reuse the key, not create one.
    vault.save(&credential("other", Some("x")), &revision(&vault), None).unwrap();
    assert_eq!(calls.lock().unwrap().last(), Some(&false));
    // A wrong key fails authentication instead of returning garbage.
    let wrong = LocalVault::with_key_provider(dir.path(), Box::new(|_: &Path, _: bool| -> Result<[u8; 32], String> { Ok([8u8; 32]) }));
    assert!(wrong.password(Some("other")).is_err());
}

#[test]
fn rejects_stale_revisions_newline_passwords_and_racing_saves() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _) = vault(dir.path());
    let stale = revision(&vault);
    vault.save(&credential("login", Some(PASSWORD)), &stale, None).unwrap();
    assert!(vault.save(&credential("other", Some(PASSWORD)), &stale, None).unwrap_err().contains("刷新"));
    assert!(vault.save(&credential("login", Some("x\ny")), &revision(&vault), None).unwrap_err().contains("格式"));
    assert!(vault.save(&credential(" ", Some("x")), &revision(&vault), None).unwrap_err().contains("凭据名称"));
    assert!(vault.save(&credential(&"n".repeat(101), Some("x")), &revision(&vault), None).unwrap_err().contains("凭据名称"));
    let now = revision(&vault);
    let wins = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for name in ["one", "two"] {
            let (vault, now, wins) = (&vault, &now, &wins);
            scope.spawn(move || {
                if vault.save(&credential(name, Some(PASSWORD)), now, None).is_ok() { wins.fetch_add(1, Ordering::SeqCst); }
            });
        }
    });
    assert_eq!(wins.load(Ordering::SeqCst), 1);
    assert_eq!(vault.list().unwrap().entries.len(), 2);
    assert!(!dir.path().join("vault.json.lock").exists());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
}

#[test]
fn keeps_the_key_in_an_owner_only_file_and_refuses_to_replace_a_lost_one() {
    let dir = tempfile::tempdir().unwrap();
    let vault = LocalVault::with_key_provider(dir.path(), Box::new(FileKey::default()));
    vault.save(&credential("login", Some(PASSWORD)), &revision(&vault), None).unwrap();
    let key_file = dir.path().join("vault.key");
    assert_eq!(std::fs::read(&key_file).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // A second vault object over the same directory reads the same key.
    let reopened = LocalVault::with_key_provider(dir.path(), Box::new(FileKey::default()));
    assert_eq!(reopened.password(Some("login")).unwrap().as_deref(), Some(PASSWORD));
    let key = std::fs::read(&key_file).unwrap();
    std::fs::remove_file(&key_file).unwrap();
    assert!(reopened.password(Some("login")).unwrap_err().contains("密钥丢失"));
    assert!(reopened.save(&credential("second", Some("x")), &revision(&reopened), None).unwrap_err().contains("密钥丢失"));
    assert!(!key_file.exists(), "a replacement key must not be created");
    assert_eq!(reopened.list().unwrap().entries.len(), 1);
    std::fs::write(&key_file, &key[..16]).unwrap();
    assert!(reopened.password(Some("login")).unwrap_err().contains("密钥格式"));
    std::fs::write(&key_file, &key).unwrap();
    assert_eq!(reopened.password(Some("login")).unwrap().as_deref(), Some(PASSWORD));
}

#[test]
fn resolves_a_hosts_login_and_sudo_references() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _) = vault(dir.path());
    vault.save(&CredentialInput { username: "admin".to_string(), ..credential("nas-admin", Some("nas-pass")) }, &revision(&vault), None).unwrap();
    vault.save(&CredentialInput { username: String::new(), ..credential("root", Some("root-pass")) }, &revision(&vault), None).unwrap();
    let hosts = vec![
        HostSpec { auth: Some(AuthMethod::Password), login_secret: Some("local:nas-admin".to_string()), sudo_secret: Some("root".to_string()), ..HostSpec::named("nas") },
        HostSpec::named("plain"),
        HostSpec { sudo_secret: Some("local:gone".to_string()), ..HostSpec::named("broken") },
    ];
    let inventory = Inventory::from_specs(hosts, Default::default(), Default::default()).unwrap();
    let nas = inventory.host("nas").unwrap();
    assert_eq!(vault.login_password(nas).unwrap().as_deref(), Some("nas-pass"));
    let sudo = vault.sudo_credential(nas).unwrap().unwrap();
    assert_eq!((sudo.password.as_str(), sudo.username.as_str()), ("root-pass", ""));
    assert_eq!(vault.sudo_password(nas).unwrap().as_deref(), Some("root-pass"));
    assert_eq!(vault.credential(Some("nas-admin")).unwrap().unwrap().username, "admin");
    let plain = inventory.host("plain").unwrap();
    assert_eq!((vault.login_password(plain).unwrap(), vault.sudo_credential(plain).unwrap()), (None, None));
    assert!(vault.sudo_password(inventory.host("broken").unwrap()).unwrap_err().contains("找不到凭据 gone"));
}

#[test]
fn commits_associations_with_the_vault_or_restores_both() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _) = vault(dir.path());
    let managed = managed_store(dir.path());
    let bind = |state: ManagedState| -> Result<ManagedState, String> {
        let mut state = state;
        state.bindings.insert("a".to_string(), CredentialBinding { auth: AuthMethod::Password, login_secret: Some("local:login".to_string()), sudo_secret: None });
        Ok(state)
    };
    // Both files change together.
    let vault_revision = revision(&vault);
    managed.change_with(&managed.read().unwrap().revision, bind, |commit| vault.save(&credential("login", Some(PASSWORD)), &vault_revision, Some(commit))).unwrap();
    assert_eq!(vault.list().unwrap().entries.len(), 1);
    assert_eq!(managed.read().unwrap().value.bindings["a"].login_secret.as_deref(), Some("local:login"));

    // A stale vault revision leaves the associations untouched.
    let before = std::fs::read_to_string(dir.path().join("managed.json")).unwrap();
    let unbind = |mut state: ManagedState| -> Result<ManagedState, String> {
        state.bindings.clear();
        Ok(state)
    };
    let error = managed.change_with(&managed.read().unwrap().revision, unbind, |commit| vault.save(&credential("second", Some("x")), &vault_revision, Some(commit))).unwrap_err();
    assert!(error.contains("刷新"), "{error}");
    assert_eq!(std::fs::read_to_string(dir.path().join("managed.json")).unwrap(), before);
    assert_eq!(vault.list().unwrap().entries.len(), 1);

    // When committing the associations fails after the vault was written, the vault is rolled back.
    let vault_before = std::fs::read_to_string(dir.path().join("vault.json")).unwrap();
    let error = vault.save(&credential("third", Some("x")), &revision(&vault), Some(&mut || Err("associations failed".to_string()))).unwrap_err();
    assert_eq!(error, "associations failed");
    assert_eq!(std::fs::read_to_string(dir.path().join("vault.json")).unwrap(), vault_before);
    // A brand-new vault file is removed again rather than left behind.
    let fresh = tempfile::tempdir().unwrap();
    let (other, _) = self::vault(fresh.path());
    assert!(other.save(&credential("x", Some("y")), &revision(&other), Some(&mut || Err("no".to_string()))).is_err());
    assert!(!fresh.path().join("vault.json").exists());
    assert!(!fresh.path().join("vault.json.lock").exists());
}

#[test]
fn stores_managed_state_with_revisions_and_applies_it_to_the_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::resolve(json!({
        "dataDir": dir.path(),
        "hosts": [{ "name": "a", "ssh": "192.0.2.1" }, { "name": "b", "policy": { "sudo": "deny" }, "loginSecret": "yaml-secret" }, { "name": "gone" }],
    }))
    .unwrap();
    std::fs::write(dir.path().join("inventory.yml"), "hosts:\n  - name: from-file\n    groups: [lab]\ngroups:\n  lab:\n    policy: { change: allow }\n").unwrap();
    let store = managed_store(dir.path());
    let empty = store.read().unwrap();
    assert_eq!(empty.value, ManagedState::default());
    assert_eq!(Inventory::load(&config, &[], None).unwrap().hosts().iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), ["a", "b", "gone", "from-file"]);

    store
        .change(&empty.revision, |mut state| {
            state.hosts.push(HostSpec { ssh: Some("ops@192.0.2.9".to_string()), ..HostSpec::named("panel") });
            state.bindings.insert("b".to_string(), CredentialBinding { auth: AuthMethod::Password, login_secret: Some("local:login".to_string()), sudo_secret: None });
            state.policies.insert("a".to_string(), PolicySpec { change: Some(Permission::Allow), ..PolicySpec::default() });
            state.policies.insert("panel".to_string(), PolicySpec::default());
            state.excluded_hosts.push("gone".to_string());
            state.checks.insert("a".to_string(), json!([{ "kind": "systemd", "unit": "nginx" }]));
            state.thresholds.insert("a".to_string(), json!({ "diskWarnPct": 70 }));
            state.mutes.insert("a".to_string(), json!([{ "code": "disk-warn" }]));
            state.mutes.insert("b".to_string(), json!([]));
            Ok(state)
        })
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.path().join("managed.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // The first revision is stale now, and a failing update writes nothing.
    assert!(store.change(&empty.revision, Ok).unwrap_err().contains("刷新"));
    let current = store.read().unwrap();
    assert!(store.change(&current.revision, |_| Err("nope".to_string())).unwrap_err().contains("nope"));
    assert!(store.change(&current.revision, |mut state| { state.hosts.push(HostSpec::named("-bad")); Ok(state) }).is_err());
    assert_eq!(store.read().unwrap().revision, current.revision);
    assert!(!current.value.mutes.contains_key("b"), "empty per-host lists are dropped");
    assert!(!dir.path().join("managed.json.lock").exists());

    // Reloading without passing the state reads it from the data directory.
    let inventory = Inventory::load(&config, &[HostSpec::named("imported"), HostSpec { description: Some("shadowed".to_string()), ..HostSpec::named("a") }], None).unwrap();
    assert_eq!(inventory.hosts().iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), ["imported", "a", "b", "from-file", "panel"]);
    let a = inventory.host("a").unwrap();
    assert_eq!(a.description, None, "a configured host replaces an imported one of the same name");
    assert_eq!((a.policy.change, a.inherited_policy.change), (Permission::Allow, Permission::Ask));
    assert_eq!(a.policy_override, Some(PolicySpec { change: Some(Permission::Allow), ..PolicySpec::default() }));
    assert_eq!(a.service_checks, Some(json!([{ "kind": "systemd", "unit": "nginx" }])));
    assert_eq!(a.threshold_override, Some(json!({ "diskWarnPct": 70 })));
    assert_eq!(a.mutes, Some(json!([{ "code": "disk-warn" }])));
    // A binding replaces the host's own credential fields; its YAML policy is untouched.
    let b = inventory.host("b").unwrap();
    assert_eq!((b.auth, b.login_secret.as_deref(), b.sudo_secret.as_deref()), (Some(AuthMethod::Password), Some("local:login"), None));
    assert_eq!((b.policy.sudo, b.policy_override.clone(), b.mutes.clone()), (Permission::Deny, None, None));
    let panel = inventory.host("panel").unwrap();
    assert_eq!((panel.destination(), panel.policy_override.clone()), ("ops@192.0.2.9", None));
    assert_eq!(inventory.host("from-file").unwrap().policy.change, Permission::Allow);
    assert!(inventory.host("gone").is_none());

    // Restoring an excluded host brings it back with nothing else changed.
    store.change(&current.revision, |mut state| { state.excluded_hosts.clear(); Ok(state) }).unwrap();
    assert!(Inventory::load(&config, &[], None).unwrap().has_host("gone"));
}

#[test]
fn accepts_older_management_files_but_fails_closed_on_malformed_ones() {
    let legacy = json!({ "version": 1, "hosts": [], "tasks": [], "bindings": {} });
    assert!(validate_managed(legacy.clone()).unwrap().excluded_hosts.is_empty());
    let with = |key: &str, value: Value| {
        let mut state = legacy.clone();
        state[key] = value;
        validate_managed(state)
    };
    assert_eq!(with("excludedHosts", json!(["a", "a"])).unwrap().excluded_hosts, ["a"]);
    for excluded in [json!(null), json!("a"), json!({}), json!([null]), json!([5]), json!([""]), json!(["a,b"]), json!(["../a"])] {
        assert_eq!(with("excludedHosts", excluded.clone()).unwrap_err(), "Invalid excluded hosts", "{excluded}");
    }
    assert_eq!(with("version", json!(2)).unwrap_err(), "Invalid WispOps management file");
    assert_eq!(with("bindings", json!([])).unwrap_err(), "Invalid WispOps management file");
    assert_eq!(with("bindings", json!({ "a": { "auth": "token" } })).unwrap_err(), "Invalid credential binding");
    assert_eq!(with("bindings", json!({ "a": { "auth": "key", "sudoSecret": 5 } })).unwrap_err(), "Invalid credential reference");
    assert_eq!(with("policies", json!([])).unwrap_err(), "Invalid policy overrides");
    assert_eq!(with("policies", json!({ "a": { "root": "allow" } })).unwrap_err(), "Unknown capability \"root\"");
    assert_eq!(with("policies", json!({ "a": { "sudo": "yes" } })).unwrap_err(), "Invalid permission for sudo");
    assert_eq!(with("mutes", json!([])).unwrap_err(), "Invalid mutes");
    assert!(with("hosts", json!([{ "name": "x", "ssh": "-oProxyCommand=evil" }])).is_err());
    assert!(with("tasks", json!([{ "name": "t", "targets": "a", "playbook": "nope" }])).is_err());
    let binding = with("bindings", json!({ "a": { "auth": "password", "loginSecret": "local:x" } })).unwrap().bindings["a"].clone();
    assert_eq!(binding, CredentialBinding { auth: AuthMethod::Password, login_secret: Some("local:x".to_string()), sudo_secret: None });
    assert_eq!(validate_policy(&json!({ "destructive": "deny" })).unwrap(), PolicySpec { destructive: Some(Permission::Deny), ..PolicySpec::default() });
    assert_eq!(validate_policy(&json!("deny")).unwrap_err(), "Invalid policy");
    // A file the plugin wrote is readable as is.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("managed.json"),
        "{\n  \"version\": 1,\n  \"hosts\": [\n    {\n      \"name\": \"web\",\n      \"ssh\": \"deploy@web\",\n      \"groups\": [],\n      \"tags\": {},\n      \"policy\": {}\n    }\n  ],\n  \"bindings\": {\n    \"web\": {\n      \"auth\": \"key\"\n    }\n  },\n  \"tasks\": [\n    {\n      \"name\": \"daily\",\n      \"notify\": [],\n      \"quietHours\": {},\n      \"targets\": \"web\",\n      \"playbook\": \"inspect\",\n      \"schedule\": {\n        \"daily\": \"08:00\",\n        \"weekdays\": [],\n        \"timeZone\": \"UTC\"\n      },\n      \"paths\": [],\n      \"commands\": []\n    }\n  ],\n  \"policies\": {},\n  \"excludedHosts\": [],\n  \"checks\": {},\n  \"thresholds\": {},\n  \"mutes\": {}\n}\n",
    )
    .unwrap();
    let state = managed_store(dir.path()).read().unwrap().value;
    assert_eq!((state.hosts[0].name.as_str(), state.tasks[0].name.as_str()), ("web", "daily"));
    let config = Config::resolve(json!({ "dataDir": dir.path(), "inventoryFile": null })).unwrap();
    let inventory = Inventory::load(&config, &[], None).unwrap();
    assert!(inventory.task("daily").unwrap().quiet_hours.is_none());
    assert_eq!(inventory.task("daily").unwrap().schedule.as_ref().unwrap().daily.as_deref(), Some("08:00"));
}

#[test]
fn reads_a_vault_file_written_by_the_plugin() {
    // `fixtures/plugin-vault.json` was produced by the plugin's own vault code with the key 07…07.
    let dir = tempfile::tempdir().unwrap();
    let original = include_str!("fixtures/plugin-vault.json");
    std::fs::write(dir.path().join("vault.json"), original).unwrap();
    let (vault, _) = vault(dir.path());
    let listing = vault.list().unwrap();
    assert_eq!(listing.entries.iter().map(|entry| (entry.name.as_str(), entry.agent)).collect::<Vec<_>>(), [("gpu-root", true), ("中文 name", false)]);
    let root = vault.credential(Some("local:gpu-root")).unwrap().unwrap();
    assert_eq!((root.password.as_str(), root.username.as_str()), ("correct horse battery staple", "root"));
    assert!(vault.password(Some("中文 name")).unwrap_err().contains("不允许自动化"));
    // Allowing automation is a metadata edit: the stored ciphertext is kept and still opens.
    vault.save(&CredentialInput { name: "中文 name".to_string(), username: String::new(), note: String::new(), agent: true, password: None }, &listing.revision, None).unwrap();
    assert_eq!(vault.password(Some("中文 name")).unwrap().as_deref(), Some("pässwörd 🙂"));
    // Rewriting keeps the plugin's layout, so the plugin could read the file back.
    assert_eq!(std::fs::read_to_string(dir.path().join("vault.json")).unwrap(), original.replace("\"agent\": false", "\"agent\": true"));
}
