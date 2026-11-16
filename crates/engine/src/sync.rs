//! Device sync through a WebDAV folder, as the plugin does it: explicit owner actions that move
//! whole encrypted snapshots, never a background merge.
//!
//! A snapshot (`{version, at, managed, credentials, templates, keys}`) holds `managed.json`, every
//! vault entry with its password, the task template library (`task-templates.json`, carried as is)
//! and, when asked for, the private keys the managed hosts name in `identityFile`. It is sealed
//! with the sync passphrase ([`crate::sync_crypto`]) before it leaves the machine; each upload is a
//! new file, so no device's version is overwritten. Not in a snapshot: the vault key, `config.json`,
//! `inventory.yml`, `settings.json` (model services), grants, audit and histories, task timers, the
//! sync settings themselves.
//!
//! Importing is preview, then pull: the preview pins the local revisions and the remote file's
//! hash, and the pull refuses when either moved, when a task timer is on, or when the preview is
//! older than ten minutes. Before replacing anything the local state is sealed into
//! `sync-backups/`; the three files are then committed together through [`LocalState::change_with`].
//!
//! The sync settings (`sync.json`) keep the WebDAV address and user in clear and the application
//! password and passphrase sealed under the vault's key ([`LocalVault::seal_aside`]).

use std::collections::HashSet;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::fsutil::{create_private_dir, expand_home, hex, random_bytes, set_mode, write_new_private};
use crate::inventory::Inventory;
use crate::managed::{LocalState, ManagedState, managed_store, validate_managed};
use crate::sync_crypto::{self, check_passphrase};
use crate::time;
use crate::vault::{LocalVault, PortableCredential};
use crate::webdav::{WebDav, WebDavSettings};

/// How long a preview may be imported.
pub const PREVIEW_MS: i64 = 10 * 60_000;
const MAX_KEY_BYTES: u64 = 128 * 1024;

static KEY_TEXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----").expect("key pattern"));

fn key_valid(text: &str) -> bool {
    text.encode_utf16().count() <= 128 * 1024 && KEY_TEXT.is_match(text)
}

fn digest(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

/// `wispops-20261116T083000123Z-<uuid v4>.json`, the plugin's snapshot name.
pub fn snapshot_name(now: i64) -> Result<String, String> {
    let at: String = time::to_iso(now).chars().filter(|c| !matches!(c, '-' | ':' | '.')).collect();
    let mut id = random_bytes::<16>()?;
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    let h = hex(&id);
    Ok(format!("wispops-{at}-{}-{}-{}-{}-{}.json", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

/// When a snapshot was made, from its name: epoch milliseconds.
pub fn snapshot_time(name: &str) -> Option<i64> {
    let stamp = name.strip_prefix("wispops-")?.get(..19)?;
    let iso = format!("{}-{}-{}T{}:{}:{}.{}Z", &stamp[..4], &stamp[4..6], &stamp[6..8], &stamp[9..11], &stamp[11..13], &stamp[13..15], &stamp[15..18]);
    time::parse_iso(&iso)
}

// ---- the task template library, carried as the plugin wrote it

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct TemplateLibrary {
    version: u32,
    entries: Vec<Value>,
}

fn validate_templates(entries: &[Value]) -> Result<(), String> {
    let mut ids = HashSet::new();
    for entry in entries {
        let id = entry.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()).ok_or_else(|| "Invalid task template".to_string())?;
        if !ids.insert(id.to_string()) { return Err("Duplicate template in snapshot".to_string()) }
    }
    Ok(())
}

fn template_store(data_dir: &Path) -> LocalState<TemplateLibrary> {
    LocalState::new(
        data_dir.join("task-templates.json"),
        || TemplateLibrary { version: 1, entries: vec![] },
        |value| {
            let library: TemplateLibrary = serde_json::from_value(value).map_err(|_| "Invalid task template library".to_string())?;
            if library.version != 1 { return Err("Invalid task template library".to_string()) }
            validate_templates(&library.entries)?;
            Ok(library)
        },
    )
}

// ---- snapshots

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFile {
    pub source: String,
    pub content: String,
}

#[derive(Serialize)]
struct Snapshot {
    version: u32,
    at: String,
    managed: ManagedState,
    credentials: Vec<PortableCredential>,
    templates: Vec<Value>,
    keys: Vec<KeyFile>,
}

/// The revisions an import must still find.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revisions {
    managed: String,
    vault: String,
    templates: String,
}

/// How much of each kind a side holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub excluded_hosts: usize,
    pub hosts: usize,
    pub credentials: usize,
    pub tasks: usize,
    pub templates: usize,
    pub keys: usize,
}

/// What importing a snapshot would bring; names and settings only, never a password or key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub url: String,
    pub name: String,
    hash: String,
    revisions: Revisions,
    pub expires: i64,
    /// When the snapshot was made.
    pub at: String,
    pub incoming: Counts,
    pub local: Counts,
    /// Incoming credentials that replace a local one of the same name.
    pub conflicts: Vec<String>,
    pub excluded_hosts: Vec<String>,
    pub local_excluded_hosts: Vec<String>,
    pub host_names: Vec<String>,
    pub credential_names: Vec<String>,
    /// Host and its permission overrides, as `change=ask, sudo=deny`.
    pub policies: Vec<(String, String)>,
    /// Credentials automation may use.
    pub automated_credentials: Vec<String>,
    /// Tasks that run with sudo: name and targets.
    pub sudo_tasks: Vec<(String, String)>,
    /// Host, login method, login and sudo credential names.
    pub bindings: Vec<(String, String, String, String)>,
}

struct Incoming {
    at: String,
    managed: ManagedState,
    credentials: Vec<PortableCredential>,
    templates: Vec<Value>,
    keys: Vec<KeyFile>,
}

fn policy_words(policy: &crate::config::PolicySpec) -> String {
    serde_json::to_value(policy).ok().and_then(|value| value.as_object().cloned()).map(|map| map.iter().map(|(key, value)| format!("{key}={}", value.as_str().unwrap_or_default())).collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

/// Sync between this data folder and a WebDAV collection.
pub struct OpsSync<'a> {
    pub data_dir: &'a Path,
    pub config: &'a Config,
    pub vault: &'a LocalVault,
}

impl OpsSync<'_> {
    fn revisions(&self) -> Result<Revisions, String> {
        Ok(Revisions { managed: managed_store(self.data_dir).read()?.revision, vault: self.vault.list()?.revision, templates: template_store(self.data_dir).read()?.revision })
    }

    fn snapshot(&self, include_keys: bool, now: i64) -> Result<(Snapshot, Revisions), String> {
        let managed = managed_store(self.data_dir).read()?;
        let (vault_revision, credentials) = self.vault.export_for_sync()?;
        let templates = template_store(self.data_dir).read()?;
        let mut keys = Vec::new();
        if include_keys {
            let mut seen = HashSet::new();
            for source in managed.value.hosts.iter().filter_map(|host| host.identity_file.clone()) {
                if !seen.insert(source.clone()) { continue }
                let unsupported = || "服务器指定的 SSH 身份文件不是受支持的私钥（最大 128 KiB）。".to_string();
                let mut file = fs::File::open(expand_home(&source)).map_err(|_| unsupported())?;
                let meta = file.metadata().map_err(|_| unsupported())?;
                if !meta.is_file() || meta.len() > MAX_KEY_BYTES { return Err(unsupported()) }
                let mut content = String::new();
                file.read_to_string(&mut content).map_err(|_| unsupported())?;
                if !key_valid(&content) { return Err(unsupported()) }
                keys.push(KeyFile { source, content });
            }
        }
        let revisions = Revisions { managed: managed.revision, vault: vault_revision, templates: templates.revision };
        if self.revisions()? != revisions { return Err("生成快照时本机数据有变化，请刷新后重试。".to_string()) }
        Ok((Snapshot { version: 1, at: time::to_iso(now), managed: managed.value, credentials, templates: templates.value.entries, keys }, revisions))
    }

    fn validate(value: Value) -> Result<Incoming, String> {
        let invalid = || "同步快照格式不正确。".to_string();
        let raw = value.as_object().ok_or_else(invalid)?;
        let list = |key: &str| raw.get(key).and_then(Value::as_array).filter(|list| list.len() <= 1000).cloned().ok_or_else(invalid);
        let at = raw.get("at").and_then(Value::as_str).filter(|at| time::parse_iso(at).is_some()).ok_or_else(invalid)?.to_string();
        if raw.get("version").and_then(Value::as_u64) != Some(1) { return Err(invalid()) }
        let (credentials, templates, keys) = (list("credentials")?, list("templates")?, list("keys")?);
        let managed = validate_managed(raw.get("managed").cloned().ok_or_else(invalid)?)?;
        validate_templates(&templates)?;
        let credentials: Vec<PortableCredential> = serde_json::from_value(Value::Array(credentials)).map_err(|_| "快照里的凭据格式不正确。".to_string())?;
        let mut names = HashSet::new();
        if credentials.iter().any(|entry| entry.name.is_empty() || entry.password.is_empty() || !names.insert(entry.name.clone())) { return Err("快照里的凭据格式不正确。".to_string()) }
        let keys: Vec<KeyFile> = serde_json::from_value(Value::Array(keys)).map_err(|_| "快照里的 SSH 私钥格式不正确。".to_string())?;
        if keys.iter().any(|key| !key_valid(&key.content) || !managed.hosts.iter().any(|host| host.identity_file.as_deref() == Some(key.source.as_str()))) { return Err("快照里的 SSH 私钥格式不正确。".to_string()) }
        Ok(Incoming { at, managed, credentials, templates, keys })
    }

    /// Seal the local state (keys too, if asked) and upload it as a new snapshot; gives its name.
    pub fn push(&self, dav: &WebDav, passphrase: &str, include_keys: bool, now: i64) -> Result<String, String> {
        check_passphrase(passphrase).map_err(|_| "同步口令至少需要 12 个字符。".to_string())?;
        let (snapshot, _) = self.snapshot(include_keys, now)?;
        let name = snapshot_name(now)?;
        let sealed = sync_crypto::seal(&snapshot, passphrase)?;
        drop(snapshot);
        dav.upload(&name, &sealed)?;
        Ok(name)
    }

    /// Download and open a snapshot and say what importing it would change.
    pub fn preview(&self, dav: &WebDav, name: &str, passphrase: &str, now: i64) -> Result<Preview, String> {
        check_passphrase(passphrase).map_err(|_| "同步口令至少需要 12 个字符。".to_string())?;
        let encrypted = dav.download(name)?;
        let incoming = Self::validate(sync_crypto::open(&encrypted, passphrase).map_err(|_| "无法解密同步快照：口令不对、数据损坏或格式不支持。".to_string())?)?;
        Inventory::load(self.config, &[], Some(&incoming.managed))?;
        let revisions = self.revisions()?;
        let local = managed_store(self.data_dir).read()?.value;
        let local_vault = self.vault.list()?.entries;
        let s = &incoming.managed;
        let mut policies: Vec<(String, String)> = s.hosts.iter().filter(|host| !host.policy.is_empty()).map(|host| (host.name.clone(), policy_words(&host.policy))).collect();
        policies.extend(s.policies.iter().map(|(host, policy)| (host.clone(), policy_words(policy))));
        Ok(Preview {
            url: dav.collection.href(),
            name: name.to_string(),
            hash: digest(&encrypted),
            revisions,
            expires: now + PREVIEW_MS,
            at: incoming.at.clone(),
            incoming: Counts { excluded_hosts: s.excluded_hosts.len(), hosts: s.hosts.len(), credentials: incoming.credentials.len(), tasks: s.tasks.len(), templates: incoming.templates.len(), keys: incoming.keys.len() },
            local: Counts { excluded_hosts: local.excluded_hosts.len(), hosts: local.hosts.len(), credentials: local_vault.len(), tasks: local.tasks.len(), templates: template_store(self.data_dir).read()?.value.entries.len(), keys: 0 },
            conflicts: incoming.credentials.iter().filter(|entry| local_vault.iter().any(|old| old.name == entry.name)).map(|entry| entry.name.clone()).collect(),
            excluded_hosts: s.excluded_hosts.clone(),
            local_excluded_hosts: local.excluded_hosts.clone(),
            host_names: s.hosts.iter().map(|host| host.name.clone()).collect(),
            credential_names: incoming.credentials.iter().map(|entry| entry.name.clone()).collect(),
            policies,
            automated_credentials: incoming.credentials.iter().filter(|entry| entry.agent).map(|entry| entry.name.clone()).collect(),
            sudo_tasks: s.tasks.iter().filter(|task| task.sudo == Some(true)).map(|task| (task.name.clone(), task.targets.clone())).collect(),
            bindings: s.bindings.iter().map(|(host, binding)| (host.clone(), serde_json::to_value(binding.auth).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(), binding.login_secret.clone().unwrap_or_default(), binding.sudo_secret.clone().unwrap_or_default())).collect(),
        })
    }

    /// Replace the local managed state, vault and templates with a previewed snapshot. Gives the
    /// name of the encrypted backup of what was there before.
    pub fn pull(&self, dav: &WebDav, preview: &Preview, passphrase: &str, has_schedules: bool, now: i64) -> Result<String, String> {
        if preview.expires < now || preview.url != dav.collection.href() { return Err("预览已过期，请重新预览。".to_string()) }
        if self.revisions()? != preview.revisions { return Err("预览之后本机数据有变化，请重新预览。".to_string()) }
        if has_schedules { return Err("请先停用这台设备上的定时任务，再导入快照。".to_string()) }
        let encrypted = dav.download(&preview.name)?;
        if digest(&encrypted) != preview.hash { return Err("预览之后云端快照有变化，请重新预览。".to_string()) }
        let mut incoming = Self::validate(sync_crypto::open(&encrypted, passphrase).map_err(|_| "无法解密同步快照：口令不对、数据损坏或格式不支持。".to_string())?)?;
        Inventory::load(self.config, &[], Some(&incoming.managed))?;

        let (backup, _) = self.snapshot(true, now)?;
        let backups = self.data_dir.join("sync-backups");
        create_private_dir(&backups).map_err(|error| format!("cannot write {}: {error}", backups.display()))?;
        let backup_name = snapshot_name(now)?;
        let sealed = sync_crypto::seal(&backup, passphrase)?;
        drop(backup);
        write_new_private(&backups.join(&backup_name), sealed.as_bytes()).map_err(|error| format!("cannot write the sync backup: {error}"))?;

        for key in &incoming.keys {
            let path = install_key(self.data_dir, &key.content)?;
            for host in incoming.managed.hosts.iter_mut().filter(|host| host.identity_file.as_deref() == Some(key.source.as_str())) {
                host.identity_file = Some(path.to_string_lossy().into_owned());
            }
        }
        let Incoming { managed, credentials, templates, .. } = incoming;
        let revisions = &preview.revisions;
        template_store(self.data_dir).change_with(
            &revisions.templates,
            |_| Ok(TemplateLibrary { version: 1, entries: templates }),
            |commit_library| {
                managed_store(self.data_dir).change_with(
                    &revisions.managed,
                    |_| Ok(managed),
                    |commit_managed| {
                        self.vault.replace_from_sync(&credentials, &revisions.vault, |commit_vault| {
                            commit_vault()?;
                            commit_managed()?;
                            commit_library()
                        })
                    },
                )
            },
        )?;
        Ok(backup_name)
    }
}

/// Write a private key content-addressed under `ssh-keys/`, never to a path the snapshot names.
fn install_key(data_dir: &Path, content: &str) -> Result<PathBuf, String> {
    let unsafe_key = || "无法安全地安装 SSH 私钥。".to_string();
    let dir = data_dir.join("ssh-keys");
    create_private_dir(&dir).map_err(|_| unsafe_key())?;
    let path = dir.join(digest(content));
    match write_new_private(&path, content.as_bytes()) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let same = fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file()) && fs::read_to_string(&path).is_ok_and(|old| old == content);
            if !same { return Err(unsafe_key()) }
        }
        Err(_) => return Err(unsafe_key()),
    }
    set_mode(&path, 0o600).map_err(|_| unsafe_key())?;
    Ok(path)
}

// ---- the sync settings of this data folder

const PASSWORD_LABEL: &str = "\0wispops-sync\0webdav-password";
const PASSPHRASE_LABEL: &str = "\0wispops-sync\0passphrase";

/// The outcome of the last sync action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastSync {
    pub at: String,
    /// `push`, `pull`, `list` or `preview`.
    pub action: String,
    pub ok: bool,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SyncFile {
    version: u32,
    url: String,
    username: String,
    /// Sealed with [`LocalVault::seal_aside`]; empty when not stored.
    password: String,
    passphrase: String,
    include_keys: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    last: Option<LastSync>,
}

fn sync_store(data_dir: &Path) -> LocalState<SyncFile> {
    LocalState::new(data_dir.join("sync.json"), || SyncFile { version: 1, ..SyncFile::default() }, |value| serde_json::from_value::<SyncFile>(value).map_err(|_| "Invalid sync settings".to_string()).map(|file| SyncFile { version: 1, ..file }))
}

/// What the window shows of the sync settings: never a password.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncSettings {
    pub url: String,
    pub username: String,
    pub has_password: bool,
    pub has_passphrase: bool,
    pub include_keys: bool,
    pub last: Option<LastSync>,
}

/// A change to the sync settings. A `None` or empty password or passphrase keeps the stored one.
#[derive(Clone, Default)]
pub struct SyncSettingsInput {
    pub url: String,
    pub username: String,
    pub password: Option<String>,
    pub passphrase: Option<String>,
    pub include_keys: bool,
}

impl std::fmt::Debug for SyncSettingsInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSettingsInput").field("url", &self.url).field("username", &self.username).field("include_keys", &self.include_keys).finish_non_exhaustive()
    }
}

pub fn load_settings(data_dir: &Path) -> Result<SyncSettings, String> {
    let file = sync_store(data_dir).read()?.value;
    Ok(SyncSettings { url: file.url, username: file.username, has_password: !file.password.is_empty(), has_passphrase: !file.passphrase.is_empty(), include_keys: file.include_keys, last: file.last })
}

pub fn save_settings(data_dir: &Path, vault: &LocalVault, input: &SyncSettingsInput) -> Result<(), String> {
    let url = input.url.trim();
    if !url.is_empty() { crate::webdav::Collection::parse(url)?; }
    if input.username.contains([':', '\r', '\n']) { return Err("WebDAV 用户名不能含冒号或换行。".to_string()) }
    let fresh = |text: &Option<String>| text.as_deref().filter(|text| !text.is_empty()).map(str::to_string);
    let (password, passphrase) = (fresh(&input.password), fresh(&input.passphrase));
    if password.as_deref().is_some_and(|password| password.contains(['\r', '\n'])) { return Err("应用密码不能含换行。".to_string()) }
    if let Some(passphrase) = &passphrase { check_passphrase(passphrase).map_err(|_| "同步口令需要 12 到 1024 个字符。".to_string())? }
    let sealed_password = password.map(|password| vault.seal_aside(PASSWORD_LABEL, &password)).transpose()?;
    let sealed_passphrase = passphrase.map(|passphrase| vault.seal_aside(PASSPHRASE_LABEL, &passphrase)).transpose()?;
    let store = sync_store(data_dir);
    store.change(&store.read()?.revision, |mut file| {
        file.url = url.to_string();
        file.username = input.username.trim().to_string();
        file.include_keys = input.include_keys;
        if let Some(sealed) = sealed_password { file.password = sealed }
        if let Some(sealed) = sealed_passphrase { file.passphrase = sealed }
        Ok(file)
    })
}

/// Forget the stored application password and passphrase.
pub fn forget_secrets(data_dir: &Path) -> Result<(), String> {
    let store = sync_store(data_dir);
    store.change(&store.read()?.revision, |file| Ok(SyncFile { password: String::new(), passphrase: String::new(), ..file }))
}

/// The WebDAV account and passphrase, decrypted for one sync action.
pub fn credentials(data_dir: &Path, vault: &LocalVault) -> Result<(WebDavSettings, String, bool), String> {
    let file = sync_store(data_dir).read()?.value;
    if file.url.is_empty() || file.username.is_empty() || file.password.is_empty() { return Err("请先填写并保存 WebDAV 地址、用户名和应用密码。".to_string()) }
    let unreadable = || "保存的同步密码无法解密，请重新填写。".to_string();
    let password = vault.open_aside(PASSWORD_LABEL, &file.password).map_err(|_| unreadable())?;
    let passphrase = if file.passphrase.is_empty() { String::new() } else { vault.open_aside(PASSPHRASE_LABEL, &file.passphrase).map_err(|_| unreadable())? };
    Ok((WebDavSettings { url: file.url, username: file.username, password }, passphrase, file.include_keys))
}

/// Keep the outcome of a sync action; a failure to write it is not the action's failure.
pub fn record(data_dir: &Path, last: LastSync) {
    let store = sync_store(data_dir);
    if let Ok(read) = store.read() {
        let _ = store.change(&read.revision, |file| Ok(SyncFile { last: Some(last), ..file }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::CredentialBinding;
    use crate::vault::CredentialInput;
    use crate::webdav::{DavRequest, DavResponse};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const PASSPHRASE: &str = "correct horse battery staple";

    /// An in-memory WebDAV folder that refuses to overwrite, like the plugin's test double.
    #[derive(Default)]
    struct Remote {
        files: Mutex<BTreeMap<String, String>>,
        log: Mutex<Vec<(&'static str, Vec<(&'static str, String)>)>>,
    }

    impl crate::webdav::Transport for Remote {
        fn send(&self, request: &DavRequest) -> Result<DavResponse, String> {
            self.log.lock().unwrap().push((request.method, request.headers.clone()));
            let name = request.url.rsplit('/').next().unwrap_or("").to_string();
            let mut files = self.files.lock().unwrap();
            let reply = |status: u16, body: String| Ok(DavResponse { status, body: body.into_bytes() });
            match request.method {
                "MKCOL" => reply(405, String::new()),
                "PUT" if files.contains_key(&name) => reply(412, String::new()),
                "PUT" => {
                    files.insert(name, String::from_utf8(request.body.clone().unwrap_or_default()).unwrap());
                    reply(201, String::new())
                }
                "PROPFIND" => reply(207, format!("<d:multistatus xmlns:d=\"DAV:\">{}</d:multistatus>", files.keys().map(|n| format!("<d:response><d:href>/dav/WispOps/{n}</d:href></d:response>")).collect::<String>())),
                _ => match files.get(&name) {
                    Some(body) => reply(200, body.clone()),
                    None => reply(404, String::new()),
                },
            }
        }
    }

    impl Remote {
        fn everything(&self) -> String {
            self.files.lock().unwrap().values().cloned().collect()
        }
    }

    struct Device {
        dir: tempfile::TempDir,
        vault: LocalVault,
        config: Config,
    }

    impl Device {
        fn new(n: u8) -> Device {
            let dir = tempfile::tempdir().unwrap();
            let vault = LocalVault::with_key_provider(dir.path(), Box::new(move |_: &Path, _: bool| Ok([n; 32])));
            let config = Config::resolve(serde_json::json!({"dataDir": dir.path().to_string_lossy()})).unwrap();
            Device { dir, vault, config }
        }

        fn sync(&self) -> OpsSync<'_> {
            OpsSync { data_dir: self.dir.path(), config: &self.config, vault: &self.vault }
        }

        fn edit(&self, update: impl FnOnce(&mut ManagedState)) {
            let store = managed_store(self.dir.path());
            store.change(&store.read().unwrap().revision, |mut state| { update(&mut state); Ok(state) }).unwrap();
        }

        fn seed(&self, key: bool) {
            let path = self.dir.path().join("identity");
            if key { fs::write(&path, "-----BEGIN OPENSSH PRIVATE KEY-----\nTEST-ONLY-KEY\n-----END OPENSSH PRIVATE KEY-----\n").unwrap() }
            self.edit(|state| {
                let mut host = crate::config::HostSpec::named("a");
                if key { host.identity_file = Some(path.to_string_lossy().into_owned()) }
                state.hosts = vec![host];
            });
            self.credential("owner-only", "password-not-in-cloud", false);
        }

        fn credential(&self, name: &str, password: &str, agent: bool) {
            let input = CredentialInput { name: name.into(), username: "alice".into(), note: String::new(), agent, password: Some(password.into()) };
            self.vault.save(&input, &self.vault.list().unwrap().revision, None).unwrap();
        }
    }

    fn dav(remote: &Remote) -> WebDav<'_> {
        WebDav::new(&WebDavSettings { url: "https://dav.jianguoyun.com/dav/WispOps/".into(), username: "test@example.org".into(), password: "test-app-password".into() }, remote).unwrap()
    }

    const NOW: i64 = 1_790_000_000_000;

    #[test]
    fn syncs_a_disabled_credential_and_an_explicit_ssh_key_across_device_keys() {
        let (a, b, remote) = (Device::new(1), Device::new(2), Remote::default());
        a.seed(true);
        let name = a.sync().push(&dav(&remote), PASSPHRASE, true, NOW).unwrap();
        assert!(crate::webdav::SNAPSHOT_NAME.is_match(&name));
        assert!(!remote.everything().contains("password-not-in-cloud"));
        assert!(!remote.everything().contains("TEST-ONLY-KEY"));
        assert_eq!(dav(&remote).list().unwrap(), vec![name.clone()]);
        let preview = b.sync().preview(&dav(&remote), &name, PASSPHRASE, NOW).unwrap();
        assert_eq!((preview.incoming.hosts, preview.incoming.credentials, preview.incoming.keys), (1, 1, 1));
        assert!(!format!("{preview:?}").contains("password-not-in-cloud"));
        let backup = b.sync().pull(&dav(&remote), &preview, PASSPHRASE, false, NOW + 1000).unwrap();
        assert!(!backup.contains("password-not-in-cloud"));
        assert_eq!(b.vault.export_for_sync().unwrap().1[0].password, "password-not-in-cloud");
        assert!(b.vault.password(Some("owner-only")).unwrap_err().contains("不允许自动化"));
        let secret = |device: &Device| fs::read_to_string(device.dir.path().join("vault.json")).unwrap();
        assert_ne!(secret(&a), secret(&b));
        let host = managed_store(b.dir.path()).read().unwrap().value.hosts[0].clone();
        let installed = host.identity_file.unwrap();
        assert!(installed.starts_with(&b.dir.path().join("ssh-keys").to_string_lossy().into_owned()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&installed).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(fs::read_dir(b.dir.path().join("sync-backups")).unwrap().count(), 1);
        // The preview is spent: the revisions it pinned are gone.
        assert!(b.sync().pull(&dav(&remote), &preview, PASSPHRASE, false, NOW + 2000).is_err());
    }

    #[test]
    fn refuses_stale_local_revisions_and_active_schedules_preserving_the_local_vault() {
        let (a, b, c, remote) = (Device::new(1), Device::new(2), Device::new(3), Remote::default());
        a.seed(false);
        let name = a.sync().push(&dav(&remote), PASSPHRASE, false, NOW).unwrap();
        let preview = b.sync().preview(&dav(&remote), &name, PASSPHRASE, NOW).unwrap();
        b.seed(false);
        assert!(b.sync().pull(&dav(&remote), &preview, PASSPHRASE, false, NOW).unwrap_err().contains("本机数据有变化"));
        let scheduled = c.sync().preview(&dav(&remote), &name, PASSPHRASE, NOW).unwrap();
        assert!(c.sync().pull(&dav(&remote), &scheduled, PASSPHRASE, true, NOW).unwrap_err().contains("定时任务"));
        assert!(c.vault.list().unwrap().entries.is_empty());
        assert!(c.sync().pull(&dav(&remote), &scheduled, PASSPHRASE, false, NOW + PREVIEW_MS + 1).unwrap_err().contains("过期"));
        assert!(c.sync().preview(&dav(&remote), &name, "incorrect-passphrase", NOW).unwrap_err().contains("无法解密"));
    }

    #[test]
    fn previews_automation_permission_sudo_tasks_and_bindings() {
        let (a, b, remote) = (Device::new(1), Device::new(2), Remote::default());
        a.seed(false);
        a.credential("automated", "never-in-preview", true);
        a.edit(|state| {
            state.bindings.insert("yaml-host".into(), CredentialBinding { auth: crate::config::AuthMethod::Password, login_secret: Some("automated".into()), sudo_secret: None });
            state.tasks = vec![serde_json::from_value(serde_json::json!({"name": "root-report", "targets": "a", "playbook": "inspect", "sudo": true})).unwrap()];
        });
        let name = a.sync().push(&dav(&remote), PASSPHRASE, false, NOW).unwrap();
        let preview = b.sync().preview(&dav(&remote), &name, PASSPHRASE, NOW).unwrap();
        assert_eq!(preview.automated_credentials, vec!["automated".to_string()]);
        assert_eq!(preview.sudo_tasks, vec![("root-report".to_string(), "a".to_string())]);
        assert!(preview.bindings.contains(&("yaml-host".into(), "password".into(), "automated".into(), String::new())));
        assert!(!format!("{preview:?}").contains("never-in-preview"));
    }

    #[test]
    fn syncs_exclusions_policies_and_templates_and_accepts_legacy_snapshots() {
        let (a, b, remote) = (Device::new(1), Device::new(2), Remote::default());
        a.edit(|state| {
            state.excluded_hosts = vec!["external".into()];
            state.policies.insert("external".into(), crate::managed::validate_policy(&serde_json::json!({"sudo": "deny"})).unwrap());
        });
        fs::write(a.dir.path().join("task-templates.json"), r#"{"version":1,"entries":[{"id":"t1","name":"kept as is"}]}"#).unwrap();
        let name = a.sync().push(&dav(&remote), PASSPHRASE, false, NOW).unwrap();
        let preview = b.sync().preview(&dav(&remote), &name, PASSPHRASE, NOW).unwrap();
        assert_eq!((preview.incoming.excluded_hosts, preview.local.excluded_hosts, preview.incoming.templates), (1, 0, 1));
        assert_eq!(preview.policies, vec![("external".to_string(), "sudo=deny".to_string())]);
        b.sync().pull(&dav(&remote), &preview, PASSPHRASE, false, NOW).unwrap();
        let state = managed_store(b.dir.path()).read().unwrap().value;
        assert_eq!(state.excluded_hosts, vec!["external".to_string()]);
        assert!(fs::read_to_string(b.dir.path().join("task-templates.json")).unwrap().contains("kept as is"));
        // Old snapshots have no excludedHosts; importing one clears the local exclusions, visibly.
        let mut legacy = sync_crypto::open(&remote.files.lock().unwrap()[&name], PASSPHRASE).unwrap();
        legacy["managed"].as_object_mut().unwrap().remove("excludedHosts");
        let old = snapshot_name(NOW + 5).unwrap();
        remote.files.lock().unwrap().insert(old.clone(), sync_crypto::seal(&legacy, PASSPHRASE).unwrap());
        let older = b.sync().preview(&dav(&remote), &old, PASSPHRASE, NOW).unwrap();
        assert_eq!((older.incoming.excluded_hosts, older.local_excluded_hosts.clone()), (0, vec!["external".to_string()]));
        b.sync().pull(&dav(&remote), &older, PASSPHRASE, false, NOW).unwrap();
        assert!(managed_store(b.dir.path()).read().unwrap().value.excluded_hosts.is_empty());
    }

    #[test]
    fn refuses_changed_remote_data_after_preview_and_never_overwrites_snapshots() {
        let (a, b, remote) = (Device::new(1), Device::new(2), Remote::default());
        a.seed(false);
        let name = a.sync().push(&dav(&remote), PASSPHRASE, false, NOW).unwrap();
        let preview = b.sync().preview(&dav(&remote), &name, PASSPHRASE, NOW).unwrap();
        remote.files.lock().unwrap().get_mut(&name).unwrap().push(' ');
        assert!(b.sync().pull(&dav(&remote), &preview, PASSPHRASE, false, NOW).unwrap_err().contains("云端快照有变化"));
        assert!(b.vault.list().unwrap().entries.is_empty());
        let log = remote.log.lock().unwrap();
        let put = log.iter().find(|(method, _)| *method == "PUT").unwrap();
        assert!(put.1.contains(&("if-none-match", "*".to_string())));
    }

    #[test]
    fn stores_the_sync_passwords_sealed_and_never_shows_them() {
        let a = Device::new(1);
        let input = SyncSettingsInput { url: "https://dav.example.org/dav/WispOps".into(), username: "me@example.org".into(), password: Some("app-password-secret".into()), passphrase: Some(PASSPHRASE.into()), include_keys: true };
        assert!(!format!("{input:?}").contains("app-password-secret"));
        save_settings(a.dir.path(), &a.vault, &input).unwrap();
        let raw = fs::read_to_string(a.dir.path().join("sync.json")).unwrap();
        assert!(!raw.contains("app-password-secret") && !raw.contains("battery"));
        let shown = load_settings(a.dir.path()).unwrap();
        assert!(shown.has_password && shown.has_passphrase && shown.include_keys);
        // An empty field keeps what is stored.
        save_settings(a.dir.path(), &a.vault, &SyncSettingsInput { password: Some(String::new()), passphrase: None, ..input.clone() }).unwrap();
        let (settings, passphrase, keys) = credentials(a.dir.path(), &a.vault).unwrap();
        assert_eq!((settings.password.as_str(), passphrase.as_str(), keys), ("app-password-secret", PASSPHRASE, true));
        assert!(!format!("{settings:?}").contains("app-password-secret"));
        assert!(save_settings(a.dir.path(), &a.vault, &SyncSettingsInput { passphrase: Some("short".into()), ..input.clone() }).is_err());
        assert!(save_settings(a.dir.path(), &a.vault, &SyncSettingsInput { url: "http://dav.example.org/".into(), ..input.clone() }).is_err());
        record(a.dir.path(), LastSync { at: time::to_iso(NOW), action: "push".into(), ok: true, message: "ok".into() });
        assert!(load_settings(a.dir.path()).unwrap().last.unwrap().ok);
        forget_secrets(a.dir.path()).unwrap();
        assert!(!load_settings(a.dir.path()).unwrap().has_password);
        assert!(credentials(a.dir.path(), &a.vault).is_err());
    }

    #[test]
    fn names_snapshots_as_the_plugin_does() {
        let name = snapshot_name(NOW).unwrap();
        assert!(crate::webdav::SNAPSHOT_NAME.is_match(&name), "{name}");
        assert_eq!(snapshot_time(&name), Some(NOW));
    }
}
