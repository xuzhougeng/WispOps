//! The encrypted password vault. Only the SSH execution path decrypts entries.
//!
//! `vault.json` holds each entry's name, username, note, automation flag and its password sealed
//! with XChaCha20-Poly1305 (random 24-byte nonce, entry name as associated data, base64 of
//! nonce ‖ ciphertext). The key lives in the macOS keychain, behind Windows DPAPI, or in an
//! owner-only `vault.key` elsewhere. The file format is the plugin's.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fsutil::{no_window, random_bytes, set_mode, write_new_private};
use crate::inventory::Host;
use crate::jsre::js_trim;
use crate::managed::LocalState;

/// Where the 32-byte vault key comes from. `create` is true only when the vault holds no entries
/// yet: a provider must never mint a replacement key for existing ciphertext.
pub trait KeyProvider: Send + Sync {
    fn key(&self, dir: &Path, create: bool) -> Result<[u8; 32], String>;
}

/// The platform's key store: macOS keychain item "WispOps Password Store" (account derived from
/// the vault directory), Windows DPAPI protecting `vault.key`, or an owner-only `vault.key`.
pub struct SystemKey;

/// An owner-only key file, `vault.key` in the vault directory unless a path is given.
#[derive(Default)]
pub struct FileKey {
    pub path: Option<PathBuf>,
}

impl KeyProvider for SystemKey {
    fn key(&self, dir: &Path, create: bool) -> Result<[u8; 32], String> {
        if cfg!(target_os = "macos") { keychain_key(dir, create) } else { file_key(&dir.join("vault.key"), create, cfg!(windows)) }
    }
}

impl KeyProvider for FileKey {
    fn key(&self, dir: &Path, create: bool) -> Result<[u8; 32], String> {
        file_key(&self.path.clone().unwrap_or_else(|| dir.join("vault.key")), create, false)
    }
}

impl<F: Fn(&Path, bool) -> Result<[u8; 32], String> + Send + Sync> KeyProvider for F {
    fn key(&self, dir: &Path, create: bool) -> Result<[u8; 32], String> {
        self(dir, create)
    }
}

/// Run a helper with its input on stdin. Secrets travel on stdin, never in process arguments or error messages.
fn run_tool(file: &str, args: &[&str], input: &str) -> Result<Vec<u8>, String> {
    let unavailable = || "无法访问系统密码库。".to_string();
    let mut child = no_window(&mut Command::new(file)).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_| unavailable())?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    let mut out = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut out).map_err(|_| unavailable())?;
    }
    let status = child.wait().map_err(|_| unavailable())?;
    if status.success() { Ok(out) } else { Err("系统密码库未授权或密钥不可用。".to_string()) }
}

/// The absolute, lexically normalized form of a path (no symlink resolution).
fn resolve_path(dir: &Path) -> PathBuf {
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::ParentDir => { out.pop(); }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn parse_hex_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) { return None }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(key)
}

/// The keychain account of a vault directory: `vault-` and the first 24 hex digits of the SHA-256 of its absolute path.
fn keychain_account(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = crate::fsutil::hex(&Sha256::digest(resolve_path(dir).to_string_lossy().as_bytes()));
    format!("vault-{}", &digest[..24])
}

/// The key in the macOS login keychain, one item per vault directory.
fn keychain_key(dir: &Path, create: bool) -> Result<[u8; 32], String> {
    let account = keychain_account(dir);
    if create {
        let key = crate::fsutil::hex(&random_bytes::<32>()?);
        // No -U: never replace an existing key, including after a lost response.
        let _ = run_tool("/usr/bin/security", &["-i"], &format!("add-generic-password -s \"WispOps Password Store\" -a \"{account}\" -w \"{key}\"\n"));
    }
    let out = run_tool("/usr/bin/security", &["find-generic-password", "-s", "WispOps Password Store", "-a", &account, "-w"], "")?;
    parse_hex_key(js_trim(&String::from_utf8_lossy(&out))).ok_or_else(|| "WispOps 密钥格式不正确。".to_string())
}

const DPAPI_PROTECT: &str = "Add-Type -AssemblyName System.Security; $k=[Convert]::FromBase64String([Console]::In.ReadToEnd()); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($k,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))";
const DPAPI_UNPROTECT: &str = "Add-Type -AssemblyName System.Security; $k=[Convert]::FromBase64String([Console]::In.ReadToEnd()); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect($k,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))";

fn dpapi(script: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let out = run_tool("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", script], &STANDARD.encode(data))?;
    STANDARD.decode(js_trim(&String::from_utf8_lossy(&out))).map_err(|_| "WispOps 密钥格式不正确。".to_string())
}

/// The key in an owner-only file; with `dpapi`, the file holds the key protected for the current Windows user.
fn file_key(file: &Path, create: bool, protect: bool) -> Result<[u8; 32], String> {
    let stored = match fs::read(file) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if !create { return Err("WispOps 密钥丢失，不能创建新密钥覆盖已有密码库。".to_string()) }
            let key = random_bytes::<32>()?;
            let stored = if protect { dpapi(DPAPI_PROTECT, &key)? } else { key.to_vec() };
            write_new_private(file, &stored).map_err(|_| "WispOps 密钥不可用。".to_string())?;
            stored
        }
        Err(_) => return Err("WispOps 密钥不可用。".to_string()),
    };
    set_mode(file, 0o600).map_err(|_| "WispOps 密钥不可用。".to_string())?;
    let key = if protect { dpapi(DPAPI_UNPROTECT, &stored)? } else { stored };
    <[u8; 32]>::try_from(key.as_slice()).map_err(|_| "WispOps 密钥格式不正确。".to_string())
}

/// A vault entry's metadata. Names, usernames and notes are plain metadata, never passwords.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInfo {
    pub name: String,
    pub username: String,
    pub note: String,
    /// Whether automation (the SSH execution path) may use the entry.
    pub agent: bool,
    pub has_secret: bool,
}

/// What a save writes. An absent or empty password keeps the stored one.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialInput {
    pub name: String,
    pub username: String,
    pub note: String,
    pub agent: bool,
    pub password: Option<String>,
}

impl std::fmt::Debug for CredentialInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialInput")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("note", &self.note)
            .field("agent", &self.agent)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SealedCredential {
    name: String,
    username: String,
    note: String,
    agent: bool,
    secret: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    entries: Vec<SealedCredential>,
}

/// The entries' metadata and the revision a save or removal must name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultListing {
    pub revision: String,
    pub entries: Vec<CredentialInfo>,
}

/// A decrypted credential, private to the execution path. `username` is the account the password
/// belongs to; blank means the host's configured SSH account.
#[derive(Clone, PartialEq, Eq)]
pub struct SudoCredential {
    pub password: String,
    pub username: String,
}

impl std::fmt::Debug for SudoCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SudoCredential").field("password", &"[REDACTED]").field("username", &self.username).finish()
    }
}

fn validate_vault(value: Value) -> Result<VaultFile, String> {
    let invalid = || "Invalid WispOps vault".to_string();
    let invalid_entry = || "Invalid WispOps vault entry".to_string();
    if value.get("version").and_then(Value::as_u64) != Some(1) { return Err(invalid()) }
    let raw = value.get("entries").and_then(Value::as_array).ok_or_else(invalid)?;
    let mut entries: Vec<SealedCredential> = Vec::new();
    for entry in raw {
        let text = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(invalid_entry);
        let sealed = SealedCredential {
            name: text("name")?,
            username: text("username")?,
            note: text("note")?,
            agent: entry.get("agent").and_then(Value::as_bool).ok_or_else(invalid_entry)?,
            secret: text("secret")?,
        };
        if sealed.name.is_empty() || entries.iter().any(|known| known.name == sealed.name) { return Err(invalid_entry()) }
        entries.push(sealed);
    }
    Ok(VaultFile { version: 1, entries })
}

fn seal(key: &[u8; 32], name: &str, password: &str) -> Result<String, String> {
    let nonce = random_bytes::<24>()?;
    // Bind ciphertext to its entry name; swapping records fails authentication.
    let sealed = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: password.as_bytes(), aad: name.as_bytes() })
        .map_err(|_| "密码加密失败。".to_string())?;
    let mut data = nonce.to_vec();
    data.extend_from_slice(&sealed);
    Ok(STANDARD.encode(data))
}

fn open(key: &[u8; 32], name: &str, secret: &str) -> Result<String, String> {
    let failed = || format!("凭据 {name} 无法解密：密文已损坏或密钥不匹配。");
    let data = STANDARD.decode(secret).or_else(|_| STANDARD_NO_PAD.decode(secret.trim_end_matches('='))).map_err(|_| failed())?;
    if data.len() < 24 { return Err(failed()) }
    let plain = XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(&data[..24]), Payload { msg: &data[24..], aad: name.as_bytes() })
        .map_err(|_| failed())?;
    String::from_utf8(plain).map_err(|_| failed())
}

/// A commit of associated state that takes part in a vault write: when it fails, the vault file is restored.
pub type Participant<'a> = &'a mut dyn FnMut() -> Result<(), String>;

pub struct LocalVault {
    dir: PathBuf,
    state: LocalState<VaultFile>,
    key_provider: Box<dyn KeyProvider>,
}

impl LocalVault {
    /// The vault in `dir`, keyed by the platform's key store.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        LocalVault::with_key_provider(dir, Box::new(SystemKey))
    }

    /// The vault in `dir` with an explicit key source ([`FileKey`], or a closure in tests).
    pub fn with_key_provider(dir: impl Into<PathBuf>, key_provider: Box<dyn KeyProvider>) -> Self {
        let dir = dir.into();
        let state = LocalState::new(dir.join("vault.json"), || VaultFile { version: 1, entries: Vec::new() }, validate_vault);
        LocalVault { dir, state, key_provider }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every entry's metadata, never a password or ciphertext.
    pub fn list(&self) -> Result<VaultListing, String> {
        let read = self.state.read()?;
        let entries = read
            .value
            .entries
            .into_iter()
            .map(|entry| CredentialInfo { name: entry.name, username: entry.username, note: entry.note, agent: entry.agent, has_secret: !entry.secret.is_empty() })
            .collect();
        Ok(VaultListing { revision: read.revision, entries })
    }

    /// Add or update an entry. An absent or empty password keeps the stored one; a new entry needs one.
    /// `commit_associations`, when given, runs after the vault file is committed; if it fails, the vault is restored.
    pub fn save(&self, input: &CredentialInput, revision: &str, commit_associations: Option<Participant<'_>>) -> Result<(), String> {
        if js_trim(&input.name).is_empty() || input.name.encode_utf16().count() > 100 || input.name.contains(['\r', '\n']) {
            return Err("凭据名称不能为空，且不能超过 100 字符。".to_string());
        }
        if let Some(password) = &input.password
            && (password.encode_utf16().count() > 16384 || password.contains(['\r', '\n', '\0']))
        {
            return Err("密码格式不正确（不支持换行或 NUL）。".to_string());
        }
        let update = |mut value: VaultFile| -> Result<VaultFile, String> {
            let mut secret = value.entries.iter().find(|entry| entry.name == input.name).map(|entry| entry.secret.clone());
            if let Some(password) = input.password.as_deref().filter(|password| !password.is_empty()) {
                let mut key = self.key_provider.key(&self.dir, value.entries.is_empty())?;
                let sealed = seal(&key, &input.name, password);
                key.fill(0);
                secret = Some(sealed?);
            }
            let Some(secret) = secret.filter(|secret| !secret.is_empty()) else { return Err("新增凭据需要填写密码。".to_string()) };
            value.entries.retain(|entry| entry.name != input.name);
            value.entries.push(SealedCredential { name: input.name.clone(), username: input.username.clone(), note: input.note.clone(), agent: input.agent, secret });
            Ok(value)
        };
        self.commit(revision, update, commit_associations)
    }

    /// Delete an entry; deleting a name that is not there only checks the revision.
    pub fn remove(&self, name: &str, revision: &str, commit_associations: Option<Participant<'_>>) -> Result<(), String> {
        let update = |mut value: VaultFile| -> Result<VaultFile, String> {
            value.entries.retain(|entry| entry.name != name);
            Ok(value)
        };
        self.commit(revision, update, commit_associations)
    }

    fn commit(&self, revision: &str, update: impl FnOnce(VaultFile) -> Result<VaultFile, String>, commit_associations: Option<Participant<'_>>) -> Result<(), String> {
        let result = match commit_associations {
            None => self.state.change(revision, update),
            Some(associations) => self.state.change_with(revision, update, |commit| {
                commit()?;
                associations()
            }),
        };
        result?;
        // The store creates the file owner-only; keep it so even if it predates this process.
        let _ = set_mode(self.state.path(), 0o600);
        Ok(())
    }

    /// Decrypt the entry a reference (`local:name` or a bare name) points at, for the execution
    /// path only. An entry with `agent: false` is refused; no reference is `None`.
    pub fn credential(&self, reference: Option<&str>) -> Result<Option<SudoCredential>, String> {
        let Some(reference) = reference.filter(|reference| !reference.is_empty()) else { return Ok(None) };
        let name = reference.strip_prefix("local:").unwrap_or(reference);
        let entries = self.state.read()?.value.entries;
        let entry = entries.iter().find(|entry| entry.name == name).ok_or_else(|| format!("WispOps 密码库中找不到凭据 {name}。"))?;
        if !entry.agent { return Err(format!("凭据 {name} 不允许自动化使用。")) }
        let mut key = self.key_provider.key(&self.dir, false)?;
        let password = open(&key, name, &entry.secret);
        key.fill(0);
        Ok(Some(SudoCredential { password: password?, username: entry.username.clone() }))
    }

    /// The password behind a reference; see [`LocalVault::credential`].
    pub fn password(&self, reference: Option<&str>) -> Result<Option<String>, String> {
        Ok(self.credential(reference)?.map(|credential| credential.password))
    }

    /// The sudo password of a host and the account it belongs to; `None` runs `sudo -n`.
    pub fn sudo_credential(&self, host: &Host) -> Result<Option<SudoCredential>, String> {
        self.credential(host.sudo_secret.as_deref())
    }

    pub fn sudo_password(&self, host: &Host) -> Result<Option<String>, String> {
        self.password(host.sudo_secret.as_deref())
    }

    /// The login password of a host with `auth: password`.
    pub fn login_password(&self, host: &Host) -> Result<Option<String>, String> {
        self.password(host.login_secret.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn derives_the_keychain_account_from_the_normalized_directory() {
        // sha256("/Users/someone/.dsh-wisp-ops"), as the plugin computed it.
        assert_eq!(keychain_account(Path::new("/Users/someone/.dsh-wisp-ops")), "vault-c70ef98ccb22568fb00175e1");
        assert_eq!(keychain_account(Path::new("/Users/someone/x/../.dsh-wisp-ops/")), keychain_account(Path::new("/Users/someone/.dsh-wisp-ops")));
        assert_eq!(keychain_account(Path::new("/Users/someone/./.dsh-wisp-ops")), keychain_account(Path::new("/Users/someone/.dsh-wisp-ops")));
    }

    #[test]
    fn parses_only_well_formed_hex_keys() {
        assert_eq!(parse_hex_key(&"0f".repeat(32)), Some([0x0f; 32]));
        assert_eq!(parse_hex_key(&"AB".repeat(32)), Some([0xab; 32]));
        assert_eq!(parse_hex_key(&"0f".repeat(31)), None);
        assert_eq!(parse_hex_key(&"zz".repeat(32)), None);
    }
}
