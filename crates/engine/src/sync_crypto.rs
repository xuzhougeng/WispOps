//! The encrypted sync envelope, in the plugin's format: a JSON object
//! `{"format":"wispops-sync","version":1,"salt","nonce","ciphertext"}` (standard base64), the key
//! derived from the sync passphrase with scrypt (N=32768, r=8, p=1, 16-byte salt, 32-byte key),
//! the JSON payload sealed with XChaCha20-Poly1305 (24-byte nonce) under a fixed associated text.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::Serialize;
use serde_json::Value;

use crate::fsutil::random_bytes;

const AAD: &[u8] = b"WispOps encrypted sync v1; scrypt N=32768 r=8 p=1; XChaCha20-Poly1305";

/// The largest envelope or WebDAV response handled; a payload may be half of it.
pub const MAX_SYNC_BYTES: usize = 8 * 1024 * 1024;

const UNDECRYPTABLE: &str = "Cannot decrypt sync snapshot: incorrect passphrase, damaged data or unsupported format";

/// Check a passphrase as the plugin does: 12 to 1024 UTF-16 code units.
pub fn check_passphrase(passphrase: &str) -> Result<(), String> {
    let units = passphrase.encode_utf16().count();
    if !(12..=1024).contains(&units) { return Err("Sync passphrase must contain 12–1024 characters".to_string()) }
    Ok(())
}

fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    check_passphrase(passphrase)?;
    let params = scrypt::Params::new(15, 8, 1, 32).map_err(|_| "scrypt parameters rejected".to_string())?;
    let mut key = [0u8; 32];
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut key).map_err(|_| "scrypt failed".to_string())?;
    Ok(key)
}

#[derive(Serialize)]
struct Envelope<'a> {
    format: &'a str,
    version: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Seal a value: serialise it, refuse a payload over half of [`MAX_SYNC_BYTES`], encrypt it.
pub fn seal<T: Serialize>(value: &T, passphrase: &str) -> Result<String, String> {
    let mut plain = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if plain.len() > MAX_SYNC_BYTES / 2 {
        plain.fill(0);
        return Err("Sync snapshot is too large".to_string());
    }
    let salt = random_bytes::<16>()?;
    let nonce = random_bytes::<24>()?;
    let mut key = derive(passphrase, &salt)?;
    let sealed = XChaCha20Poly1305::new(Key::from_slice(&key)).encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: AAD });
    key.fill(0);
    plain.fill(0);
    let ciphertext = sealed.map_err(|_| "Sync encryption failed".to_string())?;
    serde_json::to_string(&Envelope { format: "wispops-sync", version: 1, salt: STANDARD.encode(salt), nonce: STANDARD.encode(nonce), ciphertext: STANDARD.encode(ciphertext) }).map_err(|error| error.to_string())
}

/// Open an envelope. Every failure (wrong passphrase, tampering, a foreign format) reads the same.
pub fn open(text: &str, passphrase: &str) -> Result<Value, String> {
    if text.len() > MAX_SYNC_BYTES { return Err("Sync snapshot is too large".to_string()) }
    let fail = || UNDECRYPTABLE.to_string();
    let envelope: Value = serde_json::from_str(text).map_err(|_| fail())?;
    if envelope.get("format").and_then(Value::as_str) != Some("wispops-sync") || envelope.get("version").and_then(Value::as_u64) != Some(1) { return Err(fail()) }
    let field = |name: &str| envelope.get(name).and_then(Value::as_str).and_then(|text| STANDARD.decode(text).ok()).ok_or_else(fail);
    let (salt, nonce, ciphertext) = (field("salt")?, field("nonce")?, field("ciphertext")?);
    if salt.len() != 16 || nonce.len() != 24 || ciphertext.len() < 16 { return Err(fail()) }
    check_passphrase(passphrase).map_err(|_| fail())?;
    let mut key = derive(passphrase, &salt).map_err(|_| fail())?;
    let plain = XChaCha20Poly1305::new(Key::from_slice(&key)).decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: AAD });
    key.fill(0);
    let mut plain = plain.map_err(|_| fail())?;
    let value = serde_json::from_slice(&plain).map_err(|_| fail());
    plain.fill(0);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn authenticates_snapshots_and_rejects_wrong_passwords_tampering_and_weak_passphrases() {
        let encrypted = seal(&json!({"secret": "test"}), PASSPHRASE).unwrap();
        assert!(!encrypted.contains("test"));
        assert_eq!(open(&encrypted, PASSPHRASE).unwrap(), json!({"secret": "test"}));
        assert!(open(&encrypted, "incorrect-passphrase").unwrap_err().contains("Cannot decrypt"));
        let mut envelope: Value = serde_json::from_str(&encrypted).unwrap();
        let ciphertext = envelope["ciphertext"].as_str().unwrap().to_string();
        envelope["ciphertext"] = Value::String(format!("AAAA{}", &ciphertext[4..]));
        assert!(open(&envelope.to_string(), PASSPHRASE).unwrap_err().contains("Cannot decrypt"));
        assert!(seal(&json!({}), "short").unwrap_err().contains("12"));
        assert!(open("{\"format\":\"other\"}", PASSPHRASE).unwrap_err().contains("Cannot decrypt"));
    }

    #[test]
    fn writes_the_plugins_envelope() {
        let envelope: Value = serde_json::from_str(&seal(&json!([1]), PASSPHRASE).unwrap()).unwrap();
        let mut keys: Vec<&String> = envelope.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["ciphertext", "format", "nonce", "salt", "version"]);
        assert_eq!(envelope["format"], "wispops-sync");
        assert_eq!(STANDARD.decode(envelope["salt"].as_str().unwrap()).unwrap().len(), 16);
        assert_eq!(STANDARD.decode(envelope["nonce"].as_str().unwrap()).unwrap().len(), 24);
    }

    /// An envelope written by the plugin's `sealSync({ secret: 'plugin' }, 'correct horse battery staple')`
    /// (Node's scrypt and @noble/ciphers' XChaCha20-Poly1305).
    #[test]
    fn opens_an_envelope_the_plugin_wrote() {
        let text = include_str!("../tests/fixtures/plugin-sync-envelope.json");
        assert_eq!(open(text.trim(), PASSPHRASE).unwrap(), json!({"secret": "plugin"}));
    }
}
