//! WispOps operations engine: inventory, permissions, SSH, vault and audit — no GUI, no LLM.
//!
//! Everything here is synchronous. Functions that read the clock take `now` (epoch milliseconds)
//! or have an `_at(now)` variant. Errors meant for a person or the model are `Result<T, String>`.

/// Managed changes: backup → apply → verify → rollback as one remote shell transaction.
pub mod change;
/// Configuration types, defaults and validation.
pub mod config;
/// Connection diagnosis (DNS, TCP, SSH banner) without logging in.
pub mod diagnose;
/// Owner-only files and directories, random tokens, home expansion.
pub mod fsutil;
/// Inventory loading, effective host policy and the selector language.
pub mod inventory;
/// JavaScript-flavoured regular expressions on top of the `regex` crate.
pub mod jsre;
/// Revision-checked atomic JSON state and the application-managed `managed.json`.
pub mod managed;
/// Grants, per-host capability decisions and the gate for one planned action.
pub mod policy;
/// Shell command risk classification.
pub mod risk;
/// Task schedule arithmetic in IANA time zones.
pub mod schedule;
/// The blocking SSH runner over the system `ssh` binary.
pub mod ssh;
/// Importable host aliases from OpenSSH client configuration.
pub mod ssh_config;
/// Audit log, inspection history and other bounded JSON Lines stores.
pub mod store;
/// Device sync: encrypted snapshots of the managed state and vault in a WebDAV folder.
pub mod sync;
/// The sync snapshot's encrypted envelope (scrypt, XChaCha20-Poly1305), the plugin's format.
pub mod sync_crypto;
/// Epoch-millisecond clock helpers and ISO-8601 formatting.
pub mod time;
/// The encrypted password vault.
pub mod vault;
/// The WebDAV verbs device sync uses, over an injected transport.
pub mod webdav;
