//! WispOps's assistant engine. No GPUI and no SSH in here.
//!
//! - `ai`        request bodies for the three protocols, stream parsing, slash commands, transcripts
//! - `provider`  model services and their models
//! - `settings`  settings.json, and where it and the data live
//! - `skill`     the skills (folders with a `SKILL.md`) the assistant may read
//! - `markdown`  the Markdown of an answer → blocks to draw
//! - `selection` what a click selects in a text field
//! - `time`      timestamps

pub mod ai;
pub mod markdown;
pub mod provider;
pub mod selection;
pub mod settings;
pub mod skill;
pub mod time;
