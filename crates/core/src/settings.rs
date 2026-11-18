//! settings.json: the model services, the appearance and the choices made
//! on the settings pages; and where it and the operations data live.

use crate::ai::{Command, Profile};
use crate::provider::{self, Model, Provider};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The desktop interface language. Unknown values fall back to Chinese.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    #[serde(rename = "en")]
    En,
    #[default]
    #[serde(rename = "zh", other)]
    Zh,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// The folder holding the inventory, the vault, the audit log and the histories; empty means the default.
    pub data_dir: String,
    /// The model services this person can reach, each with its models.
    pub providers: Vec<Provider>,
    /// Which model (`provider::Model::id`) the assistant uses; empty is the first that can answer.
    pub chat_model: String,
    /// The slash commands the person wrote: prompt templates under a name (`ai::read_input`).
    pub commands: Vec<Command>,
    /// The skills switched off, by name; the skills themselves are folders (`skill::folder`).
    pub skills_off: Vec<String>,
    /// "light" or "dark"; empty follows the system.
    pub appearance: String,
    /// Stronger text and separators in both light and dark themes.
    pub high_contrast: bool,
    pub language: Language,
    /// Interface font family for Latin letters, digits and symbols; empty uses the platform default.
    pub font_family: String,
    /// Font family for Chinese characters, a fallback of `font_family`.
    pub cjk_font_family: String,
    /// Base interface size in logical pixels; other text sizes follow its ratio.
    pub font_size: f32,
    /// The proxy every model request goes through (`http://127.0.0.1:7890`, `socks5://…`); empty leaves it to the environment.
    pub proxy: String,
    /// How wide the reader made the assistant beside a page; 0 is the width it comes with.
    pub chat_width: f32,
    /// The assistant beside the pages is put away. Kept between runs only for the column: the floating one starts put away.
    pub chat_hidden: bool,
    /// The assistant stands beside the pages as a column at the right, not floating over them.
    pub chat_docked: bool,
    /// How tall the reader made the terminal panel under the pages; 0 is the height it comes with.
    pub terminal_height: f32,
    /// Minutes between automatic read-only inspections of every server; 0 is off.
    pub auto_inspect_minutes: u32,
    /// Minutes between automatic readings of every server's accounts (用户: logins and quotas too); 0 is off.
    pub auto_accounts_minutes: u32,
    /// Minutes between automatic security triages of every server (安全); 0 is off.
    pub auto_security_minutes: u32,
    /// Minutes between automatic looks for long-running tasks (长时任务); `None` goes along with
    /// the automatic inspection, looking at the servers it inspects.
    pub auto_long_minutes: Option<u32>,
    /// Minutes between the follow-up scans of the directories a first disk scan measured; 0 is off.
    pub disk_scan_minutes: u32,
    /// A user's task counts as long-running after this many hours.
    pub long_job_hours: u32,
    /// Ask GitHub for a newer release at start and at most once a day.
    pub auto_update_check: bool,
    /// Closing the window leaves the program running (timers, routine tasks, notifications) instead of quitting.
    pub keep_running: bool,
    /// Where state changes and routine-task runs are sent (外部 webhook 通知).
    pub webhooks: Vec<Webhook>,
    /// Which routine-task runs are sent: `always`, `problems` or `change` (`WEBHOOK_TASKS`).
    pub webhook_tasks: String,
}

/// One outgoing webhook. The URL holds the service's token and `secret` signs or authorizes:
/// both stay in this file, are sent to that endpoint only, and are never shown to the model.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Webhook {
    pub name: String,
    /// `wecom`, `dingtalk`, `feishu` or `webhook`.
    pub kind: String,
    pub url: String,
    /// DingTalk/Feishu signing secret, or a plain webhook's bearer token; empty for none.
    pub secret: String,
    /// Servers whose state the automatic inspection found changed.
    pub inspection: bool,
    /// Runs of routine tasks.
    pub tasks: bool,
}

/// Which routine-task runs a webhook gets.
pub const WEBHOOK_TASKS: [&str; 3] = ["always", "problems", "change"];

impl Default for Settings {
    fn default() -> Self {
        let providers = provider::DEFAULT_PRESETS.iter().filter_map(|key| provider::preset(key)).map(Provider::from_preset).collect();
        let mut settings = Settings { data_dir: String::new(), providers, chat_model: String::new(), commands: vec![], skills_off: vec![], appearance: String::new(), high_contrast: false, language: Language::default(), font_family: String::new(), cjk_font_family: String::new(), font_size: DEFAULT_FONT_SIZE, proxy: String::new(), chat_width: 0., chat_hidden: false, chat_docked: false, terminal_height: 0., auto_inspect_minutes: 0, auto_accounts_minutes: 0, auto_security_minutes: 0, auto_long_minutes: None, disk_scan_minutes: 1440, long_job_hours: 24, auto_update_check: true, keep_running: cfg!(target_os = "macos"), webhooks: vec![], webhook_tasks: "problems".into() };
        settings.tidy();
        settings
    }
}

pub const DEFAULT_FONT_SIZE: f32 = 13.;
pub const MIN_FONT_SIZE: f32 = 11.;
pub const MAX_FONT_SIZE: f32 = 20.;

/// The intervals 自动巡检 offers, in minutes; 0 is off.
pub const AUTO_INSPECT: [u32; 9] = [0, 5, 15, 30, 60, 180, 360, 720, 1440];

/// The intervals the automatic readings of 用户, 长时任务 and 安全 offer, in minutes; 0 is off.
pub const AUTO_PAGE: [u32; 7] = [0, 30, 60, 180, 360, 720, 1440];

/// The intervals the follow-up disk scans offer, in minutes; 0 is off.
pub const DISK_SCAN: [u32; 5] = [0, 360, 720, 1440, 10080];

/// The thresholds 长时任务 offers, in hours.
pub const LONG_JOB_HOURS: [u32; 6] = [6, 12, 24, 48, 72, 168];

/// Keep a hand-edited settings file from making the interface unusable.
pub fn font_size(value: f32) -> f32 {
    if value.is_finite() { value.clamp(MIN_FONT_SIZE, MAX_FONT_SIZE) } else { DEFAULT_FONT_SIZE }
}

/// `WISP_OPS_HOME` keeps the data and the settings of tests and
/// side-by-side builds in one folder of their own.
fn home_override() -> Option<PathBuf> {
    std::env::var("WISP_OPS_HOME").ok().filter(|home| !home.trim().is_empty()).map(PathBuf::from)
}

/// Where the operations data live unless the settings name another folder.
pub fn default_root() -> PathBuf {
    home_override().unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".wisp-ops"))
}

pub fn settings_file() -> PathBuf {
    match home_override() {
        Some(home) => home.join("settings.json"),
        None => dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("WispOps").join("settings.json"),
    }
}

/// The schemes a proxy address may have.
pub const PROXY_SCHEMES: [&str; 6] = ["http", "https", "socks4", "socks4a", "socks5", "socks5h"];

/// What is wrong with a proxy address, if anything. Empty is fine: it means
/// "not set". `direct` (no proxy at all) is only meaningful for one model
/// service, so it is accepted only where `allow_direct` says so.
pub fn proxy_problem(value: &str, allow_direct: bool) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || (allow_direct && value.eq_ignore_ascii_case("direct")) { return None }
    let Some((scheme, rest)) = value.split_once("://") else { return Some("代理地址要写完整，例如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080。".into()) };
    if !PROXY_SCHEMES.contains(&scheme.to_lowercase().as_str()) { return Some(format!("不支持 {scheme}:// 代理。可用：{}。", PROXY_SCHEMES.join("、"))) }
    let host = rest.rsplit('@').next().unwrap_or("").split(['/', ':']).next().unwrap_or("");
    if host.is_empty() || value.contains(char::is_whitespace) { return Some("代理地址里缺少主机名，或者含有空格。".into()) }
    None
}

impl Settings {
    /// A missing file is the defaults; a broken one is an error, so it is
    /// never silently overwritten with defaults.
    pub fn load(path: &Path) -> Result<Settings> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let mut settings: Settings = serde_json::from_str(&text).with_context(|| format!("设置文件格式不正确：{}", path.display()))?;
                settings.tidy();
                Ok(settings)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(err) => Err(err).with_context(|| format!("无法读取设置文件 {}", path.display())),
        }
    }

    /// API keys are in this file: it is written for its owner alone.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() { std::fs::create_dir_all(dir)? }
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&temporary, path).with_context(|| format!("无法写入设置文件 {}", path.display()))?;
        Ok(())
    }

    /// Make what was read usable: every provider and model gets an id of its
    /// own, and a binding to a model that is gone follows the default again.
    fn tidy(&mut self) {
        self.font_size = font_size(self.font_size);
        self.font_family = self.font_family.trim().to_string();
        self.cjk_font_family = self.cjk_font_family.trim().to_string();
        let mut seen = std::collections::HashSet::new();
        for p in 0..self.providers.len() {
            let id = self.providers[p].id.trim().to_string();
            if id.is_empty() || !seen.insert(id) {
                let free = (1..).map(|n| format!("p{n}")).find(|id| !self.providers.iter().any(|other| other.id == *id)).unwrap_or_default();
                seen.insert(free.clone());
                self.providers[p].id = free;
            }
        }
        let mut seen = std::collections::HashSet::new();
        for p in 0..self.providers.len() {
            for m in 0..self.providers[p].models.len() {
                let id = self.providers[p].models[m].id.trim().to_string();
                if id.is_empty() || !seen.insert(id) {
                    let free = self.free_id();
                    seen.insert(free.clone());
                    self.providers[p].models[m].id = free;
                }
            }
        }
        if self.model(&self.chat_model).is_none() { self.chat_model.clear() }
        if !self.chat_width.is_finite() || self.chat_width < 0. { self.chat_width = 0. }
        if !self.terminal_height.is_finite() || self.terminal_height < 0. { self.terminal_height = 0. }
        if !AUTO_INSPECT.contains(&self.auto_inspect_minutes) { self.auto_inspect_minutes = 0 }
        if !AUTO_PAGE.contains(&self.auto_accounts_minutes) { self.auto_accounts_minutes = 0 }
        if !AUTO_PAGE.contains(&self.auto_security_minutes) { self.auto_security_minutes = 0 }
        if self.auto_long_minutes.is_some_and(|minutes| !AUTO_PAGE.contains(&minutes)) { self.auto_long_minutes = None }
        if !DISK_SCAN.contains(&self.disk_scan_minutes) { self.disk_scan_minutes = 1440 }
        if !LONG_JOB_HOURS.contains(&self.long_job_hours) { self.long_job_hours = 24 }
        if !WEBHOOK_TASKS.contains(&self.webhook_tasks.as_str()) { self.webhook_tasks = "problems".into() }
    }

    /// The first of `m1`, `m2`, … no model has yet.
    fn free_id(&self) -> String {
        (1..).map(|n| format!("m{n}")).find(|id| self.model(id).is_none()).unwrap_or_default()
    }

    /// A model by its id, with the provider that offers it.
    pub fn model(&self, id: &str) -> Option<(&Provider, &Model)> {
        if id.is_empty() { return None }
        self.providers.iter().find_map(|provider| provider.models.iter().find(|model| model.id == id).map(|model| (provider, model)))
    }

    /// Every model of every provider, in the order they are listed.
    pub fn profiles(&self) -> Vec<Profile> {
        self.providers.iter().flat_map(|provider| provider.models.iter().map(|model| provider.profile(model))).collect()
    }

    /// The model the assistant uses: the chosen one, else the first that can
    /// answer (a key and a model name), else the first.
    pub fn chat_profile(&self) -> Option<Profile> {
        if let Some((provider, model)) = self.model(&self.chat_model) { return Some(provider.profile(model)) }
        let all = self.profiles();
        all.iter().find(|profile| profile.missing().is_none()).or(all.first()).cloned()
    }

    /// Add a provider, its models given ids, and return its place in `providers`.
    pub fn add_provider(&mut self, provider: Provider) -> usize {
        self.providers.push(Provider { id: String::new(), ..provider });
        for model in &mut self.providers.last_mut().into_iter().flat_map(|p| p.models.iter_mut()) { model.id.clear() }
        self.tidy();
        self.providers.len() - 1
    }

    pub fn remove_provider(&mut self, index: usize) {
        if index >= self.providers.len() { return }
        self.providers.remove(index);
        self.tidy();
    }

    /// One more model of a provider, and its id.
    pub fn add_model(&mut self, provider: usize, model: &str) -> Option<String> {
        let id = self.free_id();
        self.providers.get_mut(provider)?.models.push(Model { id: id.clone(), model: model.trim().to_string(), ..Default::default() });
        Some(id)
    }

    pub fn remove_model(&mut self, provider: usize, index: usize) {
        let Some(provider) = self.providers.get_mut(provider) else { return };
        if index >= provider.models.len() { return }
        provider.models.remove(index);
        self.tidy();
    }

    /// The folder holding the operations data: the configured one, else `default`.
    pub fn data_root(&self, default: &Path) -> PathBuf {
        if self.data_dir.trim().is_empty() { default.to_path_buf() } else { PathBuf::from(self.data_dir.trim()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_give_every_model_an_id_and_round_trip() {
        let settings = Settings::default();
        assert!(settings.providers.iter().all(|p| !p.id.is_empty() && p.models.iter().all(|m| !m.id.is_empty())));
        let dir = std::env::temp_dir().join(format!("wisp-ops-settings-{}", std::process::id()));
        let path = dir.join("settings.json");
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path).unwrap(), settings);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_binding_to_a_missing_model_is_dropped() {
        let mut settings = Settings { chat_model: "gone".into(), ..Settings::default() };
        settings.tidy();
        assert!(settings.chat_model.is_empty());
        assert!(settings.chat_profile().is_some());
    }
}
