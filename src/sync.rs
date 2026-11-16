//! 设置 → WebDAV 设备同步: the WebDAV account and the sync passphrase of this data folder, and the
//! plugin's explicit sync actions: upload a new encrypted snapshot (立即同步), list the snapshots
//! in the folder, preview one and, once confirmed, replace this device's servers, credentials and
//! tasks with it. All network work runs in the background (`impl Fleet` below, over
//! `wisp_ops_engine::sync`); the passwords are sealed under the vault's key and never drawn.

use crate::app::{Cmd, Workspace};
use crate::i18n::t;
use crate::input::TextInput;
use crate::ops::Fleet;
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_engine::sync::{self, LastSync, OpsSync, Preview, SyncSettings, SyncSettingsInput};
use wisp_ops_engine::sync_crypto::MAX_SYNC_BYTES;
use wisp_ops_engine::time;
use wisp_ops_engine::webdav::{DavRequest, DavResponse, Transport, WebDav};

/// The default folder, as in the plugin: Nutstore's WebDAV.
const DEFAULT_URL: &str = "https://dav.jianguoyun.com/dav/WispOps/";

/// HTTP for WebDAV through the app's client (and its proxy setting).
struct Net;

impl Transport for Net {
    fn send(&self, request: &DavRequest) -> Result<DavResponse, String> {
        let headers: Vec<(&str, &str)> = request.headers.iter().map(|(key, value)| (*key, value.as_str())).collect();
        let (status, body) = wisp_ops_net::webdav::send(request.method, &request.url, &headers, request.body.as_deref(), MAX_SYNC_BYTES as u64 + 1)?;
        Ok(DavResponse { status, body })
    }
}

/// What a sync action did, for the window.
pub enum Done {
    Saved,
    Pushed(String),
    Listed(Vec<String>),
    Previewed(Box<Preview>),
    Pulled(String),
}

impl Fleet {
    fn ops_sync(&self) -> OpsSync<'_> {
        OpsSync { data_dir: self.data_dir(), config: &self.config, vault: self.vault() }
    }

    /// The sync settings as the window shows them.
    pub fn sync_settings(&self) -> Result<SyncSettings, String> {
        sync::load_settings(self.data_dir())
    }

    fn sync_account(&self) -> Result<(wisp_ops_engine::webdav::WebDavSettings, String, bool), String> {
        sync::credentials(self.data_dir(), self.vault())
    }

    fn passphrase(passphrase: String) -> Result<String, String> {
        if passphrase.is_empty() { Err("请先填写并保存同步口令（至少 12 个字符）。".to_string()) } else { Ok(passphrase) }
    }

    fn record_sync(&self, action: &str, result: &Result<String, String>) {
        let message = match result {
            Ok(text) | Err(text) => text.clone(),
        };
        sync::record(self.data_dir(), LastSync { at: time::to_iso(time::now_ms()), action: action.to_string(), ok: result.is_ok(), message });
    }

    /// 立即同步: upload a new encrypted snapshot; gives its name.
    pub fn sync_push(&self) -> Result<String, String> {
        let result = (|| {
            let (account, passphrase, keys) = self.sync_account()?;
            let dav = WebDav::new(&account, &Net)?;
            self.ops_sync().push(&dav, &Self::passphrase(passphrase)?, keys, time::now_ms())
        })();
        self.record_sync("push", &result);
        result
    }

    pub fn sync_list(&self) -> Result<Vec<String>, String> {
        let (account, _, _) = self.sync_account()?;
        WebDav::new(&account, &Net)?.list()
    }

    pub fn sync_preview(&self, name: &str) -> Result<Preview, String> {
        let (account, passphrase, _) = self.sync_account()?;
        let dav = WebDav::new(&account, &Net)?;
        self.ops_sync().preview(&dav, name, &Self::passphrase(passphrase)?, time::now_ms())
    }

    /// Import a previewed snapshot, then read the inventory again; gives the backup's name.
    pub fn sync_pull(&self, preview: &Preview) -> Result<String, String> {
        let result = (|| {
            let (account, passphrase, _) = self.sync_account()?;
            let dav = WebDav::new(&account, &Net)?;
            self.ops_sync().pull(&dav, preview, &Self::passphrase(passphrase)?, self.timers_on(), time::now_ms())
        })();
        self.record_sync("pull", &result);
        self.refresh();
        result
    }
}

/// The section's own state: its fields, what was last read, what is running.
pub struct SyncPage {
    pub url: Entity<TextInput>,
    pub username: Entity<TextInput>,
    pub password: Entity<TextInput>,
    pub passphrase: Entity<TextInput>,
    pub settings: SyncSettings,
    pub include_keys: bool,
    /// The action running in the background.
    pub busy: Option<SyncCmd>,
    pub snapshots: Option<Vec<String>>,
    pub preview: Option<Preview>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncCmd {
    Save,
    /// Forget the stored application password and passphrase.
    Forget,
    ToggleKeys,
    Push,
    List,
    Preview(String),
    /// Import the snapshot on show; `true` once confirmed.
    Pull(bool),
    ClosePreview,
}

impl SyncPage {
    pub fn new(fleet: &Fleet, cx: &mut Context<Workspace>) -> SyncPage {
        let input = |placeholder: &'static str, masked: bool, cx: &mut Context<Workspace>| {
            cx.new(|cx| {
                let mut input = TextInput::new(placeholder, cx);
                input.masked = masked;
                input
            })
        };
        let settings = fleet.sync_settings().unwrap_or_default();
        let page = SyncPage { url: input(DEFAULT_URL, false, cx), username: input("账号邮箱", false, cx), password: input("WebDAV 应用密码", true, cx), passphrase: input("至少 12 个字符，各设备相同", true, cx), include_keys: settings.include_keys, settings, busy: None, snapshots: None, preview: None };
        page.fill(cx);
        page
    }

    /// Put the stored address and user into the fields; the secret fields stay empty and say whether one is kept.
    fn fill(&self, cx: &mut App) {
        let url = if self.settings.url.is_empty() { DEFAULT_URL } else { self.settings.url.as_str() };
        for (input, text) in [(&self.url, url), (&self.username, self.settings.username.as_str())] {
            input.update(cx, |input, cx| if input.text() != text { input.set_text(text, cx) });
        }
        let kept = |has: bool, empty: &'static str| if has { "已保存；留空则不变" } else { empty };
        self.password.update(cx, |input, cx| {
            input.set_text("", cx);
            input.set_placeholder(kept(self.settings.has_password, "WebDAV 应用密码"));
        });
        self.passphrase.update(cx, |input, cx| {
            input.set_text("", cx);
            input.set_placeholder(kept(self.settings.has_passphrase, "至少 12 个字符，各设备相同"));
        });
    }

    fn input(&self, cx: &App) -> SyncSettingsInput {
        let text = |input: &Entity<TextInput>| input.read(cx).text().to_string();
        let secret = |input: &Entity<TextInput>| Some(text(input)).filter(|text| !text.is_empty());
        SyncSettingsInput { url: text(&self.url).trim().to_string(), username: text(&self.username).trim().to_string(), password: secret(&self.password), passphrase: secret(&self.passphrase), include_keys: self.include_keys }
    }

    /// Whether the fields say something the stored settings do not.
    fn edited(&self, cx: &App) -> bool {
        let input = self.input(cx);
        let stored_url = if self.settings.url.is_empty() { DEFAULT_URL } else { self.settings.url.as_str() };
        input.password.is_some() || input.passphrase.is_some() || input.url != stored_url || input.username != self.settings.username || input.include_keys != self.settings.include_keys
    }
}

/// An engine message in the window's language: the fixed text is a key, a trailing `：HTTP 403` is kept.
fn words(message: &str) -> String {
    match message.split_once("：HTTP ") {
        Some((text, status)) => tf!("{}：HTTP {status}", "{}: HTTP {status}", t(text)),
        None => t(message).to_string(),
    }
}

fn snapshot_label(name: &str) -> String {
    sync::snapshot_time(name).map(|ms| wisp_ops_core::time::short_time(&time::to_iso(ms))).unwrap_or_else(|| name.to_string())
}

impl Workspace {
    pub fn run_sync(&mut self, cmd: SyncCmd, window: &mut Window, cx: &mut Context<Self>) {
        let _ = window;
        if self.sync.busy.is_some() && !matches!(cmd, SyncCmd::ToggleKeys | SyncCmd::ClosePreview) { return }
        match cmd {
            SyncCmd::ToggleKeys => self.sync.include_keys = !self.sync.include_keys,
            SyncCmd::ClosePreview => self.sync.preview = None,
            SyncCmd::Pull(false) => {
                let Some(preview) = &self.sync.preview else { return };
                let body = tf!(
                    "这台设备的服务器、凭据关联、权限设置、任务和整个密码库都会换成 {} 的快照（{} 台服务器、{} 条凭据、{} 个任务），不做合并。导入前会把现在的数据用同一口令加密备份到 sync-backups。",
                    "This device's servers, credential links, permissions, tasks and the whole vault are replaced by the snapshot of {} ({} servers, {} credentials, {} tasks), without merging. The current data is first backed up to sync-backups, encrypted with the same passphrase.",
                    wisp_ops_core::time::short_time(&preview.at),
                    preview.incoming.hosts,
                    preview.incoming.credentials,
                    preview.incoming.tasks
                );
                self.confirm(t("替换本机数据？"), body, t("确认替换本机数据"), Cmd::Sync(SyncCmd::Pull(true)), cx);
            }
            cmd => self.sync_in_background(cmd, cx),
        }
        cx.notify();
    }

    /// Save what the fields say (on the main thread: it is a local write), then run the action off it.
    fn sync_in_background(&mut self, cmd: SyncCmd, cx: &mut Context<Self>) {
        let fleet = self.fleet.clone();
        if cmd == SyncCmd::Forget {
            match sync::forget_secrets(fleet.data_dir()) {
                Ok(()) => self.say(t("已清除保存的 WebDAV 应用密码和同步口令"), cx),
                Err(error) => self.fail(words(&error), cx),
            }
            self.sync.settings = fleet.sync_settings().unwrap_or_default();
            self.sync.fill(cx);
            return;
        }
        if cmd == SyncCmd::Save || self.sync.edited(cx) {
            if let Err(error) = sync::save_settings(fleet.data_dir(), fleet.vault(), &self.sync.input(cx)) { return self.fail(words(&error), cx) }
            self.sync.settings = fleet.sync_settings().unwrap_or_default();
            self.sync.fill(cx);
        }
        let preview = match &cmd {
            SyncCmd::Pull(true) => match self.sync.preview.clone() {
                Some(preview) => Some(preview),
                None => return,
            },
            _ => None,
        };
        self.sync.busy = Some(cmd.clone());
        let work = cx.background_executor().spawn(async move {
            match cmd {
                SyncCmd::Push => fleet.sync_push().map(Done::Pushed),
                SyncCmd::List => fleet.sync_list().map(Done::Listed),
                SyncCmd::Preview(name) => fleet.sync_preview(&name).map(|preview| Done::Previewed(Box::new(preview))),
                SyncCmd::Pull(_) => match preview {
                    Some(preview) => fleet.sync_pull(&preview).map(Done::Pulled),
                    None => Err(String::new()),
                },
                _ => Ok(Done::Saved),
            }
        });
        cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| this.sync_done(result, cx)).ok();
        })
        .detach();
        cx.notify();
    }

    fn sync_done(&mut self, result: Result<Done, String>, cx: &mut Context<Self>) {
        self.sync.busy = None;
        self.sync.settings = self.fleet.sync_settings().unwrap_or_default();
        match result {
            Ok(Done::Saved) => self.say(t("同步设置已保存"), cx),
            Ok(Done::Pushed(name)) => {
                if let Some(list) = &mut self.sync.snapshots { list.insert(0, name) }
                self.say(t("已上传新的加密快照"), cx);
            }
            Ok(Done::Listed(names)) => self.sync.snapshots = Some(names),
            Ok(Done::Previewed(preview)) => self.sync.preview = Some(*preview),
            Ok(Done::Pulled(backup)) => {
                self.sync.preview = None;
                self.reload(cx);
                self.say(tf!("已导入快照；原数据已加密备份为 sync-backups/{backup}。定时任务仍是停用的。", "Snapshot imported; the previous data is backed up encrypted as sync-backups/{backup}. Timed tasks stay off."), cx);
            }
            Err(error) => {
                // A pull that failed may have been refused for a stale preview: it is not offered again.
                self.reload(cx);
                if !error.is_empty() { self.fail(words(&error), cx) }
            }
        }
        cx.notify();
    }

    pub fn render_sync(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let page = &self.sync;
        let busy = page.busy.clone();
        let row = |label: &str, control: AnyElement| div().flex().items_center().gap(px(16.)).child(div().w(px(120.)).flex_none().text_color(Theme::text_secondary()).child(label.to_string())).child(div().w(px(420.)).child(control));
        let small = |text: String| div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(text);
        let last = match &page.settings.last {
            None => t("还没有同步过").to_string(),
            Some(last) => {
                let action = if last.action == "pull" { t("导入") } else { t("上传") };
                let at = wisp_ops_core::time::short_time(&last.at);
                if last.ok { tf!("上次同步：{at} {action}成功", "Last sync: {action} succeeded at {at}") } else { tf!("上次同步：{at} {action}失败：{}", "Last sync: {action} failed at {at}: {}", words(&last.message)) }
            }
        };
        let last_ok = page.settings.last.as_ref().is_none_or(|last| last.ok);
        let keys = div().id("sync-keys").flex().items_center().gap(px(8.)).cursor_pointer().on_click(self.on(Cmd::Sync(SyncCmd::ToggleKeys), cx)).child(crate::settings::switch(page.include_keys)).child(t("上传时包括服务器指定的 SSH 私钥（identityFile）"));
        let working = |what: SyncCmd| busy.as_ref() == Some(&what);
        let action = |id: &'static str, label: &str, what: SyncCmd, primary: bool, cx: &mut Context<Self>| {
            let running = working(what.clone());
            let button = if primary { ui::primary_button(id, t(label).to_string()) } else { ui::secondary_button(id, t(label).to_string()) };
            button.h(text_px(28.)).when(running, |d| d.child(ui::spinner(SharedString::from(format!("{id}-spin")), 12., if primary { gpui::white() } else { Theme::text_tertiary() }))).when(busy.is_none(), |d| d.on_click(self.on(Cmd::Sync(what), cx))).when(busy.is_some(), |d| d.opacity(0.6))
        };
        let buttons = div()
            .flex()
            .items_center()
            .gap(px(8.))
            .child(action("sync-push", "立即同步", SyncCmd::Push, true, cx))
            .child(action("sync-list", "读取云端快照", SyncCmd::List, false, cx))
            .child(action("sync-save", "保存", SyncCmd::Save, false, cx))
            .when(page.settings.has_password || page.settings.has_passphrase, |d| d.child(ui::ghost_button("sync-forget", None, Some(t("清除保存的密码").into())).h(text_px(28.)).when(busy.is_none(), |d| d.on_click(self.on(Cmd::Sync(SyncCmd::Forget), cx)))));
        let snapshots = page.snapshots.as_ref().map(|names| {
            let rows = names.iter().take(20).enumerate().map(|(n, name)| {
                let shown = page.preview.as_ref().is_some_and(|preview| &preview.name == name);
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .h(text_px(32.))
                    .px(px(10.))
                    .rounded(px(8.))
                    .border_1()
                    .border_color(if shown { Theme::accent() } else { Theme::line() })
                    .child(div().w(px(96.)).flex_none().child(snapshot_label(name)))
                    .child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_size(text_px(11.)).text_color(Theme::text_tertiary()).child(name.clone()))
                    .child(action_preview(self, n, name, busy.is_none(), working(SyncCmd::Preview(name.clone())), cx))
            });
            div().flex().flex_col().gap(px(6.)).children(rows).when(names.is_empty(), |d| d.child(small(t("云端文件夹里还没有快照。").to_string())))
        });
        let preview = page.preview.as_ref().map(|preview| self.render_sync_preview(preview, busy.is_none(), cx));
        Self::sync_section()
            .child(row(t("文件夹地址"), ui::field(&page.url, window, cx).into_any_element()))
            .child(row(t("用户名"), ui::field(&page.username, window, cx).into_any_element()))
            .child(row(t("应用密码"), ui::field(&page.password, window, cx).into_any_element()))
            .child(row(t("同步口令"), ui::field(&page.passphrase, window, cx).into_any_element()))
            .child(div().pl(px(136.)).child(keys))
            .child(div().pl(px(136.)).flex().flex_col().gap(px(8.)).child(buttons).child(div().text_size(text_px(12.)).text_color(if last_ok { Theme::text_tertiary() } else { Theme::danger() }).child(last)))
            .when_some(snapshots, |d, list| d.child(div().pl(px(136.)).child(list)))
            .when_some(preview, |d, preview| d.child(div().pl(px(136.)).child(preview)))
            .into_any_element()
    }

    fn sync_section() -> Div {
        div().flex().flex_col().gap(px(10.)).child(
            div().flex().flex_col().child(div().font_weight(FontWeight::MEDIUM).child(t("WebDAV 设备同步"))).child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t(
                "在设备之间传整份加密快照：界面里添加的服务器、凭据关联、权限设置、任务、任务模板和整个密码库（含禁止自动化的凭据），可选服务器指定的 SSH 私钥。上传前用同步口令加密（scrypt + XChaCha20-Poly1305），WebDAV 只收到密文；每次上传都是新文件。不同步：密码库密钥、inventory.yml、config.json、模型服务设置、审计和历史、限时授权、定时任务的开关。应用密码和口令用本机密码库的密钥加密保存。导入要先预览，并替换本机数据。",
            ))),
        )
    }

    fn render_sync_preview(&self, preview: &Preview, idle: bool, cx: &mut Context<Self>) -> Div {
        let line = |label: &str, value: String| div().flex().gap(px(10.)).child(div().w(px(150.)).flex_none().text_color(Theme::text_secondary()).child(label.to_string())).child(div().flex_1().min_w_0().child(value));
        let list = |names: &[String]| if names.is_empty() { t("无").to_string() } else { names.join(", ") };
        let (incoming, local) = (&preview.incoming, &preview.local);
        let counts = tf!(
            "{} 台服务器、{} 条凭据、{} 个任务、{} 个模板、{} 把私钥、{} 个已移除名称",
            "{} servers, {} credentials, {} tasks, {} templates, {} keys, {} removed names",
            incoming.hosts, incoming.credentials, incoming.tasks, incoming.templates, incoming.keys, incoming.excluded_hosts
        );
        let here = tf!("{} 台服务器、{} 条凭据、{} 个任务、{} 个模板、{} 个已移除名称", "{} servers, {} credentials, {} tasks, {} templates, {} removed names", local.hosts, local.credentials, local.tasks, local.templates, local.excluded_hosts);
        let sudo: Vec<String> = preview.sudo_tasks.iter().map(|(name, targets)| format!("{name} → {targets}")).collect();
        let policies: Vec<String> = preview.policies.iter().map(|(host, words)| format!("{host}: {words}")).collect();
        let bindings: Vec<String> = preview.bindings.iter().map(|(host, auth, login, sudo)| format!("{host}: {auth}{}{}", if login.is_empty() { String::new() } else { format!(" · {login}") }, if sudo.is_empty() { String::new() } else { format!(" · sudo {sudo}") })).collect();
        div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .p(px(14.))
            .rounded(px(10.))
            .border_1()
            .border_color(Theme::line())
            .text_size(text_px(12.))
            .child(div().flex().items_center().child(div().flex_1().font_weight(FontWeight::MEDIUM).text_size(text_px(13.)).child(tf!("快照 {} 的内容", "Snapshot of {}", wisp_ops_core::time::short_time(&preview.at)))).child(ui::icon_action("sync-preview-close", "x", Theme::text_tertiary(), t("关闭预览")).on_click(self.on(Cmd::Sync(SyncCmd::ClosePreview), cx))))
            .child(line(t("快照里有"), counts))
            .child(line(t("本机现在有"), here))
            .child(line(t("服务器"), list(&preview.host_names)))
            .child(line(t("凭据"), list(&preview.credential_names)))
            .child(line(t("覆盖同名凭据"), list(&preview.conflicts)))
            .child(line(t("允许自动化的凭据"), list(&preview.automated_credentials)))
            .child(line(t("使用 sudo 的任务"), list(&sudo)))
            .child(line(t("权限设置"), list(&policies)))
            .child(line(t("凭据关联"), list(&bindings)))
            .child(line(t("已移除的服务器"), tf!("{}（本机现在：{}）", "{} (here now: {})", list(&preview.excluded_hosts), list(&preview.local_excluded_hosts))))
            .child(div().pt(px(6.)).flex().items_center().gap(px(8.)).child(ui::primary_button("sync-pull", t("导入并替换本机数据")).h(text_px(28.)).when(idle, |d| d.on_click(self.on(Cmd::Sync(SyncCmd::Pull(false)), cx))).when(!idle, |d| d.opacity(0.6))).child(div().flex_1().min_w_0().text_color(Theme::text_tertiary()).child(t("导入前请停用这台设备上的定时任务；预览 10 分钟内有效。"))))
    }
}

fn action_preview(this: &Workspace, n: usize, name: &str, idle: bool, running: bool, cx: &mut Context<Workspace>) -> Stateful<Div> {
    ui::ghost_button(("sync-preview", n), None, Some(t("解密并预览").into())).h(text_px(24.)).text_size(text_px(12.)).when(running, |d| d.child(ui::spinner(("sync-preview-spin", n), 11., Theme::text_tertiary()))).when(idle, |d| d.on_click(this.on(Cmd::Sync(SyncCmd::Preview(name.to_string())), cx)))
}

#[cfg(debug_assertions)]
impl Workspace {
    /// The `sync:` steps of `WISP_OPS_DEV`.
    pub fn dev_sync(&mut self, arg: &str, window: &mut Window, cx: &mut Context<Self>) {
        let (what, rest) = arg.split_once('=').unwrap_or((arg, ""));
        match what {
            "fill" => {
                let fields: Vec<&str> = rest.split('|').collect();
                for (input, text) in [&self.sync.url, &self.sync.username, &self.sync.password, &self.sync.passphrase].into_iter().zip(fields) {
                    input.update(cx, |input, cx| input.set_text(text, cx));
                }
            }
            "push" => self.run(Cmd::Sync(SyncCmd::Push), window, cx),
            "list" => self.run(Cmd::Sync(SyncCmd::List), window, cx),
            "preview" => {
                if let Some(name) = self.sync.snapshots.as_ref().and_then(|names| names.first().cloned()) { self.run(Cmd::Sync(SyncCmd::Preview(name)), window, cx) }
            }
            "pull" => self.run(Cmd::Sync(SyncCmd::Pull(true)), window, cx),
            "scroll" => self.settings_view.scroll.set_offset(point(px(0.), px(-10000.))),
            other => eprintln!("dev: no sync step {other}"),
        }
        cx.notify();
    }
}
