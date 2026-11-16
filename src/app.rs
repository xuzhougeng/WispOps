//! The window's state and what a click does. Everything is held in one root
//! view, `Workspace`; every click is a `Cmd` value, wired with
//! `self.on(Cmd::…, cx)` and carried out in `Workspace::run`. The pages
//! (`overview.rs`, `servers.rs`, `vault.rs`, `tasks.rs`, `audit.rs`,
//! `settings.rs`, `assistant.rs`) and the assistant (`chat.rs`) are `impl Workspace` blocks.
//!
//! Nothing is read from disk or over SSH while drawing: what the pages show
//! is kept in `View` and read again by `Workspace::reload` after anything
//! that may have changed it. Work on a server runs on the background
//! executor and comes back through `this.update`.

use crate::chat::Chat;
use crate::dialogs::Modal;
use crate::i18n::t;
use crate::input::{InputEvent, TextInput};
use crate::ops::{Fleet, View};
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use wisp_ops_core::settings::{Language, Settings, default_root, settings_file};

actions!(workspace, [Dismiss, ToggleAssistant, NewChat, ShowSettings, Refresh, FocusNext, FocusPrev]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Overview,
    Servers,
    Disk,
    LongJobs,
    Security,
    Tasks,
    Vault,
    Audit,
    /// The assistant as a page of its own, with its past conversations beside it.
    Assistant,
    Settings,
}

impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Page::Overview => "机群总览",
            Page::Servers => "服务器",
            Page::Disk => "磁盘",
            Page::LongJobs => "长时任务",
            Page::Security => "安全",
            Page::Tasks => "例行任务",
            Page::Vault => "密码库",
            Page::Audit => "操作审计",
            Page::Assistant => "助手",
            Page::Settings => "设置",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Page::Overview => "scan-text",
            Page::Servers => "library",
            Page::Disk => "hard-drive",
            Page::LongJobs => "timer",
            Page::Security => "shield",
            Page::Tasks => "list-todo",
            Page::Vault => "plug",
            Page::Audit => "history",
            Page::Assistant => "message-square",
            Page::Settings => "settings-gear",
        }
    }
}

/// The edge being dragged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edge {
    /// Between the page and the assistant.
    Chat,
}

/// What the person says to the assistant wanting to do something a host's policy asks about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent {
    Once,
    /// This call, and the same capabilities on the same hosts for a while (a grant).
    Grant,
    /// This call, and nothing asked about again in this conversation (full permission).
    Full,
    Deny,
}

#[derive(Clone, Debug)]
pub enum Cmd {
    SetPage(Page),
    Refresh,
    // ---- the assistant
    ToggleChat,
    Ask,
    StopChat,
    NewChat,
    Suggest(String),
    /// Put a request in the box for the person to finish.
    Draft(String),
    /// Open the assistant with the caret in its box, leaving what is written there.
    FocusChat,
    PickSlash(usize),
    AnswerTools(Consent),
    /// Warn about full permission before giving it.
    AskFullPermission,
    ToggleTools(usize),
    /// Show what a tool returned, in full.
    ShowOutput(usize),
    ToggleHistory,
    OpenChat(String),
    DeleteChat(String),
    RevokeGrants,
    CopyText(String),
    // ---- servers
    SelectHost(Option<String>),
    AddHost,
    EditHost(String),
    RemoveHost(String),
    ImportSshConfig,
    ToggleImport(usize),
    /// Tick every row of the import dialog, or none.
    ToggleImportAll(bool),
    ProbeHost(String),
    InspectHosts(String),
    UnblockHost(String),
    EditPolicy(String),
    /// Cycle a capability's permission in the policy dialog: capability, value.
    SetPolicy(&'static str, &'static str),
    BindCredential(String, bool),
    PickCredential(String),
    /// In the bind dialog: write a new credential, stored and linked by 保存.
    BindNewCredential,
    TestCredential,
    HostSearchChanged,
    // ---- overview
    SelectRun(String, usize),
    /// Open or close a server's panel of charts.
    OpenHost(String),
    // ---- disk
    DiskHost(String),
    /// Ask before the first full scan: it reads every local filesystem as root.
    AskFullScan(String),
    DiskScan(String, crate::scans::Scope),
    DiskPath(String),
    DiskZoom(String),
    DiskList(bool),
    ToggleDiskFree,
    SetDiskScan(u32),
    // ---- long-running tasks
    CheckLongJobs(String),
    SetLongHours(u32),
    /// Fold or unfold a server's card.
    ToggleLongHost(String),
    /// Fold (true) or unfold every server's card.
    FoldLongHosts(bool),
    /// Put a user in a server's filter, or take them out: server, user.
    LongUser(String, String),
    /// Set a server's filter to this text (empty clears it).
    LongFilter(String, String),
    // ---- security
    ScanAttacks(String),
    OpenAttack(String),
    // ---- vault
    AddCredential,
    EditCredential(String),
    DeleteCredential(String),
    ToggleAgentUse,
    // ---- tasks
    AddTask,
    EditTask(String),
    DeleteTask(String),
    RunTask(String),
    ToggleTask(String),
    PickPlaybook(&'static str),
    PickSchedule(&'static str),
    ToggleTaskSudo,
    // ---- audit
    AuditHost(Option<String>),
    AuditRange(u32),
    // ---- settings
    SetSettingsTab(crate::settings::Tab),
    SetAppearance(&'static str),
    SetLanguage(Language),
    SetFontSize(f32),
    ToggleContrast,
    SetAutoInspect(u32),
    PickChatModel(String),
    AddProvider(&'static str),
    RemoveProvider(usize),
    SelectProvider(usize),
    AddModel(usize),
    RemoveModel(usize, usize),
    SetEffort(usize, usize, &'static str),
    SetProtocol(usize, wisp_ops_core::ai::Protocol),
    ToggleSkill(String),
    RevealData,
    OpenUrl(String),
    // ---- dialogs and menus
    SubmitModal,
    CloseModal,
    Confirmed(Box<Cmd>),
}

#[derive(Clone, Debug)]
pub enum MenuKind {
    Models,
    AddProvider,
    Effort(usize, usize),
    HostActions(String),
    AutoInspect,
    DiskScan,
    LongHours,
}

#[derive(Clone)]
pub struct MenuItem {
    pub label: SharedString,
    pub checked: bool,
    pub note: Option<SharedString>,
    pub cmd: Cmd,
}

pub struct Menu {
    pub at: Point<Pixels>,
    pub items: Vec<MenuItem>,
    /// Places before which a line is drawn.
    pub breaks: Vec<usize>,
}

pub struct Toast {
    pub message: SharedString,
    pub error: bool,
    pub at: Instant,
}

pub struct Workspace {
    pub focus: FocusHandle,
    pub settings: Settings,
    settings_path: PathBuf,
    /// The inventory, the SSH runner, the vault and the stores, shared with the background work.
    pub fleet: Arc<Fleet>,
    /// What the pages draw, as last read.
    pub view: View,
    pub page: Page,
    pub chat: Chat,
    pub skills: Vec<wisp_ops_core::skill::Skill>,
    pub settings_view: crate::settings::SettingsView,
    // ---- servers
    pub selected_host: Option<String>,
    pub host_search: Entity<TextInput>,
    /// The hosts being probed or inspected from the window right now.
    pub working: HashSet<String>,
    /// The assistant's panel stays folded while there is no model it could use, until it is asked for:
    /// a third of the window for "no model configured" on every page is a poor first sight.
    pub chat_parked: bool,
    /// Why the last capability probe of a host failed, until one succeeds.
    pub probe_errors: HashMap<String, String>,
    // ---- overview: the inspection of a host that is on show (host, its place in the history).
    pub selected_run: Option<(String, usize)>,
    /// The server whose charts are open in the overview.
    pub open_host: Option<String>,
    // ---- disk: the server on show, its scans, and where in them the reader is.
    pub disk: crate::disk::DiskState,
    // ---- long-running tasks and security: the hosts being checked right now, and the triage laid open.
    pub long_working: HashSet<String>,
    /// The servers whose long-task cards are folded, and each checked server's filter.
    pub long_folded: HashSet<String>,
    pub long_filters: HashMap<String, (Entity<TextInput>, Subscription)>,
    pub attack_working: HashSet<String>,
    pub open_attack: Option<String>,
    // ---- audit
    pub audit_host: Option<String>,
    pub audit_hours: u32,
    // ---- tasks: the tasks running from the window right now.
    pub running_tasks: HashSet<String>,
    pub modal: Option<Modal>,
    pub modal_error: String,
    pub modal_busy: bool,
    /// A dialog just opened: its first field (or the window, for one without fields) takes focus when it is drawn.
    pub modal_focus: bool,
    pub modal_subscriptions: Vec<Subscription>,
    pub menu: Option<Menu>,
    pub toast: Option<Toast>,
    pub resizing: Option<Edge>,
    pub page_scroll: ScrollHandle,
    pub detail_scroll: ScrollHandle,
    _subscriptions: Vec<Subscription>,
}

impl Workspace {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let settings_path = settings_file();
        let mut toast = None;
        let settings = Settings::load(&settings_path).unwrap_or_else(|err| {
            toast = Some(Toast { message: tf!("{err:#}；本次使用默认设置。", "{err:#}; using default settings for this session.").into(), error: true, at: Instant::now() });
            Settings::default()
        });
        crate::i18n::set_language(settings.language);
        wisp_ops_net::set_proxy(&settings.proxy);
        let root = settings.data_root(&default_root());
        let fleet = Arc::new(Fleet::open(&root));
        let focus = cx.focus_handle();
        window.focus(&focus);
        theme::set_accent("teal");
        bind_keys(cx);
        let host_search = cx.new(|cx| TextInput::new("搜索名称、地址、分组", cx));
        let mut subscriptions = vec![cx.subscribe(&host_search, |this: &mut Self, _, event: &InputEvent, cx| {
            if *event == InputEvent::Changed { this.run_quiet(Cmd::HostSearchChanged, cx) }
        })];
        let chat = Chat::new(cx);
        subscriptions.push(cx.subscribe(&chat.input, |this: &mut Self, _, event: &InputEvent, cx| this.chat_input(*event, cx)));
        subscriptions.push(cx.subscribe(&chat.search, |_: &mut Self, _, event: &InputEvent, cx| if *event == InputEvent::Changed { cx.notify() }));
        let mut view = fleet.view();
        view.audit = fleet.audit(None, 24 * 7, crate::audit::AUDIT_ROWS);
        let settings_view = crate::settings::SettingsView::new(&settings, cx);
        let mut this = Workspace { focus, settings, settings_path, fleet, view, page: Page::Overview, chat, skills: vec![], settings_view, selected_host: None, host_search, working: HashSet::new(), chat_parked: true, probe_errors: HashMap::new(), selected_run: None, open_host: None, disk: Default::default(), long_working: HashSet::new(), long_folded: HashSet::new(), long_filters: HashMap::new(), attack_working: HashSet::new(), open_attack: None, audit_host: None, audit_hours: 24 * 7, running_tasks: HashSet::new(), modal: None, modal_error: String::new(), modal_busy: false, modal_focus: false, modal_subscriptions: vec![], menu: None, toast, resizing: None, page_scroll: ScrollHandle::new(), detail_scroll: ScrollHandle::new(), _subscriptions: subscriptions };
        this.apply_appearance(window);
        this.apply_typography(window, cx);
        cx.observe_window_appearance(window, |this, window, _| this.apply_appearance(window)).detach();
        this.load_skills();
        this.sync_long_filters(cx);
        if this.view.hosts.is_empty() { this.page = Page::Servers }
        this
    }

    /// Once the window is there: the timers that keep the fleet looked after while it is open.
    pub fn start(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        self.watch_fleet(cx);
    }

    pub fn on(&self, cmd: Cmd, cx: &mut Context<Self>) -> impl Fn(&ClickEvent, &mut Window, &mut App) + 'static {
        cx.listener(move |this, _, window, cx| this.run(cmd.clone(), window, cx))
    }

    /// As `on`, for something inside a row that is itself pressed: the row does not hear the click.
    pub fn on_within(&self, cmd: Cmd, cx: &mut Context<Self>) -> impl Fn(&ClickEvent, &mut Window, &mut App) + 'static {
        cx.listener(move |this, _, window, cx| {
            cx.stop_propagation();
            this.run(cmd.clone(), window, cx)
        })
    }

    pub fn on_menu(&self, kind: MenuKind, cx: &mut Context<Self>) -> impl Fn(&ClickEvent, &mut Window, &mut App) + 'static {
        cx.listener(move |this, ev: &ClickEvent, _, cx| this.open_menu(kind.clone(), ev.position(), cx))
    }

    /// The same menus under the right button, on a row that is a server.
    pub fn on_context(&self, kind: MenuKind, cx: &mut Context<Self>) -> impl Fn(&MouseDownEvent, &mut Window, &mut App) + 'static {
        cx.listener(move |this, ev: &MouseDownEvent, _, cx| {
            cx.stop_propagation();
            this.open_menu(kind.clone(), ev.position, cx)
        })
    }

    pub fn say(&mut self, message: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.show_toast(message.into(), false, cx);
    }

    pub fn fail(&mut self, message: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.show_toast(message.into(), true, cx);
    }

    fn show_toast(&mut self, message: SharedString, error: bool, cx: &mut Context<Self>) {
        let at = Instant::now();
        self.toast = Some(Toast { message, error, at });
        cx.notify();
        // Errors stay longer: they usually need reading twice.
        let seconds = if error { 7 } else { 3 };
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(std::time::Duration::from_secs(seconds)).await;
            this.update(cx, |this, cx| {
                if this.toast.as_ref().is_some_and(|t| t.at == at) {
                    this.toast = None;
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }

    pub fn save_settings(&mut self, cx: &mut Context<Self>) {
        if let Err(err) = self.settings.save(&self.settings_path) { self.fail(format!("{err:#}"), cx) }
    }

    /// Read again what the pages draw: the inventory (when its files changed), the probes, the histories, the vault's names.
    pub fn reload(&mut self, cx: &mut Context<Self>) {
        self.view = self.fleet.view();
        self.view.audit = self.fleet.audit(self.audit_host.as_deref(), self.audit_hours, crate::audit::AUDIT_ROWS);
        if self.selected_host.as_ref().is_some_and(|name| !self.view.hosts.iter().any(|host| &host.name == name)) { self.selected_host = None }
        self.sync_long_filters(cx);
        cx.notify();
    }

    /// Run a change to the fleet's own files (the inventory the window keeps, the vault), read the view again, and say a failure.
    pub fn change(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&Fleet) -> Result<(), String>) -> bool {
        let result = f(&self.fleet);
        self.reload(cx);
        match result {
            Ok(()) => true,
            Err(err) => {
                self.fail(err, cx);
                false
            }
        }
    }

    pub fn load_skills(&mut self) {
        self.skills = crate::ops::skills(&self.settings_path);
    }

    pub fn settings_path(&self) -> &std::path::Path {
        &self.settings_path
    }

    pub fn apply_appearance(&mut self, window: &mut Window) {
        let dark = match self.settings.appearance.as_str() {
            "light" => false,
            "dark" => true,
            _ => matches!(window.appearance(), WindowAppearance::Dark | WindowAppearance::VibrantDark),
        };
        theme::set_dark(dark);
        theme::set_high_contrast(self.settings.high_contrast);
        window.refresh();
    }

    pub fn apply_typography(&self, window: &mut Window, cx: &App) {
        let names = cx.text_system().all_font_names();
        // A font that is not installed (any more) falls back to the platform's choice.
        let installed = |family: &String| if family.is_empty() || names.contains(family) { family.clone() } else { String::new() };
        theme::set_typography(&installed(&self.settings.font_family), &installed(&self.settings.cjk_font_family), self.settings.font_size);
        window.refresh();
    }

    /// A command from a place that has no window at hand (an input's event); only for commands that need none.
    fn run_quiet(&mut self, cmd: Cmd, cx: &mut Context<Self>) {
        if let Cmd::HostSearchChanged = cmd { cx.notify() }
    }

    // ---- menus

    pub fn open_menu(&mut self, kind: MenuKind, at: Point<Pixels>, cx: &mut Context<Self>) {
        let mut items: Vec<MenuItem> = vec![];
        let mut breaks = vec![];
        let item = |label: &str, checked: bool, note: Option<String>, cmd: Cmd| MenuItem { label: label.to_string().into(), checked, note: note.map(Into::into), cmd };
        match kind {
            MenuKind::Models => {
                let chosen = self.settings.chat_profile().map(|profile| profile.id).unwrap_or_default();
                for provider in &self.settings.providers {
                    if provider.models.is_empty() { continue }
                    if !items.is_empty() { breaks.push(items.len()) }
                    let keyless = provider.key().is_empty();
                    for model in &provider.models {
                        items.push(item(&model.model, model.id == chosen, Some(if keyless { tf!("{} · 缺 Key", "{} · no key", provider.title()) } else { provider.title() }), Cmd::PickChatModel(model.id.clone())));
                    }
                }
                if !items.is_empty() { breaks.push(items.len()) }
                items.push(item(t("管理模型…"), false, None, Cmd::SetPage(Page::Settings)));
            }
            MenuKind::AddProvider => {
                for preset in &wisp_ops_core::provider::PRESETS {
                    items.push(item(preset.name, false, None, Cmd::AddProvider(preset.key)));
                }
                breaks.push(items.len());
                items.push(item(t("自定义（OpenAI 兼容）"), false, None, Cmd::AddProvider("")));
            }
            MenuKind::Effort(provider, model) => {
                let current = self.settings.providers.get(provider).and_then(|p| p.models.get(model)).map(|m| m.effort.clone()).unwrap_or_default();
                for (key, label) in wisp_ops_core::ai::EFFORTS {
                    items.push(item(t(label), current == key, None, Cmd::SetEffort(provider, model, key)));
                }
            }
            MenuKind::HostActions(name) => {
                items.push(item(t("巡检"), false, None, Cmd::InspectHosts(name.clone())));
                items.push(item(t("探测能力"), false, None, Cmd::ProbeHost(name.clone())));
                breaks.push(items.len());
                items.push(item(t("让助手汇报状态"), false, None, Cmd::Suggest(format!("/inspect {name}"))));
                items.push(item(t("让助手诊断磁盘"), false, None, Cmd::Draft(format!("/disk {name} /"))));
                items.push(item(t("让助手做安全排查"), false, None, Cmd::Suggest(format!("/security {name}"))));
                breaks.push(items.len());
                // On the servers page the row itself opens the server.
                if self.page != Page::Servers { items.push(item(t("查看详情"), false, None, Cmd::SelectHost(Some(name.clone())))) }
                items.push(item(t("查看磁盘占用"), false, None, Cmd::DiskHost(name.clone())));
                items.push(item(t("查看操作审计"), false, None, Cmd::AuditHost(Some(name.clone()))));
                breaks.push(items.len());
                items.push(item(t("配置普通用户…"), false, None, Cmd::BindCredential(name.clone(), false)));
                items.push(item(t("配置 sudoer…"), false, None, Cmd::BindCredential(name.clone(), true)));
                if self.view.hosts.iter().any(|host| host.name == name && host.managed) {
                    breaks.push(items.len());
                    items.push(item(t("编辑服务器"), false, None, Cmd::EditHost(name.clone())));
                    items.push(item(t("删除服务器"), false, None, Cmd::RemoveHost(name)));
                }
            }
            MenuKind::AutoInspect => {
                for minutes in wisp_ops_core::settings::AUTO_INSPECT {
                    items.push(item(&crate::settings::interval_label(minutes), self.settings.auto_inspect_minutes == minutes, None, Cmd::SetAutoInspect(minutes)));
                }
            }
            MenuKind::DiskScan => {
                for minutes in wisp_ops_core::settings::DISK_SCAN {
                    items.push(item(&crate::disk::rescan_label(minutes), self.settings.disk_scan_minutes == minutes, None, Cmd::SetDiskScan(minutes)));
                }
            }
            MenuKind::LongHours => {
                for hours in wisp_ops_core::settings::LONG_JOB_HOURS {
                    items.push(item(&crate::longrun::hours_label(hours), self.settings.long_job_hours == hours, None, Cmd::SetLongHours(hours)));
                }
            }
        }
        self.menu = Some(Menu { at, items, breaks });
        cx.notify();
    }

    // ---- commands

    pub fn run(&mut self, cmd: Cmd, window: &mut Window, cx: &mut Context<Self>) {
        self.menu = None;
        match cmd {
            Cmd::SetPage(page) => {
                if page == Page::Assistant && self.page != Page::Assistant { self.chat.back = self.page }
                self.page = page;
                if page == Page::Assistant { self.enter_assistant(window, cx) }
                if matches!(page, Page::Audit | Page::Overview | Page::Tasks | Page::LongJobs | Page::Security) { self.reload(cx) }
                if page == Page::Disk { self.load_disk(cx) }
            }
            Cmd::Refresh => {
                self.reload(cx);
                self.say(t("已重新读取"), cx);
            }
            // On the assistant's own page there is no panel to fold: the shortcut goes back to the page it came from.
            Cmd::ToggleChat if self.page == Page::Assistant => self.run(Cmd::SetPage(self.chat.back), window, cx),
            // Parked for want of a model, the panel is closed whatever the setting says: the first press opens it.
            Cmd::ToggleChat if self.chat_closed() && !self.settings.chat_hidden => self.chat_parked = false,
            Cmd::ToggleChat => {
                self.chat_parked = false;
                self.settings.chat_hidden = !self.settings.chat_hidden;
                self.save_settings(cx);
            }
            Cmd::Ask => self.ask(cx),
            Cmd::StopChat => self.stop_chat(cx),
            Cmd::NewChat => {
                self.new_chat(cx);
                if self.page == Page::Assistant { self.focus_composer(window, cx) }
            }
            Cmd::Suggest(text) => {
                self.show_chat(cx);
                self.chat.input.update(cx, |input, cx| input.set_text(&text, cx));
                self.ask(cx);
            }
            Cmd::Draft(text) => {
                self.show_chat(cx);
                self.chat.history = None;
                self.chat.input.update(cx, |input, cx| {
                    input.set_text(&text, cx);
                    input.focus(window);
                });
            }
            Cmd::FocusChat => {
                self.show_chat(cx);
                self.chat.history = None;
                self.chat.input.update(cx, |input, _| input.focus(window));
            }
            Cmd::PickSlash(at) => self.pick_slash(at, cx),
            Cmd::AnswerTools(consent) => self.answer_tools(consent, cx),
            Cmd::AskFullPermission => self.confirm(
                t("完全授权这次对话？"),
                t("之后这次对话里，助手对清单中所有服务器的变更、sudo 和破坏性操作（包括删除文件、停服务、重启）都不再询问，直接执行。只有权限设为「拒绝」的操作和禁止清单里的命令仍会被拒绝。授权到撤销或开始新对话为止；每条命令仍记入操作审计。"),
                t("完全授权"),
                Cmd::AnswerTools(Consent::Full),
                cx,
            ),
            Cmd::ToggleTools(first) => {
                if !self.chat.tools_open.remove(&first) { self.chat.tools_open.insert(first); }
            }
            Cmd::ShowOutput(at) => self.show_output(at, window, cx),
            Cmd::ToggleHistory => self.toggle_history(cx),
            Cmd::OpenChat(id) => {
                self.open_chat(&id, cx);
                if self.page == Page::Assistant { self.focus_composer(window, cx) }
            }
            Cmd::DeleteChat(id) => self.delete_chat(&id, cx),
            Cmd::RevokeGrants => {
                self.fleet.revoke_grants(&self.chat.session);
                self.say(t("已撤销这次对话的全部授权"), cx);
            }
            Cmd::CopyText(text) => {
                cx.write_to_clipboard(ClipboardItem::new_string(text));
                self.say(t("已复制"), cx);
            }
            Cmd::RevealData => cx.open_with_system(self.fleet.data_dir()),
            Cmd::OpenUrl(url) => cx.open_url(&url),
            Cmd::SubmitModal => self.submit_modal(window, cx),
            Cmd::CloseModal => self.close_modal(window, cx),
            Cmd::Confirmed(cmd) => {
                self.modal = None;
                self.run_confirmed(*cmd, window, cx);
            }
            cmd @ (Cmd::SelectHost(_) | Cmd::AddHost | Cmd::EditHost(_) | Cmd::RemoveHost(_) | Cmd::ImportSshConfig | Cmd::ToggleImport(_) | Cmd::ToggleImportAll(_) | Cmd::ProbeHost(_) | Cmd::InspectHosts(_) | Cmd::UnblockHost(_) | Cmd::EditPolicy(_) | Cmd::SetPolicy(..) | Cmd::BindCredential(..) | Cmd::PickCredential(_) | Cmd::BindNewCredential | Cmd::TestCredential | Cmd::HostSearchChanged) => self.run_servers(cmd, window, cx),
            cmd @ (Cmd::DiskHost(_) | Cmd::AskFullScan(_) | Cmd::DiskScan(..) | Cmd::DiskPath(_) | Cmd::DiskZoom(_) | Cmd::DiskList(_) | Cmd::ToggleDiskFree) => self.run_disk(cmd, cx),
            Cmd::CheckLongJobs(selector) => self.check_long_jobs(selector, false, cx),
            cmd @ (Cmd::ToggleLongHost(_) | Cmd::FoldLongHosts(_) | Cmd::LongUser(..) | Cmd::LongFilter(..)) => self.run_longrun(cmd, cx),
            Cmd::ScanAttacks(selector) => self.scan_attacks(selector, cx),
            Cmd::OpenAttack(host) => self.open_attack = if self.open_attack.as_ref() == Some(&host) { None } else { Some(host) },
            Cmd::SelectRun(host, at) => {
                self.open_host = Some(host.clone());
                self.selected_run = if self.selected_run.as_ref() == Some(&(host.clone(), at)) { None } else { Some((host, at)) };
            }
            Cmd::OpenHost(host) => {
                self.selected_run = None;
                self.open_host = if self.open_host.as_ref() == Some(&host) { None } else { Some(host) };
            }
            cmd @ (Cmd::AddCredential | Cmd::EditCredential(_) | Cmd::DeleteCredential(_) | Cmd::ToggleAgentUse) => self.run_vault(cmd, window, cx),
            cmd @ (Cmd::AddTask | Cmd::EditTask(_) | Cmd::DeleteTask(_) | Cmd::RunTask(_) | Cmd::ToggleTask(_) | Cmd::PickPlaybook(_) | Cmd::PickSchedule(_) | Cmd::ToggleTaskSudo) => self.run_tasks(cmd, window, cx),
            Cmd::AuditHost(host) => {
                self.audit_host = host;
                self.page = Page::Audit;
                self.reload_audit(cx);
            }
            Cmd::AuditRange(hours) => {
                self.audit_hours = hours;
                self.reload_audit(cx);
            }
            cmd => self.run_settings(cmd, window, cx),
        }
        cx.notify();
    }

    /// What a confirmation dialog stood before.
    fn run_confirmed(&mut self, cmd: Cmd, window: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            Cmd::RemoveHost(name) => {
                if self.change(cx, |fleet| fleet.remove_host(&name)) { self.say(tf!("已删除 {name}", "Removed {name}"), cx) }
            }
            Cmd::DeleteCredential(name) => {
                if self.change(cx, |fleet| fleet.delete_credential(&name)) { self.say(tf!("已删除凭据 {name}", "Deleted credential {name}"), cx) }
            }
            Cmd::DeleteTask(name) => {
                if self.change(cx, |fleet| fleet.delete_task(&name)) { self.say(tf!("已删除任务 {name}", "Deleted task {name}"), cx) }
            }
            Cmd::RemoveProvider(index) => {
                self.settings.remove_provider(index);
                self.settings_view.selected = 0;
                self.settings_view.sync(&self.settings, cx);
                self.save_settings(cx);
            }
            other => self.run(other, window, cx),
        }
    }

    pub fn dismiss(&mut self, _: &Dismiss, window: &mut Window, cx: &mut Context<Self>) {
        if self.menu.take().is_some() {
        } else if self.modal.is_some() {
            self.close_modal(window, cx);
        } else if self.chat.history.take().is_some() {
        } else if self.chat.busy && self.chat.input.focus_handle(cx).is_focused(window) {
            self.stop_chat(cx);
        }
        cx.notify();
    }

    /// Tab and Shift+Tab: the next or previous text field in the order drawn. While a dialog is
    /// open, focus stays among its fields; the page behind it is drawn too, so steps that land
    /// there are passed over. A dialog without fields keeps focus where it is.
    fn focus_step(&mut self, forward: bool, window: &mut Window, cx: &mut Context<Self>) {
        let step = |window: &mut Window| if forward { window.focus_next() } else { window.focus_prev() };
        let Some(modal) = self.modal.as_ref() else { return step(window) };
        let fields: Vec<FocusHandle> = modal.inputs().into_iter().map(|input| input.focus_handle(cx)).collect();
        if fields.is_empty() { return }
        let start = window.focused(cx);
        // Bounded: a field not drawn this frame is no tab stop, and the order wraps around.
        for _ in 0..256 {
            step(window);
            let now = window.focused(cx);
            if now.as_ref().is_some_and(|now| fields.contains(now)) { return }
            if now.is_none() || now == start { break }
        }
        if let Some(start) = start { window.focus(&start) }
    }

    /// Bring the panel back, unless the assistant's own page is open: there the conversation is on show already.
    pub fn show_chat(&mut self, cx: &mut Context<Self>) {
        self.chat_parked = false;
        if self.settings.chat_hidden && self.page != Page::Assistant {
            self.settings.chat_hidden = false;
            self.save_settings(cx);
        }
    }

    /// Whether a model is set up that the assistant could ask: one with a key.
    pub fn chat_configured(&self) -> bool {
        self.settings.chat_profile().is_some_and(|profile| !profile.key().is_empty())
    }

    /// Whether the assistant's panel is folded away: by choice, or parked until there is a model to talk to.
    pub fn chat_closed(&self) -> bool {
        self.settings.chat_hidden || (self.chat_parked && !self.chat_configured())
    }

    pub fn chat_width(&self) -> f32 {
        if self.settings.chat_width > 0. { self.settings.chat_width } else { 440. }
    }

    fn drag_chat(&mut self, event: &MouseMoveEvent, window: &mut Window, cx: &mut Context<Self>) {
        if event.pressed_button != Some(MouseButton::Left) { return self.end_drag(cx) }
        let width = f32::from(window.viewport_size().width);
        self.settings.chat_width = (width - f32::from(event.position.x)).clamp(340., (width - SIDEBAR_W - 380.).max(340.));
        cx.notify();
    }

    fn end_drag(&mut self, cx: &mut Context<Self>) {
        if self.resizing.take().is_some() { self.save_settings(cx) }
        cx.notify();
    }
}

pub const SIDEBAR_W: f32 = 208.;

fn bind_keys(cx: &mut App) {
    cx.clear_key_bindings();
    crate::input::bind_keys(cx);
    let context = Some("Workspace");
    cx.bind_keys([
        KeyBinding::new("escape", Dismiss, context),
        KeyBinding::new("secondary-j", ToggleAssistant, context),
        KeyBinding::new("secondary-n", NewChat, context),
        KeyBinding::new("secondary-,", ShowSettings, context),
        KeyBinding::new("secondary-r", Refresh, context),
        // A field's own Tab (choosing in a list) comes first; otherwise these move between fields.
        KeyBinding::new("tab", FocusNext, context),
        KeyBinding::new("shift-tab", FocusPrev, context),
    ]);
}

impl Render for Workspace {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let page = match self.page {
            Page::Overview => self.render_overview(window, cx),
            Page::Servers => self.render_servers(window, cx),
            Page::Disk => self.render_disk(window, cx),
            Page::LongJobs => self.render_longrun(window, cx),
            Page::Security => self.render_security(window, cx),
            Page::Tasks => self.render_tasks(window, cx),
            Page::Vault => self.render_vault(window, cx),
            Page::Audit => self.render_audit(window, cx),
            Page::Assistant => self.render_assistant(window, cx),
            Page::Settings => self.render_settings(window, cx),
        };
        // The assistant's page draws the conversation itself: the panel (and its edge) is left out, whatever `chat_hidden` says.
        let chat_shown = !self.chat_closed() && self.page != Page::Assistant;
        let chat = chat_shown.then(|| self.render_chat(window, cx));
        let chat_width = self.chat_width();
        div()
            .id("workspace")
            .key_context("Workspace")
            .track_focus(&self.focus)
            .relative()
            .size_full()
            .bg(Theme::bg_window())
            .font(theme::ui_font())
            .text_size(text_px(13.))
            .line_height(text_px(20.))
            .text_color(Theme::text())
            .on_action(cx.listener(Self::dismiss))
            .on_action(cx.listener(|this, _: &ToggleAssistant, window, cx| this.run(Cmd::ToggleChat, window, cx)))
            .on_action(cx.listener(|this, _: &NewChat, window, cx| this.run(Cmd::NewChat, window, cx)))
            .on_action(cx.listener(|this, _: &ShowSettings, window, cx| this.run(Cmd::SetPage(Page::Settings), window, cx)))
            .on_action(cx.listener(|this, _: &Refresh, window, cx| this.run(Cmd::Refresh, window, cx)))
            .on_action(cx.listener(|this, _: &FocusNext, window, cx| this.focus_step(true, window, cx)))
            .on_action(cx.listener(|this, _: &FocusPrev, window, cx| this.focus_step(false, window, cx)))
            .child(
                div()
                    .flex()
                    .size_full()
                    .child(self.render_sidebar(cx))
                    // The page: one plane from the top of the window to its bottom.
                    .child(div().flex().flex_col().flex_1().min_w_0().h_full().bg(Theme::bg_body()).border_l_1().border_color(Theme::line()).child(ui::title_strip()).child(div().flex().flex_col().flex_1().min_h_0().child(page)))
                    .when_some(chat, |d, chat| {
                        d.child(
                            div()
                                .relative()
                                .flex()
                                .flex_col()
                                .flex_none()
                                .w(px(chat_width))
                                .h_full()
                                .bg(Theme::bg_body())
                                .border_l_1()
                                .border_color(Theme::line())
                                .child(ui::title_strip())
                                .child(div().flex().flex_col().flex_1().min_h_0().child(chat))
                                // The edge between the page and the assistant, to be dragged.
                                .child(div().id("chat-edge").absolute().top_0().left(px(-3.)).w(px(6.)).h_full().cursor_col_resize().on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.resizing = Some(Edge::Chat);
                                    cx.notify();
                                }))),
                        )
                    }),
            )
            .children(self.render_modal(window, cx))
            .children(self.render_menu(cx))
            .children(self.render_toast())
            // While an edge is held, a layer over everything hears the pointer wherever it goes.
            .children(self.resizing.map(|_| {
                div()
                    .id("resize-layer")
                    .absolute()
                    .top_0()
                    .left_0()
                    .size_full()
                    .occlude()
                    .cursor_col_resize()
                    .on_mouse_move(cx.listener(|this, event: &MouseMoveEvent, window, cx| this.drag_chat(event, window, cx)))
                    .on_mouse_up(MouseButton::Left, cx.listener(|this, _, _, cx| this.end_drag(cx)))
            }))
            .children(ui::window_controls(window))
    }
}

impl Workspace {
    /// The navigation: what to look at (the fleet, its servers), what is done regularly, what is managed.
    fn render_sidebar(&self, cx: &mut Context<Self>) -> Div {
        let row = |page: Page, count: Option<usize>, this: &Self, cx: &mut Context<Self>| {
            let active = this.page == page;
            div()
                .id(SharedString::from(format!("nav-{}", page.title())))
                .flex()
                .items_center()
                .gap(px(9.))
                .h(text_px(32.))
                .px(px(10.))
                .rounded(px(7.))
                .cursor_pointer()
                .when(active, |d| d.bg(Theme::pressed()).font_weight(FontWeight::MEDIUM))
                .hover(|s| s.bg(Theme::hover()))
                .on_click(this.on(Cmd::SetPage(page), cx))
                .child(ui::icon(page.icon(), 15., if active { Theme::accent() } else { Theme::text_secondary() }))
                .child(div().flex_1().min_w_0().truncate().child(t(page.title())))
                // A number only where something waits to be looked at; red is for trouble, and long tasks are mostly not that.
                .when_some(count.filter(|count| *count > 0), |d, count| d.child(div().flex_none().text_size(text_px(12.)).text_color(if page == Page::LongJobs { Theme::text_tertiary() } else { Theme::danger() }).child(count.to_string())))
        };
        let troubled = self.view.hosts.iter().filter(|host| matches!(host.state(), "crit" | "unreachable")).count();
        let long = self.long_jobs_shown().iter().map(|(_, jobs)| jobs.len()).sum();
        let attacked = self.view.attacks.values().filter(|row| crate::security::worst(row) == "crit").count();
        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(SIDEBAR_W))
            .h_full()
            .child(ui::title_strip())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .px(px(10.))
                    .pb(px(10.))
                    .gap(px(2.))
                    .child(div().flex().items_center().gap(px(8.)).h(ui::head_h()).px(px(8.)).child(div().flex().flex_none().items_center().justify_center().size(px(26.)).rounded(px(7.)).bg(Theme::accent()).child(ui::icon("scan-text", 15., Theme::on_accent()))).child(div().flex().flex_col().min_w_0().child(div().text_size(text_px(14.)).font_weight(FontWeight::SEMIBOLD).child("WispOps")).child(div().truncate().text_size(text_px(11.)).line_height(text_px(14.)).text_color(Theme::text_tertiary()).child(tf!("{} 台服务器", "{} servers", self.view.hosts.len())))))
                    .child(row(Page::Overview, Some(troubled), self, cx))
                    .child(row(Page::Servers, None, self, cx))
                    .child(div().h(px(10.)))
                    .child(row(Page::Disk, None, self, cx))
                    .child(row(Page::LongJobs, Some(long), self, cx))
                    .child(row(Page::Security, Some(attacked), self, cx))
                    .child(div().h(px(10.)))
                    .child(row(Page::Tasks, None, self, cx))
                    .child(row(Page::Audit, None, self, cx))
                    .child(div().h(px(10.)))
                    .child(row(Page::Assistant, None, self, cx))
                    .child(div().flex_1())
                    .child(div().h(px(1.)).mx(px(6.)).my(px(6.)).bg(Theme::line()))
                    .child(row(Page::Vault, None, self, cx))
                    .child(row(Page::Settings, None, self, cx)),
            )
    }

    fn render_menu(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let menu = self.menu.as_ref()?;
        let mut rows: Vec<AnyElement> = vec![];
        for (i, item) in menu.items.iter().enumerate() {
            if menu.breaks.contains(&i) { rows.push(div().flex_none().h(px(1.)).mx(px(6.)).my(px(4.)).bg(Theme::line()).into_any_element()) }
            rows.push(ui::menu_row(("menu", i), item.label.clone(), item.checked, item.note.clone()).on_click(self.on(item.cmd.clone(), cx)).into_any_element());
        }
        let at = menu.at;
        let close = |this: &mut Self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<Self>| {
            this.menu = None;
            cx.notify();
        };
        Some(
            div()
                .id("menu-layer")
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .occlude()
                .on_mouse_down(MouseButton::Left, cx.listener(close))
                .on_mouse_down(MouseButton::Right, cx.listener(close))
                .child(anchored().position(at).snap_to_window_with_margin(px(8.)).child(ui::popover().id("menu").max_h(px(520.)).overflow_y_scroll().on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation()).children(rows)))
                .into_any_element(),
        )
    }

    fn render_toast(&self) -> Option<AnyElement> {
        let toast = self.toast.as_ref()?;
        let (mark, color) = if toast.error { ("x", Theme::danger()) } else { ("check", Theme::success()) };
        Some(
            div()
                .absolute()
                .top(px(18.))
                .left_0()
                .w_full()
                .flex()
                .justify_center()
                .child(div().flex().items_center().gap(px(8.)).max_w(px(640.)).px(px(14.)).py(px(9.)).rounded(px(10.)).bg(Theme::bg_body()).border_1().border_color(Theme::line()).shadow(theme::shadow_panel()).child(ui::icon(mark, 14., color)).child(div().min_w_0().child(toast.message.clone())))
                .into_any_element(),
        )
    }

    /// A page's header: its title, a line of what it is, and its actions at the right.
    /// With the assistant folded away, the way back to it stands last, where its panel's head was.
    pub fn page_head(&self, title: &str, about: impl Into<SharedString>, actions: Vec<AnyElement>, cx: &mut Context<Self>) -> Div {
        ui::column_head()
            .px(px(24.))
            .gap(px(8.))
            .child(div().flex().flex_col().flex_1().min_w_0().child(div().truncate().text_size(text_px(ui::HEAD_TITLE)).font_weight(FontWeight::SEMIBOLD).child(title.to_string())).child(div().truncate().text_size(text_px(12.)).line_height(text_px(17.)).text_color(Theme::text_tertiary()).child(about.into())))
            .children(actions)
            .when(self.chat_closed() && self.page != Page::Assistant, |d| d.child(ui::ghost_button("open-assistant", Some("message-square"), Some(t("助手").into())).tooltip(ui::tip(t("打开助手"))).on_click(self.on(Cmd::FocusChat, cx))))
    }
}

/// Debug builds only: `WISP_OPS_DEV=page:servers,3@shot:/tmp/a.png` puts the
/// window into a state at start and writes it to a picture, for looking at it
/// while developing without the screen.
#[cfg(debug_assertions)]
impl Workspace {
    pub fn dev_start(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Ok(steps) = std::env::var("WISP_OPS_DEV") else { return };
        for step in steps.split(',') {
            match step.split_once('@').and_then(|(seconds, later)| Some((seconds.parse::<u64>().ok()?, later.to_string()))) {
                Some((seconds, later)) => {
                    cx.spawn_in(window, async move |this, cx| {
                        cx.background_executor().timer(std::time::Duration::from_secs(seconds)).await;
                        this.update_in(cx, |this, window, cx| this.dev_step(&later, window, cx)).ok();
                    })
                    .detach();
                }
                None => self.dev_step(step, window, cx),
            }
        }
    }

    fn dev_step(&mut self, step: &str, window: &mut Window, cx: &mut Context<Self>) {
        let (name, arg) = step.split_once(':').unwrap_or((step, ""));
        match name {
            "page" => {
                let page = match arg {
                    "servers" => Page::Servers,
                    "disk" => Page::Disk,
                    "jobs" => Page::LongJobs,
                    "security" => Page::Security,
                    "tasks" => Page::Tasks,
                    "vault" => Page::Vault,
                    "audit" => Page::Audit,
                    "assistant" => Page::Assistant,
                    "settings" => Page::Settings,
                    _ => Page::Overview,
                };
                self.run(Cmd::SetPage(page), window, cx);
            }
            "host" => self.run(Cmd::SelectHost(Some(arg.to_string())), window, cx),
            "open" => self.run(Cmd::OpenHost(arg.to_string()), window, cx),
            "chat" => self.settings.chat_hidden = arg == "off",
            "dark" => {
                self.settings.appearance = "dark".into();
                self.apply_appearance(window);
            }
            "en" => crate::i18n::set_language(Language::En),
            "ask" => self.run(Cmd::Suggest(arg.replace('+', " ")), window, cx),
            "type" => self.run(Cmd::Draft(arg.replace('+', " ")), window, cx),
            // A key as the keyboard sends it, to the focused element: `key:tab`, `key:shift-tab`.
            "key" => match Keystroke::parse(arg) {
                // Deferred: the key reaches this workspace, which is being updated now.
                Ok(keystroke) => window.defer(cx, move |window, cx| _ = window.dispatch_keystroke(keystroke, cx)),
                Err(_) => eprintln!("dev: not a key {arg}"),
            },
            "assistant" => self.run(Cmd::FocusChat, window, cx),
            "toggle-chat" => self.run(Cmd::ToggleChat, window, cx),
            "host-menu" => self.open_menu(MenuKind::HostActions(arg.to_string()), point(px(520.), px(260.)), cx),
            "consent" => self.run(Cmd::AnswerTools(match arg { "deny" => Consent::Deny, "grant" => Consent::Grant, "full" => Consent::Full, _ => Consent::Once }), window, cx),
            "inspect" => self.run(Cmd::InspectHosts(arg.to_string()), window, cx),
            "disk-host" => self.run(Cmd::DiskHost(arg.to_string()), window, cx),
            "disk-scan" => {
                let (host, scope) = arg.split_once('/').unwrap_or((arg, "home"));
                self.run(Cmd::DiskScan(host.to_string(), match scope { "full" => crate::scans::Scope::Full, "again" => crate::scans::Scope::Again, _ => crate::scans::Scope::Home }), window, cx);
            }
            "zoom" => self.run(Cmd::DiskZoom(arg.to_string()), window, cx),
            "disk-list" => self.run(Cmd::DiskList(arg != "map"), window, cx),
            "long-check" => self.run(Cmd::CheckLongJobs(arg.to_string()), window, cx),
            // `long-fold:<host>`, or `long-fold:all` / `long-fold:none`.
            "long-fold" => self.run(match arg { "all" => Cmd::FoldLongHosts(true), "none" => Cmd::FoldLongHosts(false), host => Cmd::ToggleLongHost(host.to_string()) }, window, cx),
            // `long-filter:<host>=<words, + for spaces>`; `long-user:<host>=<user>`.
            "long-filter" | "long-user" => {
                let (host, text) = arg.split_once('=').unwrap_or((arg, ""));
                let (host, text) = (host.to_string(), text.replace('+', " "));
                self.run(if name == "long-user" { Cmd::LongUser(host, text) } else { Cmd::LongFilter(host, text) }, window, cx);
            }
            "attack-scan" => self.run(Cmd::ScanAttacks(arg.to_string()), window, cx),
            "open-attack" => self.run(Cmd::OpenAttack(arg.to_string()), window, cx),
            "add-host" => self.run(Cmd::AddHost, window, cx),
            // The import dialog, a tick on its nth row, and a capability probe: `import`, `toggle-import:0`, `probe:all`.
            "import" => self.run(Cmd::ImportSshConfig, window, cx),
            "toggle-import" => self.run(Cmd::ToggleImport(arg.parse().unwrap_or(0)), window, cx),
            "probe" => self.run(Cmd::ProbeHost(arg.to_string()), window, cx),
            "add-task" => self.run(Cmd::AddTask, window, cx),
            "schedule" => self.run(Cmd::PickSchedule(match arg { "cron" => "cron", "every" => "every", "manual" => "manual", _ => "daily" }), window, cx),
            "cron" => {
                if let Some(Modal::Task(form)) = self.modal.as_ref() { form.cron.clone().update(cx, |input, cx| input.set_text(&arg.replace('+', " "), cx)) }
            }
            "add-credential" => self.run(Cmd::AddCredential, window, cx),
            "policy" => self.run(Cmd::EditPolicy(arg.to_string()), window, cx),
            // The credential dialog of a server: `bind:web-01` for its login, `bind-sudo:web-01`; `bind-new` writes a new one.
            "bind" | "bind-sudo" => self.run(Cmd::BindCredential(arg.to_string(), name == "bind-sudo"), window, cx),
            "bind-new" => self.run(Cmd::BindNewCredential, window, cx),
            // The dialog's button: Enter in a field needs the window to be the active one.
            "submit" => self.run(Cmd::SubmitModal, window, cx),
            "history" => self.run(Cmd::ToggleHistory, window, cx),
            "find-chat" => self.chat.search.update(cx, |input, cx| input.set_text(&arg.replace('+', " "), cx)),
            "open-chat" => self.run(Cmd::OpenChat(arg.to_string()), window, cx),
            "tab" => self.run(Cmd::SetSettingsTab(match arg { "general" => crate::settings::Tab::General, "skills" => crate::settings::Tab::Skills, _ => crate::settings::Tab::Models }), window, cx),
            "shot" => {
                let path = PathBuf::from(arg);
                window.defer(cx, move |window, cx| {
                    let Some((width, height, mut pixels)) = window.render_offscreen(cx) else { return eprintln!("shot: this platform cannot render off the screen") };
                    for pixel in pixels.as_chunks_mut::<4>().0 {
                        pixel.swap(0, 2);
                    }
                    match image::RgbaImage::from_raw(width as u32, height as u32, pixels).map(|picture| picture.save(&path)) {
                        Some(Ok(())) => eprintln!("shot: {}", path.display()),
                        other => eprintln!("shot: not written ({other:?})"),
                    }
                });
            }
            "quit" => cx.quit(),
            other => eprintln!("dev: unknown step {other}"),
        }
        cx.notify();
    }
}
