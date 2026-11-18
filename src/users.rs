//! 用户: the accounts on each server. Reading them needs no root (the password states do: then
//! the window reads as root wherever it may). From here accounts are created, on one server or
//! on many at once, and given a new password; both need root, are settled by each server's
//! policy (`Fleet::create_accounts`, `Fleet::reset_account_password`) and are written in the
//! audit without any password. A password the window makes up is shown once, after the run.

use crate::app::{Cmd, Page, Workspace};
use crate::dialogs::{Modal, segmented};
use crate::i18n::t;
use crate::input::TextInput;
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use std::collections::HashSet;
use std::collections::HashMap;
use wisp_ops_collect::accounts::{Account, AccountsReport, AccountsSnapshot, PasswordState};
use wisp_ops_collect::logins::{FailTotal, LOG_DAYS, LogSource, LoginSession, LoginSource, SessionEnd};
use wisp_ops_collect::quotas::{QuotaReport, QuotaState, QuotaUse};
use wisp_ops_collect::sections::format_kb;
use wisp_ops_core::time;
use wisp_ops_engine::accounts::{self as change, NewAccounts, NewPassword, Outcome};

/// The width of the list of servers at the left.
const HOSTS_W: f32 = 210.;
/// The most accounts a server's table draws; the filter finds the rest.
const MAX_ROWS: usize = 300;

/// What the page holds besides what `View` has.
pub struct UsersState {
    pub host: Option<String>,
    /// The account on show, with its logins and quotas, instead of the list.
    pub account: Option<String>,
    /// System accounts (below `UID_MIN`) are listed too.
    pub show_system: bool,
    pub filter: Entity<TextInput>,
    /// The servers being read, and those being changed, right now.
    pub reading: HashSet<String>,
    pub changing: HashSet<String>,
}

impl UsersState {
    pub fn new(cx: &mut App) -> (UsersState, Entity<TextInput>) {
        let filter = cx.new(|cx| TextInput::new("按用户名、姓名或组筛选", cx));
        (UsersState { host: None, account: None, show_system: false, filter: filter.clone(), reading: HashSet::new(), changing: HashSet::new() }, filter)
    }
}

/// Accounts to be created, as the dialog holds them.
pub struct NewUsersForm {
    pub targets: Entity<TextInput>,
    pub names: Entity<TextInput>,
    pub groups: Entity<TextInput>,
    pub shell: Entity<TextInput>,
    /// `random`, `same` or `locked`.
    pub password_mode: &'static str,
    pub password: Entity<TextInput>,
    pub expire: bool,
}

impl NewUsersForm {
    pub fn inputs(&self) -> Vec<&Entity<TextInput>> {
        let NewUsersForm { targets, names, groups, shell, password_mode, password, expire: _ } = self;
        let mut fields = vec![names, targets, groups, shell];
        if *password_mode == "same" { fields.push(password) }
        fields
    }
}

/// A new password for one account.
pub struct ResetForm {
    pub host: String,
    pub account: String,
    /// `random` or `written`.
    pub mode: &'static str,
    pub password: Entity<TextInput>,
    pub again: Entity<TextInput>,
    pub expire: bool,
}

impl ResetForm {
    pub fn inputs(&self) -> Vec<&Entity<TextInput>> {
        let ResetForm { host: _, account: _, mode, password, again, expire: _ } = self;
        if *mode == "written" { vec![password, again] } else { vec![] }
    }
}

/// Whether an account answers the filter: each word, case aside, is in its name, its full name or one of its groups.
pub fn account_matches(account: &Account, filter: &str) -> bool {
    filter.split_whitespace().all(|word| {
        let word = word.to_lowercase();
        account.name.to_lowercase().contains(&word) || account.gecos.to_lowercase().contains(&word) || account.primary_group.to_lowercase() == word || account.groups.iter().any(|group| group.to_lowercase() == word)
    })
}

/// The state of a password in words, and the colour of its chip.
fn password_chip(account: &Account) -> Option<(&'static str, &'static str)> {
    match account.password {
        PasswordState::Set if account.changed_day == Some(0) => Some(("info", "须改密码")),
        PasswordState::Set => Some(("ok", "已设置")),
        PasswordState::Locked => Some(("warn", "已锁定")),
        PasswordState::None => Some(("", "无密码")),
        PasswordState::Empty => Some(("crit", "空密码")),
        PasswordState::Unknown => None,
    }
}

/// Today as days since 1970, as `shadow` counts.
fn today() -> i64 {
    time::now_millis() as i64 / 86_400_000
}

/// Where a login came from: an address, or this machine itself.
pub fn place(from: &str) -> String {
    if from.is_empty() { t("本机").to_string() } else { from.to_string() }
}

/// How sshd let someone in (or not), in words.
pub fn method_words(method: &str) -> String {
    match method {
        "password" => t("密码").to_string(),
        "publickey" => t("公钥").to_string(),
        "keyboard-interactive" => t("键盘交互").to_string(),
        "hostbased" => t("主机认证").to_string(),
        "none" => t("无认证").to_string(),
        "gssapi-with-mic" | "gssapi-keyex" => "GSSAPI".to_string(),
        "" => "—".to_string(),
        other => other.to_string(),
    }
}

/// A length of time in words: minutes, hours and minutes, or days and hours.
pub fn span_words(millis: i64) -> String {
    let minutes = millis.max(0) / 60_000;
    match minutes {
        0 => t("不到 1 分钟").to_string(),
        1..60 => tf!("{minutes} 分钟", "{minutes} min"),
        60..1440 => tf!("{} 小时 {} 分", "{} h {} min", minutes / 60, minutes % 60),
        _ => tf!("{} 天 {} 小时", "{} d {} h", minutes / 1440, minutes % 1440 / 60),
    }
}

/// How long a session lasted, or how it ended.
pub fn session_words(session: &LoginSession) -> String {
    match &session.end {
        SessionEnd::Open => t("仍在线").to_string(),
        SessionEnd::At(end) => span_words(time::millis(end) - time::millis(&session.start)),
        SessionEnd::Crash => t("系统崩溃时中断").to_string(),
        SessionEnd::Down => t("关机时中断").to_string(),
        SessionEnd::Gone => t("没有登出记录").to_string(),
    }
}

/// Use against its limit: `8.0G / 12G`, or the use alone without one.
pub fn quota_words(row: &QuotaUse) -> String {
    match row.limit_kb() {
        Some(limit) => format!("{} / {}", format_kb(row.used_kb as f64), format_kb(limit as f64)),
        None => format_kb(row.used_kb as f64),
    }
}

/// How a quota stands, as a chip: full, over the soft limit, nearly full.
fn quota_chip(row: &QuotaUse) -> Option<(&'static str, &'static str)> {
    if row.at_hard() { Some(("crit", "已满")) } else if row.over_soft() { Some(("warn", "超出软限制")) } else if row.ratio().is_some_and(|ratio| ratio >= 0.9) { Some(("warn", "将满")) } else { None }
}

/// Files used against their limit.
fn files_words(row: &QuotaUse) -> String {
    match [row.files_hard, row.files_soft].into_iter().find(|limit| *limit > 0) {
        Some(limit) => format!("{} / {limit}", row.files),
        None => row.files.to_string(),
    }
}

/// The SSH logins of a server in a line: how many came in, how many failed, and the tries at names that do not exist.
pub fn login_summary(report: &AccountsReport) -> String {
    let logins = &report.logins;
    let known = |name: &str| report.accounts.iter().any(|account| account.name == name);
    let since = match (logins.log, logins.log_since.as_deref()) {
        (LogSource::Journal, _) => tf!("近 {} 天", "In the last {} days", LOG_DAYS),
        (_, Some(at)) => tf!("自 {} 起", "Since {}", time::date_text(at)),
        _ => t("日志里").to_string(),
    };
    let mut words = match logins.log {
        LogSource::None if !report.as_root => return t("SSH 登录日志要以 root 读取：现在只有 wtmp 里的登录时间和地址").to_string(),
        LogSource::None => return t("没有找到 SSH 登录日志（journal、auth.log、secure 和 btmp 都没有记录）").to_string(),
        LogSource::Btmp => {
            let failed: u64 = logins.fail_totals.iter().filter(|row| known(&row.user)).map(|row| row.count).sum();
            tf!("{since}失败的登录 {failed} 次（来自 btmp，没有成功登录的记录）", "{since}: {failed} failed logins (from btmp, which keeps no successful ones)")
        }
        _ => {
            let accepted: u64 = logins.accepted.iter().map(|row| row.count).sum();
            let failed: u64 = logins.fail_totals.iter().filter(|row| !row.invalid && known(&row.user)).map(|row| row.count).sum();
            tf!("{since} SSH 登录成功 {accepted} 次，失败 {failed} 次", "{since}: {accepted} SSH logins, {failed} failed")
        }
    };
    let (unknown, names) = logins.unknown_names(&known);
    if unknown > 0 {
        let names: Vec<&str> = names.iter().take(5).map(|row| row.user.as_str()).collect();
        words.push_str(&tf!("；另有 {unknown} 次试的是不存在的账号（{}）", "; {unknown} more tried accounts that do not exist ({})", names.join("、")));
    }
    words
}

/// The disk quotas of a server in a line: which filesystems have them and whether the use could be read.
pub fn quota_summary(report: &AccountsReport) -> Option<String> {
    let quotas: &QuotaReport = &report.quotas;
    if quotas.filesystems.is_empty() { return None }
    let filesystems: Vec<String> = quotas.filesystems.iter().map(|fs| tf!("{}（{}）", "{} ({})", fs.mount, t(match fs.state { QuotaState::On => "已开启", QuotaState::Off => "未开启", QuotaState::Unknown => "挂载选项里有" }))).collect();
    let mut words = tf!("磁盘配额：{}", "Disk quotas: {}", filesystems.join("、"));
    if !quotas.tools {
        words.push_str(t("；没有安装 quota 工具（repquota），读不到用量"));
    } else if quotas.any_on() && !quotas.read {
        words.push_str(if report.as_root { t("；repquota 没有读到用量") } else { t("；用量要以 root 读取") });
    }
    Some(words)
}

/// What became of one account, in words.
fn outcome_words(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Created => t("已创建").to_string(),
        Outcome::Exists => t("已存在，未改动").to_string(),
        Outcome::NoPassword(why) => tf!("已创建，但密码没有设上（账号是锁定的）：{why}", "Created, but the password did not take (the account is locked): {why}"),
        Outcome::Reset => t("已重置").to_string(),
        Outcome::Missing => t("没有这个账号").to_string(),
        Outcome::Failed(why) => tf!("失败：{why}", "Failed: {why}"),
    }
}

/// What a creation did, to read and copy: by server, each account and the password made up for it.
pub fn creation_report(outcomes: &[crate::accounts::HostOutcome]) -> String {
    let mut lines = vec![];
    let shown = outcomes.iter().any(|host| host.accounts.iter().any(|(_, _, password)| password.is_some()));
    if shown { lines.push(t("随机密码只显示这一次：关闭前复制下来，分别交给各人。").to_string()); lines.push(String::new()) }
    let width = outcomes.iter().flat_map(|host| host.accounts.iter().map(|(name, ..)| name.chars().count())).max().unwrap_or(0);
    for host in outcomes {
        lines.push(host.host.clone());
        if let Some(error) = &host.error { lines.push(format!("  {}", tf!("没有执行：{error}", "Not done: {error}"))) }
        for (name, outcome, password) in &host.accounts {
            let pad = " ".repeat(width.saturating_sub(name.chars().count()));
            match password {
                Some(password) => lines.push(format!("  {name}{pad}  {}  {password}", outcome_words(outcome))),
                None => lines.push(format!("  {name}{pad}  {}", outcome_words(outcome))),
            }
        }
        lines.push(String::new());
    }
    lines.join("\n").trim_end().to_string()
}

/// A section of the account view: a title and a note, then a table of rows (a column of `None`
/// width takes what is left), then a line under it. Without rows or a line, the note says it all.
fn account_table(id: &'static str, title: &str, note: String, columns: &[(&str, Option<f32>)], rows: Vec<Vec<AnyElement>>, footer: Option<String>) -> AnyElement {
    let cell = |width: Option<f32>| match width {
        Some(width) => div().w(px(width)).flex_none().min_w_0(),
        None => div().flex_1().min_w(px(120.)),
    };
    let head = div().flex().items_center().gap(px(10.)).h(text_px(24.)).px(px(10.)).text_size(text_px(11.)).text_color(Theme::text_tertiary()).children(columns.iter().map(|(label, width)| cell(*width).child(label.to_string())));
    let empty = rows.is_empty();
    let lines = rows.into_iter().map(|cells| div().flex().items_center().gap(px(10.)).h(text_px(30.)).px(px(10.)).rounded(px(6.)).text_size(text_px(12.)).hover(|s| s.bg(Theme::hover())).children(cells.into_iter().zip(columns.iter()).map(|(content, (_, width))| cell(*width).child(content))));
    div()
        .id(id)
        .flex()
        .flex_col()
        .gap(px(6.))
        .pt(px(4.))
        .child(ui::panel_head(title.to_string(), note))
        .when(!empty || footer.is_some(), |d| {
            d.child(
                div()
                    .flex()
                    .flex_col()
                    .rounded(px(10.))
                    .border_1()
                    .border_color(Theme::line())
                    .p(px(6.))
                    .when(!empty, |d| d.child(head).children(lines))
                    .children(footer.map(|text| div().px(px(10.)).py(px(6.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(text))),
            )
        })
        .into_any_element()
}

impl Workspace {
    /// The page is entered: a server is on show, the selected one if there is one.
    pub fn enter_users(&mut self) {
        if self.users.host.as_ref().is_none_or(|name| !self.view.hosts.iter().any(|host| &host.name == name)) {
            self.users.host = self.selected_host.clone().or_else(|| self.view.hosts.first().map(|host| host.name.clone()));
        }
    }

    pub fn run_users(&mut self, cmd: Cmd, window: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            Cmd::UsersHost(name) => {
                if self.users.host.as_ref() != Some(&name) { self.users.account = None }
                self.users.host = Some(name);
                self.users.filter.update(cx, |input, cx| input.set_text("", cx));
            }
            Cmd::UsersAccount(account) => {
                self.users.account = account;
                self.page_scroll.set_offset(point(px(0.), px(0.)));
            }
            Cmd::UsersSystem => self.users.show_system = !self.users.show_system,
            Cmd::ReadAccounts(selector) => self.read_accounts(selector, false, cx),
            Cmd::NewUsers => {
                let targets = self.users.host.clone().unwrap_or_default();
                let form = NewUsersForm {
                    names: self.modal_input("每行一个用户名，也可以用空格或逗号隔开", "", true, cx),
                    targets: self.modal_input("服务器名或选择器，如 gpu-01、@gpu、all", &targets, false, cx),
                    groups: self.modal_input("可选，如 docker,video", "", false, cx),
                    shell: self.modal_input("/bin/bash", "/bin/bash", false, cx),
                    password_mode: "random",
                    password: self.modal_input("所有新账号的初始密码", "", false, cx),
                    expire: true,
                };
                form.password.update(cx, |input, _| input.masked = true);
                self.open_modal(Modal::NewUsers(form), cx);
            }
            Cmd::ResetPassword(host, account) => {
                let form = ResetForm { host, account, mode: "random", password: self.modal_input("新密码", "", false, cx), again: self.modal_input("再输入一次", "", false, cx), expire: false };
                for input in [&form.password, &form.again] { input.update(cx, |input, _| input.masked = true) }
                self.open_modal(Modal::ResetPassword(form), cx);
            }
            Cmd::UsersPasswordMode(mode) => {
                match &mut self.modal {
                    Some(Modal::NewUsers(form)) => form.password_mode = mode,
                    Some(Modal::ResetPassword(form)) => form.mode = mode,
                    _ => {}
                }
                self.modal_error.clear();
                // A field that appears takes the caret.
                let input = match &self.modal {
                    Some(Modal::NewUsers(form)) if mode == "same" => Some(form.password.clone()),
                    Some(Modal::ResetPassword(form)) if mode == "written" => Some(form.password.clone()),
                    _ => None,
                };
                if let Some(input) = input { input.update(cx, |input, _| input.focus(window)) }
            }
            Cmd::UsersExpire => match &mut self.modal {
                Some(Modal::NewUsers(form)) => form.expire = !form.expire,
                Some(Modal::ResetPassword(form)) => form.expire = !form.expire,
                _ => {}
            },
            _ => {}
        }
        cx.notify();
    }

    /// Read the accounts of the selected servers off the main thread. `timed` is the page's
    /// automatic reading: it says nothing when done.
    pub fn read_accounts(&mut self, selector: String, timed: bool, cx: &mut Context<Self>) {
        let names: Vec<String> = match self.fleet.select_names(&selector) {
            Ok(names) => names.into_iter().filter(|name| !self.users.reading.contains(name)).collect(),
            Err(error) => return if !timed { self.fail(error, cx) },
        };
        if names.is_empty() { return }
        self.users.reading.extend(names.iter().cloned());
        let (fleet, selector) = (self.fleet.clone(), names.join(","));
        let work = cx.background_executor().spawn(async move { fleet.read_accounts(&selector, timed) });
        cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                for name in &names { this.users.reading.remove(name); }
                this.reload(cx);
                match result {
                    _ if timed => {}
                    Ok(words) => this.say(words, cx),
                    Err(error) => this.fail(error, cx),
                }
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// The dialog's button: check what is written, then run it off the main thread. The dialog
    /// closes at once; what came of it opens in its place (with the passwords made up, if any).
    pub fn submit_users(&mut self, cx: &mut Context<Self>) -> Result<(), String> {
        let text = |input: &Entity<TextInput>, cx: &App| input.read(cx).text().trim().to_string();
        match &self.modal {
            Some(Modal::NewUsers(form)) => {
                let names = change::parse_names(&text(&form.names, cx))?;
                if names.is_empty() { return Err(t("写上要创建的用户名。").into()) }
                let selector = text(&form.targets, cx);
                if selector.is_empty() { return Err(t("写上在哪些服务器上创建。").into()) }
                let hosts = self.fleet.select_names(&selector)?;
                let groups = change::parse_names(&text(&form.groups, cx).replace(',', " "))?;
                let shell = text(&form.shell, cx);
                if let Some(problem) = change::shell_problem(&shell) { return Err(problem) }
                let password = match form.password_mode {
                    "same" => {
                        let written = form.password.read(cx).text().to_string();
                        if let Some(problem) = change::password_problem(&written) { return Err(problem) }
                        NewPassword::Same(written)
                    }
                    "locked" => NewPassword::Locked,
                    _ => NewPassword::Random,
                };
                let spec = NewAccounts { names, groups, shell, expire: form.expire && password != NewPassword::Locked };
                self.users.changing.extend(hosts.iter().cloned());
                let fleet = self.fleet.clone();
                let work = cx.background_executor().spawn(async move { fleet.create_accounts(&selector, &spec, &password) });
                cx.spawn(async move |this, cx| {
                    let result = work.await;
                    this.update(cx, |this, cx| {
                        for name in &hosts { this.users.changing.remove(name); }
                        this.reload(cx);
                        match result {
                            Ok(outcomes) => {
                                let created: usize = outcomes.iter().map(|host| host.accounts.iter().filter(|(_, outcome, _)| matches!(outcome, Outcome::Created | Outcome::NoPassword(_))).count()).sum();
                                let text = creation_report(&outcomes);
                                this.open_modal(Modal::Text { title: tf!("创建了 {created} 个账号", "Created {created} accounts"), text, scroll: ScrollHandle::new() }, cx);
                            }
                            Err(error) => this.fail(error, cx),
                        }
                    })
                    .ok();
                })
                .detach();
                Ok(())
            }
            Some(Modal::ResetPassword(form)) => {
                let written = if form.mode == "written" {
                    let (password, again) = (form.password.read(cx).text().to_string(), form.again.read(cx).text().to_string());
                    if let Some(problem) = change::password_problem(&password) { return Err(problem) }
                    if password != again { return Err(t("两次输入的密码不一样。").into()) }
                    Some(password)
                } else {
                    None
                };
                let (host, account, expire) = (form.host.clone(), form.account.clone(), form.expire);
                self.users.changing.insert(host.clone());
                let fleet = self.fleet.clone();
                let (on, whose) = (host.clone(), account.clone());
                let work = cx.background_executor().spawn(async move { fleet.reset_account_password(&on, &whose, written, expire) });
                cx.spawn(async move |this, cx| {
                    let result = work.await;
                    this.update(cx, |this, cx| {
                        this.users.changing.remove(&host);
                        this.reload(cx);
                        match result {
                            Ok(Some(password)) => {
                                let text = tf!("{account}@{host} 的新密码：\n\n    {password}\n\n只显示这一次：关闭前复制下来交给本人。", "The new password of {account}@{host}:\n\n    {password}\n\nShown this once: copy it before closing and pass it on.");
                                this.open_modal(Modal::Text { title: tf!("已重置 {account} 的密码", "Reset the password of {account}"), text, scroll: ScrollHandle::new() }, cx);
                            }
                            Ok(None) => this.say(tf!("已重置 {account}@{host} 的密码", "Reset the password of {account}@{host}"), cx),
                            Err(error) => this.fail(error, cx),
                        }
                    })
                    .ok();
                })
                .detach();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    // ---- drawing

    pub fn render_users(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let busy = !self.users.reading.is_empty();
        let actions = vec![
            ui::ghost_button("users-system", Some("eye"), Some(if self.users.show_system { t("隐藏系统账号") } else { t("显示系统账号") }.into())).on_click(self.on(Cmd::UsersSystem, cx)).into_any_element(),
            ui::ghost_button("users-auto", Some("history"), Some(tf!("自动巡检：{}", "Auto inspection: {}", crate::settings::interval_label(self.settings.auto_accounts_minutes)).into())).on_click(self.on_menu(crate::app::MenuKind::AutoAccounts, cx)).into_any_element(),
            ui::secondary_button("users-new", t("批量创建用户")).child(ui::icon("plus", 13., Theme::text_secondary())).on_click(self.on(Cmd::NewUsers, cx)).into_any_element(),
            ui::primary_button("users-read-all", if busy { t("正在读取…") } else { t("读取全部") }).when(busy, |b| b.opacity(0.6)).on_click(self.on(Cmd::ReadAccounts("all".into()), cx)).into_any_element(),
        ];
        let head = self.page_head(t("用户"), t("每台服务器上的账号；创建用户和重置密码需要 root，按每台的权限策略执行并记入审计"), actions, cx);
        if self.view.hosts.is_empty() {
            return div().flex().flex_col().size_full().child(head).child(ui::empty_state("users", t("清单里还没有服务器"), t("先在「服务器」里添加，或从 ~/.ssh/config 导入。")).child(ui::primary_button("users-add", t("去添加服务器")).on_click(self.on(Cmd::SetPage(Page::Servers), cx)))).into_any_element();
        }
        let hosts = div().id("users-hosts").flex().flex_col().flex_none().w(px(HOSTS_W)).h_full().overflow_y_scroll().px(px(8.)).py(px(10.)).gap(px(1.)).border_r_1().border_color(Theme::line()).children(self.view.hosts.iter().map(|host| {
            let active = self.users.host.as_ref() == Some(&host.name);
            let snapshot = self.view.accounts.get(&host.name);
            let people = snapshot.map(|row| row.report.accounts.iter().filter(|account| !row.report.system(account)).count());
            let working = self.users.reading.contains(&host.name) || self.users.changing.contains(&host.name);
            div()
                .id(SharedString::from(format!("users-host-{}", host.name)))
                .flex()
                .flex_none()
                .items_center()
                .gap(px(8.))
                .h(text_px(34.))
                .px(px(10.))
                .rounded(px(7.))
                .cursor_pointer()
                .when(active, |d| d.bg(Theme::accent_soft()).font_weight(FontWeight::MEDIUM))
                .hover(|s| s.bg(Theme::hover()))
                .on_click(self.on(Cmd::UsersHost(host.name.clone()), cx))
                .child(if working { ui::spinner(SharedString::from(format!("users-working-{}", host.name)), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(8.)).m(px(2.)).rounded_full().bg(if snapshot.is_some() { Theme::success() } else { Theme::line_strong() }).into_any_element() })
                .child(div().flex_1().min_w_0().truncate().child(host.name.clone()))
                .children(people.map(|count| div().flex_none().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(count.to_string())))
        }));
        let detail = match self.users.host.clone() {
            Some(name) => self.render_users_host(&name, window, cx),
            None => div().into_any_element(),
        };
        div().flex().flex_col().size_full().child(head).child(div().flex().flex_1().min_h_0().child(hosts).child(detail)).into_any_element()
    }

    fn render_users_host(&self, name: &str, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let snapshot: Option<&AccountsSnapshot> = self.view.accounts.get(name);
        let reading = self.users.reading.contains(name);
        let changing = self.users.changing.contains(name);
        let about = match snapshot {
            Some(row) if row.report.shadow_readable => tf!("读取于 {} · 以 root 读取", "Read {} · as root", time::short_time(&row.at)),
            Some(row) => tf!("读取于 {} · 没有以 root 读取，看不到密码状态（在「服务器」里关联 sudo 凭据后重新读取）", "Read {} · not as root, so password states are unknown (link a sudo credential on the Servers page and read again)", time::short_time(&row.at)),
            None => t("还没有读取").to_string(),
        };
        let buttons = div()
            .flex()
            .flex_none()
            .items_center()
            .gap(px(6.))
            .when(reading || changing, |d| d.child(div().flex().items_center().gap(px(6.)).mr(px(6.)).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(ui::spinner("users-busy", 12., Theme::accent())).child(if changing { t("正在修改…") } else { t("正在读取…") })))
            .child(ui::secondary_button("users-create-here", t("创建用户")).h(text_px(28.)).on_click(self.on(Cmd::NewUsers, cx)))
            .when(!reading, |d| d.child(ui::primary_button("users-read", if snapshot.is_some() { t("重新读取") } else { t("读取") }).h(text_px(28.)).on_click(self.on(Cmd::ReadAccounts(name.to_string()), cx))));
        let top = div().flex().flex_col().gap(px(2.)).child(div().flex().items_center().gap(px(12.)).child(div().flex_1().min_w_0().truncate().text_size(text_px(15.)).font_weight(FontWeight::SEMIBOLD).child(name.to_string())).child(buttons)).child(div().text_size(text_px(12.)).line_height(text_px(17.)).text_color(Theme::text_tertiary()).child(about));
        let column = div().id("users-detail").flex().flex_col().flex_1().min_w_0().h_full().overflow_y_scroll().track_scroll(&self.page_scroll).px(px(24.)).py(px(16.)).gap(px(12.)).child(top);
        let Some(row) = snapshot else {
            return column
                .child(ui::empty_state("users", t("还没有读取这台服务器的账号"), t("读取 passwd 和 group（含 LDAP 等目录里的账号）。能以 root 读取时，还会看每个账号的密码状态：只看是否设置、是否锁定，不取密码本身。")).when(!reading, |d| d.child(ui::primary_button("users-first-read", t("读取账号")).on_click(self.on(Cmd::ReadAccounts(name.to_string()), cx)))))
                .into_any_element();
        };
        let report = &row.report;
        if let Some(account) = self.users.account.as_ref().and_then(|wanted| report.accounts.iter().find(|account| &account.name == wanted)) {
            return self.render_account(name, report, account, column, changing, cx);
        }
        let filter = self.users.filter.read(cx).text().trim().to_string();
        let system = report.accounts.iter().filter(|account| report.system(account)).count();
        let online = report.accounts.iter().filter(|account| account.sessions > 0).count();
        let shown: Vec<&Account> = report.accounts.iter().filter(|account| (self.users.show_system || !report.system(account)) && account_matches(account, &filter)).collect();
        let mut summary = vec![tf!("{} 个用户账号", "{} user accounts", report.accounts.len() - system)];
        summary.push(if self.users.show_system { tf!("{system} 个系统账号", "{system} system accounts") } else { tf!("{system} 个系统账号（已隐藏）", "{system} system accounts (hidden)") });
        if online > 0 { summary.push(tf!("{online} 个在线", "{online} signed in")) }
        if report.truncated { summary.push(tf!("账号太多，只读了前 {}", "too many accounts: only the first {} were read", wisp_ops_collect::accounts::MAX_LINES)) }
        // What each account's row needs from the logins, gathered once.
        let mut last_login: HashMap<&str, (&str, &str)> = HashMap::new();
        for (user, at, from) in report.logins.sessions.iter().map(|session| (session.user.as_str(), session.start.as_str(), session.from.as_str())).chain(report.logins.accepted.iter().map(|row| (row.user.as_str(), row.last.as_str(), row.from.as_str()))) {
            let entry = last_login.entry(user).or_insert((at, from));
            if at > entry.0 { *entry = (at, from) }
        }
        let open_from: HashMap<&str, &str> = report.logins.sessions.iter().filter(|session| session.end == SessionEnd::Open).map(|session| (session.user.as_str(), session.from.as_str())).collect();
        let failures: HashMap<&str, &FailTotal> = report.logins.fail_totals.iter().map(|row| (row.user.as_str(), row)).collect();
        let quotas = report.quotas.any_on() || !report.quotas.usage.is_empty();
        let cell = |width: f32| div().w(px(width)).flex_none().min_w_0();
        let columns = div()
            .flex()
            .items_center()
            .gap(px(10.))
            .h(text_px(24.))
            .px(px(10.))
            .text_size(text_px(11.))
            .text_color(Theme::text_tertiary())
            .child(div().flex_1().min_w(px(140.)).child(t("用户")))
            .child(cell(52.).text_right().child("UID"))
            .child(div().flex_1().min_w(px(80.)).child(t("组")))
            .child(cell(74.).child(t("密码")))
            .when(quotas, |d| d.child(cell(120.).child(t("磁盘配额"))))
            .child(cell(170.).child(t("最近登录")))
            .child(cell(54.).child(t("失败")))
            .child(cell(72.));
        let today = today();
        let rows = shown.iter().take(MAX_ROWS).map(|account| {
            let expired = account.expires_day.is_some_and(|day| day > 0 && day <= today);
            let chip = password_chip(account);
            let mut groups = vec![account.primary_group.clone()];
            groups.extend(account.groups.iter().cloned());
            let groups = groups.into_iter().filter(|group| !group.is_empty()).collect::<Vec<_>>().join(", ");
            let tip = format!("{}\nUID {} · GID {}\n{}\n{}", account.name, account.uid, account.gid, account.home, account.shell);
            let login = match (open_from.get(account.name.as_str()), last_login.get(account.name.as_str())) {
                (Some(from), _) => div().flex().items_center().gap(px(6.)).min_w_0().child(ui::status_chip("ok", t("在线"))).child(div().min_w_0().truncate().text_color(Theme::text_secondary()).child(place(from))).into_any_element(),
                (None, Some((at, from))) => div().min_w_0().truncate().text_color(Theme::text_secondary()).child(format!("{} · {}", time::short_time(at), place(from))).into_any_element(),
                (None, None) => div().text_color(Theme::text_placeholder()).child("—").into_any_element(),
            };
            let failed = failures.get(account.name.as_str()).map(|row| row.count).unwrap_or(0);
            let quota = report.quotas.fullest(&account.name);
            div()
                .id(SharedString::from(format!("account-{name}-{}", account.name)))
                .group("account")
                .flex()
                .items_center()
                .gap(px(10.))
                .h(text_px(34.))
                .px(px(10.))
                .rounded(px(6.))
                .text_size(text_px(12.))
                .cursor_pointer()
                .hover(|s| s.bg(Theme::hover()))
                .tooltip(ui::tip(tip))
                .on_click(self.on(Cmd::UsersAccount(Some(account.name.clone())), cx))
                .child(
                    div()
                        .flex()
                        .flex_1()
                        .min_w(px(140.))
                        .items_center()
                        .gap(px(6.))
                        .child(div().flex_none().font_weight(FontWeight::MEDIUM).when(!account.can_log_in(), |d| d.text_color(Theme::text_tertiary())).child(account.name.clone()))
                        .when(account.admin(), |d| d.child(ui::status_chip("info", t("管理员"))))
                        .when(!account.gecos.is_empty() && account.gecos != account.name, |d| d.child(div().min_w_0().truncate().text_color(Theme::text_tertiary()).child(account.gecos.clone()))),
                )
                .child(cell(52.).text_right().font_family(theme::MONO_FONT).text_color(Theme::text_secondary()).child(account.uid.to_string()))
                .child(div().flex_1().min_w(px(80.)).truncate().text_color(Theme::text_secondary()).child(groups))
                .child(cell(74.).child(match (expired, chip) {
                    (true, _) => ui::status_chip("warn", t("已过期")).into_any_element(),
                    (_, Some((state, label))) => ui::status_chip(state, t(label)).into_any_element(),
                    (_, None) => div().text_color(Theme::text_placeholder()).child("—").into_any_element(),
                }))
                .when(quotas, |d| {
                    d.child(cell(120.).child(match quota {
                        Some(row) => match quota_chip(row) {
                            Some((state, _)) => ui::status_chip(state, &quota_words(row)).into_any_element(),
                            None => div().truncate().text_color(Theme::text_secondary()).child(quota_words(row)).into_any_element(),
                        },
                        None => div().text_color(Theme::text_placeholder()).child("—").into_any_element(),
                    }))
                })
                .child(cell(170.).child(login))
                .child(cell(54.).child(if failed > 0 { ui::status_chip(if failed >= 10 { "warn" } else { "" }, &failed.to_string()).into_any_element() } else { div().text_color(Theme::text_placeholder()).child("—").into_any_element() }))
                .child(
                    cell(72.)
                        .flex()
                        .items_center()
                        .justify_end()
                        .gap(px(2.))
                        .child(ui::ghost_button(SharedString::from(format!("account-reset-{name}-{}", account.name)), None, Some(t("重置密码").into())).h(text_px(24.)).text_size(text_px(12.)).opacity(0.).group_hover("account", |s| s.opacity(1.)).when(changing, |b| b.invisible()).on_click(self.on_within(Cmd::ResetPassword(name.to_string(), account.name.clone()), cx)))
                        .child(ui::icon("chevron-right", 13., Theme::text_placeholder())),
                )
        });
        let rows: Vec<Stateful<Div>> = rows.collect();
        let note = |text: String| div().flex().items_start().gap(px(6.)).text_size(text_px(12.)).line_height(text_px(17.)).text_color(Theme::text_tertiary()).child(text);
        column
            .child(div().flex().items_center().gap(px(12.)).child(div().w(px(280.)).child(ui::field(&self.users.filter, window, cx))).child(div().flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(summary.join(" · "))))
            .child(div().flex().flex_col().gap(px(2.)).child(note(login_summary(report))).children(quota_summary(report).map(note)))
            .child(div().flex().flex_col().rounded(px(10.)).border_1().border_color(Theme::line()).p(px(6.)).child(columns).children(rows).when(shown.is_empty(), |d| d.child(div().px(px(10.)).py(px(8.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("没有符合筛选的账号")))))
            .when(shown.len() > MAX_ROWS, |d| d.child(div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("还有 {} 个账号没有列出，用上面的筛选缩小范围", "{} more accounts are not listed: narrow them with the filter above", shown.len() - MAX_ROWS))))
            .into_any_element()
    }

    /// One account: who it is, its disk quotas, its sessions, where it logs in from and the logins that failed.
    fn render_account(&self, host: &str, report: &AccountsReport, account: &Account, column: Stateful<Div>, changing: bool, cx: &mut Context<Self>) -> AnyElement {
        let logins = report.logins.of(&account.name);
        let quotas = report.quotas.of(&account.name);
        let today = today();
        let expired = account.expires_day.is_some_and(|day| day > 0 && day <= today);
        let back = ui::ghost_button("users-back", Some("arrow-left"), Some(t("全部账号").into())).h(text_px(26.)).text_size(text_px(12.)).on_click(self.on(Cmd::UsersAccount(None), cx));
        let mut groups = vec![account.primary_group.clone()];
        groups.extend(account.groups.iter().cloned());
        let groups = groups.into_iter().filter(|group| !group.is_empty()).collect::<Vec<_>>().join(", ");
        let facts = [format!("UID {} · GID {}", account.uid, account.gid), tf!("组 {groups}", "groups {groups}"), tf!("主目录 {}", "home {}", account.home), format!("Shell {}", account.shell)].join(" · ");
        let head = div()
            .flex()
            .items_start()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap(px(4.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(div().text_size(text_px(16.)).font_weight(FontWeight::SEMIBOLD).child(account.name.clone()))
                            .when(account.admin(), |d| d.child(ui::status_chip("info", t("管理员"))))
                            .when(expired, |d| d.child(ui::status_chip("warn", t("已过期"))))
                            .when(!expired, |d| d.children(password_chip(account).map(|(state, label)| ui::status_chip(state, t(label)))))
                            .when(account.sessions > 0, |d| d.child(ui::status_chip("ok", &tf!("在线 {}", "{} signed in", account.sessions))))
                            .when(!account.gecos.is_empty() && account.gecos != account.name, |d| d.child(div().min_w_0().truncate().text_size(text_px(13.)).text_color(Theme::text_tertiary()).child(account.gecos.clone()))),
                    )
                    .child(div().text_size(text_px(12.)).line_height(text_px(17.)).text_color(Theme::text_tertiary()).child(facts)),
            )
            .when(!changing, |d| d.child(ui::secondary_button("account-reset", t("重置密码")).h(text_px(28.)).on_click(self.on(Cmd::ResetPassword(host.to_string(), account.name.clone()), cx))));
        let mut sections: Vec<AnyElement> = vec![];
        // Disk quotas, where the server has them.
        if !report.quotas.filesystems.is_empty() || !quotas.is_empty() {
            let note = match (report.quotas.read, quotas.is_empty()) {
                (_, false) => String::new(),
                (true, true) => t("在开了配额的文件系统上，这个账号没有用量，也没有限额").to_string(),
                (false, true) => quota_summary(report).unwrap_or_default(),
            };
            let rows = quotas
                .iter()
                .map(|row| {
                    let grace = row.grace.or(row.files_grace).and_then(|at| chrono::DateTime::from_timestamp(at, 0)).map(|at| tf!("宽限到 {}", "grace until {}", time::short_time(&at.to_rfc3339())));
                    vec![
                        div().truncate().font_family(theme::MONO_FONT).child(row.mount.clone()).into_any_element(),
                        div().child(format_kb(row.used_kb as f64)).into_any_element(),
                        div().text_color(Theme::text_secondary()).child(if row.soft_kb > 0 { format_kb(row.soft_kb as f64) } else { "—".into() }).into_any_element(),
                        div().text_color(Theme::text_secondary()).child(if row.hard_kb > 0 { format_kb(row.hard_kb as f64) } else { "—".into() }).into_any_element(),
                        div().text_color(Theme::text_secondary()).child(files_words(row)).into_any_element(),
                        match quota_chip(row) {
                            Some((state, label)) => div().flex().items_center().gap(px(6.)).child(ui::status_chip(state, t(label))).children(grace.map(|grace| div().truncate().text_color(Theme::text_tertiary()).child(grace))).into_any_element(),
                            None => div().text_color(Theme::text_placeholder()).child("—").into_any_element(),
                        },
                    ]
                })
                .collect();
            sections.push(account_table("account-quotas", t("磁盘配额"), note, &[(t("文件系统"), None), (t("已用"), Some(80.)), (t("软限制"), Some(80.)), (t("硬限制"), Some(80.)), (t("文件数"), Some(100.)), (t("状态"), Some(200.))], rows, None));
        }
        // Sessions from wtmp.
        const SESSIONS: usize = 30;
        let note = if !report.logins.sessions_read {
            t("读不到 wtmp（没有 last 命令，或它不支持 --time-format）").to_string()
        } else {
            let since = report.logins.sessions_since.as_deref().map(|at| tf!("，wtmp 自 {} 起", " since {}", time::date_text(at))).unwrap_or_default();
            tf!("来自 wtmp：最近 2000 次登录里有 {} 次{since}", "From wtmp: {} of the last 2000 logins{since}", logins.sessions.len())
        };
        let rows = logins
            .sessions
            .iter()
            .take(SESSIONS)
            .map(|session| {
                vec![
                    div().child(time::short_time(&session.start)).into_any_element(),
                    div().truncate().font_family(theme::MONO_FONT).child(place(&session.from)).into_any_element(),
                    div().truncate().text_color(Theme::text_secondary()).child(session.tty.clone()).into_any_element(),
                    if session.end == SessionEnd::Open { div().flex().child(ui::status_chip("ok", t("仍在线"))).into_any_element() } else { div().truncate().text_color(if matches!(session.end, SessionEnd::Crash | SessionEnd::Down) { Theme::warning() } else { Theme::text_secondary() }).child(session_words(session)).into_any_element() },
                ]
            })
            .collect();
        let more = (logins.sessions.len() > SESSIONS).then(|| tf!("只列出最近 {SESSIONS} 次", "Only the latest {SESSIONS} are listed"));
        sections.push(account_table("account-sessions", t("最近登录"), note, &[(t("时间"), Some(110.)), (t("来源"), None), (t("终端"), Some(90.)), (t("时长"), Some(140.))], rows, more));
        // Logins sshd accepted and refused.
        let source = match report.logins.log {
            LogSource::Journal => tf!("来自 journal，近 {} 天", "From the journal, the last {} days", LOG_DAYS),
            LogSource::File => tf!("来自 auth.log / secure{}", "From auth.log / secure{}", report.logins.log_since.as_deref().map(|at| tf!("，自 {} 起", ", since {}", time::date_text(at))).unwrap_or_default()),
            LogSource::Btmp => t("来自 btmp：只记失败，不记方式").to_string(),
            LogSource::None if !report.as_root => t("SSH 登录日志要以 root 读取（在「服务器」里关联 sudo 凭据后重新读取）").to_string(),
            LogSource::None => t("没有找到 SSH 登录日志").to_string(),
        };
        let source_rows = |rows: &[&LoginSource]| -> Vec<Vec<AnyElement>> {
            rows.iter()
                .map(|row| {
                    vec![
                        div().truncate().font_family(theme::MONO_FONT).child(place(&row.from)).into_any_element(),
                        div().text_color(Theme::text_secondary()).child(method_words(&row.method)).into_any_element(),
                        div().child(row.count.to_string()).into_any_element(),
                        div().text_color(Theme::text_secondary()).child(time::short_time(&row.first)).into_any_element(),
                        div().text_color(Theme::text_secondary()).child(time::short_time(&row.last)).into_any_element(),
                    ]
                })
                .collect()
        };
        let source_columns = [(t("来源"), None), (t("方式"), Some(80.)), (t("次数"), Some(50.)), (t("首次"), Some(100.)), (t("最近"), Some(100.))];
        if report.logins.log != LogSource::Btmp {
            let empty = (report.logins.log != LogSource::None && logins.accepted.is_empty()).then(|| t("这段时间里没有成功的 SSH 登录").to_string());
            sections.push(account_table("account-accepted", t("SSH 登录来源"), source.clone(), &source_columns, source_rows(&logins.accepted), empty));
        }
        let failed_note = match logins.failures {
            Some(total) => tf!("{source}：失败 {} 次，来自 {} 个地址，最近一次 {}", "{source}: {} failures from {} addresses, the latest {}", total.count, total.sources, time::short_time(&total.last)),
            None => source,
        };
        let empty = (report.logins.log != LogSource::None && logins.failed.is_empty()).then(|| t("这段时间里没有失败的登录").to_string());
        sections.push(account_table("account-failed", t("失败的登录"), failed_note, &source_columns, source_rows(&logins.failed), empty));
        column.child(div().flex().child(back)).child(head).children(sections).into_any_element()
    }

    /// The dialogs of this page: what they say and their button.
    pub fn users_form_body(&self, modal: &Modal, window: &Window, cx: &mut Context<Self>) -> (String, f32, Div, Option<String>, bool) {
        let field = |label: &str, input: &Entity<TextInput>, window: &Window, cx: &App| ui::form_row(t(label).to_string(), ui::field(input, window, cx));
        let tick = |id: &'static str, on: bool, label: &str, this: &Self, cx: &mut Context<Self>| {
            div().id(id).flex().items_center().gap(px(8.)).cursor_pointer().on_click(this.on(Cmd::UsersExpire, cx)).child(div().flex().flex_none().items_center().justify_center().size(px(16.)).rounded(px(4.)).border_1().border_color(if on { Theme::accent() } else { Theme::line_strong() }).when(on, |d| d.bg(Theme::accent()).child(ui::icon("check", 12., Theme::on_accent())))).child(t(label).to_string())
        };
        let note = |text: &str| div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t(text).to_string());
        let choice = |key: &'static str, label: &str, chosen: &str, this: &Self, cx: &mut Context<Self>| (div().id(SharedString::from(format!("users-password-{key}"))).on_click(this.on(Cmd::UsersPasswordMode(key), cx)).child(t(label).to_string()), chosen == key);
        match modal {
            Modal::NewUsers(form) => {
                let count = change::parse_names(form.names.read(cx).text()).map(|names| names.len()).unwrap_or(0);
                let body = div()
                    .flex()
                    .flex_col()
                    .gap(px(12.))
                    .child(field("用户名", &form.names, window, cx))
                    .child(field("在哪些服务器上创建", &form.targets, window, cx))
                    .child(div().flex().gap(px(12.)).child(div().flex_1().child(field("附加组（逗号分隔，须已存在）", &form.groups, window, cx))).child(div().w(px(160.)).child(field("登录 shell", &form.shell, window, cx))))
                    .child(ui::form_row(t("初始密码").to_string(), segmented(vec![choice("random", "每人随机生成", form.password_mode, self, cx), choice("same", "统一密码", form.password_mode, self, cx), choice("locked", "不设密码（锁定）", form.password_mode, self, cx)])))
                    .when(form.password_mode == "same", |d| d.child(field("初始密码", &form.password, window, cx)))
                    .when(form.password_mode != "locked", |d| d.child(tick("users-expire", form.expire, "首次登录时必须修改密码", self, cx)))
                    .child(note(match form.password_mode {
                        "random" => "每台服务器上的每个账号各生成一个密码，创建完成后只显示这一次。",
                        "same" => "密码随脚本经 SSH 交给 chpasswd，不出现在命令行和审计里。",
                        _ => "账号先锁定，之后在这里重置密码，或放好 SSH 公钥再用。",
                    }))
                    .child(note("以 root 执行 useradd -m：已存在的账号不会改动。每台服务器的权限策略拒绝变更或 sudo 时，整批都不执行。"));
                (t("批量创建用户").to_string(), 540., body, Some(if count > 0 { tf!("创建 {count} 个账号", "Create {count} accounts") } else { t("创建").to_string() }), false)
            }
            Modal::ResetPassword(form) => {
                let body = div()
                    .flex()
                    .flex_col()
                    .gap(px(12.))
                    .child(ui::form_row(t("新密码").to_string(), segmented(vec![choice("random", "随机生成", form.mode, self, cx), choice("written", "自己填写", form.mode, self, cx)])))
                    .when(form.mode == "written", |d| d.child(field("新密码", &form.password, window, cx)).child(field("再输入一次", &form.again, window, cx)))
                    .child(tick("users-reset-expire", form.expire, "下次登录时必须修改密码", self, cx))
                    .child(note(if form.mode == "random" { "生成 16 位随机密码，改好后只显示这一次。" } else { "密码随脚本经 SSH 交给 chpasswd，不出现在命令行和审计里。" }))
                    .child(note("以 root 执行；账号若已锁定，设了新密码也就解锁了。"));
                (tf!("重置 {}@{} 的密码", "Reset the password of {}@{}", form.account, form.host), 480., body, Some(t("重置密码").to_string()), true)
            }
            _ => (String::new(), 400., div(), None, false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{account_matches, creation_report, login_summary, quota_summary, quota_words, session_words, span_words};
    use crate::accounts::HostOutcome;
    use wisp_ops_collect::accounts::Account;
    use wisp_ops_engine::accounts::Outcome;

    #[test]
    fn accounts_are_found_by_name_full_name_or_group() {
        let account = Account { name: "alice".into(), gecos: "Alice Liu".into(), primary_group: "alice".into(), groups: vec!["docker".into()], ..Default::default() };
        assert!(account_matches(&account, ""));
        assert!(account_matches(&account, "ALI"));
        assert!(account_matches(&account, "liu docker"));
        assert!(!account_matches(&account, "dock"));
        assert!(!account_matches(&account, "bob"));
    }

    #[test]
    fn a_creation_reads_by_server_with_the_passwords_made_up() {
        let outcomes = [
            HostOutcome { host: "gpu-01".into(), accounts: vec![("alice".into(), Outcome::Created, Some("Pw1".into())), ("bob".into(), Outcome::Exists, None)], error: None },
            HostOutcome { host: "web-01".into(), accounts: vec![], error: Some("unreachable".into()) },
        ];
        let text = creation_report(&outcomes);
        assert!(text.contains("gpu-01\n  alice  已创建  Pw1\n  bob    已存在，未改动"), "{text}");
        assert!(text.contains("web-01\n  没有执行：unreachable"), "{text}");
    }

    #[test]
    fn lengths_and_sessions_read_as_words() {
        use wisp_ops_collect::logins::{LoginSession, SessionEnd};
        assert_eq!(span_words(30_000), "不到 1 分钟");
        assert_eq!(span_words(27 * 60_000), "27 分钟");
        assert_eq!(span_words(90 * 60_000), "1 小时 30 分");
        assert_eq!(span_words((26 * 60 + 5) * 60_000), "1 天 2 小时");
        let session = |end| LoginSession { user: "alice".into(), tty: "pts/0".into(), from: String::new(), start: "2026-11-16T04:32:00Z".into(), end };
        assert_eq!(session_words(&session(SessionEnd::At("2026-11-16T05:00:00Z".into()))), "28 分钟");
        assert_eq!(session_words(&session(SessionEnd::Open)), "仍在线");
        assert_eq!(session_words(&session(SessionEnd::Crash)), "系统崩溃时中断");
    }

    #[test]
    fn a_server_sums_up_its_logins_and_quotas() {
        use wisp_ops_collect::accounts::{Account, AccountsReport};
        use wisp_ops_collect::logins::{FailTotal, LogSource, LoginReport, LoginSource};
        use wisp_ops_collect::quotas::{QuotaFs, QuotaReport, QuotaState, QuotaUse};
        let accounts = vec![Account { name: "root".into(), ..Default::default() }, Account { name: "alice".into(), uid: 1001, ..Default::default() }];
        let fail = |user: &str, count, invalid| FailTotal { user: user.into(), count, sources: 1, invalid, first: String::new(), last: String::new() };
        let logins = LoginReport {
            log: LogSource::Journal,
            accepted: vec![LoginSource { user: "alice".into(), count: 12, ..Default::default() }],
            fail_totals: vec![fail("root", 300, false), fail("admin", 40, true), fail("ghost", 2, false)],
            ..Default::default()
        };
        let mut report = AccountsReport { accounts, as_root: true, logins, ..Default::default() };
        assert_eq!(login_summary(&report), "近 30 天 SSH 登录成功 12 次，失败 300 次；另有 42 次试的是不存在的账号（admin、ghost）");
        report.logins = LoginReport::default();
        report.as_root = false;
        assert!(login_summary(&report).contains("root"));
        assert_eq!(quota_summary(&report), None);
        report.quotas = QuotaReport { tools: true, read: false, filesystems: vec![QuotaFs { mount: "/data".into(), state: QuotaState::On, ..Default::default() }, QuotaFs { mount: "/scratch".into(), state: QuotaState::Off, ..Default::default() }], usage: vec![] };
        assert_eq!(quota_summary(&report).as_deref(), Some("磁盘配额：/data（已开启）、/scratch（未开启）；用量要以 root 读取"));
        let row = QuotaUse { used_kb: 8 * 1024 * 1024, hard_kb: 12 * 1024 * 1024, ..Default::default() };
        assert_eq!(quota_words(&row), "8.0G / 12.0G");
    }
}
