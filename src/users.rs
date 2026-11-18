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
use wisp_ops_collect::accounts::{Account, AccountsSnapshot, PasswordState};
use wisp_ops_core::time;
use wisp_ops_engine::accounts::{self as change, NewAccounts, NewPassword, Outcome};

/// The width of the list of servers at the left.
const HOSTS_W: f32 = 210.;
/// The most accounts a server's table draws; the filter finds the rest.
const MAX_ROWS: usize = 300;

/// What the page holds besides what `View` has.
pub struct UsersState {
    pub host: Option<String>,
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
        (UsersState { host: None, show_system: false, filter: filter.clone(), reading: HashSet::new(), changing: HashSet::new() }, filter)
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
                self.users.host = Some(name);
                self.users.filter.update(cx, |input, cx| input.set_text("", cx));
            }
            Cmd::UsersSystem => self.users.show_system = !self.users.show_system,
            Cmd::ReadAccounts(selector) => self.read_accounts(selector, cx),
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

    /// Read the accounts of the selected servers off the main thread.
    pub fn read_accounts(&mut self, selector: String, cx: &mut Context<Self>) {
        let names: Vec<String> = match self.fleet.select_names(&selector) {
            Ok(names) => names.into_iter().filter(|name| !self.users.reading.contains(name)).collect(),
            Err(error) => return self.fail(error, cx),
        };
        if names.is_empty() { return }
        self.users.reading.extend(names.iter().cloned());
        let (fleet, selector) = (self.fleet.clone(), names.join(","));
        let work = cx.background_executor().spawn(async move { fleet.read_accounts(&selector) });
        cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                for name in &names { this.users.reading.remove(name); }
                this.reload(cx);
                match result {
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
        let filter = self.users.filter.read(cx).text().trim().to_string();
        let system = report.accounts.iter().filter(|account| report.system(account)).count();
        let online = report.accounts.iter().filter(|account| account.sessions > 0).count();
        let shown: Vec<&Account> = report.accounts.iter().filter(|account| (self.users.show_system || !report.system(account)) && account_matches(account, &filter)).collect();
        let mut summary = vec![tf!("{} 个用户账号", "{} user accounts", report.accounts.len() - system)];
        summary.push(if self.users.show_system { tf!("{system} 个系统账号", "{system} system accounts") } else { tf!("{system} 个系统账号（已隐藏）", "{system} system accounts (hidden)") });
        if online > 0 { summary.push(tf!("{online} 个在线", "{online} signed in")) }
        if report.truncated { summary.push(tf!("账号太多，只读了前 {}", "too many accounts: only the first {} were read", wisp_ops_collect::accounts::MAX_LINES)) }
        let cell = |width: f32| div().w(px(width)).flex_none();
        let columns = div().flex().items_center().gap(px(10.)).h(text_px(24.)).px(px(10.)).text_size(text_px(11.)).text_color(Theme::text_tertiary()).child(div().flex_1().min_w(px(150.)).child(t("用户"))).child(cell(60.).text_right().child("UID")).child(div().flex_1().min_w(px(100.)).child(t("组"))).child(cell(120.).child("Shell")).child(cell(78.).child(t("密码"))).child(cell(56.).child(t("在线"))).child(cell(76.));
        let today = today();
        let rows = shown.iter().take(MAX_ROWS).map(|account| {
            let expired = account.expires_day.is_some_and(|day| day > 0 && day <= today);
            let chip = password_chip(account);
            let mut groups = vec![account.primary_group.clone()];
            groups.extend(account.groups.iter().cloned());
            let groups = groups.into_iter().filter(|group| !group.is_empty()).collect::<Vec<_>>().join(", ");
            let tip = format!("{}\nUID {} · GID {}\n{}\n{}", account.name, account.uid, account.gid, account.home, account.shell);
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
                .hover(|s| s.bg(Theme::hover()))
                .tooltip(ui::tip(tip))
                .child(
                    div()
                        .flex()
                        .flex_1()
                        .min_w(px(150.))
                        .items_center()
                        .gap(px(6.))
                        .child(div().flex_none().font_weight(FontWeight::MEDIUM).when(!account.can_log_in(), |d| d.text_color(Theme::text_tertiary())).child(account.name.clone()))
                        .when(account.admin(), |d| d.child(ui::status_chip("info", t("管理员"))))
                        .when(!account.gecos.is_empty() && account.gecos != account.name, |d| d.child(div().min_w_0().truncate().text_color(Theme::text_tertiary()).child(account.gecos.clone()))),
                )
                .child(cell(60.).text_right().font_family(theme::MONO_FONT).text_color(Theme::text_secondary()).child(account.uid.to_string()))
                .child(div().flex_1().min_w(px(100.)).truncate().text_color(Theme::text_secondary()).child(groups))
                .child(cell(120.).truncate().font_family(theme::MONO_FONT).text_color(if account.can_log_in() { Theme::text_secondary() } else { Theme::text_placeholder() }).child(account.shell.clone()))
                .child(cell(78.).child(match (expired, chip) {
                    (true, _) => ui::status_chip("warn", t("已过期")).into_any_element(),
                    (_, Some((state, label))) => ui::status_chip(state, t(label)).into_any_element(),
                    (_, None) => div().text_color(Theme::text_placeholder()).child("—").into_any_element(),
                }))
                .child(cell(56.).child(if account.sessions > 0 { ui::status_chip("ok", &account.sessions.to_string()).into_any_element() } else { div().into_any_element() }))
                .child(cell(76.).flex().justify_end().child(ui::ghost_button(SharedString::from(format!("account-reset-{name}-{}", account.name)), None, Some(t("重置密码").into())).h(text_px(24.)).text_size(text_px(12.)).opacity(0.).group_hover("account", |s| s.opacity(1.)).when(changing, |b| b.invisible()).on_click(self.on(Cmd::ResetPassword(name.to_string(), account.name.clone()), cx))))
        });
        let rows: Vec<Stateful<Div>> = rows.collect();
        column
            .child(div().flex().items_center().gap(px(12.)).child(div().w(px(280.)).child(ui::field(&self.users.filter, window, cx))).child(div().flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(summary.join(" · "))))
            .child(div().flex().flex_col().rounded(px(10.)).border_1().border_color(Theme::line()).p(px(6.)).child(columns).children(rows).when(shown.is_empty(), |d| d.child(div().px(px(10.)).py(px(8.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("没有符合筛选的账号")))))
            .when(shown.len() > MAX_ROWS, |d| d.child(div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("还有 {} 个账号没有列出，用上面的筛选缩小范围", "{} more accounts are not listed: narrow them with the filter above", shown.len() - MAX_ROWS))))
            .into_any_element()
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
    use super::{account_matches, creation_report};
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
}
