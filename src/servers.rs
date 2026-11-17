//! 服务器: the inventory as a list, and beside it the server picked: how it
//! is reached, what it can do (the probe), what the assistant may do on it
//! (the three permissions), which credentials it uses, and its last
//! inspection. Servers written in `inventory.yml` are shown but edited
//! there; those added here or taken from `~/.ssh/config` are the window's.

use crate::app::{Cmd, MenuKind, Workspace};
use crate::dialogs::{BindForm, HostForm, ImportForm, Modal, PolicyForm};
use crate::i18n::t;
use crate::ops::{HostDraft, HostView, NewLogin};
use crate::theme::{Theme, text_px};
use crate::tools;
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::time;

/// The colour that says a state: of a server, a run, a finding.
pub fn state_color(state: &str) -> Hsla {
    match state {
        "ok" => Theme::success(),
        "warn" | "info" => Theme::star(),
        "crit" => Theme::danger(),
        "unreachable" => Theme::text_tertiary(),
        _ => Theme::line_strong(),
    }
}

pub fn state_label(state: &str) -> &'static str {
    match state {
        "ok" => "正常",
        "info" => "提示",
        "warn" => "警告",
        "crit" => "严重",
        "unreachable" => "不可达",
        _ => "未巡检",
    }
}

/// A name for a credential made from a server's bind dialog: the server and its user for a login,
/// the server and `sudo` for sudo, with a number added while the name is taken.
pub fn new_credential_name(host: &str, sudo: bool, user: &str, taken: &[&str]) -> String {
    let base = match (sudo, user.trim()) {
        (true, _) => format!("{host}-sudo"),
        (false, "") => format!("{host}-login"),
        (false, user) => format!("{host}-{user}"),
    };
    std::iter::once(base.clone()).chain((2..).map(|n| format!("{base}-{n}"))).find(|name| !taken.contains(&name.as_str())).unwrap_or(base)
}

impl Workspace {
    pub fn run_servers(&mut self, cmd: Cmd, window: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            Cmd::SelectHost(name) => {
                self.selected_host = name;
                self.page = crate::app::Page::Servers;
            }
            Cmd::AddHost => self.host_dialog(None, cx),
            Cmd::EditHost(name) => self.host_dialog(Some(name), cx),
            Cmd::RemoveHost(name) => self.confirm(t("删除服务器"), tf!("从清单里删除 {name}？它的凭据关联和权限设置一并去掉；巡检历史和审计记录保留。", "Remove {name} from the inventory? Its credential links and permission settings go with it; inspection history and audit records stay."), t("删除"), Cmd::RemoveHost(name), cx),
            Cmd::ImportSshConfig => {
                let rows = self.fleet.import_candidates().into_iter().map(|(alias, target)| (alias, target, true)).collect();
                self.open_modal(Modal::Import(ImportForm { rows }), cx);
            }
            Cmd::ToggleImport(at) => {
                if let Some(Modal::Import(form)) = self.modal.as_mut() && let Some(row) = form.rows.get_mut(at) { row.2 = !row.2 }
            }
            Cmd::ToggleImportAll(on) => {
                if let Some(Modal::Import(form)) = self.modal.as_mut() { form.rows.iter_mut().for_each(|row| row.2 = on) }
            }
            Cmd::ProbeHost(selector) => self.probe_hosts(selector, cx),
            Cmd::InspectHosts(selector) => self.inspect_hosts(selector, false, cx),
            Cmd::UnblockHost(name) => {
                self.fleet.unblock(&name);
                self.reload(cx);
                self.say(tf!("已解除 {name} 的登录暂停", "Login pause lifted for {name}"), cx);
            }
            Cmd::EditPolicy(name) => {
                let Some(host) = self.view.hosts.iter().find(|host| host.name == name) else { return };
                let values = [("change", host.policy_own[0].clone()), ("sudo", host.policy_own[1].clone()), ("destructive", host.policy_own[2].clone())];
                self.open_modal(Modal::Policy(PolicyForm { host: name, values, inherited: host.policy_inherited.clone() }), cx);
            }
            Cmd::SetPolicy(capability, value) => {
                if let Some(Modal::Policy(form)) = self.modal.as_mut() && let Some(slot) = form.values.iter_mut().find(|(key, _)| *key == capability) { slot.1 = value.to_string() }
            }
            Cmd::BindCredential(name, sudo) => {
                let Some(host) = self.view.hosts.iter().find(|host| host.name == name) else { return };
                let picked = if sudo { host.sudo_secret.clone() } else { host.login_secret.clone() };
                self.modal_subscriptions.clear();
                self.open_modal(Modal::Bind(BindForm { host: name, sudo, picked, testing: false, tested: None, new: None }), cx);
            }
            Cmd::PickCredential(name) => {
                if let Some(Modal::Bind(form)) = self.modal.as_mut() {
                    form.picked = name;
                    form.tested = None;
                    // The fields of a credential being written go, and the password typed with them.
                    if form.new.take().is_some() {
                        self.modal_subscriptions.clear();
                        self.modal_error.clear();
                    }
                }
            }
            Cmd::BindNewCredential => {
                let Some(Modal::Bind(form)) = self.modal.as_ref() else { return };
                if form.new.is_some() { return }
                let (host, sudo) = (form.host.clone(), form.sudo);
                let user = self.view.hosts.iter().find(|known| known.name == host).map(|known| known.user.clone()).unwrap_or_default();
                let taken: Vec<&str> = self.view.credentials.iter().map(|credential| credential.name.as_str()).collect();
                let name = new_credential_name(&host, sudo, &user, &taken);
                // A login credential is the server's own user's password; a sudo one names an account only when it is another.
                let new = self.credential_form(&name, if sudo { "" } else { &user }, "", true, cx);
                if let Some(Modal::Bind(form)) = self.modal.as_mut() {
                    form.new = Some(new);
                    form.tested = None;
                }
                self.modal_error.clear();
                // The caret goes to the first new field.
                self.modal_focus = true;
            }
            Cmd::TestCredential => self.test_credential(cx),
            Cmd::HostLogin(login) => {
                let first = self.view.credentials.first().map(|credential| credential.name.clone()).unwrap_or_default();
                if let Some(Modal::Host(form)) = self.modal.as_mut() {
                    form.login = login;
                    if login == "vault" && form.picked.is_empty() { form.picked = first }
                    // A password typed and then turned away from does not stay in a field out of sight.
                    if login != "password" { form.password.update(cx, |input, cx| input.set_text("", cx)) }
                    self.modal_error.clear();
                    if login == "password" { form.password.update(cx, |input, _| input.focus(window)) }
                }
            }
            Cmd::HostPick(name) => {
                if let Some(Modal::Host(form)) = self.modal.as_mut() { form.picked = name }
            }
            Cmd::HostSudoToo => {
                if let Some(Modal::Host(form)) = self.modal.as_mut() { form.sudo = !form.sudo }
            }
            _ => {}
        }
    }

    fn host_dialog(&mut self, editing: Option<String>, cx: &mut Context<Self>) {
        self.modal_subscriptions.clear();
        let host = editing.as_ref().and_then(|name| self.view.hosts.iter().find(|host| &host.name == name)).cloned();
        let text = |pick: fn(&HostView) -> String| host.as_ref().map(pick).unwrap_or_default();
        let form = HostForm {
            name: self.modal_input("web-01", &text(|h| h.name.clone()), false, cx),
            address: self.modal_input("10.0.0.12 或 web-01.example.com", &text(|h| h.ssh.clone()), false, cx),
            user: self.modal_input("留空用 ssh_config 或当前用户", &text(|h| h.user.clone()), false, cx),
            port: self.modal_input("22", &text(|h| h.port.map(|port| port.to_string()).unwrap_or_default()), false, cx),
            groups: self.modal_input("web, prod", &text(|h| h.groups.join(", ")), false, cx),
            jump: self.modal_input("bastion 或 user@bastion", &text(|h| h.jump.clone()), false, cx),
            identity: self.modal_input("~/.ssh/id_ed25519", &text(|h| h.identity.clone()), false, cx),
            description: self.modal_input("这台服务器是做什么的", &text(|h| h.description.clone()), false, cx),
            login: "key",
            password: self.modal_input("", "", false, cx),
            picked: String::new(),
            sudo: false,
            editing,
        };
        form.password.update(cx, |input, _| input.masked = true);
        self.open_modal(Modal::Host(form), cx);
    }

    /// The servers' dialogs, submitted.
    pub fn submit_servers(&mut self, _: &mut Window, cx: &mut Context<Self>) -> Result<(), String> {
        match self.modal.as_ref() {
            Some(Modal::Host(form)) => {
                let read = |input: &Entity<crate::input::TextInput>| input.read(cx).text().trim().to_string();
                let port = read(&form.port);
                let draft = HostDraft {
                    name: read(&form.name),
                    ssh: read(&form.address),
                    user: read(&form.user),
                    port: if port.is_empty() { None } else { Some(port.parse::<u16>().ok().filter(|port| *port > 0).ok_or_else(|| t("端口应是 1 到 65535 之间的数字。").to_string())?) },
                    groups: read(&form.groups).split([',', '，', ' ']).map(str::trim).filter(|group| !group.is_empty()).map(String::from).collect(),
                    jump: read(&form.jump),
                    identity: read(&form.identity),
                    description: read(&form.description),
                };
                let (editing, name) = (form.editing.clone(), draft.name.clone());
                match &editing {
                    Some(_) => self.fleet.save_host(editing.as_deref(), draft)?,
                    None => {
                        let taken: Vec<&str> = self.view.credentials.iter().map(|credential| credential.name.as_str()).collect();
                        let login = match form.login {
                            "password" => NewLogin::Password { name: new_credential_name(&name, false, &draft.user, &taken), password: form.password.read(cx).text().to_string(), sudo: form.sudo },
                            "vault" => NewLogin::Credential { name: form.picked.clone(), sudo: form.sudo },
                            _ => NewLogin::Key,
                        };
                        self.fleet.add_host(draft, login)?;
                        // The password leaves the field with the dialog.
                        form.password.update(cx, |input, cx| input.set_text("", cx));
                    }
                }
                self.reload(cx);
                self.selected_host = Some(name.clone());
                // A new server is looked at once: what it is and what it can do.
                if editing.is_none() { self.probe_hosts(name, cx) }
                Ok(())
            }
            Some(Modal::Policy(form)) => {
                let values = [form.values[0].1.clone(), form.values[1].1.clone(), form.values[2].1.clone()];
                self.fleet.set_policy(&form.host, &values)?;
                self.reload(cx);
                Ok(())
            }
            Some(Modal::Bind(BindForm { host, sudo, new: Some(new), .. })) => {
                let (name, username, password, note) = Self::read_credential_form(new, cx)?;
                // Stored and linked in one step: a link that cannot be written takes the credential back out of the vault.
                self.fleet.create_and_bind(host, *sudo, &name, &username, &password, &note, new.agent)?;
                new.password.update(cx, |input, cx| input.set_text("", cx));
                let host = host.clone();
                self.reload(cx);
                self.say(tf!("已新建凭据「{name}」并关联到 {host}", "Created credential “{name}” and linked it to {host}"), cx);
                Ok(())
            }
            Some(Modal::Bind(form)) => {
                self.fleet.bind_credential(&form.host, form.sudo, &form.picked)?;
                self.reload(cx);
                Ok(())
            }
            Some(Modal::Import(form)) => {
                let picked: Vec<String> = form.rows.iter().filter(|row| row.2).map(|row| row.0.clone()).collect();
                if picked.is_empty() { return Err(t("先勾选要导入的 Host。").to_string()) }
                self.fleet.import_hosts(&picked)?;
                self.reload(cx);
                self.say(tf!("已导入 {} 台服务器", "Imported {} servers", picked.len()), cx);
                self.probe_hosts(picked.join(","), cx);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Try the credential picked in the dialog, without saving the link: log in, and for sudo, validate it.
    fn test_credential(&mut self, cx: &mut Context<Self>) {
        let Some(Modal::Bind(form)) = self.modal.as_mut() else { return };
        // A credential not yet stored is not tried: the test takes passwords from the vault only.
        if form.testing || form.new.is_some() { return }
        form.testing = true;
        form.tested = None;
        let (fleet, host, sudo, picked) = (self.fleet.clone(), form.host.clone(), form.sudo, form.picked.clone());
        let work = cx.background_executor().spawn(async move { fleet.test_credential(&host, sudo, &picked) });
        let (host, picked) = (form.host.clone(), form.picked.clone());
        cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                // The dialog may have been closed, or another credential picked, meanwhile.
                if let Some(Modal::Bind(form)) = this.modal.as_mut() && form.host == host && form.picked == picked {
                    form.testing = false;
                    form.tested = Some(match result { Ok(words) => (words, false), Err(words) => (words, true) });
                }
                this.reload(cx);
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// Probe what the selected servers are (read-only), off the main thread.
    pub fn probe_hosts(&mut self, selector: String, cx: &mut Context<Self>) {
        let names: Vec<String> = match self.fleet.select_names(&selector) {
            Ok(names) => names.into_iter().filter(|name| !self.working.contains(name)).collect(),
            Err(err) => return self.fail(err, cx),
        };
        if names.is_empty() { return }
        self.working.extend(names.iter().cloned());
        let fleet = self.fleet.clone();
        let selector = names.join(",");
        let task = cx.background_executor().spawn(async move { fleet.probe_each(&selector) });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                for name in &names { this.working.remove(name); }
                this.reload(cx);
                match result {
                    Ok(results) => {
                        let failed: Vec<String> = results.iter().filter(|(_, error)| error.is_some()).map(|(host, _)| host.clone()).collect();
                        // What failed stays on the server's row and in its panel until a probe succeeds.
                        for (host, error) in results.iter() {
                            match error {
                                Some(error) => this.probe_errors.insert(host.clone(), error.clone()),
                                None => this.probe_errors.remove(host),
                            };
                        }
                        if failed.is_empty() { this.say(tf!("已探测 {} 台服务器", "Probed {} servers", results.len()), cx) } else { this.fail(tf!("{} 台探测失败：{}。原因在服务器的「能力」里。", "The probe failed on {} servers: {}. The reason is under the server's capabilities.", failed.len(), failed.join("、")), cx) }
                    }
                    Err(err) => this.fail(err, cx),
                }
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// Inspect the selected servers (read-only, no sudo) and write the history.
    pub fn inspect_hosts(&mut self, selector: String, quiet: bool, cx: &mut Context<Self>) {
        let _ = quiet;
        self.host_work(selector, cx, |fleet, selector| fleet.inspect(selector, "window"));
    }

    fn host_work(&mut self, selector: String, cx: &mut Context<Self>, work: impl FnOnce(&crate::ops::Fleet, &str) -> Result<String, String> + Send + 'static) {
        let names = self.fleet.select_names(&selector);
        let names: Vec<String> = match names {
            Ok(names) => names.into_iter().filter(|name| !self.working.contains(name)).collect(),
            Err(err) => return self.fail(err, cx),
        };
        if names.is_empty() { return }
        self.working.extend(names.iter().cloned());
        let fleet = self.fleet.clone();
        let selector = names.join(",");
        let task = cx.background_executor().spawn(async move { work(&fleet, &selector) });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                for name in &names { this.working.remove(name); }
                this.reload(cx);
                match result {
                    Ok(words) if !words.is_empty() => this.say(words, cx),
                    Ok(_) => {}
                    Err(err) => this.fail(err, cx),
                }
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// Every minute while the program runs: read the inventory again when
    /// its files changed, inspect the servers whose last inspection is older
    /// than the chosen interval, and run the tasks that are due.
    pub fn watch_fleet(&mut self, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(std::time::Duration::from_secs(60)).await;
                let alive = this.update(cx, |this, cx| {
                    if this.fleet.refresh() { this.reload(cx) }
                    let minutes = this.settings.auto_inspect_minutes;
                    if minutes > 0 {
                        let due = this.fleet.inspection_due(minutes);
                        if !due.is_empty() {
                            this.host_work(due.join(","), cx, |fleet, selector| fleet.inspect(selector, "auto").map(|_| String::new()));
                            // The same servers are looked over for tasks that have run too long.
                            this.check_long_jobs(due.join(","), true, cx);
                        }
                    }
                    this.run_due_tasks(cx);
                    this.run_due_disk_scans(cx);
                });
                if alive.is_err() { break }
            }
        })
        .detach();
    }

    // ---- drawing

    pub fn render_servers(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let query = self.host_search.read(cx).text().trim().to_lowercase();
        let hosts: Vec<&HostView> = self.view.hosts.iter().filter(|host| query.is_empty() || host.name.to_lowercase().contains(&query) || host.address.to_lowercase().contains(&query) || host.groups.iter().any(|group| group.to_lowercase().contains(&query)) || host.description.to_lowercase().contains(&query)).collect();
        let selected = self.selected_host.as_ref().and_then(|name| self.view.hosts.iter().find(|host| &host.name == name));
        let actions = vec![
            ui::ghost_button("servers-import", Some("folder-open"), Some(t("从 ssh_config 导入").into())).on_click(self.on(Cmd::ImportSshConfig, cx)).into_any_element(),
            ui::primary_button("servers-add", t("添加服务器")).child(ui::icon("plus", 14., Theme::on_accent())).on_click(self.on(Cmd::AddHost, cx)).into_any_element(),
        ];
        let about = match &self.view.inventory_error {
            Some(_) => t("清单文件有错误，下面显示的是上一次读到的内容").to_string(),
            None => tf!("清单里的 {} 台服务器；助手只能按这里的名称操作", "{} servers in the inventory; the assistant addresses them by these names only", self.view.hosts.len()),
        };
        let list: AnyElement = if self.view.hosts.is_empty() {
            ui::empty_state("library", t("清单里还没有服务器"), t("添加一台：填地址、用户名和端口；或者从 ~/.ssh/config 批量导入。也可以手写数据文件夹里的 inventory.yml。保存后会做一次只读的能力探测。")).child(div().flex().gap(px(8.)).child(ui::primary_button("empty-add", t("添加服务器")).on_click(self.on(Cmd::AddHost, cx))).child(ui::secondary_button("empty-import", t("从 ssh_config 导入")).on_click(self.on(Cmd::ImportSshConfig, cx)))).into_any_element()
        } else {
            div()
                .id("servers-list")
                .flex()
                .flex_col()
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .track_scroll(&self.page_scroll)
                .px(px(24.))
                .pt(px(8.))
                .pb(px(16.))
                .when(!hosts.is_empty(), |d| d.child(ui::panel().p(px(4.)).gap(px(1.)).children(hosts.iter().map(|host| self.render_host_row(host, cx)))))
                .when(hosts.is_empty(), |d| d.child(div().p(px(24.)).text_color(Theme::text_tertiary()).child(t("没有符合搜索的服务器。"))))
                .into_any_element()
        };
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(self.page_head(t("服务器"), about, actions, cx))
            .when_some(self.view.inventory_error.as_ref(), |d, error| d.child(div().px(px(24.)).pt(px(10.)).child(ui::error_line(error))))
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(div().flex().flex_col().flex_1().min_w_0().when(!self.view.hosts.is_empty(), |d| d.bg(Theme::bg_sunken())).when(!self.view.hosts.is_empty(), |d| d.child(div().px(px(24.)).pt(px(12.)).pb(px(4.)).child(div().max_w(px(360.)).child(ui::field(&self.host_search, window, cx))))).child(list))
                    .when_some(selected, |d, host| d.child(self.render_host_detail(host, cx))),
            )
            .into_any_element()
    }

    fn render_host_row(&self, host: &HostView, cx: &mut Context<Self>) -> AnyElement {
        let active = self.selected_host.as_ref() == Some(&host.name);
        let state = host.state();
        let working = self.working.contains(&host.name);
        let failed = self.probe_errors.get(&host.name);
        let facts = match (&host.probe, failed) {
            (_, Some(_)) => t("探测失败").to_string(),
            (Some(probe), None) => probe.line(),
            (None, None) => t("未探测").to_string(),
        };
        div()
            .id(SharedString::from(format!("host-{}", host.name)))
            .flex()
            .items_center()
            .gap(px(12.))
            .w_full()
            .h(text_px(52.))
            .px(px(12.))
            .rounded(px(8.))
            .cursor_pointer()
            .when(active, |d| d.bg(Theme::accent_soft()))
            .hover(|s| s.bg(Theme::hover()))
            .on_click(self.on(Cmd::SelectHost(if active { None } else { Some(host.name.clone()) }), cx))
            .on_mouse_down(MouseButton::Right, self.on_context(MenuKind::HostActions(host.name.clone()), cx))
            .child(if working { ui::spinner(SharedString::from(format!("host-working-{}", host.name)), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(9.)).m(px(1.5)).rounded_full().bg(state_color(state)).into_any_element() })
            .child(div().flex().flex_col().w(px(200.)).flex_none().child(div().truncate().font_weight(FontWeight::MEDIUM).child(host.name.clone())).child(div().truncate().text_size(text_px(12.)).line_height(text_px(16.)).text_color(Theme::text_tertiary()).child(host.shown_address().to_string())))
            .child(div().flex().flex_none().w(px(150.)).gap(px(4.)).overflow_hidden().children(host.groups.iter().take(3).map(|group| ui::chip(group.clone(), Theme::text_secondary(), Theme::groove()))))
            .child(div().id(SharedString::from(format!("host-facts-{}", host.name))).flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(if failed.is_some() { Theme::danger() } else { Theme::text_secondary() }).when_some(failed.cloned(), |d, error| d.tooltip(ui::tip(error))).child(facts))
            .when(host.blocked_until.is_some(), |d| d.child(ui::status_chip("deny", t("登录已暂停"))))
            .child(ui::ghost_button(SharedString::from(format!("host-menu-{}", host.name)), Some("ellipsis"), None).on_click({
                let open = self.on_menu(MenuKind::HostActions(host.name.clone()), cx);
                move |ev, window, cx| {
                    cx.stop_propagation();
                    open(ev, window, cx);
                }
            }))
            .into_any_element()
    }

    /// Why nothing reaches a server whose logins are paused, with the way out. The pages
    /// that run something on a server show it where the result would have been.
    pub fn render_blocked(&self, host: &HostView, place: &str, cx: &mut Context<Self>) -> Option<Div> {
        let until = host.blocked_until.as_ref()?;
        Some(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .p(px(10.))
                .rounded(px(8.))
                .bg(Theme::danger_soft())
                .text_size(text_px(12.))
                .line_height(text_px(18.))
                .child(div().flex_1().min_w_0().text_color(Theme::danger()).child(tf!("认证失败，登录暂停到 {}，以免反复登录被当成暴力破解。检查用户名、密钥或凭据后解除。", "Authentication failed; logins are paused until {} so retries are not taken for brute force. Check the user, key or credential, then resume.", time::short_time(until))))
                .child(ui::secondary_button(SharedString::from(format!("{place}-unblock-{}", host.name)), t("解除")).flex_none().h(text_px(24.)).on_click(self.on(Cmd::UnblockHost(host.name.clone()), cx))),
        )
    }

    /// The panel of the server picked: a column of its own beside the list.
    fn render_host_detail(&self, host: &HostView, cx: &mut Context<Self>) -> AnyElement {
        let name = host.name.clone();
        let working = self.working.contains(&host.name);
        let block = |title: &str, action: Option<AnyElement>, body: AnyElement| ui::panel().gap(px(6.)).px(px(12.)).pt(px(8.)).pb(px(12.)).child(div().flex().items_center().h(text_px(24.)).child(div().flex_1().child(ui::caption(title.to_string()))).children(action)).child(body);
        let fact = |label: &str, value: String| div().flex().gap(px(10.)).child(div().w(px(84.)).flex_none().text_color(Theme::text_tertiary()).child(label.to_string())).child(div().flex_1().min_w_0().child(value));

        let connection = div()
            .flex()
            .flex_col()
            .gap(px(4.))
            .text_size(text_px(12.))
            .line_height(text_px(19.))
            .child(fact(t("地址"), host.address.clone()))
            .when(!host.target.is_empty(), |d| d.child(fact(t("连接到"), host.target.clone())))
            .when(!host.jump.is_empty(), |d| d.child(fact(t("跳板机"), host.jump.clone())))
            .when(!host.identity.is_empty(), |d| d.child(fact(t("私钥"), host.identity.clone())))
            .child(fact(t("来源"), t(host.source_label()).to_string()))
            .when(!host.description.is_empty(), |d| d.child(fact(t("备注"), host.description.clone())));

        let abilities = match &host.probe {
            Some(probe) => div()
                .flex()
                .flex_col()
                .gap(px(4.))
                .text_size(text_px(12.))
                .line_height(text_px(19.))
                .child(fact(t("系统"), format!("{} {}", probe.os, probe.arch)))
                .child(fact(t("核数"), probe.cores.clone()))
                .when(probe.gpus > 0, |d| d.child(fact("GPU", probe.gpus.to_string())))
                .when(probe.scheduler != "none" && !probe.scheduler.is_empty(), |d| d.child(fact(t("调度器"), probe.scheduler.clone())))
                .child(fact("sudo", t(tools::privilege_label(&probe.privilege)).to_string()))
                .child(fact("Docker", probe.docker.clone()))
                .child(fact(t("探测于"), time::short_time(&probe.at))),
            None => div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("还没有探测过：系统、核数、GPU、调度器和 sudo 是否可用。")),
        };
        // The last probe that failed, until one succeeds: a toast alone is gone before it is read.
        let abilities = match self.probe_errors.get(&host.name) {
            Some(error) => div().flex().flex_col().gap(px(8.)).child(div().px(px(8.)).py(px(6.)).rounded(px(6.)).bg(Theme::danger_soft()).text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::danger()).child(tf!("上次探测失败：{error}", "The last probe failed: {error}"))).child(abilities),
            None => abilities,
        };

        let permissions = div().flex().flex_col().gap(px(6.)).children(["change", "sudo", "destructive"].iter().enumerate().map(|(n, capability)| {
            let own = !host.policy_own[n].is_empty();
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .text_size(text_px(12.))
                .child(div().w(px(84.)).flex_none().text_color(Theme::text_tertiary()).child(t(tools::capability_label(capability)).to_string()))
                .child(ui::status_chip(&host.policy[n], t(tools::permission_label(&host.policy[n]))))
                .when(own, |d| d.child(div().text_color(Theme::text_placeholder()).child(t("此处设置"))))
        }));

        let mut credential = |sudo: bool, secret: &str| {
            let label = if sudo { "sudo" } else { t("SSH 登录") };
            let value = match (secret.is_empty(), sudo) {
                (false, _) => secret.to_string(),
                (true, true) => t("未关联（免密或不用）").to_string(),
                (true, false) => t("SSH 密钥").to_string(),
            };
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .text_size(text_px(12.))
                .child(div().w(px(84.)).flex_none().text_color(Theme::text_tertiary()).child(label.to_string()))
                .child(div().flex_1().min_w_0().truncate().child(value))
                .child(ui::ghost_button(if sudo { "bind-sudo" } else { "bind-login" }, None, Some(if secret.is_empty() { t("关联").into() } else { t("更换").into() })).h(text_px(24.)).text_size(text_px(12.)).text_color(Theme::accent()).on_click(self.on(Cmd::BindCredential(name.clone(), sudo), cx)))
        };
        let credentials = div().flex().flex_col().gap(px(4.)).child(credential(false, &host.login_secret)).child(credential(true, &host.sudo_secret));

        let latest = host.runs.last();
        let health: AnyElement = match latest {
            None => div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("还没有巡检记录。")).into_any_element(),
            Some(run) => {
                let problems: Vec<_> = run.findings.iter().filter(|finding| finding.severity != "info").take(8).collect();
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .text_size(text_px(12.))
                    .line_height(text_px(18.))
                    .child(div().flex().items_center().gap(px(8.)).child(ui::status_chip(&run.state, t(state_label(&run.state)))).child(div().text_color(Theme::text_tertiary()).child(time::short_time(&run.at)))).children(run.metrics_line().map(|line| div().text_color(Theme::text_secondary()).child(line)))
                    .children(problems.into_iter().map(|finding| div().flex().items_start().gap(px(6.)).child(div().flex_none().mt(px(6.)).size(px(6.)).rounded_full().bg(state_color(&finding.severity))).child(div().flex_1().min_w_0().text_color(if finding.muted { Theme::text_tertiary() } else { Theme::text() }).child(finding.words()))))
                    .into_any_element()
            }
        };

        div()
            .relative()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(360.))
            .h_full()
            .border_l_1()
            .border_color(Theme::line())
            .bg(Theme::bg_window())
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .gap(px(8.))
                    .h(text_px(48.))
                    .px(px(16.))
                    .border_b_1()
                    .border_color(Theme::line())
                    .child(div().flex_none().size(px(9.)).rounded_full().bg(state_color(host.state())))
                    .child(div().flex_1().min_w_0().truncate().text_size(text_px(14.)).font_weight(FontWeight::SEMIBOLD).child(host.name.clone()))
                    .child(ui::icon_action("detail-close", "x", Theme::text_tertiary(), t("收起")).on_click(self.on(Cmd::SelectHost(None), cx))),
            )
            .child(
                div()
                    .id("host-detail")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .track_scroll(&self.detail_scroll)
                    .px(px(14.))
                    .py(px(14.))
                    .gap(px(10.))
                    .children(self.render_blocked(host, "detail", cx))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap(px(6.))
                            .child(ui::secondary_button("detail-inspect", t("巡检")).h(text_px(28.)).when(working, |b| b.opacity(0.5)).on_click(self.on(Cmd::InspectHosts(name.clone()), cx)))
                            .child(ui::secondary_button("detail-space", t("磁盘占用")).h(text_px(28.)).on_click(self.on(Cmd::DiskHost(name.clone()), cx)))
                            .child(ui::secondary_button("detail-disk", t("诊断磁盘")).h(text_px(28.)).child(ui::icon("sparkle", 12., Theme::accent())).on_click(self.on(Cmd::Draft(format!("/disk {name} /")), cx)))
                            .child(ui::secondary_button("detail-security", t("安全排查")).h(text_px(28.)).child(ui::icon("sparkle", 12., Theme::accent())).on_click(self.on(Cmd::Suggest(format!("/security {name}")), cx)))
                            .child(ui::secondary_button("detail-audit", t("审计")).h(text_px(28.)).on_click(self.on(Cmd::AuditHost(Some(name.clone())), cx))),
                    )
                    .child(block(t("最近一次巡检"), None, health))
                    .child(block(t("连接"), host.managed.then(|| ui::ghost_button("detail-edit", None, Some(t("编辑").into())).h(text_px(24.)).text_size(text_px(12.)).text_color(Theme::accent()).on_click(self.on(Cmd::EditHost(name.clone()), cx)).into_any_element()), connection.into_any_element()))
                    .child(block(t("能力"), Some(ui::ghost_button("detail-probe", None, Some(t("立即探测").into())).h(text_px(24.)).text_size(text_px(12.)).text_color(Theme::accent()).on_click(self.on(Cmd::ProbeHost(name.clone()), cx)).into_any_element()), abilities.into_any_element()))
                    .child(block(t("操作权限"), Some(ui::ghost_button("detail-policy", None, Some(t("编辑").into())).h(text_px(24.)).text_size(text_px(12.)).text_color(Theme::accent()).on_click(self.on(Cmd::EditPolicy(name.clone()), cx)).into_any_element()), permissions.into_any_element()))
                    .child(block(t("凭据"), None, credentials.into_any_element()))
                    .when(host.managed, |d| d.child(div().flex().child(ui::ghost_button("detail-remove", Some("bin"), Some(t("删除服务器").into())).text_color(Theme::danger()).on_click(self.on(Cmd::RemoveHost(name.clone()), cx)))))
                    .when(!host.managed, |d| d.child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_placeholder()).child(t("这台服务器写在 inventory.yml 里，连接信息在那里修改；权限和凭据可以在这里设置。")))),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::new_credential_name;

    #[test]
    fn a_new_credential_is_named_after_the_server_and_what_it_is_for() {
        assert_eq!(new_credential_name("cpu", false, "ops", &[]), "cpu-ops");
        assert_eq!(new_credential_name("cpu", false, " ", &[]), "cpu-login");
        assert_eq!(new_credential_name("cpu", true, "ops", &[]), "cpu-sudo");
        assert_eq!(new_credential_name("cpu", true, "", &["cpu-sudo", "cpu-sudo-2"]), "cpu-sudo-3");
        assert_eq!(new_credential_name("cpu", false, "ops", &["cpu-sudo"]), "cpu-ops");
    }
}
