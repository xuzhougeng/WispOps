//! Dialogs: what each holds while it is open, and how it is drawn. A dialog
//! is a `Modal` value; what its button does is `Workspace::submit_modal`,
//! which hands each form to the page it belongs to.

use crate::app::{Cmd, Workspace};
use crate::i18n::t;
use crate::input::{InputEvent, TextInput};
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};

/// A server being added or edited.
pub struct HostForm {
    /// The server being edited; `None` for a new one.
    pub editing: Option<String>,
    pub name: Entity<TextInput>,
    pub address: Entity<TextInput>,
    pub user: Entity<TextInput>,
    pub port: Entity<TextInput>,
    pub groups: Entity<TextInput>,
    pub jump: Entity<TextInput>,
    pub identity: Entity<TextInput>,
    pub description: Entity<TextInput>,
}

/// What a host's policy says for the three capabilities; empty inherits.
pub struct PolicyForm {
    pub host: String,
    pub values: [(&'static str, String); 3],
    /// What applies when a capability inherits: the group's or the default.
    pub inherited: [String; 3],
}

pub struct CredentialForm {
    pub editing: Option<String>,
    pub name: Entity<TextInput>,
    pub username: Entity<TextInput>,
    pub password: Entity<TextInput>,
    pub note: Entity<TextInput>,
    /// Whether the assistant's and the timer's commands may use it.
    pub agent: bool,
}

impl CredentialForm {
    /// The fields in the order drawn. Taken apart field by field, so a field added is not left out of Tab.
    pub fn inputs(&self) -> Vec<&Entity<TextInput>> {
        let CredentialForm { editing: _, name, username, password, note, agent: _ } = self;
        vec![name, username, password, note]
    }
}

/// Linking a credential to a host's SSH login or its sudo.
pub struct BindForm {
    pub host: String,
    pub sudo: bool,
    /// The credential picked; empty is none (an SSH key, passwordless sudo).
    pub picked: String,
    pub testing: bool,
    /// What the test said: the words, and whether it failed.
    pub tested: Option<(String, bool)>,
    /// A credential being written here, to be stored and linked by 保存; while it is, `picked` is passed over.
    pub new: Option<CredentialForm>,
}

/// Hosts of `~/.ssh/config` to take into the inventory.
pub struct ImportForm {
    /// The alias, what it connects to, and whether it is ticked.
    pub rows: Vec<(String, String, bool)>,
}

pub struct TaskForm {
    pub editing: Option<String>,
    pub name: Entity<TextInput>,
    pub description: Entity<TextInput>,
    pub targets: Entity<TextInput>,
    pub playbook: &'static str,
    pub paths: Entity<TextInput>,
    pub instruction: Entity<TextInput>,
    pub commands: Entity<TextInput>,
    /// `manual`, `daily` or `every`.
    pub schedule: &'static str,
    pub daily: Entity<TextInput>,
    pub every: Entity<TextInput>,
    pub sudo: bool,
    /// The check script of the `script` playbook.
    pub script: String,
}

pub enum Modal {
    Confirm { title: String, message: String, label: String, danger: bool, cmd: Cmd },
    /// Something to read: what a tool returned, an inspection's findings.
    Text { title: String, text: String, scroll: ScrollHandle },
    Host(HostForm),
    Policy(PolicyForm),
    Credential(CredentialForm),
    Bind(BindForm),
    Import(ImportForm),
    Task(TaskForm),
}

impl Modal {
    /// The text fields of the dialog in the order drawn, the first being where the caret starts;
    /// Tab moves among those drawn (a task's paths or time only show for some choices). The forms
    /// are taken apart field by field, so a form that gains a field does not build until it is here.
    pub fn inputs(&self) -> Vec<&Entity<TextInput>> {
        match self {
            Modal::Host(HostForm { editing: _, name, address, user, port, groups, jump, identity, description }) => vec![name, groups, address, user, port, jump, identity, description],
            Modal::Credential(form) | Modal::Bind(BindForm { new: Some(form), .. }) => form.inputs(),
            Modal::Task(TaskForm { editing: _, name, description, targets, playbook: _, paths, instruction, commands, schedule: _, daily, every, sudo: _, script: _ }) => vec![name, description, targets, paths, commands, instruction, daily, every],
            Modal::Policy(PolicyForm { host: _, values: _, inherited: _ }) | Modal::Bind(BindForm { host: _, sudo: _, picked: _, testing: _, tested: _, new: None }) | Modal::Import(ImportForm { rows: _ }) => vec![],
            Modal::Confirm { .. } | Modal::Text { .. } => vec![],
        }
    }
}

impl Workspace {
    /// A text field of a dialog: Enter in a one-line field submits, Escape closes.
    pub fn modal_input(&mut self, placeholder: &'static str, text: &str, multiline: bool, cx: &mut Context<Self>) -> Entity<TextInput> {
        let input = cx.new(|cx| {
            let input = TextInput::new(placeholder, cx).with_text(text);
            if multiline { input.multiline(3) } else { input }
        });
        self.modal_subscriptions.push(cx.subscribe(&input, move |this: &mut Self, _, event: &InputEvent, cx| match event {
            InputEvent::Submit if !multiline => this.submit_pending(cx),
            InputEvent::Cancel => {
                this.modal = None;
                this.modal_subscriptions.clear();
                cx.notify();
            }
            InputEvent::Changed if !this.modal_error.is_empty() => {
                this.modal_error.clear();
                cx.notify();
            }
            _ => {}
        }));
        input
    }

    /// Enter in a field: the dialog is submitted once a window is at hand.
    fn submit_pending(&mut self, cx: &mut Context<Self>) {
        cx.defer(|cx| {
            let Some(window) = cx.active_window().and_then(|window| window.downcast::<Workspace>()) else { return };
            window.update(cx, |this, window, cx| this.submit_modal(window, cx)).ok();
        });
    }

    pub fn open_modal(&mut self, modal: Modal, cx: &mut Context<Self>) {
        self.modal = Some(modal);
        self.modal_error.clear();
        self.modal_busy = false;
        self.modal_focus = true;
        cx.notify();
    }

    pub fn close_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.modal = None;
        self.modal_error.clear();
        self.modal_busy = false;
        self.modal_subscriptions.clear();
        window.focus(&self.focus);
        cx.notify();
    }

    pub fn confirm(&mut self, title: impl Into<String>, message: impl Into<String>, label: impl Into<String>, cmd: Cmd, cx: &mut Context<Self>) {
        self.open_modal(Modal::Confirm { title: title.into(), message: message.into(), label: label.into(), danger: true, cmd }, cx);
    }

    pub fn submit_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(modal) = self.modal.as_ref() else { return };
        let done = match modal {
            Modal::Confirm { cmd, .. } => {
                let cmd = cmd.clone();
                self.modal = None;
                self.run(Cmd::Confirmed(Box::new(cmd)), window, cx);
                return;
            }
            Modal::Text { .. } => Ok(()),
            Modal::Host(_) | Modal::Policy(_) | Modal::Bind(_) | Modal::Import(_) => self.submit_servers(window, cx),
            Modal::Credential(_) => self.submit_vault(window, cx),
            Modal::Task(_) => self.submit_task(window, cx),
        };
        match done {
            Ok(()) => self.close_modal(window, cx),
            Err(err) => {
                self.modal_error = err;
                cx.notify();
            }
        }
    }

    pub fn render_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) -> Option<AnyElement> {
        let modal = self.modal.as_ref()?;
        // The caret goes to the first field of a dialog just opened. One without fields takes
        // focus from the page behind it, so keys typed there do not land in a hidden field.
        if std::mem::take(&mut self.modal_focus) {
            let focus = modal.inputs().first().map(|input| input.focus_handle(cx)).unwrap_or_else(|| self.focus.clone());
            window.focus(&focus);
        }
        let field = |label: &str, input: &Entity<TextInput>, window: &Window, cx: &App| ui::form_row(t(label).to_string(), ui::field(input, window, cx));
        let (title, width, body, label, danger): (String, f32, Div, Option<String>, bool) = match modal {
            Modal::Confirm { title, message, label, danger, .. } => (title.clone(), 440., div().child(div().text_color(Theme::text_secondary()).line_height(text_px(21.)).child(message.clone())), Some(label.clone()), *danger),
            Modal::Text { title, text, scroll } => (
                title.clone(),
                820.,
                div().child(
                    div()
                        .id("modal-text")
                        .max_h(px(520.))
                        .overflow_y_scroll()
                        .track_scroll(scroll)
                        .px(px(12.))
                        .py(px(10.))
                        .rounded(px(8.))
                        .border_1()
                        .border_color(Theme::line())
                        .bg(Theme::bg_sunken())
                        .font_family(theme::MONO_FONT)
                        .text_size(text_px(12.))
                        .line_height(text_px(18.))
                        .child(if text.is_empty() { t("（没有内容）").to_string() } else { text.clone() }),
                ),
                None,
                false,
            ),
            Modal::Host(form) => (
                if form.editing.is_some() { t("编辑服务器").to_string() } else { t("添加服务器").to_string() },
                520.,
                div()
                    .flex()
                    .flex_col()
                    .gap(px(12.))
                    .child(div().flex().gap(px(12.)).child(div().flex_1().child(field("名称", &form.name, window, cx))).child(div().flex_1().child(field("分组（逗号分隔）", &form.groups, window, cx))))
                    .child(field("地址（主机名、IP 或 ssh_config 里的别名）", &form.address, window, cx))
                    .child(div().flex().gap(px(12.)).child(div().flex_1().child(field("用户名", &form.user, window, cx))).child(div().w(px(120.)).child(field("端口", &form.port, window, cx))))
                    .child(div().flex().gap(px(12.)).child(div().flex_1().child(field("跳板机（可选）", &form.jump, window, cx))).child(div().flex_1().child(field("私钥文件（可选）", &form.identity, window, cx))))
                    .child(field("备注", &form.description, window, cx))
                    .child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("默认用本机的 SSH 密钥和 ~/.ssh/config 登录；需要密码登录或 sudo 密码时，保存后在服务器详情里关联密码库的凭据。保存后会做一次只读的能力探测。"))),
                Some(t("保存").to_string()),
                false,
            ),
            Modal::Policy(form) => {
                let rows = form.values.iter().enumerate().map(|(n, (capability, value))| {
                    let choice = |key: &'static str, label: String, this: &Self, cx: &mut Context<Self>| {
                        let chosen = value == key;
                        div()
                            .id(SharedString::from(format!("policy-{capability}-{key}")))
                            .flex()
                            .flex_1()
                            .items_center()
                            .justify_center()
                            .h(text_px(26.))
                            .rounded(px(6.))
                            .cursor_pointer()
                            .text_size(text_px(12.))
                            .when(chosen, |d| d.bg(Theme::segment()).shadow(theme::shadow_card()).font_weight(FontWeight::MEDIUM))
                            .when(!chosen, |d| d.text_color(Theme::text_secondary()))
                            .on_click(this.on(Cmd::SetPolicy(capability, key), cx))
                            .child(label)
                    };
                    div()
                        .flex()
                        .items_center()
                        .gap(px(12.))
                        .child(div().w(px(150.)).flex().flex_col().child(div().child(t(crate::tools::capability_label(capability)).to_string())).child(div().text_size(text_px(11.)).line_height(text_px(15.)).text_color(Theme::text_tertiary()).child(t(crate::tools::capability_about(capability)).to_string())))
                        .child(
                            div()
                                .flex()
                                .flex_1()
                                .gap(px(2.))
                                .p(px(2.))
                                .rounded(px(8.))
                                .bg(Theme::groove())
                                .child(choice("", tf!("继承（{}）", "Inherit ({})", t(crate::tools::permission_label(&form.inherited[n]))), self, cx))
                                .child(choice("allow", t("允许").to_string(), self, cx))
                                .child(choice("ask", t("询问").to_string(), self, cx))
                                .child(choice("deny", t("拒绝").to_string(), self, cx)),
                        )
                });
                (
                    tf!("{} 的操作权限", "Permissions of {}", form.host),
                    600.,
                    div().flex().flex_col().gap(px(14.)).children(rows).child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("只读命令和内置的巡检、诊断始终允许。「询问」每次在助手里等你批准；「拒绝」是绝对的，批准和限时授权都不能覆盖。"))),
                    Some(t("保存").to_string()),
                    false,
                )
            }
            Modal::Credential(form) => (if form.editing.is_some() { t("编辑凭据").to_string() } else { t("新建凭据").to_string() }, 480., self.credential_fields(form, window, cx), Some(t("保存").to_string()), false),
            Modal::Bind(form) => {
                let none = if form.sudo { t("不关联（免密 sudo，或不用 sudo）") } else { t("不关联（用 SSH 密钥登录）") };
                let row = |id: String, chosen: bool, label: String, note: String, cmd: Cmd, this: &Self, cx: &mut Context<Self>| {
                    div()
                        .id(SharedString::from(format!("bind-{id}")))
                        .flex()
                        .flex_none()
                        .items_center()
                        .gap(px(10.))
                        .px(px(10.))
                        .h(text_px(36.))
                        .rounded(px(8.))
                        .border_1()
                        .border_color(if chosen { Theme::accent() } else { Theme::line() })
                        .when(chosen, |d| d.bg(Theme::accent_soft()))
                        .cursor_pointer()
                        .hover(|s| s.bg(Theme::hover()))
                        .on_click(this.on(cmd, cx))
                        .child(div().flex().flex_none().items_center().justify_center().size(px(14.)).rounded_full().border_1().border_color(if chosen { Theme::accent() } else { Theme::line_strong() }).when(chosen, |d| d.child(div().size(px(8.)).rounded_full().bg(Theme::accent()))))
                        .child(div().flex_1().min_w_0().truncate().child(label))
                        .child(div().flex_none().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(note))
                };
                let picking = form.new.is_none();
                let mut rows = vec![row("none".into(), picking && form.picked.is_empty(), none.to_string(), String::new(), Cmd::PickCredential(String::new()), self, cx)];
                for (n, credential) in self.view.credentials.iter().enumerate() {
                    rows.push(row(format!("{n}"), picking && form.picked == credential.name, credential.name.clone(), if credential.agent { credential.username.clone() } else { t("不允许自动化使用").to_string() }, Cmd::PickCredential(credential.name.clone()), self, cx));
                }
                rows.push(row("new".into(), !picking, t("新建凭据…").to_string(), t("存入密码库并关联").to_string(), Cmd::BindNewCredential, self, cx));
                let test = ui::secondary_button("bind-test", if form.sudo { t("测试 sudo") } else { t("测试 SSH 登录") }).h(text_px(28.));
                (
                    if form.sudo { tf!("{} 的 sudo 凭据", "sudo credential of {}", form.host) } else { tf!("{} 的 SSH 登录凭据", "SSH login credential of {}", form.host) },
                    500.,
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(8.))
                        .children(rows)
                        .when(self.view.credentials.is_empty() && picking, |d| d.child(div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("密码库还是空的：选「新建凭据…」在这里写一条。"))))
                        .when_some(form.new.as_ref(), |d, new| d.child(div().pl(px(24.)).pt(px(4.)).child(self.credential_fields(new, window, cx))))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(10.))
                                .pt(px(4.))
                                // A password not yet in the vault is not tried: it would have to reach SSH some other way.
                                .map(|d| if picking { d.child(test.on_click(self.on(Cmd::TestCredential, cx))) } else { d.child(test.opacity(0.5).cursor_default()) })
                                .when(!picking, |d| d.child(div().flex_1().min_w_0().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("保存后再测试：密码只从密码库交给 SSH。"))))
                                .when(form.testing, |d| d.child(ui::spinner("bind-testing", 14., Theme::accent())))
                                .when_some(form.tested.as_ref(), |d, (words, failed)| d.child(div().flex_1().min_w_0().text_size(text_px(12.)).line_height(text_px(18.)).text_color(if *failed { Theme::danger() } else { Theme::success() }).child(words.clone()))),
                        ),
                    Some(if picking { t("保存").to_string() } else { t("保存并关联").to_string() }),
                    false,
                )
            }
            Modal::Import(form) => (
                t("从 ssh_config 导入").to_string(),
                520.,
                div()
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("勾选要加入清单的 Host 别名。导入的服务器通过别名连接，密钥、跳板机等仍由 ssh_config 决定；通配模式和 Match 块不会列出。")))
                    .when(form.rows.len() > 1, |d| {
                        let all = form.rows.iter().all(|row| row.2);
                        d.child(div().flex().child(ui::ghost_button("import-all", None, Some(if all { t("全不选") } else { t("全选") }.into())).h(text_px(24.)).text_size(text_px(12.)).text_color(Theme::accent()).on_click(self.on(Cmd::ToggleImportAll(!all), cx))))
                    })
                    .child(div().id("import-rows").flex().flex_col().max_h(px(360.)).overflow_y_scroll().children(form.rows.iter().enumerate().map(|(n, (alias, target, ticked))| {
                        div()
                            .id(("import", n))
                            .flex()
                            .items_center()
                            .gap(px(10.))
                            .h(text_px(32.))
                            .px(px(8.))
                            .rounded(px(6.))
                            .cursor_pointer()
                            .hover(|s| s.bg(Theme::hover()))
                            .on_click(self.on(Cmd::ToggleImport(n), cx))
                            .child(div().flex().flex_none().items_center().justify_center().size(px(16.)).rounded(px(4.)).border_1().border_color(if *ticked { Theme::accent() } else { Theme::line_strong() }).when(*ticked, |d| d.bg(Theme::accent()).child(ui::icon("check", 12., Theme::on_accent()))))
                            .child(div().flex_none().w(px(180.)).truncate().child(alias.clone()))
                            .child(div().flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(target.clone()))
                    })))
                    .when(form.rows.is_empty(), |d| d.child(div().py(px(16.)).text_color(Theme::text_tertiary()).child(t("没有可导入的 Host：~/.ssh/config 里的都已在清单里，或者文件不存在。")))),
                Some(tf!("导入 {} 台", "Import {}", form.rows.iter().filter(|row| row.2).count())),
                false,
            ),
            Modal::Task(form) => self.task_form_body(form, window, cx),
        };
        let reading = label.is_none();
        // An import with nothing ticked has nothing to do: the button says so before it is pressed.
        let idle = matches!(&self.modal, Some(Modal::Import(form)) if !form.rows.iter().any(|row| row.2));
        Some(
            div()
                .id("modal-layer")
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .occlude()
                .bg(Theme::scrim())
                .child(
                    ui::dialog(width)
                        .child(ui::dialog_title(title))
                        .child(div().id("modal-body").flex().flex_col().flex_1().min_h_0().overflow_y_scroll().px(px(20.)).py(px(10.)).gap(px(10.)).child(body).child(ui::error_line(&self.modal_error)))
                        .child(
                            div()
                                .flex()
                                .flex_none()
                                .items_center()
                                .justify_end()
                                .gap(px(8.))
                                .px(px(20.))
                                .py(px(14.))
                                .when(self.modal_busy, |d| d.child(ui::spinner("modal-busy", 14., Theme::accent())))
                                .when(reading, |d| {
                                    let text = if let Some(Modal::Text { text, .. }) = &self.modal { text.clone() } else { String::new() };
                                    d.child(ui::secondary_button("modal-copy", t("复制")).on_click(self.on(Cmd::CopyText(text), cx)))
                                })
                                .child(ui::secondary_button("modal-cancel", if reading { t("关闭") } else { t("取消") }).on_click(self.on(Cmd::CloseModal, cx)))
                                .when_some(label, |d, label| d.child(ui::primary_button("modal-submit", label).when(danger, |b| b.bg(Theme::danger())).when(idle, |b| b.opacity(0.5)).on_click(self.on(Cmd::SubmitModal, cx)))),
                        ),
                )
                .into_any_element(),
        )
    }
}

/// A group of choices of which one holds: the segmented control of a form.
pub fn segmented(choices: Vec<(Stateful<Div>, bool)>) -> Div {
    div().flex().gap(px(2.)).p(px(2.)).rounded(px(8.)).bg(Theme::groove()).children(choices.into_iter().map(|(choice, chosen)| {
        choice.flex().flex_1().items_center().justify_center().h(text_px(26.)).px(px(10.)).rounded(px(6.)).cursor_pointer().text_size(text_px(12.)).whitespace_nowrap().when(chosen, |d| d.bg(Theme::segment()).shadow(theme::shadow_card()).font_weight(FontWeight::MEDIUM)).when(!chosen, |d| d.text_color(Theme::text_secondary()))
    }))
}
