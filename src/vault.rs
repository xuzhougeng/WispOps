//! 密码库: the credentials SSH logins and sudo use. Only names, user names
//! and notes are ever shown: a password goes in here and from here to SSH,
//! never back to the window or to the model.

use crate::app::{Cmd, Workspace};
use crate::dialogs::{BindForm, CredentialForm, Modal};
use crate::i18n::t;
use crate::theme::{Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};

impl Workspace {
    pub fn run_vault(&mut self, cmd: Cmd, _: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            Cmd::AddCredential => self.credential_dialog(None, cx),
            Cmd::EditCredential(name) => self.credential_dialog(Some(name), cx),
            Cmd::DeleteCredential(name) => {
                let used = self.credential_uses(&name);
                let message = if used.is_empty() { tf!("删除凭据「{name}」？", "Delete credential “{name}”?") } else { tf!("删除凭据「{name}」？这些服务器还在用它：{}。删除后它们的 SSH 登录改回密钥，sudo 改回未关联。", "Delete credential “{name}”? These servers still use it: {}. Their SSH login goes back to keys and their sudo to unlinked.", used.join("、")) };
                self.confirm(t("删除凭据"), message, t("删除"), Cmd::DeleteCredential(name), cx);
            }
            Cmd::ToggleAgentUse => {
                if let Some(Modal::Credential(form) | Modal::Bind(BindForm { new: Some(form), .. })) = self.modal.as_mut() { form.agent = !form.agent }
            }
            _ => {}
        }
    }

    /// The servers a credential is linked to, each with what for.
    fn credential_uses(&self, name: &str) -> Vec<String> {
        self.view.hosts.iter().filter_map(|host| match (host.login_secret == name, host.sudo_secret == name) {
            (true, true) => Some(format!("{}（SSH + sudo）", host.name)),
            (true, false) => Some(format!("{}（SSH）", host.name)),
            (false, true) => Some(format!("{}（sudo）", host.name)),
            _ => None,
        }).collect()
    }

    fn credential_dialog(&mut self, editing: Option<String>, cx: &mut Context<Self>) {
        self.modal_subscriptions.clear();
        let known = editing.as_ref().and_then(|name| self.view.credentials.iter().find(|credential| &credential.name == name)).cloned();
        let form = match known {
            Some(known) => CredentialForm { editing, ..self.credential_form(&known.name, &known.username, &known.note, known.agent, cx) },
            None => self.credential_form("", "", "", true, cx),
        };
        self.open_modal(Modal::Credential(form), cx);
    }

    /// The fields of a credential, filled in; the password always starts empty. Shared by the vault's
    /// dialog and the bind dialog's 新建凭据, which adds them to the dialog that is open.
    pub fn credential_form(&mut self, name: &str, username: &str, note: &str, agent: bool, cx: &mut Context<Self>) -> CredentialForm {
        let name = self.modal_input("prod-root", name, false, cx);
        let username = self.modal_input("", username, false, cx);
        let password = self.modal_input("", "", false, cx);
        password.update(cx, |input, _| input.masked = true);
        CredentialForm { editing: None, name, username, password, note: self.modal_input("", note, false, cx), agent }
    }

    /// What a credential form holds, checked: name, user name, password, note. A new one needs a password.
    pub fn read_credential_form(form: &CredentialForm, cx: &App) -> Result<(String, String, String, String), String> {
        let read = |input: &Entity<crate::input::TextInput>| input.read(cx).text().to_string();
        let (name, username, password, note) = (read(&form.name).trim().to_string(), read(&form.username).trim().to_string(), read(&form.password), read(&form.note).trim().to_string());
        if name.is_empty() { return Err(t("凭据要有名称。").to_string()) }
        if form.editing.is_none() && password.is_empty() { return Err(t("填写密码。").to_string()) }
        Ok((name, username, password, note))
    }

    pub fn submit_vault(&mut self, _: &mut Window, cx: &mut Context<Self>) -> Result<(), String> {
        let Some(Modal::Credential(form)) = self.modal.as_ref() else { return Ok(()) };
        let (name, username, password, note) = Self::read_credential_form(form, cx)?;
        self.fleet.save_credential(form.editing.as_deref(), &name, &username, &password, &note, form.agent)?;
        // The password leaves the field with the dialog.
        form.password.update(cx, |input, cx| input.set_text("", cx));
        self.reload(cx);
        Ok(())
    }

    /// The fields of a credential form as drawn, with the agent switch and what is kept where.
    pub fn credential_fields(&self, form: &CredentialForm, window: &Window, cx: &mut Context<Self>) -> Div {
        let field = |label: &str, input: &Entity<crate::input::TextInput>, cx: &App| ui::form_row(t(label).to_string(), ui::field(input, window, cx));
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field("名称", &form.name, cx))
            .child(field("用户名（sudo 用另一个账号时填写，否则留空）", &form.username, cx))
            .child(field(if form.editing.is_some() { "密码（留空保留原密码）" } else { "密码" }, &form.password, cx))
            .child(field("备注", &form.note, cx))
            .child(
                div()
                    .id("credential-agent")
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .cursor_pointer()
                    .on_click(self.on(Cmd::ToggleAgentUse, cx))
                    .child(div().flex().flex_none().items_center().justify_center().size(px(16.)).rounded(px(4.)).border_1().border_color(if form.agent { Theme::accent() } else { Theme::line_strong() }).when(form.agent, |d| d.bg(Theme::accent()).child(ui::icon("check", 12., Theme::on_accent()))))
                    .child(t("允许助手和定时任务的命令使用这条凭据")),
            )
            .child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("密码加密保存在本机，只交给 SSH 和 sudo；界面和模型都读不到它。名称、用户名和备注不加密，不要在这些地方写密码。")))
    }

    pub fn render_vault(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let actions = vec![ui::primary_button("vault-add", t("新建凭据")).child(ui::icon("plus", 14., Theme::on_accent())).on_click(self.on(Cmd::AddCredential, cx)).into_any_element()];
        let body: AnyElement = if self.view.credentials.is_empty() {
            ui::empty_state("plug", t("密码库是空的"), t("用密钥登录、免密 sudo 的服务器不需要它。需要密码登录或 sudo 密码时，在这里新建凭据，再到服务器详情里关联。")).into_any_element()
        } else {
            div()
                .id("vault-list")
                .flex()
                .flex_col()
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .px(px(24.))
                .py(px(16.))
                .gap(px(8.))
                .children(self.view.credentials.iter().map(|credential| {
                    let uses = self.credential_uses(&credential.name);
                    div()
                        .flex()
                        .items_center()
                        .gap(px(12.))
                        .max_w(px(820.))
                        .px(px(14.))
                        .py(px(10.))
                        .rounded(px(10.))
                        .border_1()
                        .border_color(Theme::line())
                        .child(div().flex().flex_none().items_center().justify_center().size(px(30.)).rounded(px(8.)).bg(Theme::accent_soft()).child(ui::icon("plug", 15., Theme::accent())))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w_0()
                                .child(div().flex().items_center().gap(px(8.)).child(div().truncate().font_weight(FontWeight::MEDIUM).child(credential.name.clone())).when(!credential.username.is_empty(), |d| d.child(div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(credential.username.clone()))).when(!credential.agent, |d| d.child(ui::status_chip("ask", t("不允许自动化使用")))))
                                .child(div().truncate().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_secondary()).child(if uses.is_empty() { t("还没有服务器使用").to_string() } else { uses.join("、") }))
                                .when(!credential.note.is_empty(), |d| d.child(div().truncate().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(credential.note.clone()))),
                        )
                        .child(ui::ghost_button(SharedString::from(format!("credential-edit-{}", credential.name)), Some("pen-line"), None).tooltip(ui::tip(t("编辑"))).on_click(self.on(Cmd::EditCredential(credential.name.clone()), cx)))
                        .child(ui::ghost_button(SharedString::from(format!("credential-delete-{}", credential.name)), Some("bin"), None).tooltip(ui::tip(t("删除"))).on_click(self.on(Cmd::DeleteCredential(credential.name.clone()), cx)))
                }))
                .into_any_element()
        };
        div().flex().flex_col().size_full().child(self.page_head(t("密码库"), tf!("加密保存在本机；密钥在{}。密码只交给 SSH，不回显，也不给模型", "Encrypted on this computer; the key is in {}. Passwords go to SSH only, never shown and never given to the model", t(self.view.vault_key_place)), actions, cx)).when_some(self.view.vault_error.as_ref(), |d, error| d.child(div().px(px(24.)).pt(px(10.)).child(ui::error_line(error)))).child(body).into_any_element()
    }
}
