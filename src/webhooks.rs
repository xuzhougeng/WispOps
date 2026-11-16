//! 设置 › 通用 › 外部通知: the webhooks the automatic inspection and the
//! routine tasks send to (`crate::notify`), their dialog and its test. The
//! URL and the secret stay in settings.json; the page names an endpoint by
//! its host only and never puts a saved secret back into a field.

use crate::app::{Cmd, Workspace};
use crate::dialogs::{Modal, segmented};
use crate::i18n::t;
use crate::input::TextInput;
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::settings::Webhook;
use wisp_ops_engine::notify::{self, Kind};

/// A webhook being added or edited.
pub struct WebhookForm {
    /// Its place in `settings.webhooks`; `None` for a new one.
    pub editing: Option<usize>,
    pub name: Entity<TextInput>,
    pub url: Entity<TextInput>,
    /// Empty while editing keeps the saved secret.
    pub secret: Entity<TextInput>,
    pub kind: &'static str,
    pub inspection: bool,
    pub tasks: bool,
    pub testing: bool,
    /// What the test said, and whether it failed.
    pub tested: Option<(String, bool)>,
}

impl WebhookForm {
    pub fn inputs(&self) -> Vec<&Entity<TextInput>> {
        let WebhookForm { editing: _, name, url, secret, kind, inspection: _, tasks: _, testing: _, tested: _ } = self;
        if *kind == "wecom" { vec![name, url] } else { vec![name, url, secret] }
    }
}

const KINDS: [(&str, &str); 4] = [("wecom", "企业微信"), ("dingtalk", "钉钉"), ("feishu", "飞书"), ("webhook", "通用 webhook")];

fn kind_label(kind: &str) -> &'static str {
    KINDS.iter().find(|(key, _)| *key == kind).map_or("通用 webhook", |(_, label)| label)
}

fn kind_key(kind: &str) -> &'static str {
    Kind::parse(kind).as_str()
}

impl Workspace {
    pub fn run_webhooks(&mut self, cmd: Cmd, cx: &mut Context<Self>) {
        match cmd {
            Cmd::AddWebhook => self.webhook_dialog(None, cx),
            Cmd::EditWebhook(index) => self.webhook_dialog(Some(index), cx),
            Cmd::RemoveWebhook(index) => {
                let name = self.settings.webhooks.get(index).map(|webhook| webhook.name.clone()).unwrap_or_default();
                return self.confirm(t("删除通知渠道"), tf!("删除「{name}」？它的地址和密钥也会从设置里去掉。", "Remove “{name}”? Its address and secret are removed from the settings too."), t("删除"), Cmd::DropWebhook(index), cx);
            }
            Cmd::DropWebhook(index) => {
                if index < self.settings.webhooks.len() { self.settings.webhooks.remove(index); }
                self.save_webhooks(cx);
            }
            Cmd::SetWebhookTasks(mode) => {
                self.settings.webhook_tasks = mode.into();
                self.save_webhooks(cx);
            }
            Cmd::PickWebhookKind(kind) => {
                if let Some(Modal::Webhook(form)) = self.modal.as_mut() {
                    form.kind = kind;
                    form.tested = None;
                }
            }
            Cmd::ToggleWebhookEvent(event) => {
                if let Some(Modal::Webhook(form)) = self.modal.as_mut() {
                    if event == "inspection" { form.inspection = !form.inspection } else { form.tasks = !form.tasks }
                }
            }
            Cmd::TestWebhook(None) => self.test_webhook_form(cx),
            Cmd::TestWebhook(Some(index)) => {
                let Some(webhook) = self.settings.webhooks.get(index).cloned() else { return };
                let work = cx.background_executor().spawn(async move { crate::notify::test(&webhook).map(|_| webhook.name.clone()).map_err(|err| (webhook.name.clone(), err)) });
                cx.spawn(async move |this, cx| {
                    let result = work.await;
                    this.update(cx, |this, cx| match result {
                        Ok(name) => this.say(tf!("测试通知已发送到 {name}", "Test notification sent to {name}"), cx),
                        Err((name, err)) => this.fail(tf!("测试通知没有发到 {name}：{err}", "The test notification did not reach {name}: {err}"), cx),
                    })
                    .ok();
                })
                .detach();
            }
            _ => {}
        }
        cx.notify();
    }

    fn save_webhooks(&mut self, cx: &mut Context<Self>) {
        self.save_settings(cx);
        crate::notify::configure(&self.settings, None);
    }

    fn webhook_dialog(&mut self, editing: Option<usize>, cx: &mut Context<Self>) {
        self.modal_subscriptions.clear();
        let saved = editing.and_then(|index| self.settings.webhooks.get(index)).cloned();
        let has_secret = saved.as_ref().is_some_and(|webhook| !webhook.secret.is_empty());
        let saved = saved.unwrap_or(Webhook { kind: "webhook".into(), inspection: true, tasks: true, ..Default::default() });
        let secret = self.modal_input(if has_secret { "已保存；留空则不变" } else { "可选" }, "", false, cx);
        secret.update(cx, |input, _| input.masked = true);
        let form = WebhookForm { editing, name: self.modal_input("ops-alerts", &saved.name, false, cx), url: self.modal_input("https://…", &saved.url, false, cx), secret, kind: kind_key(&saved.kind), inspection: saved.inspection, tasks: saved.tasks, testing: false, tested: None };
        self.open_modal(Modal::Webhook(form), cx);
    }

    /// The webhook the dialog describes, its saved secret kept when the field is left empty.
    fn webhook_of(&self, form: &WebhookForm, cx: &App) -> Result<Webhook, String> {
        let name = form.name.read(cx).text().trim().to_string();
        let url = form.url.read(cx).text().trim().to_string();
        let typed = form.secret.read(cx).text().trim().to_string();
        if !wisp_ops_engine::config::is_valid_name(&name) { return Err(t("名称只能用字母、数字和 - _ .，以字母或数字开头。").into()) }
        if self.settings.webhooks.iter().enumerate().any(|(n, webhook)| Some(n) != form.editing && webhook.name == name) { return Err(tf!("已经有一个叫 {name} 的通知渠道。", "There is already a channel named {name}.")) }
        if url.is_empty() { return Err(t("填写 webhook 地址。").into()) }
        if notify::url_problem(&url).is_some() { return Err(t("地址要以 https:// 开头，且不能带用户名和密码（本机的 127.0.0.1 可以用 http://）。").into()) }
        let saved = form.editing.and_then(|index| self.settings.webhooks.get(index)).map(|webhook| webhook.secret.clone()).unwrap_or_default();
        let secret = if form.kind == "wecom" { String::new() } else if typed.is_empty() { saved } else { typed };
        Ok(Webhook { name, kind: form.kind.into(), url, secret, inspection: form.inspection, tasks: form.tasks })
    }

    pub fn submit_webhook(&mut self, cx: &mut Context<Self>) -> Result<(), String> {
        let Some(Modal::Webhook(form)) = self.modal.as_ref() else { return Ok(()) };
        let webhook = self.webhook_of(form, cx)?;
        match form.editing {
            Some(index) if index < self.settings.webhooks.len() => self.settings.webhooks[index] = webhook,
            _ => self.settings.webhooks.push(webhook),
        }
        self.save_webhooks(cx);
        Ok(())
    }

    /// 发送测试通知 from the dialog, with what is typed there, before it is saved.
    fn test_webhook_form(&mut self, cx: &mut Context<Self>) {
        let Some(Modal::Webhook(form)) = self.modal.as_ref() else { return };
        if form.testing { return }
        let webhook = match self.webhook_of(form, cx) {
            Ok(webhook) => webhook,
            Err(err) => {
                if let Some(Modal::Webhook(form)) = self.modal.as_mut() { form.tested = Some((err, true)) }
                return;
            }
        };
        if let Some(Modal::Webhook(form)) = self.modal.as_mut() {
            form.testing = true;
            form.tested = None;
        }
        let work = cx.background_executor().spawn(async move { crate::notify::test(&webhook) });
        cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                if let Some(Modal::Webhook(form)) = this.modal.as_mut() {
                    form.testing = false;
                    form.tested = Some(match result { Ok(()) => (t("测试通知已发出，对方已接收。").to_string(), false), Err(err) => (tf!("发送失败：{err}", "Failed: {err}"), true) });
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    pub fn webhook_form_body(&self, form: &WebhookForm, window: &Window, cx: &mut Context<Self>) -> (String, f32, Div, Option<String>, bool) {
        let field = |label: &str, input: &Entity<TextInput>, window: &Window, cx: &App| ui::form_row(t(label).to_string(), ui::field(input, window, cx));
        let kinds = segmented(KINDS.iter().map(|(key, label)| (div().id(SharedString::from(format!("webhook-kind-{key}"))).child(t(label).to_string()).on_click(self.on(Cmd::PickWebhookKind(key), cx)), form.kind == *key)).collect()).w(px(400.));
        let check = |id: &'static str, on: bool, label: &str, cmd: Cmd, cx: &mut Context<Self>| {
            div()
                .id(id)
                .flex()
                .items_center()
                .gap(px(8.))
                .cursor_pointer()
                .on_click(self.on(cmd, cx))
                .child(div().flex().flex_none().items_center().justify_center().size(px(16.)).rounded(px(4.)).border_1().border_color(if on { Theme::accent() } else { Theme::line_strong() }).when(on, |d| d.bg(Theme::accent()).child(ui::icon("check", 12., Theme::on_accent()))))
                .child(div().flex_1().min_w_0().child(t(label).to_string()))
        };
        let secret_label = match form.kind {
            "webhook" => "Bearer 令牌（可选，作为 Authorization 头发送）",
            _ => "加签密钥（可选，机器人开了「加签」时填写）",
        };
        let body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field("名称（字母、数字、- _ .）", &form.name, window, cx))
            .child(ui::form_row(t("类型").to_string(), kinds))
            .child(field("Webhook 地址（含令牌）", &form.url, window, cx))
            .when(form.kind != "wecom", |d| d.child(field(secret_label, &form.secret, window, cx)))
            .child(ui::form_row(t("发送什么").to_string(), div().flex().flex_col().gap(px(8.)).child(check("webhook-inspection", form.inspection, "自动巡检发现服务器状态变化（变差、不可达、恢复）", Cmd::ToggleWebhookEvent("inspection"), cx)).child(check("webhook-tasks", form.tasks, "例行任务的运行结果", Cmd::ToggleWebhookEvent("tasks"), cx))))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(ui::secondary_button("webhook-test", t("发送测试通知")).h(text_px(28.)).on_click(self.on(Cmd::TestWebhook(None), cx)))
                    .when(form.testing, |d| d.child(ui::spinner("webhook-testing", 14., Theme::accent())))
                    .when_some(form.tested.as_ref(), |d, (words, failed)| d.child(div().flex_1().min_w_0().text_size(text_px(12.)).line_height(text_px(18.)).text_color(if *failed { Theme::danger() } else { Theme::success() }).child(words.clone()))),
            )
            .child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("消息只含服务器名称、发现的问题和任务摘要，不含密码和凭据。地址和密钥明文保存在本机的 settings.json（仅本人可读）里，只发给这个地址，助手看不到。")));
        (if form.editing.is_some() { t("编辑通知渠道").to_string() } else { t("添加通知渠道").to_string() }, 560., body, Some(t("保存").to_string()), false)
    }

    /// The section of 设置 › 通用.
    pub fn render_webhooks(&self, cx: &mut Context<Self>) -> Div {
        let rows = self.settings.webhooks.iter().enumerate().map(|(n, webhook)| {
            let events: Vec<&str> = [(webhook.inspection, "状态变化"), (webhook.tasks, "例行任务")].into_iter().filter(|(on, _)| *on).map(|(_, label)| t(label)).collect();
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .h(text_px(40.))
                .px(px(10.))
                .rounded(px(8.))
                .border_1()
                .border_color(Theme::line())
                .child(div().flex_none().font_weight(FontWeight::MEDIUM).child(webhook.name.clone()))
                .child(ui::chip(t(kind_label(&webhook.kind)).to_string(), Theme::text_secondary(), Theme::bg_sunken()))
                .child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(notify::url_host(&webhook.url)))
                .child(div().flex_none().text_size(text_px(12.)).text_color(if events.is_empty() { Theme::warning() } else { Theme::text_secondary() }).child(if events.is_empty() { t("不发送").to_string() } else { events.join(" · ") }))
                .child(ui::ghost_button(("webhook-test", n), None, Some(t("测试").into())).h(text_px(24.)).text_size(text_px(12.)).on_click(self.on(Cmd::TestWebhook(Some(n)), cx)))
                .child(ui::ghost_button(("webhook-edit", n), None, Some(t("编辑").into())).h(text_px(24.)).text_size(text_px(12.)).on_click(self.on(Cmd::EditWebhook(n), cx)))
                .child(ui::icon_action(("webhook-remove", n), "x", Theme::text_tertiary(), t("删除这个通知渠道")).on_click(self.on(Cmd::RemoveWebhook(n), cx)))
                }).collect::<Vec<_>>();
        let mode = self.settings.webhook_tasks.as_str();
        let modes = segmented(vec![
            (div().id("webhook-tasks-always").child(t("每次运行")).on_click(self.on(Cmd::SetWebhookTasks("always"), cx)), mode == "always"),
            (div().id("webhook-tasks-problems").child(t("发现问题时")).on_click(self.on(Cmd::SetWebhookTasks("problems"), cx)), mode == "problems"),
            (div().id("webhook-tasks-change").child(t("问题有变化时")).on_click(self.on(Cmd::SetWebhookTasks("change"), cx)), mode == "change"),
        ])
        .w(px(360.));
        let last = crate::notify::last().filter(|_| !self.settings.webhooks.is_empty()).map(|last| {
            let at = last.at.get(..16).unwrap_or(&last.at).replace('T', " ");
            let event = if last.event == "inspection" { t("状态变化").to_string() } else { tf!("任务 {}", "task {}", last.event) };
            if last.failed.is_empty() {
                (tf!("上次通知 {at} UTC（{event}）：已发送", "Last notification {at} UTC ({event}): sent"), false)
            } else {
                let failed: Vec<String> = last.failed.iter().map(|(name, why)| if why.is_empty() { name.clone() } else { format!("{name}（{why}）") }).collect();
                (tf!("上次通知 {at} UTC（{event}）没有发到：{}", "Last notification {at} UTC ({event}) did not reach: {}", failed.join("、")), true)
            }
        });
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(div().flex().flex_col().child(div().font_weight(FontWeight::MEDIUM).child(t("外部通知"))).child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("把自动巡检发现的状态变化（变差、不可达、恢复）和例行任务的结果发到企业微信、钉钉、飞书或任何 webhook。第一次看到的状态只作基准，不发送；发送失败不影响巡检和任务。"))))
            .children(rows)
            .when(self.settings.webhooks.is_empty(), |d| d.child(div().text_color(Theme::text_tertiary()).child(t("还没有通知渠道。"))))
            .child(div().flex().items_center().gap(px(16.)).child(ui::secondary_button("webhook-add", t("添加通知渠道")).h(text_px(28.)).on_click(self.on(Cmd::AddWebhook, cx))))
            .child(div().flex().items_center().gap(px(16.)).child(div().w(px(120.)).flex_none().text_color(Theme::text_secondary()).child(t("例行任务"))).child(modes))
            .when_some(last, |d, (words, failed)| d.child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(if failed { Theme::warning() } else { Theme::text_tertiary() }).child(words)))
    }
}
