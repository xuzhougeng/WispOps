//! 检查脚本: the second tab of 例行任务. The library of check scripts a person accepted, the
//! drafts the assistant proposed (`ops_script_draft`) waiting for review, and the way from an
//! accepted script to a routine task that runs it. Accepting is done here and only here.

use crate::app::{Cmd, Workspace};
use crate::check_scripts::{DraftRow, ScriptRow};
use crate::dialogs::Modal;
use crate::i18n::t;
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::time;
use wisp_ops_engine::check_scripts::CheckScript;

/// What the tab shows: whether it is the one on show, and the script or draft laid open.
#[derive(Default)]
pub struct ScriptsState {
    pub tab: bool,
    /// `draft:<id>` or `script:<id>`.
    pub open: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ScriptCmd {
    /// Show the scripts (true) or the tasks.
    Tab(bool),
    /// Lay a script or draft open to read it, or fold it again.
    Open(String),
    AskAccept(String),
    Accept(String),
    AskDeleteDraft(String),
    DeleteDraft(String),
    AskDelete(String),
    Delete(String),
    /// Open a new routine task that runs this script.
    UseInTask(String),
    /// In the task dialog: the script the task runs.
    PickForTask(String),
}

const CONTRACT: &str = "脚本约定：退出码 0 为正常、1 为警告、2 为严重，其他为脚本出错；第一行非空输出是摘要，其余是证据；可选的一行 WISPOPS-JSON: {\"名称\": 数值} 记录指标。";

impl Workspace {
    pub fn run_scripts(&mut self, cmd: ScriptCmd, _: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            ScriptCmd::Tab(on) => {
                self.scripts.tab = on;
                self.reload(cx);
            }
            ScriptCmd::Open(key) => self.scripts.open = if self.scripts.open.as_ref() == Some(&key) { None } else { Some(key) },
            ScriptCmd::AskAccept(id) => {
                let Some(row) = self.view.scripts.drafts.iter().find(|row| row.draft.id == id) else { return };
                let title = row.draft.script.title.clone();
                let message = if row.replaces { tf!("接受「{title}」并替换脚本库里的同名脚本？用它的例行任务以后运行新版本。接受后，例行任务会在服务器上无人值守地运行它，请确认读过全文。", "Accept “{title}” and replace the script of the same id in the library? Tasks that use it run the new version from now on. Once accepted, routine tasks run it on servers unattended: make sure you have read all of it.") } else { tf!("接受「{title}」进入脚本库？接受后，例行任务会在服务器上无人值守地运行它，请确认读过全文。", "Accept “{title}” into the script library? Once accepted, routine tasks run it on servers unattended: make sure you have read all of it.") };
                self.open_modal(Modal::Confirm { title: t("接受检查脚本").to_string(), message, label: t("接受").to_string(), danger: false, cmd: Cmd::Scripts(ScriptCmd::Accept(id)) }, cx);
            }
            ScriptCmd::Accept(id) => {
                let mut accepted = None;
                if self.change(cx, |fleet| fleet.accept_script_draft(&id).map(|script| accepted = Some(script.title))) && let Some(title) = accepted { self.say(tf!("已接受「{title}」", "Accepted “{title}”"), cx) }
            }
            ScriptCmd::AskDeleteDraft(id) => {
                let title = self.view.scripts.drafts.iter().find(|row| row.draft.id == id).map(|row| row.draft.script.title.clone()).unwrap_or_default();
                self.confirm(t("删除草稿"), tf!("删除草稿「{title}」？", "Delete the draft “{title}”?"), t("删除"), Cmd::Scripts(ScriptCmd::DeleteDraft(id)), cx);
            }
            ScriptCmd::DeleteDraft(id) => {
                if self.change(cx, |fleet| fleet.delete_script_draft(&id)) { self.say(t("已删除草稿"), cx) }
            }
            ScriptCmd::AskDelete(id) => self.confirm(t("删除检查脚本"), tf!("从脚本库删除「{id}」？", "Delete “{id}” from the script library?"), t("删除"), Cmd::Scripts(ScriptCmd::Delete(id)), cx),
            ScriptCmd::Delete(id) => {
                if self.change(cx, |fleet| fleet.delete_script(&id)) { self.say(tf!("已删除脚本 {id}", "Deleted script {id}"), cx) }
            }
            ScriptCmd::UseInTask(id) => {
                let Some(row) = self.view.scripts.scripts.iter().find(|row| row.script.id == id) else { return };
                let draft = crate::ops::TaskDraft { name: id.clone(), description: row.script.title.clone(), playbook: "script".into(), script: id, targets: "all".into(), daily: "08:30".into(), every_minutes: 60, schedule: "daily".into(), ..Default::default() };
                self.task_dialog_with(None, draft, cx);
            }
            ScriptCmd::PickForTask(id) => {
                if let Some(Modal::Task(form)) = self.modal.as_mut() { form.script = id }
            }
        }
    }

    /// The tab switch of 例行任务, with the number of drafts waiting.
    pub fn tasks_tabs(&self, cx: &mut Context<Self>) -> AnyElement {
        let waiting = self.view.scripts.drafts.len();
        let scripts = if waiting == 0 { t("检查脚本").to_string() } else { tf!("检查脚本 · {waiting} 份待审", "Check scripts · {waiting} to review") };
        crate::dialogs::segmented(vec![
            (div().id("tasks-tab-tasks").child(t("任务列表")).on_click(self.on(Cmd::Scripts(ScriptCmd::Tab(false)), cx)), !self.scripts.tab),
            (div().id("tasks-tab-scripts").child(scripts).on_click(self.on(Cmd::Scripts(ScriptCmd::Tab(true)), cx)), self.scripts.tab),
        ])
        .into_any_element()
    }

    /// The accepted scripts a task can run, as choices in the task dialog.
    pub fn script_choices(&self, picked: &str, cx: &mut Context<Self>) -> Div {
        let scripts = &self.view.scripts.scripts;
        if scripts.is_empty() { return div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("脚本库还是空的：先在「检查脚本」里接受一份草稿。")) }
        div().flex().flex_wrap().gap(px(6.)).children(scripts.iter().map(|row| {
            let chosen = row.script.id == picked;
            div()
                .id(SharedString::from(format!("task-script-{}", row.script.id)))
                .flex()
                .flex_col()
                .w(px(178.))
                .px(px(10.))
                .py(px(7.))
                .rounded(px(8.))
                .border_1()
                .border_color(if chosen { Theme::accent() } else { Theme::line() })
                .when(chosen, |d| d.bg(Theme::accent_soft()))
                .cursor_pointer()
                .hover(|s| s.bg(Theme::hover()))
                .on_click(self.on(Cmd::Scripts(ScriptCmd::PickForTask(row.script.id.clone())), cx))
                .child(div().truncate().font_weight(FontWeight::MEDIUM).child(row.script.title.clone()))
                .child(div().truncate().text_size(text_px(11.)).line_height(text_px(15.)).text_color(if row.refusal.is_some() { Theme::danger() } else { Theme::text_tertiary() }).child(if row.refusal.is_some() { t("现在不能运行").to_string() } else { row.script.id.clone() }))
        }))
    }

    pub fn render_scripts(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let library = &self.view.scripts;
        let ask = t("帮我写一个只读的检查脚本，用 ops_script_draft 提交草稿：检查");
        let actions = vec![self.tasks_tabs(cx), ui::secondary_button("script-ask", t("让助手起草")).child(ui::icon("sparkle", 12., Theme::accent())).on_click(self.on(Cmd::Draft(ask.to_string()), cx)).into_any_element()];
        let body: AnyElement = if library.scripts.is_empty() && library.drafts.is_empty() && library.error.is_none() {
            ui::empty_state("file-text", t("还没有检查脚本"), t("检查脚本是一段只读的 shell 脚本，由例行任务在服务器上运行，按退出码判断正常、警告或严重。让助手起草，草稿会出现在这里，你读过并接受后才能使用。"))
                .child(ui::primary_button("script-empty-ask", t("让助手起草")).on_click(self.on(Cmd::Draft(ask.to_string()), cx)))
                .into_any_element()
        } else {
            let drafts: Vec<AnyElement> = library.drafts.iter().map(|row| self.draft_card(row, cx)).collect();
            let scripts: Vec<AnyElement> = library.scripts.iter().map(|row| self.script_card(row, cx)).collect();
            div()
                .id("scripts-list")
                .flex()
                .flex_col()
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .track_scroll(&self.page_scroll)
                .px(px(24.))
                .py(px(16.))
                .gap(px(10.))
                .when_some(library.error.as_ref(), |d, error| d.child(div().max_w(px(900.)).child(ui::error_line(error))))
                .when(!drafts.is_empty(), |d| d.child(ui::caption(tf!("待审核的草稿（{}）", "Drafts to review ({})", drafts.len()))).children(drafts))
                .child(div().when(!library.drafts.is_empty(), |d| d.pt(px(8.))).child(ui::caption(tf!("脚本库（{}）", "Script library ({})", scripts.len()))))
                .when(scripts.is_empty(), |d| d.child(div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("还没有接受的脚本。"))))
                .children(scripts)
                .child(div().max_w(px(900.)).pt(px(6.)).text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t(CONTRACT)))
                .into_any_element()
        };
        div().flex().flex_col().size_full().child(self.page_head(t("例行任务"), t("检查脚本：助手起草，你读过并接受后，例行任务才能运行它"), actions, cx)).child(body).into_any_element()
    }

    fn draft_card(&self, row: &DraftRow, cx: &mut Context<Self>) -> AnyElement {
        let id = row.draft.id.clone();
        let key = format!("draft:{id}");
        let refused = row.refusal.is_some();
        card(&key, &row.draft.script, tf!("草稿 · {}", "Draft · {}", time::short_time(&row.draft.created_at)), self.scripts.open.as_ref() == Some(&key))
            .when(row.replaces, |d| d.child(div().text_size(text_px(12.)).text_color(Theme::warning()).child(t("接受后会替换脚本库里的同名脚本。"))))
            .when_some(row.refusal.as_ref(), |d, reason| d.child(ui::error_line(&tf!("不能接受：{reason}", "Cannot be accepted: {reason}"))))
            .child(
                div()
                    .flex()
                    .gap(px(6.))
                    .child(ui::primary_button(SharedString::from(format!("draft-accept-{id}")), t("接受")).h(text_px(28.)).when(refused, |b| b.opacity(0.5)).when(!refused, |b| b.on_click(self.on(Cmd::Scripts(ScriptCmd::AskAccept(id.clone())), cx))))
                    .when(long(&row.draft.script), |d| d.child(open_button(&key, self.scripts.open.as_ref() == Some(&key), self, cx)))
                    .child(div().flex_1())
                    .child(ui::ghost_button(SharedString::from(format!("draft-delete-{id}")), Some("bin"), None).tooltip(ui::tip(t("删除草稿"))).on_click(self.on(Cmd::Scripts(ScriptCmd::AskDeleteDraft(id.clone())), cx))),
            )
            .into_any_element()
    }

    fn script_card(&self, row: &ScriptRow, cx: &mut Context<Self>) -> AnyElement {
        let id = row.script.id.clone();
        let key = format!("script:{id}");
        card(&key, &row.script, tf!("更新于 {}", "Updated {}", time::short_time(&row.script.updated_at)), self.scripts.open.as_ref() == Some(&key))
            .when(!row.used_by.is_empty(), |d| d.child(div().flex().gap(px(6.)).text_size(text_px(12.)).child(div().text_color(Theme::text_tertiary()).child(t("例行任务"))).child(div().text_color(Theme::text_secondary()).child(row.used_by.join(", ")))))
            .when_some(row.refusal.as_ref(), |d, reason| d.child(ui::error_line(&tf!("现在不能运行：{reason}", "Cannot run now: {reason}"))))
            .child(
                div()
                    .flex()
                    .gap(px(6.))
                    .child(ui::secondary_button(SharedString::from(format!("script-use-{id}")), t("用作例行任务")).h(text_px(28.)).child(ui::icon("list-todo", 12., Theme::text_secondary())).on_click(self.on(Cmd::Scripts(ScriptCmd::UseInTask(id.clone())), cx)))
                    .when(long(&row.script), |d| d.child(open_button(&key, self.scripts.open.as_ref() == Some(&key), self, cx)))
                    .child(div().flex_1())
                    .child(ui::ghost_button(SharedString::from(format!("script-delete-{id}")), Some("bin"), None).tooltip(ui::tip(t("删除"))).on_click(self.on(Cmd::Scripts(ScriptCmd::AskDelete(id.clone())), cx))),
            )
            .into_any_element()
    }
}

/// A script's card: title, id, digest, timeout, the line about it, and its text (its head while folded).
/// Lines are not wrapped (a wrapped line is measured short in the scrolling list): long ones scroll sideways.
fn card(key: &str, script: &CheckScript, when: String, open: bool) -> Div {
    let lines: Vec<&str> = script.content.lines().collect();
    let shown = if open || !long(script) { script.content.trim_end().to_string() } else { format!("{}\n…", lines[..6].join("\n")) };
    div()
        .flex()
        .flex_none()
        .flex_col()
        .gap(px(8.))
        .w_full()
        .max_w(px(900.))
        .px(px(14.))
        .py(px(12.))
        .rounded(px(10.))
        .border_1()
        .border_color(Theme::line())
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(div().flex_none().font_weight(FontWeight::MEDIUM).child(script.title.clone()))
                .child(ui::chip(script.id.clone(), Theme::text_secondary(), Theme::groove()))
                .child(div().flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(script.description.clone()))
                .child(div().flex_none().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("超时 {} 秒 · sha256 {} · {when}", "Timeout {} s · sha256 {} · {when}", script.timeout_sec, &script.sha256[..12]))),
        )
        .child(div().id(SharedString::from(format!("script-text-{key}"))).w_full().overflow_x_scroll().whitespace_nowrap().px(px(10.)).py(px(8.)).rounded(px(6.)).bg(Theme::bg_sunken()).font_family(theme::MONO_FONT).text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_secondary()).child(shown))
}

/// Whether a folded card shows only the head of the script.
fn long(script: &CheckScript) -> bool {
    script.content.lines().count() > 8
}

fn open_button(key: &str, open: bool, this: &Workspace, cx: &mut Context<Workspace>) -> Stateful<Div> {
    ui::ghost_button(SharedString::from(format!("script-open-{key}")), Some(if open { "chevron-up" } else { "chevron-down" }), Some(if open { t("收起") } else { t("查看全文") }.into())).on_click(this.on(Cmd::Scripts(ScriptCmd::Open(key.to_string())), cx))
}
