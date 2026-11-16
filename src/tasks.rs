//! 例行任务: a read-only check bound to some servers, run on demand or on
//! this window's timer. A run collects and records without the model; the
//! assistant is asked for a report only when the person wants one, and then
//! reads what was already collected (`ops_task mode=last`).

use crate::app::{Cmd, Workspace};
use crate::dialogs::{Modal, TaskForm, segmented};
use crate::i18n::t;
use crate::ops::TaskDraft;
use crate::servers::state_color;
use crate::theme::{Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::time;

/// The playbooks a task of the window can run, and what each is called.
pub const PLAYBOOKS: [(&str, &str, &str); 6] = [
    ("inspect", "健康巡检", "负载、内存、磁盘、失败的服务、GPU、作业队列"),
    ("disk", "磁盘诊断", "大目录和大文件、是否被占用、可回收的缓存"),
    ("space", "目录空间占用", "逐层统计目录大小，与上次比较增长"),
    ("new-files", "新增文件分析", "最近新增的文件：多少、在哪、是谁的、是什么"),
    ("security", "安全排查", "SSH 暴力破解、可疑进程和外连、异常账户"),
    ("custom", "自定义命令", "在每台服务器上执行你写的只读命令"),
];

pub fn playbook_label(key: &str) -> &'static str {
    PLAYBOOKS.iter().find(|(known, ..)| *known == key).map_or("检查脚本", |(_, label, _)| label)
}

impl Workspace {
    pub fn run_tasks(&mut self, cmd: Cmd, _: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            Cmd::AddTask => self.task_dialog(None, cx),
            Cmd::EditTask(name) => self.task_dialog(Some(name), cx),
            Cmd::DeleteTask(name) => self.confirm(t("删除任务"), tf!("删除例行任务「{name}」？它的运行记录保留。", "Delete task “{name}”? Its run records are kept."), t("删除"), Cmd::DeleteTask(name), cx),
            Cmd::RunTask(name) => self.run_task(name, false, cx),
            Cmd::ToggleTask(name) => {
                self.change(cx, |fleet| fleet.toggle_task(&name));
            }
            Cmd::PickPlaybook(playbook) => {
                if let Some(Modal::Task(form)) = self.modal.as_mut() { form.playbook = playbook }
            }
            Cmd::PickSchedule(schedule) => {
                if let Some(Modal::Task(form)) = self.modal.as_mut() { form.schedule = schedule }
            }
            Cmd::ToggleTaskSudo => {
                if let Some(Modal::Task(form)) = self.modal.as_mut() { form.sudo = !form.sudo }
            }
            _ => {}
        }
    }

    fn task_dialog(&mut self, editing: Option<String>, cx: &mut Context<Self>) {
        self.modal_subscriptions.clear();
        let known = editing.as_ref().and_then(|name| self.view.tasks.iter().find(|task| &task.name == name)).map(|task| task.draft.clone()).unwrap_or_else(|| TaskDraft { playbook: "inspect".into(), targets: "all".into(), daily: "08:30".into(), every_minutes: 60, schedule: "daily".into(), ..Default::default() });
        let form = TaskForm {
            name: self.modal_input("morning-check", &known.name, false, cx),
            description: self.modal_input("每天早上看一眼", &known.description, false, cx),
            targets: self.modal_input("all、@gpu、web-01,web-02", &known.targets, false, cx),
            playbook: PLAYBOOKS.iter().map(|(key, ..)| *key).find(|key| *key == known.playbook).unwrap_or("inspect"),
            paths: self.modal_input("/data, /home", &known.paths.join(", "), false, cx),
            instruction: self.modal_input("报告里要说什么、怎么判断正常", &known.instruction, true, cx),
            commands: self.modal_input("每行一条只读命令，例如：systemctl is-active nginx", &known.commands.join("\n"), true, cx),
            schedule: match known.schedule.as_str() { "daily" => "daily", "every" => "every", _ => "manual" },
            daily: self.modal_input("08:30", &known.daily, false, cx),
            every: self.modal_input("60", &known.every_minutes.to_string(), false, cx),
            sudo: known.sudo,
            editing,
        };
        self.open_modal(Modal::Task(form), cx);
    }

    pub fn submit_task(&mut self, _: &mut Window, cx: &mut Context<Self>) -> Result<(), String> {
        let Some(Modal::Task(form)) = self.modal.as_ref() else { return Ok(()) };
        let read = |input: &Entity<crate::input::TextInput>| input.read(cx).text().trim().to_string();
        let every = read(&form.every);
        let draft = TaskDraft {
            name: read(&form.name),
            description: read(&form.description),
            targets: read(&form.targets),
            playbook: form.playbook.into(),
            paths: read(&form.paths).split([',', '，', '\n']).map(str::trim).filter(|path| !path.is_empty()).map(String::from).collect(),
            instruction: read(&form.instruction),
            commands: read(&form.commands).lines().map(str::trim).filter(|line| !line.is_empty()).map(String::from).collect(),
            schedule: form.schedule.into(),
            daily: read(&form.daily),
            every_minutes: if form.schedule == "every" { every.parse::<u32>().ok().filter(|minutes| *minutes > 0).ok_or_else(|| t("间隔应是大于 0 的分钟数。").to_string())? } else { 60 },
            sudo: form.sudo,
        };
        self.fleet.save_task(form.editing.as_deref(), draft)?;
        self.reload(cx);
        Ok(())
    }

    /// Run a task now, off the main thread: collect, record, and say what came of it.
    pub fn run_task(&mut self, name: String, timed: bool, cx: &mut Context<Self>) {
        if !self.running_tasks.insert(name.clone()) { return }
        let fleet = self.fleet.clone();
        let task = cx.background_executor().spawn({
            let name = name.clone();
            async move { fleet.run_task(&name, timed) }
        });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                this.running_tasks.remove(&name);
                this.reload(cx);
                match result {
                    // A run on the timer says something only when it found something.
                    Ok((problems, summary)) if problems => this.fail(tf!("任务 {name} 发现问题：{summary}", "Task {name} found problems: {summary}"), cx),
                    Ok((_, summary)) if !timed => this.say(tf!("任务 {name} 完成：{summary}", "Task {name} done: {summary}"), cx),
                    Ok(_) => {}
                    Err(err) => this.fail(tf!("任务 {name} 没有运行：{err}", "Task {name} did not run: {err}"), cx),
                }
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// The tasks whose time has come (called every minute by `watch_fleet`).
    pub fn run_due_tasks(&mut self, cx: &mut Context<Self>) {
        for name in self.fleet.due_tasks() {
            self.run_task(name, true, cx);
        }
    }

    pub fn task_form_body(&self, form: &TaskForm, window: &Window, cx: &mut Context<Self>) -> (String, f32, Div, Option<String>, bool) {
        let field = |label: &str, input: &Entity<crate::input::TextInput>, window: &Window, cx: &App| ui::form_row(t(label).to_string(), ui::field(input, window, cx));
        let playbooks = div().flex().flex_wrap().gap(px(6.)).children(PLAYBOOKS.iter().map(|(key, label, about)| {
            let chosen = form.playbook == *key;
            div()
                .id(SharedString::from(format!("playbook-{key}")))
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
                .on_click(self.on(Cmd::PickPlaybook(key), cx))
                .child(div().font_weight(FontWeight::MEDIUM).child(t(label).to_string()))
                .child(div().text_size(text_px(11.)).line_height(text_px(15.)).text_color(Theme::text_tertiary()).child(t(about).to_string()))
        }));
        let schedules = segmented(vec![
            (div().id("schedule-manual").child(t("仅手动")).on_click(self.on(Cmd::PickSchedule("manual"), cx)), form.schedule == "manual"),
            (div().id("schedule-daily").child(t("每天")).on_click(self.on(Cmd::PickSchedule("daily"), cx)), form.schedule == "daily"),
            (div().id("schedule-every").child(t("固定间隔")).on_click(self.on(Cmd::PickSchedule("every"), cx)), form.schedule == "every"),
        ])
        .w(px(260.));
        let wants_paths = matches!(form.playbook, "disk" | "space" | "new-files");
        let body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(div().flex().gap(px(12.)).child(div().w(px(200.)).child(field("标识（字母、数字、- _ .）", &form.name, window, cx))).child(div().flex_1().child(field("说明", &form.description, window, cx))))
            .child(field("服务器（选择器）", &form.targets, window, cx))
            .child(ui::form_row(t("检查内容").to_string(), playbooks))
            .when(wants_paths, |d| d.child(field("路径（逗号分隔）", &form.paths, window, cx)))
            .child(field(if form.playbook == "custom" { "只读命令（每行一条）" } else { "附加的只读命令（可选，每行一条）" }, &form.commands, window, cx))
            .child(field("报告要求（助手汇报时照此写）", &form.instruction, window, cx))
            .child(div().flex().items_end().gap(px(12.)).child(ui::form_row(t("运行时间").to_string(), schedules)).when(form.schedule == "daily", |d| d.child(div().w(px(100.)).child(ui::field(&form.daily, window, cx)))).when(form.schedule == "every", |d| d.child(div().w(px(100.)).child(ui::field(&form.every, window, cx))).child(div().pb(px(8.)).text_color(Theme::text_tertiary()).child(t("分钟")))))
            .child(
                div()
                    .id("task-sudo")
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .cursor_pointer()
                    .on_click(self.on(Cmd::ToggleTaskSudo, cx))
                    .child(div().flex().flex_none().items_center().justify_center().size(px(16.)).rounded(px(4.)).border_1().border_color(if form.sudo { Theme::accent() } else { Theme::line_strong() }).when(form.sudo, |d| d.bg(Theme::accent()).child(ui::icon("check", 12., Theme::on_accent()))))
                    .child(t("用 sudo 运行采集器（预先授权这个任务的只读采集；服务器策略写了拒绝 sudo 时仍然拒绝）")),
            )
            .child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("任务只采集和记录，不做任何变更。命令在保存时按与助手相同的分类器校验，只接受只读命令。定时运行需要这个窗口开着。")));
        (if form.editing.is_some() { t("编辑例行任务").to_string() } else { t("新建例行任务").to_string() }, 620., body, Some(t("保存").to_string()), false)
    }

    pub fn render_tasks(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let actions = vec![ui::primary_button("task-add", t("新建任务")).child(ui::icon("plus", 14., Theme::on_accent())).on_click(self.on(Cmd::AddTask, cx)).into_any_element()];
        let body: AnyElement = if self.view.tasks.is_empty() {
            ui::empty_state("list-todo", t("还没有例行任务"), t("例行任务把一项只读检查（巡检、磁盘、新增文件、安全排查，或你写的只读命令）绑到一些服务器上，按时运行并记录。正常的运行不消耗模型；想看报告时再让助手读已经采集的结果。")).child(ui::primary_button("task-empty-add", t("新建任务")).on_click(self.on(Cmd::AddTask, cx))).into_any_element()
        } else {
            div()
                .id("tasks-list")
                .flex()
                .flex_col()
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .track_scroll(&self.page_scroll)
                .px(px(24.))
                .py(px(16.))
                .gap(px(10.))
                .children(self.view.tasks.iter().map(|task| {
                    let running = self.running_tasks.contains(&task.name);
                    let name = task.name.clone();
                    let state = task.last.as_ref().map_or("none", |last| if last.problems { "crit" } else { "ok" });
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(8.))
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
                                .child(if running { ui::spinner(SharedString::from(format!("task-running-{name}")), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(9.)).m(px(1.5)).rounded_full().bg(state_color(state)).into_any_element() })
                                .child(div().font_weight(FontWeight::MEDIUM).child(task.name.clone()))
                                .child(ui::chip(t(playbook_label(&task.draft.playbook)).to_string(), Theme::text_secondary(), Theme::groove()))
                                .when(task.draft.sudo, |d| d.child(ui::status_chip("sudo", "sudo")))
                                .child(div().flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(task.draft.description.clone()))
                                .when(task.scheduled, |d| {
                                    d.child(div().id(SharedString::from(format!("task-toggle-{name}"))).flex().items_center().gap(px(6.)).cursor_pointer().text_size(text_px(12.)).text_color(Theme::text_secondary()).on_click(self.on(Cmd::ToggleTask(name.clone()), cx)).child(if task.enabled { t("定时已启用") } else { t("定时未启用") }).child(crate::settings::switch(task.enabled)))
                                }),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap(px(16.))
                                .text_size(text_px(12.))
                                .line_height(text_px(18.))
                                .text_color(Theme::text_secondary())
                                .child(div().flex().gap(px(6.)).child(div().text_color(Theme::text_tertiary()).child(t("服务器"))).child(task.draft.targets.clone()))
                                .child(div().flex().gap(px(6.)).child(div().text_color(Theme::text_tertiary()).child(t("时间"))).child(task.when.clone()))
                                .when_some(task.next.as_ref().filter(|_| task.enabled), |d, next| d.child(div().flex().gap(px(6.)).child(div().text_color(Theme::text_tertiary()).child(t("下次"))).child(time::short_time(next))))
                                .when_some(task.last.as_ref(), |d, last| d.child(div().flex().gap(px(6.)).child(div().text_color(Theme::text_tertiary()).child(t("上次"))).child(time::short_time(&last.at)))),
                        )
                        .when_some(task.last.as_ref(), |d, last| d.child(div().px(px(10.)).py(px(6.)).rounded(px(6.)).bg(Theme::bg_sunken()).text_size(text_px(12.)).line_height(text_px(18.)).text_color(if last.problems { Theme::danger() } else { Theme::text_secondary() }).child(last.summary.clone())))
                        .when_some(task.error.as_ref(), |d, error| d.child(ui::error_line(error)))
                        .child(
                            div()
                                .flex()
                                .gap(px(6.))
                                .child(ui::secondary_button(SharedString::from(format!("task-run-{name}")), if running { t("正在运行…") } else { t("运行一次") }).h(text_px(28.)).when(running, |b| b.opacity(0.5)).on_click(self.on(Cmd::RunTask(name.clone()), cx)))
                                .when(task.last.is_some(), |d| d.child(ui::secondary_button(SharedString::from(format!("task-report-{name}")), t("让助手汇报")).h(text_px(28.)).child(ui::icon("sparkle", 12., Theme::accent())).on_click(self.on(Cmd::Suggest(tf!("读取例行任务 {name} 最近一次运行的结果（ops_task name={name} mode=last，不要重新运行），按它的要求写报告。", "Read the latest run of task {name} (ops_task name={name} mode=last; do not run it again) and write the report it asks for.")), cx))))
                                .child(div().flex_1())
                                .when(task.managed, |d| d.child(ui::ghost_button(SharedString::from(format!("task-edit-{name}")), Some("pen-line"), None).tooltip(ui::tip(t("编辑"))).on_click(self.on(Cmd::EditTask(name.clone()), cx))).child(ui::ghost_button(SharedString::from(format!("task-delete-{name}")), Some("bin"), None).tooltip(ui::tip(t("删除"))).on_click(self.on(Cmd::DeleteTask(name.clone()), cx))))
                                .when(!task.managed, |d| d.child(div().text_size(text_px(12.)).text_color(Theme::text_placeholder()).child(t("写在 inventory.yml 里")))),
                        )
                }))
                .into_any_element()
        };
        div().flex().flex_col().size_full().child(self.page_head(t("例行任务"), t("按时运行的只读检查：采集和记录不消耗模型，报告由助手按需来写"), actions, cx)).child(body).into_any_element()
    }
}
