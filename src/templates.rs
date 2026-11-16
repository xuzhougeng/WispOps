//! 任务模板库: reusable read-only checks without servers or sudo. A task can start
//! from one (built-in, saved, or a draft the assistant proposed and the person saved);
//! a task can be kept as one. The model only proposes drafts (`ops_template_draft`):
//! saving a draft, linking servers and scheduling stay in the window.

use crate::app::{Cmd, Workspace};
use crate::dialogs::{Modal, TaskForm};
use crate::i18n::t;
use crate::input::TextInput;
use crate::ops::{Fleet, TaskDraft};
use crate::theme::{Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use wisp_ops_core::time;
use wisp_ops_engine::config::{MAX_TASK_COMMANDS, TaskSchedule, TaskSpec};
use wisp_ops_engine::templates::{self, TEMPLATE_REPORT_RULES, TaskTemplate, TemplateDefinition, TemplateDraft, TemplateLimits, TemplateParameter};

/// The library as the window draws it.
#[derive(Clone, Debug, Default)]
pub struct Library {
    /// Built-in first, then the person's own, each with how many tasks came from it.
    pub templates: Vec<(TaskTemplate, usize)>,
    /// Oldest first, as queued.
    pub drafts: Vec<TemplateDraft>,
    pub error: Option<String>,
}

/// What a task form carries without showing it, kept as it was; and, for a task being made
/// from a template, the template and the values its parameters take.
#[derive(Default)]
pub struct TaskOrigin {
    pub template: Option<String>,
    pub days: Option<u64>,
    pub hours: Option<u64>,
    pub filling: Option<Filling>,
}

pub struct Filling {
    pub template: TaskTemplate,
    pub values: Vec<(TemplateParameter, Entity<TextInput>)>,
}

impl TaskOrigin {
    pub fn of(draft: &TaskDraft) -> TaskOrigin {
        TaskOrigin { template: draft.template.clone(), days: draft.days, hours: draft.hours, filling: None }
    }

    pub fn inputs(&self) -> Vec<&Entity<TextInput>> {
        self.filling.iter().flat_map(|filling| filling.values.iter().map(|(_, input)| input)).collect()
    }
}

/// A template being saved to the library: from a task, or a draft under review.
pub struct TemplateForm {
    /// What is kept as it is: playbook, paths, windows, schedule, parameters.
    pub source: TaskTemplate,
    /// The draft this saves, which then leaves the queue.
    pub draft: Option<String>,
    pub id: Entity<TextInput>,
    pub title: Entity<TextInput>,
    pub category: Entity<TextInput>,
    pub description: Entity<TextInput>,
    pub instruction: Entity<TextInput>,
    pub commands: Entity<TextInput>,
}

impl TemplateForm {
    pub fn inputs(&self) -> Vec<&Entity<TextInput>> {
        let TemplateForm { source: _, draft: _, id, title, category, description, instruction, commands } = self;
        vec![id, title, category, description, instruction, commands]
    }
}

impl Fleet {
    fn template_limits(&self) -> TemplateLimits {
        TemplateLimits { disk_warn_pct: self.thresholds.disk_warn_pct, disk_crit_pct: self.thresholds.disk_crit_pct, inode_warn_pct: self.thresholds.inode_warn_pct, gpu_temp_warn_c: self.thresholds.gpu_temp_warn_c }
    }

    /// The library and the drafts; `tasks` are the inventory's, to count which came from what.
    pub fn templates(&self, tasks: &[TaskSpec]) -> Library {
        let mut error = None;
        let all = templates::library(self.data_dir(), &self.template_limits(), &self.config.time_zone).unwrap_or_else(|failed| {
            error = Some(failed);
            templates::builtin_templates(&self.template_limits(), &self.config.time_zone)
        });
        let drafts = templates::draft_store(self.data_dir()).read().map(|read| read.value.entries).unwrap_or_else(|failed| {
            error.get_or_insert(failed);
            vec![]
        });
        let templates = all.into_iter().map(|template| {
            let uses = tasks.iter().filter(|task| task.template.as_deref() == Some(template.id.as_str())).count();
            (template, uses)
        }).collect();
        Library { templates, drafts, error }
    }

    pub fn save_template(&self, template: &Value, draft: Option<&str>) -> Result<(), String> {
        templates::save_template(self.data_dir(), template, false, draft, &self.extra_read).map(|_| ())
    }

    pub fn delete_template(&self, id: &str) -> Result<(), String> {
        templates::delete_template(self.data_dir(), id)
    }

    pub fn discard_template_draft(&self, id: &str) -> Result<(), String> {
        templates::discard_draft(self.data_dir(), id)
    }

    /// `ops_template_draft`: queue a draft for the person. Nothing is saved to the library,
    /// no server is linked and nothing is scheduled or run.
    pub fn draft_template(&self, args: &Value) -> Result<String, String> {
        let id = args["id"].as_str().unwrap_or("");
        if templates::library(self.data_dir(), &self.template_limits(), &self.config.time_zone)?.iter().any(|template| template.id == id) { return Err(format!("template id \"{id}\" is already in the task library; choose another id")) }
        let mut definition = json!({"playbook": args["playbook"], "instruction": args["instruction"], "schedule": {"daily": args["daily"].as_str().unwrap_or("08:30"), "timeZone": args["timeZone"].as_str().unwrap_or(&self.config.time_zone)}});
        for key in ["paths", "days", "hours", "commands", "script"] {
            if !args[key].is_null() { definition[key] = args[key].clone() }
        }
        let template = json!({"id": args["id"], "title": args["title"], "category": args["category"], "description": args["description"], "parameters": if args["parameters"].is_null() { json!([]) } else { args["parameters"].clone() }, "definition": definition});
        let draft = templates::add_template_draft(self.data_dir(), &template, &self.extra_read, wisp_ops_engine::time::now_ms())?;
        Ok(format!("Draft \"{}\" ({}) is waiting for review. Nothing was added to the task library and no task was created: ask the user to open WispOps → Tasks → 从模板新建 (New from template), check the draft under \"assistant's drafts\" and save it; they then link servers to it when creating a task.", draft.template.title, draft.template.id))
    }
}

/// The task form a template opens with; the instruction and commands keep their `{{key}}` placeholders until it is saved.
fn draft_from(template: &TaskTemplate) -> TaskDraft {
    let definition = &template.definition;
    let schedule = definition.schedule.as_ref();
    TaskDraft {
        name: template.id.trim_start_matches("builtin.").to_string(),
        description: t(&template.title).to_string(),
        targets: "all".into(),
        playbook: definition.playbook.as_str().into(),
        paths: definition.paths.clone(),
        instruction: definition.instruction.clone(),
        commands: definition.commands.clone(),
        schedule: match schedule { Some(schedule) if schedule.cron.is_some() => "cron", Some(schedule) if schedule.daily.is_some() => "daily", Some(schedule) if schedule.every_minutes.is_some() => "every", _ => "manual" }.into(),
        daily: schedule.and_then(|schedule| schedule.daily.clone()).unwrap_or_else(|| "08:30".into()),
        weekdays: schedule.map(|schedule| schedule.weekdays.clone()).unwrap_or_default(),
        every_minutes: schedule.and_then(|schedule| schedule.every_minutes).unwrap_or(60) as u32,
        time_zone: schedule.and_then(|schedule| schedule.time_zone.clone()),
        cron: schedule.and_then(|schedule| schedule.cron.clone()).unwrap_or_else(|| crate::ops::DEFAULT_CRON.into()),
        sudo: false,
        // The template names the script; whether this device has accepted it is checked when the task is saved.
        script: definition.script.clone().unwrap_or_default(),
        days: definition.days,
        hours: definition.hours,
        template: Some(template.id.clone()),
    }
}

/// A task kept as a template: what it does, without its servers, sudo or name.
fn template_of_task(task: &TaskSpec) -> TaskTemplate {
    // A task made from a template carries the report rules already; they are added again when the template is used.
    let instruction = task.instruction.clone().unwrap_or_default();
    let instruction = instruction.strip_suffix(TEMPLATE_REPORT_RULES).map(String::from).unwrap_or(instruction);
    let schedule = task.schedule.clone().filter(TaskSchedule::is_timed);
    TaskTemplate {
        id: task.name.clone(),
        title: task.description.clone().unwrap_or_else(|| task.name.clone()),
        description: task.description.clone().unwrap_or_default(),
        category: t("自定义").to_string(),
        definition: TemplateDefinition { playbook: task.playbook, instruction, paths: task.paths.clone(), days: task.days, hours: task.hours, schedule, commands: task.commands.clone(), script: task.script.clone() },
        parameters: vec![],
    }
}

fn lines(input: &Entity<TextInput>, cx: &App) -> Vec<String> {
    input.read(cx).text().lines().map(str::trim).filter(|line| !line.is_empty()).map(String::from).collect()
}

impl Workspace {
    pub fn run_templates(&mut self, cmd: Cmd, _: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            Cmd::OpenTemplates => {
                self.reload(cx);
                self.modal_subscriptions.clear();
                self.open_modal(Modal::Templates, cx);
            }
            Cmd::UseTemplate(id) => {
                let Some((template, _)) = self.view.templates.templates.iter().find(|(template, _)| template.id == id).cloned() else { return self.fail(t("模板已不存在，请刷新任务库。"), cx) };
                self.task_dialog_with(None, draft_from(&template), cx);
                let values = template.parameters.iter().map(|parameter| (parameter.clone(), self.modal_input("", parameter.default_value.as_deref().unwrap_or(""), parameter.key == "urls", cx))).collect();
                if let Some(Modal::Task(form)) = self.modal.as_mut() { form.origin.filling = Some(Filling { template, values }) }
            }
            Cmd::SaveAsTemplate(name) => {
                let Some(task) = self.fleet.inventory().task(&name).cloned() else { return };
                self.template_dialog(template_of_task(&task), None, cx);
            }
            Cmd::ReviewDraft(id) => {
                let Some(draft) = self.view.templates.drafts.iter().find(|draft| draft.id == id).cloned() else { return };
                self.template_dialog(draft.template, Some(draft.id), cx);
            }
            Cmd::DiscardDraft(id) => {
                let discarded = self.change(cx, |fleet| fleet.discard_template_draft(&id));
                if discarded { self.say(t("草稿已删除。"), cx) }
            }
            Cmd::AskDeleteTemplate(id) => {
                let title = self.view.templates.templates.iter().find(|(template, _)| template.id == id).map(|(template, _)| template.title.clone()).unwrap_or_else(|| id.clone());
                self.confirm(t("删除模板"), tf!("删除模板「{title}」？用它建的任务保留各自的规则。", "Delete template “{title}”? Tasks made from it keep their own rules."), t("删除"), Cmd::DeleteTemplate(id), cx);
            }
            Cmd::DeleteTemplate(id) => {
                let deleted = self.change(cx, |fleet| fleet.delete_template(&id));
                if deleted { self.say(t("模板已删除。"), cx) }
            }
            _ => {}
        }
    }

    fn template_dialog(&mut self, source: TaskTemplate, draft: Option<String>, cx: &mut Context<Self>) {
        self.modal_subscriptions.clear();
        let form = TemplateForm {
            id: self.modal_input("nginx-health", &source.id, false, cx),
            title: self.modal_input("模板名称", &source.title, false, cx),
            category: self.modal_input("基础运维、安全、应用服务…", &source.category, false, cx),
            description: self.modal_input("一句话说明", &source.description, false, cx),
            instruction: self.modal_input("检查什么、怎么判断、怎么汇报", &source.definition.instruction, true, cx),
            commands: self.modal_input("每行一条只读命令", &source.definition.commands.join("\n"), true, cx),
            source,
            draft,
        };
        self.open_modal(Modal::Template(form), cx);
    }

    pub fn submit_template(&mut self, _: &mut Window, cx: &mut Context<Self>) -> Result<(), String> {
        let Some(Modal::Template(form)) = self.modal.as_ref() else { return Ok(()) };
        let read = |input: &Entity<TextInput>| input.read(cx).text().trim().to_string();
        let mut template = serde_json::to_value(&form.source).map_err(|error| error.to_string())?;
        template["id"] = json!(read(&form.id));
        template["title"] = json!(read(&form.title));
        template["category"] = json!(read(&form.category));
        template["description"] = json!(read(&form.description));
        template["definition"]["instruction"] = json!(read(&form.instruction));
        template["definition"]["commands"] = json!(lines(&form.commands, cx));
        let draft = form.draft.clone();
        self.fleet.save_template(&template, draft.as_deref())?;
        self.reload(cx);
        self.say(t("已保存到任务模板库。新建任务时可以从它开始；已有的任务不会改变。"), cx);
        Ok(())
    }

    /// A task form opened from a template: its parameters' values put into the instruction and commands.
    pub fn fill_from_template(form: &TaskForm, mut draft: TaskDraft, cx: &App) -> Result<TaskDraft, String> {
        let Some(filling) = &form.origin.filling else { return Ok(draft) };
        let values: BTreeMap<String, String> = filling.values.iter().map(|(parameter, input)| (parameter.key.clone(), input.read(cx).text().to_string())).collect();
        let (instruction, commands) = templates::fill(&filling.template, &draft.instruction, &draft.commands, &values)?;
        if commands.len() > MAX_TASK_COMMANDS { return Err(tf!("最多 {MAX_TASK_COMMANDS} 条命令。", "At most {MAX_TASK_COMMANDS} commands.")) }
        draft.instruction = instruction;
        draft.commands = commands;
        draft.template = Some(filling.template.id.clone());
        Ok(draft)
    }

    /// The parameters of the template a new task starts from, drawn in its form.
    pub fn template_fields(&self, form: &TaskForm, window: &Window, cx: &App) -> Option<Div> {
        let filling = form.origin.filling.as_ref()?;
        Some(
            div()
                .flex()
                .flex_col()
                .gap(px(10.))
                .px(px(12.))
                .py(px(10.))
                .rounded(px(8.))
                .bg(Theme::bg_sunken())
                .child(div().flex().items_center().gap(px(6.)).child(ui::icon("library", 13., Theme::accent())).child(div().font_weight(FontWeight::MEDIUM).child(tf!("来自模板「{}」", "From template “{}”", t(&filling.template.title)))))
                .children(filling.values.iter().map(|(parameter, input)| {
                    let label = if parameter.required { format!("{} *", t(&parameter.label)) } else { t(&parameter.label).to_string() };
                    ui::form_row(label, div().flex().flex_col().gap(px(4.)).child(ui::field(input, window, cx)).when(!parameter.hint.is_empty(), |d| d.child(div().text_size(text_px(11.)).line_height(text_px(15.)).text_color(Theme::text_tertiary()).child(t(&parameter.hint).to_string()))))
                }))
                .child(div().text_size(text_px(11.)).line_height(text_px(16.)).text_color(Theme::text_tertiary()).child(t("报告要求和命令里的 {{参数}} 在保存时换成这里填的值；在命令里它是一个加了引号的词，不会多出一条命令。模板以后改动或删除，这个任务不受影响。"))),
        )
    }

    /// The library: drafts the assistant proposed, then every template by category.
    pub fn template_library_body(&self, cx: &mut Context<Self>) -> (String, f32, Div, Option<String>, bool) {
        let library = &self.view.templates;
        let small = |text: String| div().text_size(text_px(12.)).line_height(text_px(17.)).text_color(Theme::text_tertiary()).child(text);
        let row = || div().flex().items_center().gap(px(10.)).px(px(12.)).py(px(9.)).rounded(px(8.)).border_1().border_color(Theme::line());
        let mut body = div().flex().flex_col().gap(px(8.)).when_some(library.error.as_ref(), |d, error| d.child(ui::error_line(error)));
        if !library.drafts.is_empty() {
            body = body.child(ui::caption(tf!("助手提议的草稿（{}）", "The assistant's drafts ({})", library.drafts.len()))).children(library.drafts.iter().rev().map(|draft| {
                let id = draft.id.clone();
                row()
                    .border_color(Theme::accent())
                    .child(ui::icon("sparkle", 14., Theme::accent()))
                    .child(div().flex().flex_col().flex_1().min_w_0().child(div().font_weight(FontWeight::MEDIUM).truncate().child(draft.template.title.clone())).child(small(format!("{} · {} · {}", draft.template.id, draft.template.category, time::short_time(&draft.created_at)))).when(!draft.template.description.is_empty(), |d| d.child(small(draft.template.description.clone()))))
                    .child(ui::secondary_button(SharedString::from(format!("draft-review-{id}")), t("审核保存")).h(text_px(28.)).on_click(self.on(Cmd::ReviewDraft(id.clone()), cx)))
                    .child(ui::ghost_button(SharedString::from(format!("draft-discard-{id}")), Some("bin"), None).tooltip(ui::tip(t("删除草稿"))).on_click(self.on(Cmd::DiscardDraft(id), cx)))
            })).child(small(t("草稿不会自己变成任务：审核保存后进入模板库，新建任务时再选服务器。").to_string()));
        }
        let mut categories: Vec<&str> = vec![];
        for (template, _) in &library.templates {
            if !categories.contains(&template.category.as_str()) { categories.push(&template.category) }
        }
        for category in categories {
            body = body.child(div().pt(px(6.)).child(ui::caption(t(category).to_string()))).children(library.templates.iter().filter(|(template, _)| template.category == category).map(|(template, uses)| {
                let id = template.id.clone();
                row()
                    .id(SharedString::from(format!("template-{id}")))
                    .cursor_pointer()
                    .hover(|s| s.bg(Theme::hover()))
                    .on_click(self.on(Cmd::UseTemplate(id.clone()), cx))
                    .child(div().flex().flex_col().flex_1().min_w_0().child(div().flex().items_center().gap(px(6.)).child(div().font_weight(FontWeight::MEDIUM).child(t(&template.title).to_string())).child(ui::chip(t(crate::tasks::playbook_label(template.definition.playbook.as_str())).to_string(), Theme::text_secondary(), Theme::groove())).when(*uses > 0, |d| d.child(small(tf!("{uses} 个任务在用", "used by {uses} task(s)"))))).child(small(t(&template.description).to_string())))
                    .when(!template.builtin(), |d| d.child(ui::ghost_button(SharedString::from(format!("template-delete-{id}")), Some("bin"), None).tooltip(ui::tip(t("删除模板"))).on_click(self.on_within(Cmd::AskDeleteTemplate(id.clone()), cx))))
                    .child(ui::icon("chevron-right", 14., Theme::text_tertiary()))
            }));
        }
        (t("从模板新建任务").to_string(), 640., body, Some(t("空白任务").to_string()), false)
    }

    pub fn template_form_body(&self, form: &TemplateForm, window: &Window, cx: &mut Context<Self>) -> (String, f32, Div, Option<String>, bool) {
        let field = |label: &str, input: &Entity<TextInput>, window: &Window, cx: &App| ui::form_row(t(label).to_string(), ui::field(input, window, cx));
        let definition = &form.source.definition;
        let mut kept = vec![tf!("检查内容：{}", "Check: {}", t(crate::tasks::playbook_label(definition.playbook.as_str())))];
        if !definition.paths.is_empty() { kept.push(tf!("路径：{}", "Paths: {}", definition.paths.join(", "))) }
        if let Some(days) = definition.days { kept.push(tf!("回看 {days} 天", "Look back {days} day(s)")) }
        if let Some(hours) = definition.hours { kept.push(tf!("回溯 {hours} 小时", "Look back {hours} hour(s)")) }
        if let Some(daily) = definition.schedule.as_ref().and_then(|schedule| schedule.daily.as_ref()) { kept.push(tf!("建议每天 {daily}", "Suggested daily at {daily}")) }
        if !form.source.parameters.is_empty() { kept.push(tf!("参数：{}", "Parameters: {}", form.source.parameters.iter().map(|parameter| format!("{{{{{}}}}} {}", parameter.key, parameter.label)).collect::<Vec<_>>().join("、"))) }
        let body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .when(form.draft.is_some(), |d| d.child(div().flex().items_center().gap(px(6.)).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(ui::icon("sparkle", 12., Theme::accent())).child(t("这是助手提议的草稿。看过、改好后保存到模板库；它不会自己关联服务器或运行。"))))
            .child(div().flex().gap(px(12.)).child(div().w(px(200.)).child(field("标识（字母、数字、- _ .）", &form.id, window, cx))).child(div().flex_1().child(field("名称", &form.title, window, cx))))
            .child(div().flex().gap(px(12.)).child(div().w(px(200.)).child(field("分类", &form.category, window, cx))).child(div().flex_1().child(field("说明", &form.description, window, cx))))
            .child(field("报告要求（检查什么、怎么判断）", &form.instruction, window, cx))
            .child(field("只读命令（每行一条，可用 {{参数}}）", &form.commands, window, cx))
            .child(div().px(px(10.)).py(px(7.)).rounded(px(6.)).bg(Theme::bg_sunken()).text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_secondary()).child(kept.join(" · ")))
            .child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(t("模板不保存服务器和 sudo；命令在保存时按与助手相同的分类器校验，只接受只读命令。")));
        (if form.draft.is_some() { t("审核模板草稿").to_string() } else { t("存为模板").to_string() }, 620., body, Some(t("保存到模板库").to_string()), false)
    }

    /// A line on the tasks page while the assistant's drafts wait.
    pub fn drafts_band(&self, cx: &mut Context<Self>) -> Option<Div> {
        let count = self.view.templates.drafts.len();
        (count > 0).then(|| {
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .mx(px(24.))
                .mt(px(12.))
                .px(px(12.))
                .py(px(8.))
                .max_w(px(900.))
                .rounded(px(8.))
                .bg(Theme::accent_soft())
                .text_size(text_px(12.))
                .child(ui::icon("sparkle", 13., Theme::accent()))
                .child(div().flex_1().child(tf!("助手提议了 {count} 个任务模板草稿，等你审核。", "The assistant proposed {count} task template draft(s) for you to review.")))
                .child(ui::secondary_button("drafts-open", t("查看")).h(text_px(26.)).on_click(self.on(Cmd::OpenTemplates, cx)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{draft_from, template_of_task};
    use wisp_ops_engine::config::{Playbook, TaskSchedule, TaskSpec};
    use wisp_ops_engine::templates::{TEMPLATE_REPORT_RULES, TemplateLimits, builtin_templates};

    #[test]
    fn a_template_opens_the_task_form_with_its_placeholders_and_origin() {
        let all = builtin_templates(&TemplateLimits { disk_warn_pct: 80., disk_crit_pct: 90., inode_warn_pct: 80., gpu_temp_warn_c: 85. }, "UTC");
        let services = all.iter().find(|template| template.id == "builtin.services").unwrap();
        let draft = draft_from(services);
        assert_eq!((draft.name.as_str(), draft.playbook.as_str(), draft.schedule.as_str(), draft.daily.as_str()), ("services", "custom", "daily", "08:30"));
        assert!(draft.commands[0].contains("{{services}}"));
        assert!(!draft.sudo);
        assert_eq!(draft.template.as_deref(), Some("builtin.services"));
        let security = draft_from(all.iter().find(|template| template.id == "builtin.security").unwrap());
        assert_eq!(security.hours, Some(24));
    }

    #[test]
    fn a_task_kept_as_a_template_loses_its_servers_sudo_and_report_rules() {
        let task = TaskSpec { name: "web-check".into(), description: Some("网站".into()), targets: "web-*".into(), playbook: Playbook::Custom, instruction: Some(format!("看状态码{TEMPLATE_REPORT_RULES}")), commands: vec!["curl -sSI https://a".into()], schedule: Some(TaskSchedule { every_minutes: Some(30), ..Default::default() }), sudo: Some(true), template: Some("builtin.web".into()), ..Default::default() };
        let template = template_of_task(&task);
        assert_eq!(template.definition.instruction, "看状态码");
        assert_eq!(template.definition.schedule.as_ref().and_then(|schedule| schedule.every_minutes), Some(30));
        let value = serde_json::to_value(&template).unwrap();
        assert!(value["definition"].get("targets").is_none() && value["definition"].get("sudo").is_none());
        wisp_ops_engine::templates::validate_template(&value, &Default::default()).unwrap();
    }
}
