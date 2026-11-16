//! 长时任务: which servers have user work that has been running for too
//! long. A check reads the process table (and Slurm's queue) of each server
//! and keeps the tasks of ordinary accounts older than the threshold; login
//! shells, tmux and the like are not tasks. It needs no root and calls no
//! model; the servers the automatic inspection visits are checked with it.

use crate::app::{Cmd, MenuKind, Page, Workspace};
use crate::i18n::t;
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_collect::longrun::{LongJob, LongKind, LongRunSnapshot};
use wisp_ops_collect::sections::format_kb;
use wisp_ops_core::time;

/// A threshold in words.
pub fn hours_label(hours: u32) -> String {
    if hours >= 48 && hours.is_multiple_of(24) { tf!("{} 天", "{} days", hours / 24) } else { tf!("{hours} 小时", "{hours} hours") }
}

/// How long something has run, in the interface's words.
pub fn elapsed_words(seconds: f64) -> String {
    let total = seconds.max(0.) as u64;
    let (days, hours, minutes) = (total / 86400, total % 86400 / 3600, total % 3600 / 60);
    if days > 0 {
        tf!("{days} 天 {hours} 小时", "{days}d {hours}h")
    } else if hours > 0 {
        tf!("{hours} 小时 {minutes} 分", "{hours}h {minutes}m")
    } else {
        tf!("{minutes} 分钟", "{minutes}m")
    }
}

impl Workspace {
    /// The servers with tasks over the threshold now set, the most tasks first, each with its tasks.
    pub fn long_jobs_shown(&self) -> Vec<(&str, Vec<&LongJob>)> {
        let floor = f64::from(self.settings.long_job_hours) * 3600.;
        let mut rows: Vec<(&str, Vec<&LongJob>)> = self.view.long_runs.iter().map(|(host, row)| (host.as_str(), row.report.jobs.iter().filter(|job| job.elapsed_sec >= floor).collect::<Vec<_>>())).filter(|(_, jobs)| !jobs.is_empty()).collect();
        rows.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
        rows
    }

    /// Check the selected servers off the main thread. The check that rides with the automatic inspection is quiet.
    pub fn check_long_jobs(&mut self, selector: String, quiet: bool, cx: &mut Context<Self>) {
        let names: Vec<String> = match self.fleet.select_names(&selector) {
            Ok(names) => names.into_iter().filter(|name| !self.long_working.contains(name)).collect(),
            Err(error) => return if !quiet { self.fail(error, cx) },
        };
        if names.is_empty() { return }
        self.long_working.extend(names.iter().cloned());
        let (fleet, hours) = (self.fleet.clone(), self.settings.long_job_hours);
        let selector = names.join(",");
        let work = cx.background_executor().spawn(async move { fleet.long_jobs(&selector, hours, if quiet { "auto" } else { "long-jobs" }) });
        cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                for name in &names { this.long_working.remove(name); }
                this.reload(cx);
                match result {
                    _ if quiet => {}
                    Ok(words) => this.say(words, cx),
                    Err(error) => this.fail(error, cx),
                }
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    pub fn render_longrun(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let hours = self.settings.long_job_hours;
        let busy = !self.long_working.is_empty();
        let shown = self.long_jobs_shown();
        let actions = vec![
            ui::ghost_button("long-hours", Some("timer"), Some(tf!("阈值：{}", "Threshold: {}", hours_label(hours)).into())).on_click(self.on_menu(MenuKind::LongHours, cx)).into_any_element(),
            ui::secondary_button("long-report", t("让助手分析")).child(ui::icon("sparkle", 13., Theme::accent())).on_click(self.on(Cmd::Suggest(tf!("用 ops_jobs 检查全部服务器上运行超过 {hours} 小时的用户任务，说明每个任务是谁的、在做什么、是否像被遗忘或卡住，并给出建议（只读，不要终止任何进程）。", "Use ops_jobs to check every server for user tasks running longer than {hours} hours; say whose each is, what it is doing, whether it looks forgotten or stuck, and what you suggest (read-only; do not kill anything).")), cx)).into_any_element(),
            ui::primary_button("long-check", if busy { t("正在检查…") } else { t("检查全部") }).when(busy, |b| b.opacity(0.6)).on_click(self.on(Cmd::CheckLongJobs("all".into()), cx)).into_any_element(),
        ];
        let head = self.page_head(t("长时任务"), tf!("各服务器上运行超过 {} 的用户任务；登录 shell、tmux 这类会话进程不算", "User tasks that have run longer than {} on each server; login shells, tmux and the like do not count", hours_label(hours)), actions, cx);
        if self.view.hosts.is_empty() {
            return div().flex().flex_col().size_full().child(head).child(ui::empty_state("timer", t("清单里还没有服务器"), t("先在「服务器」里添加，或从 ~/.ssh/config 导入。")).child(ui::primary_button("long-add", t("去添加服务器")).on_click(self.on(Cmd::SetPage(Page::Servers), cx)))).into_any_element();
        }
        let jobs: Vec<&LongJob> = shown.iter().flat_map(|(_, jobs)| jobs.iter().copied()).collect();
        let longest = jobs.iter().map(|job| job.elapsed_sec).fold(0., f64::max);
        let tile = |label: &str, value: String, quiet: bool| div().flex().flex_col().flex_1().gap(px(2.)).px(px(14.)).py(px(10.)).rounded(px(10.)).border_1().border_color(Theme::line()).child(div().text_size(text_px(12.)).text_color(Theme::text_secondary()).child(label.to_string())).child(div().text_size(text_px(22.)).line_height(text_px(28.)).font_weight(FontWeight::SEMIBOLD).text_color(if quiet { Theme::text_placeholder() } else { Theme::text() }).child(value));
        let tiles = div()
            .flex()
            .gap(px(10.))
            .child(tile(t("有长时任务的服务器"), shown.len().to_string(), shown.is_empty()))
            .child(tile(t("长时任务"), jobs.len().to_string(), jobs.is_empty()))
            .child(tile(t("几乎不用 CPU（疑似遗忘）"), jobs.iter().filter(|job| job.idle()).count().to_string(), !jobs.iter().any(|job| job.idle())))
            .child(tile(t("运行最久"), if jobs.is_empty() { "—".into() } else { elapsed_words(longest) }, jobs.is_empty()));

        let unchecked: Vec<&str> = self.view.hosts.iter().filter(|host| !self.view.long_runs.contains_key(&host.name)).map(|host| host.name.as_str()).collect();
        let clear: Vec<&str> = self.view.hosts.iter().filter(|host| self.view.long_runs.contains_key(&host.name) && !shown.iter().any(|(name, _)| *name == host.name)).map(|host| host.name.as_str()).collect();
        // A check made with a higher threshold has not looked at what the lower one now asks about.
        let stale: Vec<&str> = self.view.long_runs.iter().filter(|(_, row)| row.report.min_seconds > f64::from(hours) * 3600.).map(|(host, _)| host.as_str()).collect();
        let quiet_line = |label: String, names: &[&str]| div().flex().gap(px(8.)).text_size(text_px(12.)).line_height(text_px(18.)).child(div().flex_none().text_color(Theme::text_tertiary()).child(label)).child(div().flex_1().min_w_0().text_color(Theme::text_secondary()).child(names.join("、")));
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(head)
            .child(
                div()
                    .id("long-body")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .track_scroll(&self.page_scroll)
                    .px(px(24.))
                    .py(px(16.))
                    .gap(px(16.))
                    .child(tiles)
                    .when(!stale.is_empty(), |d| d.child(div().px(px(10.)).py(px(7.)).rounded(px(8.)).bg(Theme::bg_sunken()).text_size(text_px(12.)).text_color(Theme::warning()).child(tf!("{} 上次检查用的阈值更高，按现在的 {} 重新检查后才完整。", "{} were last checked with a higher threshold; check again for the full picture at {}.", stale.join("、"), hours_label(hours)))))
                    .children(shown.iter().map(|(host, jobs)| self.render_long_host(host, jobs, cx)))
                    .when(shown.is_empty() && unchecked.len() < self.view.hosts.len(), |d| d.child(div().py(px(18.)).text_color(Theme::text_tertiary()).child(tf!("已检查的服务器上没有运行超过 {} 的用户任务。", "No user task has run longer than {} on the servers checked.", hours_label(hours)))))
                    .when(!clear.is_empty() && !shown.is_empty(), |d| d.child(quiet_line(t("没有长时任务").to_string(), &clear)))
                    .when(!unchecked.is_empty(), |d| d.child(quiet_line(t("还没有检查").to_string(), &unchecked))),
            )
            .into_any_element()
    }

    fn render_long_host(&self, host: &str, jobs: &[&LongJob], cx: &mut Context<Self>) -> AnyElement {
        let row: Option<&LongRunSnapshot> = self.view.long_runs.get(host);
        let working = self.long_working.contains(host);
        let cell = |width: f32| div().w(px(width)).flex_none();
        let head = div()
            .flex()
            .items_center()
            .gap(px(8.))
            .h(text_px(32.))
            .child(if working { ui::spinner(SharedString::from(format!("long-working-{host}")), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(9.)).m(px(1.5)).rounded_full().bg(Theme::star()).into_any_element() })
            .child(div().id(SharedString::from(format!("long-host-{host}"))).font_weight(FontWeight::MEDIUM).cursor_pointer().hover(|s| s.text_color(Theme::accent())).on_click(self.on(Cmd::SelectHost(Some(host.to_string())), cx)).child(host.to_string()))
            .child(div().text_size(text_px(12.)).text_color(Theme::text_secondary()).child(tf!("{} 个任务", "{} tasks", jobs.len())))
            .child(div().flex_1())
            .children(row.map(|row| div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("检查于 {}", "checked {}", time::short_time(&row.at)))))
            .child(ui::icon_action(SharedString::from(format!("long-check-{host}")), "loader", Theme::text_tertiary(), t("重新检查")).on_click(self.on(Cmd::CheckLongJobs(host.to_string()), cx)));
        let columns = div().flex().items_center().gap(px(10.)).h(text_px(24.)).px(px(10.)).text_size(text_px(11.)).text_color(Theme::text_tertiary()).child(cell(110.).child(t("用户"))).child(cell(110.).child(t("已运行"))).child(cell(64.).text_right().child("CPU")).child(cell(64.).text_right().child(t("内存"))).child(cell(84.).child("PID")).child(div().flex_1().child(t("命令")));
        div()
            .flex()
            .flex_col()
            .rounded(px(10.))
            .border_1()
            .border_color(Theme::line())
            .px(px(8.))
            .pb(px(6.))
            .child(div().px(px(6.)).child(head))
            .child(columns)
            .children(jobs.iter().take(40).enumerate().map(|(at, job)| {
                let scheduler = job.kind == LongKind::Slurm;
                let mark = match (scheduler, job.state.as_str(), job.idle()) {
                    (true, ..) => Some(("info", "Slurm".to_string())),
                    (_, "stopped", _) => Some(("warn", t("已暂停").to_string())),
                    (_, "zombie", _) => Some(("crit", t("僵尸").to_string())),
                    (_, _, true) => Some(("warn", t("空闲").to_string())),
                    _ => None,
                };
                div()
                    .id(SharedString::from(format!("long-job-{host}-{at}")))
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .h(text_px(30.))
                    .px(px(10.))
                    .rounded(px(6.))
                    .text_size(text_px(12.))
                    .hover(|s| s.bg(Theme::hover()))
                    .tooltip(ui::tip(job.command.clone()))
                    .child(cell(110.).truncate().font_weight(FontWeight::MEDIUM).child(job.user.clone()))
                    .child(cell(110.).child(elapsed_words(job.elapsed_sec)))
                    .child(cell(64.).text_right().text_color(Theme::text_secondary()).child(if scheduler { "—".to_string() } else { format!("{:.0}%", job.cpu_pct) }))
                    .child(cell(64.).text_right().text_color(Theme::text_secondary()).child(if scheduler { "—".to_string() } else { format_kb(job.rss_kb) }))
                    .child(cell(84.).truncate().font_family(theme::MONO_FONT).text_color(Theme::text_tertiary()).child(job.id.clone()))
                    .child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_color(Theme::text_secondary()).child(job.command.clone()))
                    .when(job.children > 0, |d| d.child(div().flex_none().text_color(Theme::text_placeholder()).child(tf!("+{} 子进程", "+{} children", job.children))))
                    .children(mark.map(|(state, label)| ui::status_chip(state, &label)))
            }))
            .when(jobs.len() > 40, |d| d.child(div().px(px(10.)).py(px(4.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("还有 {} 个，可让助手列出", "{} more; the assistant can list them", jobs.len() - 40))))
            .into_any_element()
    }
}
