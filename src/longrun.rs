//! 长时任务: which servers have user work that has been running for too
//! long. A check reads the process table (and Slurm's queue) of each server
//! and keeps the tasks of ordinary accounts older than the threshold; login
//! shells, tmux and the like are not tasks. It needs no root and calls no
//! model; the servers the automatic inspection visits are checked with it.

use crate::app::{Cmd, MenuKind, Page, Workspace};
use crate::i18n::t;
use crate::input::{InputEvent, TextInput};
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

/// Whether a task answers a server's filter: each word of it, case aside, is in the user or in the command.
pub fn job_matches(user: &str, command: &str, filter: &str) -> bool {
    let (user, command) = (user.to_lowercase(), command.to_lowercase());
    filter.split_whitespace().all(|word| {
        let word = word.to_lowercase();
        user.contains(&word) || command.contains(&word)
    })
}

/// A filter with this user put in, or taken out when it is there already. Another of the server's users gives way to it: a task has one user, so two would match nothing.
pub fn toggle_user(filter: &str, user: &str, users: &[&str]) -> String {
    let words: Vec<&str> = filter.split_whitespace().collect();
    if words.contains(&user) { return words.into_iter().filter(|word| *word != user).collect::<Vec<_>>().join(" ") }
    words.into_iter().filter(|word| !users.contains(word)).chain([user]).collect::<Vec<_>>().join(" ")
}

impl Workspace {
    /// A filter for each server that has been checked, made when it first shows and dropped when it goes.
    pub fn sync_long_filters(&mut self, cx: &mut Context<Self>) {
        let runs = &self.view.long_runs;
        self.long_filters.retain(|host, _| runs.contains_key(host));
        self.long_folded.retain(|host| runs.contains_key(host));
        let missing: Vec<String> = runs.keys().filter(|host| !self.long_filters.contains_key(*host)).cloned().collect();
        for host in missing {
            let input = cx.new(|cx| TextInput::new("按用户或程序筛选", cx));
            let subscription = cx.subscribe(&input, |_: &mut Self, input, event: &InputEvent, cx| match event {
                InputEvent::Changed => cx.notify(),
                InputEvent::Cancel => input.update(cx, |input, cx| input.set_text("", cx)),
                _ => {}
            });
            self.long_filters.insert(host, (input, subscription));
        }
    }

    /// What a server's filter holds now.
    fn long_filter(&self, host: &str, cx: &App) -> String {
        self.long_filters.get(host).map(|(input, _)| input.read(cx).text().trim().to_string()).unwrap_or_default()
    }

    pub fn run_longrun(&mut self, cmd: Cmd, cx: &mut Context<Self>) {
        let set = |this: &Self, host: &str, text: &str, cx: &mut Context<Self>| {
            if let Some((input, _)) = this.long_filters.get(host) { input.update(cx, |input, cx| input.set_text(text, cx)) }
        };
        match cmd {
            Cmd::ToggleLongHost(host) => {
                if !self.long_folded.remove(&host) { self.long_folded.insert(host); }
            }
            Cmd::FoldLongHosts(fold) => self.long_folded = if fold { self.long_jobs_shown().into_iter().map(|(host, _)| host.to_string()).collect() } else { Default::default() },
            Cmd::LongUser(host, user) => {
                let mut users: Vec<&str> = self.view.long_runs.get(&host).map(|row| row.report.jobs.iter().map(|job| job.user.as_str()).collect()).unwrap_or_default();
                users.sort_unstable();
                users.dedup();
                let text = toggle_user(&self.long_filter(&host, cx), &user, &users);
                set(self, &host, &text, cx);
            }
            Cmd::LongFilter(host, text) => set(self, &host, &text, cx),
            _ => {}
        }
        cx.notify();
    }

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

    pub fn render_longrun(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let window: &Window = window;
        let hours = self.settings.long_job_hours;
        let busy = !self.long_working.is_empty();
        let shown = self.long_jobs_shown();
        let all_folded = shown.iter().all(|(host, _)| self.long_folded.contains(*host));
        let mut actions = vec![];
        if shown.len() > 1 {
            actions.push(ui::ghost_button("long-fold-all", Some(if all_folded { "chevron-down" } else { "chevron-up" }), Some(if all_folded { t("全部展开") } else { t("全部折叠") }.into())).on_click(self.on(Cmd::FoldLongHosts(!all_folded), cx)).into_any_element());
        }
        actions.extend([
            ui::ghost_button("long-hours", Some("timer"), Some(tf!("阈值：{}", "Threshold: {}", hours_label(hours)).into())).on_click(self.on_menu(MenuKind::LongHours, cx)).into_any_element(),
            ui::secondary_button("long-report", t("让助手分析")).child(ui::icon("sparkle", 13., Theme::accent())).on_click(self.on(Cmd::Suggest(tf!("用 ops_jobs 检查全部服务器上运行超过 {hours} 小时的用户任务，说明每个任务是谁的、在做什么、是否像被遗忘或卡住，并给出建议（只读，不要终止任何进程）。", "Use ops_jobs to check every server for user tasks running longer than {hours} hours; say whose each is, what it is doing, whether it looks forgotten or stuck, and what you suggest (read-only; do not kill anything).")), cx)).into_any_element(),
            ui::primary_button("long-check", if busy { t("正在检查…") } else { t("检查全部") }).when(busy, |b| b.opacity(0.6)).on_click(self.on(Cmd::CheckLongJobs("all".into()), cx)).into_any_element(),
        ]);
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
                    .children(shown.iter().map(|(host, jobs)| self.render_long_host(host, jobs, window, cx)))
                    .when(shown.is_empty() && unchecked.len() < self.view.hosts.len(), |d| d.child(div().py(px(18.)).text_color(Theme::text_tertiary()).child(tf!("已检查的服务器上没有运行超过 {} 的用户任务。", "No user task has run longer than {} on the servers checked.", hours_label(hours)))))
                    .when(!clear.is_empty() && !shown.is_empty(), |d| d.child(quiet_line(t("没有长时任务").to_string(), &clear)))
                    .when(!unchecked.is_empty(), |d| d.child(quiet_line(t("还没有检查").to_string(), &unchecked))),
            )
            .into_any_element()
    }

    fn render_long_host(&self, host: &str, all: &[&LongJob], window: &Window, cx: &mut Context<Self>) -> AnyElement {
        let row: Option<&LongRunSnapshot> = self.view.long_runs.get(host);
        let working = self.long_working.contains(host);
        let folded = self.long_folded.contains(host);
        let filter = self.long_filter(host, cx);
        let jobs: Vec<&LongJob> = all.iter().copied().filter(|job| job_matches(&job.user, &job.command, &filter)).collect();
        let picked: Vec<&str> = filter.split_whitespace().collect();
        let cell = |width: f32| div().w(px(width)).flex_none();
        let head = div()
            .id(SharedString::from(format!("long-head-{host}")))
            .flex()
            .items_center()
            .gap(px(8.))
            .h(text_px(32.))
            .cursor_pointer()
            .on_click(self.on(Cmd::ToggleLongHost(host.to_string()), cx))
            .child(ui::icon(if folded { "chevron-right" } else { "chevron-down" }, 13., Theme::text_tertiary()))
            .child(if working { ui::spinner(SharedString::from(format!("long-working-{host}")), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(9.)).m(px(1.5)).rounded_full().bg(Theme::star()).into_any_element() })
            .child(div().font_weight(FontWeight::MEDIUM).child(host.to_string()))
            .child(div().text_size(text_px(12.)).text_color(Theme::text_secondary()).child(if filter.is_empty() { tf!("{} 个任务", "{} tasks", all.len()) } else { tf!("{} / {} 个任务", "{} / {} tasks", jobs.len(), all.len()) }))
            .child(div().flex_1())
            .children(row.map(|row| div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("检查于 {}", "checked {}", time::short_time(&row.at)))))
            .child(ui::icon_action(SharedString::from(format!("long-check-{host}")), "loader", Theme::text_tertiary(), t("重新检查")).on_click(self.on_within(Cmd::CheckLongJobs(host.to_string()), cx)));
        let card = div().flex().flex_col().rounded(px(10.)).border_1().border_color(Theme::line()).px(px(8.)).child(div().px(px(6.)).child(head));
        if folded { return card.into_any_element() }
        let search = self.long_filters.get(host).map(|(input, _)| {
            div()
                .flex()
                .items_center()
                .gap(px(6.))
                .px(px(6.))
                .pb(px(4.))
                .child(div().w(px(280.)).child(ui::field(input, window, cx)))
                .when(!filter.is_empty(), |d| d.child(ui::icon_action(SharedString::from(format!("long-clear-{host}")), "x", Theme::text_tertiary(), t("清除筛选")).on_click(self.on(Cmd::LongFilter(host.to_string(), String::new()), cx))))
        });
        let columns = div().flex().items_center().gap(px(10.)).h(text_px(24.)).px(px(10.)).text_size(text_px(11.)).text_color(Theme::text_tertiary()).child(cell(92.).child(t("用户"))).child(cell(104.).child(t("已运行"))).child(cell(64.).text_right().child("CPU")).child(cell(64.).text_right().child(t("内存"))).child(cell(76.).child("PID")).child(div().flex_1().child(t("命令")));
        let groups = group_jobs(&jobs);
        card.pb(px(6.))
            .children(search)
            .when(jobs.is_empty(), |d| d.child(div().px(px(10.)).py(px(6.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("没有任务符合筛选"))))
            .when(!jobs.is_empty(), |d| d.child(columns))
            .children(groups.iter().take(40).enumerate().map(|(at, group)| {
                let job = group.first;
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
                    .tooltip(ui::tip(if group.count > 1 { format!("{}\nPID {}", job.command, group.ids.join(", ")) } else { job.command.clone() }))
                    .child({
                        let on = picked.contains(&job.user.as_str());
                        cell(92.).id(SharedString::from(format!("long-user-{host}-{at}"))).truncate().font_weight(FontWeight::MEDIUM).cursor_pointer().when(on, |d| d.text_color(Theme::accent())).hover(|s| s.text_color(Theme::accent())).tooltip(ui::tip(if on { t("取消按此用户筛选") } else { t("只看此用户的任务") })).on_click(self.on(Cmd::LongUser(host.to_string(), job.user.clone()), cx)).child(job.user.clone())
                    })
                    .child(cell(104.).child(elapsed_words(group.elapsed_sec)))
                    .child(cell(64.).text_right().text_color(Theme::text_secondary()).child(if scheduler { "—".to_string() } else { format!("{:.0}%", group.cpu_pct) }))
                    .child(cell(64.).text_right().text_color(Theme::text_secondary()).child(if scheduler { "—".to_string() } else { format_kb(group.rss_kb) }))
                    .child(if group.count > 1 { cell(76.).truncate().text_color(Theme::text_secondary()).child(tf!("{} 个进程", "{} processes", group.count)) } else { cell(76.).truncate().font_family(theme::MONO_FONT).text_color(Theme::text_tertiary()).child(job.id.clone()) })
                    .child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_color(Theme::text_secondary()).child(job.command.clone()))
                    .when(group.children > 0, |d| d.child(div().flex_none().text_color(Theme::text_placeholder()).child(tf!("+{} 子进程", "+{} children", group.children))))
                    .children(mark.map(|(state, label)| ui::status_chip(state, &label)))
            }))
            .when(groups.len() > 40, |d| d.child(div().px(px(10.)).py(px(4.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("还有 {} 行，用上面的筛选缩小范围，或让助手列出", "{} more rows: narrow them with the filter above, or have the assistant list them", groups.len() - 40))))
            .into_any_element()
    }
}

/// The same command of the same user in the same condition, as one row: six `vim x.sh` left
/// open are one thing to deal with.
pub struct JobGroup<'a> {
    pub first: &'a LongJob,
    pub count: usize,
    /// The PIDs (or scheduler ids) in it.
    pub ids: Vec<&'a str>,
    /// The longest of them.
    pub elapsed_sec: f64,
    /// CPU, memory and folded children added up.
    pub cpu_pct: f64,
    pub rss_kb: f64,
    pub children: u32,
}

/// Fold the jobs that differ only in their PID, keeping the order they came in.
pub fn group_jobs<'a>(jobs: &[&'a LongJob]) -> Vec<JobGroup<'a>> {
    let mut groups: Vec<JobGroup<'a>> = vec![];
    for job in jobs {
        let alike = |first: &LongJob| first.kind == job.kind && first.user == job.user && first.command == job.command && first.state == job.state && first.idle() == job.idle();
        match groups.iter_mut().find(|group| alike(group.first)) {
            Some(group) => {
                group.count += 1;
                group.ids.push(&job.id);
                group.elapsed_sec = group.elapsed_sec.max(job.elapsed_sec);
                group.cpu_pct += job.cpu_pct;
                group.rss_kb += job.rss_kb;
                group.children += job.children;
            }
            None => groups.push(JobGroup { first: job, count: 1, ids: vec![&job.id], elapsed_sec: job.elapsed_sec, cpu_pct: job.cpu_pct, rss_kb: job.rss_kb, children: job.children }),
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::{LongJob, LongKind, group_jobs, job_matches, toggle_user};

    #[test]
    fn jobs_that_differ_only_in_pid_are_one_row() {
        let job = |id: &str, user: &str, command: &str, hours: f64, cpu: f64| LongJob { kind: LongKind::Process, id: id.into(), user: user.into(), elapsed_sec: hours * 3600., cpu_pct: cpu, mem_pct: 0., rss_kb: 100., state: "sleeping".into(), children: 0, command: command.into() };
        let jobs = [job("1", "jal", "vim a.sh", 30., 0.), job("2", "gj", "vim a.sh", 29., 0.), job("3", "jal", "vim a.sh", 28., 0.), job("4", "jal", "vim a.sh", 27., 40.)];
        let groups = group_jobs(&jobs.iter().collect::<Vec<_>>());
        // The busy one is not folded into the idle ones.
        assert_eq!(groups.iter().map(|group| (group.first.id.as_str(), group.count)).collect::<Vec<_>>(), [("1", 2), ("2", 1), ("4", 1)]);
        assert_eq!((groups[0].ids.clone(), groups[0].elapsed_sec, groups[0].rss_kb), (vec!["1", "3"], 30. * 3600., 200.));
    }

    #[test]
    fn a_filter_matches_user_or_command_word_by_word() {
        assert!(job_matches("alice", "python train.py", ""));
        assert!(job_matches("alice", "python train.py", "ALI"));
        assert!(job_matches("alice", "Python train.py", "python"));
        assert!(job_matches("alice", "python train.py", "alice train"));
        assert!(job_matches("alice", "python train.py", "  py   ali "));
        assert!(!job_matches("alice", "python train.py", "bob"));
        assert!(!job_matches("alice", "python train.py", "alice rsync"));
    }

    #[test]
    fn a_user_goes_in_and_comes_out() {
        let users = ["alice", "bob"];
        assert_eq!(toggle_user("", "alice", &users), "alice");
        assert_eq!(toggle_user("alice", "alice", &users), "");
        assert_eq!(toggle_user("python  alice", "alice", &users), "python");
        assert_eq!(toggle_user("python alice", "bob", &users), "python bob");
        assert_eq!(toggle_user("ali", "alice", &users), "ali alice");
    }
}
