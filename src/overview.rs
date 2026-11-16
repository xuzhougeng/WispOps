//! 机群总览: the fleet at a glance. Each server is a row: its last
//! inspections as squares (the oldest at the left) and how full its disk and
//! memory are now. A row opens into a panel of charts: every mount, the
//! memory, the load and the GPUs over the inspections kept. It reads the
//! saved history only: no server is connected to and no model is called to
//! draw it.

use crate::app::{Cmd, MenuKind, Page, SIDEBAR_W, Workspace};
use crate::i18n::t;
use crate::ops::{HostView, RunView};
use crate::servers::{state_color, state_label};
use crate::theme::{Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::time;

/// The inspections of a server the matrix shows.
pub const RUNS_SHOWN: usize = 30;
/// The mounts a server's panel draws, the fullest first.
const MOUNTS_SHOWN: usize = 8;
/// The servers "需要关注" lists before it points at the table below.
const ATTENTION_ROWS: usize = 6;

/// The colour of a measure against its (warning, critical) thresholds.
fn level(value: f64, limits: (f64, f64)) -> Hsla {
    if value >= limits.1 { Theme::danger() } else if value >= limits.0 { Theme::star() } else { Theme::accent() }
}

/// What the page has room for.
struct Room {
    squares: usize,
    memory: bool,
    load: bool,
}

impl Workspace {
    pub fn render_overview(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let hosts = &self.view.hosts;
        let count = |state: &str| hosts.iter().filter(|host| host.state() == state).count();
        let counts = [("ok", count("ok")), ("warn", count("warn") + count("info")), ("crit", count("crit")), ("unreachable", count("unreachable")), ("none", count("none"))];
        let busy = !self.working.is_empty();
        let actions = vec![
            ui::ghost_button("overview-auto", Some("history"), Some(tf!("自动巡检：{}", "Auto inspection: {}", crate::settings::interval_label(self.settings.auto_inspect_minutes)).into())).on_click(self.on_menu(MenuKind::AutoInspect, cx)).into_any_element(),
            ui::secondary_button("overview-report", t("让助手汇报")).child(ui::icon("sparkle", 13., Theme::accent())).on_click(self.on(Cmd::Suggest("/inspect all".into()), cx)).into_any_element(),
            ui::primary_button("overview-inspect", if busy { t("正在巡检…") } else { t("巡检全部") }).when(busy, |b| b.opacity(0.6)).on_click(self.on(Cmd::InspectHosts("all".into()), cx)).into_any_element(),
        ];
        if hosts.is_empty() {
            return div()
                .flex()
                .flex_col()
                .size_full()
                .child(self.page_head(t("机群总览"), t("每台服务器最近的巡检"), vec![], cx))
                .child(ui::empty_state("scan-text", t("清单里还没有服务器"), t("先在「服务器」里添加，或从 ~/.ssh/config 导入。")).child(ui::primary_button("overview-add", t("去添加服务器")).on_click(self.on(Cmd::SetPage(Page::Servers), cx))))
                .into_any_element();
        }
        // The page's own width: the window less the sidebar and the assistant.
        let inner = f32::from(window.viewport_size().width) - SIDEBAR_W - if self.chat_closed() { 0. } else { self.chat_width() } - 122.;
        let room = Room { squares: if inner >= 900. { RUNS_SHOWN } else if inner >= 600. { 12 } else { 0 }, memory: inner >= 600., load: inner >= 750. };

        let total = hosts.len().max(1) as f32;
        let tiles = div().flex().gap(px(10.)).children(counts.into_iter().map(|(state, count)| {
            ui::panel()
                .flex_1()
                .min_w_0()
                .gap(px(2.))
                .px(px(14.))
                .pt(px(11.))
                .pb(px(12.))
                .child(div().flex().items_center().gap(px(6.)).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(div().flex_none().size(px(8.)).rounded_full().bg(state_color(state))).child(div().truncate().child(t(state_label(state)).to_string())))
                .child(div().text_size(text_px(24.)).line_height(text_px(32.)).font_weight(FontWeight::SEMIBOLD).text_color(if count == 0 { Theme::text_placeholder() } else { Theme::text() }).child(count.to_string()))
                // Its share of the fleet.
                .child(div().mt(px(4.)).h(px(3.)).rounded_full().bg(Theme::groove()).child(div().h_full().rounded_full().bg(state_color(state)).w(relative(count as f32 / total))))
        }));

        // The servers that want looking at come first; within a state, by name.
        let mut rows: Vec<&HostView> = hosts.iter().collect();
        let rank = |state: &str| match state { "crit" => 0, "unreachable" => 1, "warn" => 2, "info" => 3, "ok" => 4, _ => 5 };
        rows.sort_by(|a, b| rank(a.state()).cmp(&rank(b.state())).then(a.name.cmp(&b.name)));

        // What the latest inspections found: a line a server, the worst server and its worst finding first.
        let mut found: Vec<(&HostView, Vec<&crate::ops::FindingView>)> = rows.iter().filter_map(|host| {
            let mut problems: Vec<_> = host.runs.last()?.findings.iter().filter(|finding| !finding.muted && finding.severity != "info").collect();
            problems.sort_by_key(|finding| rank(&finding.severity));
            (!problems.is_empty()).then_some((*host, problems))
        }).collect();
        found.sort_by_key(|(_, problems)| rank(&problems[0].severity));
        let total_found: usize = found.iter().map(|(_, problems)| problems.len()).sum();
        let more = found.len().saturating_sub(ATTENTION_ROWS);
        let attention = (!found.is_empty()).then(|| {
            ui::panel()
                .px(px(16.))
                .py(px(12.))
                .gap(px(6.))
                .child(ui::panel_head(t("需要关注").to_string(), tf!("最近一次巡检：{} 台服务器的 {} 项发现", "The latest inspections: {1} findings on {0} servers", found.len(), total_found)))
                .children(found.iter().take(ATTENTION_ROWS).enumerate().map(|(n, (host, problems))| {
                    let words = problems.iter().take(3).map(|finding| finding.words()).collect::<Vec<_>>().join(if crate::i18n::is_english() { "; " } else { "；" });
                    div()
                        .id(("attention", n))
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .h(text_px(26.))
                        .mx(px(-6.))
                        .px(px(6.))
                        .rounded(px(6.))
                        .text_size(text_px(12.))
                        .cursor_pointer()
                        .hover(|s| s.bg(Theme::hover()))
                        .on_click(self.on(Cmd::OpenHost(host.name.clone()), cx))
                        .child(div().flex_none().size(px(6.)).rounded_full().bg(state_color(&problems[0].severity)))
                        .child(div().flex_none().w(px(120.)).truncate().font_weight(FontWeight::MEDIUM).child(host.name.clone()))
                        .child(div().flex_1().min_w_0().truncate().text_color(Theme::text_secondary()).child(words))
                        .child(div().flex_none().text_color(Theme::text_tertiary()).child(if problems.len() == 1 && crate::i18n::is_english() { "1 finding".to_string() } else { tf!("{} 项", "{} findings", problems.len()) }))
                }))
                .when(more > 0, |d| d.child(div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("还有 {more} 台，在下面的列表里", "{more} more servers in the list below"))))
        });

        let label = |words: &str| div().text_size(text_px(11.)).text_color(Theme::text_tertiary()).child(t(words).to_string());
        let columns = div()
            .flex()
            .items_center()
            .gap(px(12.))
            .h(text_px(28.))
            .px(px(16.))
            .border_b_1()
            .border_color(Theme::line())
            .child(label("服务器").ml(px(38.)).flex_1().min_w(px(110.)))
            .when(room.squares > 0, |d| d.child(label("巡检记录").flex().justify_end().flex_none().w(px((room.squares * 8) as f32))))
            .child(label("磁盘（最满的挂载点）").flex_none().w(px(190.)).truncate())
            .when(room.memory, |d| d.child(label("内存已用").flex_none().w(px(120.))))
            .when(room.load, |d| d.child(label("负载 · GPU").flex_none().w(px(124.))))
            // Under these: the inspect button and the menu's.
            .child(div().flex_none().w(px(24.)))
            .child(div().flex_none().w(px(28.)));
        let fleet = ui::panel()
            .child(div().px(px(16.)).pt(px(12.)).pb(px(6.)).child(ui::panel_head(t("服务器").to_string(), t("点一行展开磁盘、内存、负载和 GPU 的变化").to_string())))
            .child(columns)
            .children(rows.iter().enumerate().map(|(n, host)| self.render_matrix_row(host, &room, n + 1 == rows.len(), cx)));
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(self.page_head(t("机群总览"), t("每台服务器最近的巡检；点一行看各项指标的变化"), actions, cx))
            .child(
                div()
                    .id("overview-body")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .track_scroll(&self.page_scroll)
                    .bg(Theme::bg_sunken())
                    .px(px(24.))
                    .py(px(16.))
                    .gap(px(12.))
                    .child(tiles)
                    .children(attention)
                    .child(fleet),
            )
            .into_any_element()
    }

    fn render_matrix_row(&self, host: &HostView, room: &Room, last: bool, cx: &mut Context<Self>) -> AnyElement {
        let working = self.working.contains(&host.name);
        let open = self.open_host.as_ref() == Some(&host.name);
        let limits = self.view.limits;
        let shown = &host.runs[host.runs.len().saturating_sub(room.squares)..];
        let offset = host.runs.len() - shown.len();
        let picked = self.selected_run.as_ref().filter(|(name, _)| name == &host.name).map(|(_, at)| *at);
        let squares = div().flex().flex_none().items_center().gap(px(2.)).w(px((room.squares * 8) as f32)).justify_end().children(shown.iter().enumerate().map(|(n, run)| {
            let at = offset + n;
            div()
                .id(SharedString::from(format!("run-{}-{at}", host.name)))
                .flex_none()
                .w(px(6.))
                .h(px(18.))
                .rounded(px(2.))
                .bg(state_color(&run.state))
                .when(run.state == "unreachable", |d| d.opacity(0.45))
                .when(picked == Some(at), |d| d.border_1().border_color(Theme::text()))
                .cursor_pointer()
                .hover(|s| s.opacity(0.7))
                .tooltip(ui::tip(format!("{} · {}", time::short_time(&run.at), t(state_label(&run.state)))))
                .on_click(self.on_within(Cmd::SelectRun(host.name.clone(), at), cx))
        }));
        let latest = host.runs.last();
        let quiet = |words: String| div().truncate().text_size(text_px(12.)).text_color(Theme::text_placeholder()).child(words);
        let number = |words: String| div().flex_none().w(px(36.)).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(div().flex().justify_end().child(words));
        let disk = match latest.and_then(|run| run.disk_max.as_ref()) {
            Some((mount, pct)) => div().flex().items_center().gap(px(8.)).child(div().flex_none().w(px(64.)).truncate().text_size(text_px(12.)).text_color(Theme::text_secondary()).child(mount.clone())).child(ui::meter(*pct, level(*pct, limits.disk))).child(number(format!("{pct:.0}%"))),
            None => quiet(if host.runs.is_empty() { t("未巡检").to_string() } else { "—".into() }),
        };
        let memory = match latest.and_then(|run| run.mem_avail_pct) {
            Some(free) => div().flex().items_center().gap(px(8.)).child(ui::meter(100. - free, level(100. - free, (100. - limits.mem_avail.0, 100. - limits.mem_avail.1)))).child(number(format!("{:.0}%", 100. - free))),
            None => quiet("—".into()),
        };
        let cores = host.probe.as_ref().and_then(|probe| probe.cores.parse::<f64>().ok()).filter(|cores| *cores > 0.);
        let load = match latest.and_then(|run| run.load1) {
            Some(load) => div().flex().items_center().gap(px(6.)).text_size(text_px(12.)).child(div().flex_none().size(px(6.)).rounded_full().bg(level(load / cores.unwrap_or(1.), if cores.is_some() { limits.load_per_core } else { (f64::MAX, f64::MAX) }))).child(div().text_color(Theme::text_secondary()).child(format!("{load:.2}"))).children(latest.and_then(|run| run.gpu_util_pct).map(|gpu| div().truncate().text_color(Theme::text_tertiary()).child(format!("GPU {gpu:.0}%")))),
            None => quiet("—".into()),
        };
        let about = host.probe.as_ref().map(|probe| probe.line()).unwrap_or_else(|| host.shown_address().to_string());
        div()
            .flex()
            .flex_col()
            .when(!last, |d| d.border_b_1().border_color(Theme::line()))
            .child(
                div()
                    .id(SharedString::from(format!("overview-host-{}", host.name)))
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .h(text_px(52.))
                    .px(px(16.))
                    .cursor_pointer()
                    .when(open, |d| d.bg(Theme::accent_soft().opacity(0.5)))
                    .hover(|s| s.bg(Theme::hover()))
                    .when(last && !open, |d| d.rounded_b(px(12.)))
                    .on_click(self.on(Cmd::OpenHost(host.name.clone()), cx))
                    .on_mouse_down(MouseButton::Right, self.on_context(MenuKind::HostActions(host.name.clone()), cx))
                    .child(ui::icon(if open { "chevron-down" } else { "chevron-right" }, 14., Theme::text_tertiary()))
                    .child(if working { ui::spinner(SharedString::from(format!("overview-working-{}", host.name)), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(9.)).m(px(1.5)).rounded_full().bg(state_color(host.state())).into_any_element() })
                    .child(div().flex().flex_col().flex_1().min_w(px(110.)).child(div().truncate().font_weight(FontWeight::MEDIUM).child(host.name.clone())).child(div().truncate().text_size(text_px(11.)).line_height(text_px(15.)).text_color(Theme::text_tertiary()).child(about)))
                    .when(room.squares > 0, |d| d.child(squares))
                    .child(disk.flex_none().w(px(190.)))
                    .when(room.memory, |d| d.child(memory.flex_none().w(px(120.))))
                    .when(room.load, |d| d.child(load.flex_none().w(px(124.)).overflow_hidden()))
                    .child(ui::icon_action(SharedString::from(format!("overview-inspect-{}", host.name)), "loader", Theme::text_tertiary(), t("立即巡检")).on_click(self.on_within(Cmd::InspectHosts(host.name.clone()), cx)))
                    .child(ui::ghost_button(SharedString::from(format!("overview-menu-{}", host.name)), Some("ellipsis"), None).on_click({
                        let open = self.on_menu(MenuKind::HostActions(host.name.clone()), cx);
                        move |ev, window, cx| {
                            cx.stop_propagation();
                            open(ev, window, cx);
                        }
                    })),
            )
            .when(open, |d| d.child(self.render_host_charts(host, picked, cores, cx)))
            .into_any_element()
    }

    /// The panel a row opens into: what the inspection on show found, and each measure over the inspections kept.
    fn render_host_charts(&self, host: &HostView, picked: Option<usize>, cores: Option<f64>, cx: &mut Context<Self>) -> AnyElement {
        let limits = self.view.limits;
        let name = &host.name;
        let shell = div().flex().flex_col().gap(px(10.)).px(px(16.)).pt(px(4.)).pb(px(14.)).bg(Theme::accent_soft().opacity(0.5));
        let links = div()
            .flex()
            .flex_none()
            .gap(px(6.))
            .child(ui::secondary_button(SharedString::from(format!("charts-disk-{name}")), t("诊断磁盘")).h(text_px(26.)).text_size(text_px(12.)).child(ui::icon("sparkle", 12., Theme::accent())).on_click(self.on(Cmd::Draft(format!("/disk {name} /")), cx)))
            .child(ui::secondary_button(SharedString::from(format!("charts-server-{name}")), t("服务器详情")).h(text_px(26.)).text_size(text_px(12.)).child(ui::icon("chevron-right", 12., Theme::text_tertiary())).on_click(self.on(Cmd::SelectHost(Some(name.clone())), cx)));
        // The reachable inspections carry the measures; the others are gaps in every line.
        let Some(run) = picked.and_then(|at| host.runs.get(at)).or(host.runs.last()) else {
            return shell.child(div().flex().items_center().gap(px(10.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(div().flex_1().child(t("还没有巡检记录：巡检一次后，这里画出磁盘、内存、负载和 GPU 的变化。").to_string())).child(ui::secondary_button(SharedString::from(format!("charts-inspect-{name}")), t("巡检")).h(text_px(26.)).on_click(self.on(Cmd::InspectHosts(name.clone()), cx)))).into_any_element();
        };
        let runs = &host.runs;
        let latest = runs.iter().rev().find(|run| run.state != "unreachable");
        let series = |pick: &dyn Fn(&RunView) -> Option<f64>| -> Vec<Option<f64>> { runs.iter().map(|run| if run.state == "unreachable" { None } else { pick(run) }).collect() };
        let tips = |values: &[Option<f64>], say: &dyn Fn(f64) -> String| -> Vec<String> { runs.iter().zip(values).map(|(run, value)| format!("{} · {}", time::short_time(&run.at), value.map_or_else(|| t(if run.state == "unreachable" { "不可达" } else { "没有数据" }).to_string(), say))).collect() };
        let span = |values: &[Option<f64>]| values.iter().flatten().fold(None, |range: Option<(f64, f64)>, value| Some(range.map_or((*value, *value), |(low, high)| (low.min(*value), high.max(*value)))));
        let percent = |value: f64| format!("{value:.0}%");
        // The times the lines run between, under a chart.
        let axis = || div().when(runs.len() < 2, |d| d.opacity(0.)).flex().justify_between().text_size(text_px(10.)).line_height(text_px(13.)).text_color(Theme::text_placeholder()).child(runs.first().map(|run| time::short_time(&run.at)).unwrap_or_default()).child(runs.last().map(|run| time::short_time(&run.at)).unwrap_or_default());
        let card = |title: &str| ui::panel().flex_1().min_w_0().gap(px(6.)).px(px(14.)).py(px(12.)).child(ui::caption(t(title).to_string()));
        let figure = |value: String, unit: &str| div().flex().items_end().gap(px(4.)).child(div().text_size(text_px(22.)).line_height(text_px(26.)).font_weight(FontWeight::SEMIBOLD).child(value)).child(div().pb(px(3.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(unit.to_string()));
        let note = |words: String| div().truncate().text_size(text_px(12.)).line_height(text_px(17.)).text_color(Theme::text_secondary()).child(words);
        let absent = || div().py(px(8.)).text_size(text_px(12.)).text_color(Theme::text_placeholder()).child(t("巡检没有采到这一项。").to_string());

        // ---- what the inspection on show found
        let problems: Vec<_> = run.findings.iter().filter(|finding| finding.severity != "info").collect();
        let found = div()
            .flex()
            .items_start()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap(px(4.))
                    .text_size(text_px(12.))
                    .line_height(text_px(18.))
                    .child(div().flex().items_center().gap(px(8.)).child(ui::status_chip(&run.state, t(state_label(&run.state)))).child(div().text_color(Theme::text_tertiary()).child(if picked.is_some() { tf!("{} 的巡检", "inspection of {}", time::short_time(&run.at)) } else { tf!("最近一次巡检 · {}", "latest inspection · {}", time::short_time(&run.at)) })).when(problems.is_empty(), |d| d.child(div().text_color(Theme::text_tertiary()).child(t(if run.state == "unreachable" { "这次没有连上服务器。" } else { "这次巡检没有发现问题。" }).to_string()))))
                    .children(problems.iter().map(|finding| div().flex().items_start().gap(px(6.)).child(div().flex_none().mt(px(6.)).size(px(6.)).rounded_full().bg(state_color(&finding.severity))).child(div().flex_1().min_w_0().text_color(if finding.muted { Theme::text_tertiary() } else { Theme::text() }).child(finding.words())))),
            )
            .child(links);

        // ---- disks: every mount, the fullest first
        let mut mounts: Vec<(String, f64)> = latest.map(|run| run.disks.clone()).unwrap_or_default();
        mounts.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        let hidden = mounts.len().saturating_sub(MOUNTS_SHOWN);
        let disks = card("磁盘")
            .when(mounts.is_empty(), |d| d.child(absent()))
            .children(mounts.iter().take(MOUNTS_SHOWN).enumerate().map(|(n, (mount, pct))| {
                let values = series(&|run: &RunView| run.disks.iter().find(|(name, _)| name == mount).map(|(_, pct)| *pct));
                // The change over what is drawn: from the first inspection that saw the mount.
                let change = values.iter().flatten().next().map(|first| pct - first).unwrap_or(0.);
                let moved = change.abs() >= 0.5;
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .h(px(30.))
                    .text_size(text_px(12.))
                    .child(div().flex_none().w(px(120.)).truncate().child(mount.clone()))
                    .child(div().flex().flex_none().items_center().w(px(90.)).child(ui::meter(*pct, level(*pct, limits.disk))))
                    .child(div().flex().flex_none().justify_end().w(px(36.)).font_weight(FontWeight::MEDIUM).child(percent(*pct)))
                    .child(div().flex_1().min_w(px(60.)).child(ui::trend(&format!("disk-{name}-{n}"), values.clone(), tips(&values, &percent), 100., level(*pct, limits.disk), 26.)))
                    .child(div().flex().flex_none().justify_end().w(px(62.)).text_color(if moved && change > 0. { Theme::text() } else { Theme::text_tertiary() }).child(if moved { tf!("{change:+.1} 点", "{change:+.1} pts") } else if runs.len() < 2 { String::new() } else { t("持平").to_string() }))
            }))
            .when(hidden > 0, |d| d.child(note(tf!("另有 {hidden} 个挂载点未列出", "{hidden} more mounts not listed"))))
            .when(!mounts.is_empty(), |d| d.child(div().pl(px(276.)).pr(px(72.)).child(axis())));

        // ---- memory: what is used
        let used = series(&|run: &RunView| run.mem_avail_pct.map(|free| 100. - free));
        let memory = card("内存").map(|d| match (latest.and_then(|run| run.mem_avail_pct), span(&used)) {
            (Some(free), Some((low, high))) => {
                let colour = level(100. - free, (100. - limits.mem_avail.0, 100. - limits.mem_avail.1));
                d.child(figure(percent(100. - free), t("已用")))
                    .child(note(tf!("可用 {free:.0}% · 波动 {low:.0}%–{high:.0}%", "{free:.0}% free · ranged {low:.0}%–{high:.0}%")))
                    .child(ui::trend(&format!("mem-{name}"), used.clone(), tips(&used, &percent), 100., colour, 52.))
                    .child(axis())
            }
            _ => d.child(absent()),
        });

        // ---- processor: the load, and the share of the cores in use when it was sampled
        let loads = series(&|run: &RunView| run.load1);
        let busy = series(&|run: &RunView| run.cpu_pct);
        let processor = card("CPU 负载").map(|d| match (latest.and_then(|run| run.load1), span(&loads)) {
            (Some(load), Some((low, high))) => {
                let colour = cores.map_or(Theme::accent(), |cores| level(load / cores, limits.load_per_core));
                let per_core = cores.map(|cores| tf!("每核 {:.2} · {cores:.0} 核 · ", "{:.2} per core · {cores:.0} cores · ", load / cores)).unwrap_or_default();
                d.child(figure(format!("{load:.2}"), t("1 分钟负载")))
                    .child(note(format!("{per_core}{}", tf!("波动 {low:.2}–{high:.2}", "ranged {low:.2}–{high:.2}"))))
                    .child(ui::trend(&format!("load-{name}"), loads.clone(), tips(&loads, &|load| format!("{load:.2}")), (high * 1.25).max(1.), colour, 52.))
                    .when_some(latest.and_then(|run| run.cpu_pct), |d, now| d.child(note(tf!("CPU 使用率 {now:.0}%", "CPU in use {now:.0}%"))).child(ui::trend(&format!("cpu-{name}"), busy.clone(), tips(&busy, &percent), 100., Theme::accent(), 30.)))
                    .child(axis())
            }
            _ => d.child(absent()),
        });

        // ---- GPUs, where the server has any
        let gpu_use = series(&|run: &RunView| run.gpu_util_pct);
        let gpu_memory = series(&|run: &RunView| run.gpu_mem_pct);
        let gpu_heat = series(&|run: &RunView| run.gpu_temp_c);
        let has_gpu = host.probe.as_ref().is_some_and(|probe| probe.gpus > 0) || [&gpu_use, &gpu_memory, &gpu_heat].iter().any(|values| values.iter().any(Option::is_some));
        let gpus = has_gpu.then(|| {
            let degrees = |value: f64| format!("{value:.0}°C");
            let row = |words: &str, id: &str, values: &Vec<Option<f64>>, now: Option<f64>, say: &dyn Fn(f64) -> String, top: f64, colour: Hsla| {
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .h(px(34.))
                    .text_size(text_px(12.))
                    .child(div().flex_none().w(px(64.)).text_color(Theme::text_secondary()).child(t(words).to_string()))
                    .child(div().flex().flex_none().justify_end().w(px(44.)).font_weight(FontWeight::MEDIUM).child(now.map_or_else(|| "—".to_string(), say)))
                    .child(div().flex_1().min_w(px(60.)).child(ui::trend(&format!("{id}-{name}"), values.clone(), tips(values, say), top, colour, 30.)))
            };
            let now = |pick: &dyn Fn(&RunView) -> Option<f64>| latest.and_then(pick);
            let heat = now(&|run| run.gpu_temp_c);
            let count = host.probe.as_ref().map(|probe| probe.gpus).filter(|count| *count > 0);
            card("GPU")
                .map(|d| if [&gpu_use, &gpu_memory, &gpu_heat].iter().all(|values| values.iter().all(Option::is_none)) {
                    d.child(absent())
                } else {
                    d.child(row("利用率", "gpu-use", &gpu_use, now(&|run| run.gpu_util_pct), &percent, 100., Theme::accent()))
                        .child(row("显存已用", "gpu-mem", &gpu_memory, now(&|run| run.gpu_mem_pct), &percent, 100., Theme::accent()))
                        .child(row("最高温度", "gpu-heat", &gpu_heat, heat, &degrees, 100., if heat.is_some_and(|heat| heat >= limits.gpu_temp) { Theme::star() } else { Theme::accent() }))
                        .child(axis())
                })
                .when_some(count, |d, count| d.child(div().text_size(text_px(11.)).line_height(text_px(16.)).text_color(Theme::text_tertiary()).child(tf!("{count} 块 GPU：利用率取平均，显存取合计，温度取最热的一块", "{count} GPUs: mean utilisation, total memory, the hottest one"))))
        });

        // ---- how long a login takes
        let logins = series(&|run: &RunView| run.login_ms);
        let login = card("登录耗时").map(|d| match (latest.and_then(|run| run.login_ms), span(&logins)) {
            (Some(ms), Some((low, high))) => d.child(figure(format!("{ms:.0}"), "ms")).child(note(tf!("波动 {low:.0}–{high:.0} ms", "ranged {low:.0}–{high:.0} ms"))).child(ui::trend(&format!("login-{name}"), logins.clone(), tips(&logins, &|ms| format!("{ms:.0} ms")), (high * 1.25).max(1.), Theme::accent(), 52.)).child(axis()),
            _ => d.child(absent()),
        });

        shell
            .child(found)
            .child(disks.flex_none())
            // As many beside each other as fit; the rest go under.
            .child(div().flex().flex_wrap().gap(px(10.)).child(memory.min_w(px(230.))).child(processor.min_w(px(230.))).children(gpus.map(|gpus| gpus.min_w(px(230.)))).child(login.min_w(px(230.))))
            .into_any_element()
    }
}
