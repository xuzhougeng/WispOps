//! 机群总览: every server's last inspections as a row of squares, the
//! oldest at the left. It reads the saved history only: no server is
//! connected to and no model is called to draw it.

use crate::app::{Cmd, MenuKind, Page, Workspace};
use crate::i18n::t;
use crate::ops::HostView;
use crate::servers::{state_color, state_label};
use crate::theme::{Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::time;

/// The inspections of a server the matrix shows.
pub const RUNS_SHOWN: usize = 30;

impl Workspace {
    pub fn render_overview(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
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
                .child(self.page_head(t("机群总览"), t("每台服务器最近的巡检"), vec![]))
                .child(ui::empty_state("scan-text", t("清单里还没有服务器"), t("先在「服务器」里添加，或从 ~/.ssh/config 导入。")).child(ui::primary_button("overview-add", t("去添加服务器")).on_click(self.on(Cmd::SetPage(Page::Servers), cx))))
                .into_any_element();
        }
        let tiles = div().flex().gap(px(10.)).children(counts.into_iter().map(|(state, count)| {
            div()
                .flex()
                .flex_col()
                .flex_1()
                .gap(px(2.))
                .px(px(14.))
                .py(px(10.))
                .rounded(px(10.))
                .border_1()
                .border_color(Theme::line())
                .child(div().flex().items_center().gap(px(6.)).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(div().size(px(8.)).rounded_full().bg(state_color(state))).child(t(state_label(state))))
                .child(div().text_size(text_px(22.)).line_height(text_px(28.)).font_weight(FontWeight::SEMIBOLD).text_color(if count == 0 { Theme::text_placeholder() } else { Theme::text() }).child(count.to_string()))
        }));
        // The servers that want looking at come first; within a state, by name.
        let mut rows: Vec<&HostView> = hosts.iter().collect();
        let rank = |state: &str| match state { "crit" => 0, "unreachable" => 1, "warn" => 2, "info" => 3, "ok" => 4, _ => 5 };
        rows.sort_by(|a, b| rank(a.state()).cmp(&rank(b.state())).then(a.name.cmp(&b.name)));
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(self.page_head(t("机群总览"), t("每台服务器最近的巡检，左边最早；点方块看当次的发现"), actions))
            .child(
                div()
                    .id("overview-body")
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
                    .child(div().flex().flex_col().children(rows.into_iter().map(|host| self.render_matrix_row(host, cx)))),
            )
            .into_any_element()
    }

    fn render_matrix_row(&self, host: &HostView, cx: &mut Context<Self>) -> AnyElement {
        let working = self.working.contains(&host.name);
        let shown = &host.runs[host.runs.len().saturating_sub(RUNS_SHOWN)..];
        let offset = host.runs.len() - shown.len();
        let picked = self.selected_run.as_ref().filter(|(name, _)| name == &host.name).map(|(_, at)| *at);
        let squares = div().flex().flex_none().items_center().gap(px(2.)).w(px((RUNS_SHOWN * 12) as f32)).justify_end().children(shown.iter().enumerate().map(|(n, run)| {
            let at = offset + n;
            div()
                .id(SharedString::from(format!("run-{}-{at}", host.name)))
                .flex_none()
                .w(px(10.))
                .h(px(18.))
                .rounded(px(2.))
                .bg(state_color(&run.state))
                .when(run.state == "unreachable", |d| d.opacity(0.45))
                .when(picked == Some(at), |d| d.border_2().border_color(Theme::text()))
                .cursor_pointer()
                .hover(|s| s.opacity(0.75))
                .tooltip(ui::tip(format!("{} · {}", time::short_time(&run.at), t(state_label(&run.state)))))
                .on_click(self.on(Cmd::SelectRun(host.name.clone(), at), cx))
        }));
        let latest = host.runs.last();
        let metrics = latest.and_then(|run| run.metrics_line()).unwrap_or_default();
        let detail = picked.and_then(|at| host.runs.get(at)).map(|run| {
            let problems: Vec<_> = run.findings.iter().filter(|finding| finding.severity != "info").collect();
            div()
                .flex()
                .flex_col()
                .gap(px(4.))
                .ml(px(21.))
                .mb(px(8.))
                .px(px(12.))
                .py(px(10.))
                .rounded(px(8.))
                .bg(Theme::bg_sunken())
                .text_size(text_px(12.))
                .line_height(text_px(18.))
                .child(div().flex().items_center().gap(px(8.)).child(ui::status_chip(&run.state, t(state_label(&run.state)))).child(div().text_color(Theme::text_tertiary()).child(time::short_time(&run.at))).children(run.metrics_line().map(|line| div().text_color(Theme::text_secondary()).child(line))))
                .children(problems.iter().map(|finding| div().flex().items_start().gap(px(6.)).child(div().flex_none().mt(px(6.)).size(px(6.)).rounded_full().bg(state_color(&finding.severity))).child(div().flex_1().min_w_0().text_color(if finding.muted { Theme::text_tertiary() } else { Theme::text() }).child(finding.message.clone()))))
                .when(problems.is_empty(), |d| d.child(div().text_color(Theme::text_tertiary()).child(t("这次巡检没有发现问题。"))))
        });
        div()
            .flex()
            .flex_col()
            .border_b_1()
            .border_color(Theme::line())
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .h(text_px(40.))
                    .child(if working { ui::spinner(SharedString::from(format!("overview-working-{}", host.name)), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(9.)).m(px(1.5)).rounded_full().bg(state_color(host.state())).into_any_element() })
                    .child(div().id(SharedString::from(format!("overview-host-{}", host.name))).w(px(170.)).flex_none().truncate().font_weight(FontWeight::MEDIUM).cursor_pointer().hover(|s| s.text_color(Theme::accent())).on_click(self.on(Cmd::SelectHost(Some(host.name.clone())), cx)).child(host.name.clone()))
                    .child(squares)
                    .child(div().flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(Theme::text_secondary()).child(if host.runs.is_empty() { t("未巡检").to_string() } else { metrics }))
                    .child(ui::icon_action(SharedString::from(format!("overview-inspect-{}", host.name)), "loader", Theme::text_tertiary(), t("立即巡检")).on_click(self.on(Cmd::InspectHosts(host.name.clone()), cx))),
            )
            .children(detail)
            .into_any_element()
    }
}
