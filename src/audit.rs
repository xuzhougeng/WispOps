//! 操作审计: every remote command the assistant, the window and the tasks
//! ran, with its risk, how it was authorized and how it ended. No credential
//! is in it.

use crate::app::{Cmd, Workspace};
use crate::dialogs::segmented;
use crate::i18n::t;
use crate::theme::{self, Theme, text_px};
use crate::tools;
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::time;

/// The most rows the page shows.
pub const AUDIT_ROWS: usize = 500;

impl Workspace {
    pub fn reload_audit(&mut self, cx: &mut Context<Self>) {
        self.view.audit = self.fleet.audit(self.audit_host.as_deref(), self.audit_hours, AUDIT_ROWS);
        cx.notify();
    }

    pub fn render_audit(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let ranges = segmented([(24, "24 小时"), (24 * 7, "7 天"), (24 * 30, "30 天")].into_iter().map(|(hours, label)| (div().id(SharedString::from(format!("audit-range-{hours}"))).child(t(label)).on_click(self.on(Cmd::AuditRange(hours), cx)), self.audit_hours == hours)).collect()).w(px(220.));
        let mut actions = vec![];
        if let Some(host) = &self.audit_host {
            actions.push(div().flex().items_center().gap(px(4.)).h(text_px(26.)).pl(px(10.)).pr(px(4.)).rounded(px(13.)).bg(Theme::accent_soft()).text_size(text_px(12.)).child(host.clone()).child(ui::icon_action("audit-host-clear", "x", Theme::text_tertiary(), t("看全部服务器")).on_click(self.on(Cmd::AuditHost(None), cx))).into_any_element());
        }
        actions.push(ranges.into_any_element());
        let rows = &self.view.audit;
        let body: AnyElement = if rows.is_empty() {
            ui::empty_state("history", t("这段时间没有记录"), t("助手、这个窗口和例行任务执行的每一条远程命令都会记在这里。")).into_any_element()
        } else {
            let head = div().flex().flex_none().items_center().gap(px(12.)).h(text_px(30.)).px(px(24.)).border_b_1().border_color(Theme::line()).text_size(text_px(11.)).text_color(Theme::text_tertiary()).child(div().w(px(92.)).flex_none().child(t("时间"))).child(div().w(px(130.)).flex_none().child(t("服务器"))).child(div().w(px(92.)).flex_none().child(t("来源"))).child(div().w(px(110.)).flex_none().child(t("风险"))).child(div().w(px(70.)).flex_none().child(t("授权"))).child(div().w(px(84.)).flex_none().child(t("结果"))).child(div().flex_1().child(t("命令")));
            let list = div().id("audit-list").flex().flex_col().flex_1().min_h_0().overflow_y_scroll().track_scroll(&self.page_scroll).children(rows.iter().enumerate().map(|(n, row)| {
                let ok = row.status == "ok";
                div()
                    .id(("audit", n))
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .w_full()
                    .h(text_px(34.))
                    .px(px(24.))
                    .border_b_1()
                    .border_color(Theme::line())
                    .text_size(text_px(12.))
                    .cursor_pointer()
                    .hover(|s| s.bg(Theme::hover()))
                    .on_click(cx.listener({
                        let (title, text) = (format!("{} · {}", row.host, time::short_time(&row.at)), row.detail());
                        move |this, _, _, cx| this.open_modal(crate::dialogs::Modal::Text { title: title.clone(), text: text.clone(), scroll: ScrollHandle::new() }, cx)
                    }))
                    .child(div().w(px(92.)).flex_none().text_color(Theme::text_tertiary()).child(time::short_time(&row.at)))
                    .child(div().w(px(130.)).flex_none().truncate().child(row.host.clone()))
                    .child(div().w(px(92.)).flex_none().truncate().text_color(Theme::text_secondary()).child(t(tools::origin_label(&row.tool)).to_string()))
                    .child(div().w(px(110.)).flex_none().flex().gap(px(4.)).child(ui::status_chip(&row.risk, t(tools::risk_label(&row.risk)))).when(row.sudo, |d| d.child(ui::status_chip("sudo", "sudo"))))
                    .child(div().w(px(70.)).flex_none().truncate().text_color(Theme::text_secondary()).child(t(tools::authorization_label(&row.authorization)).to_string()))
                    .child(div().w(px(84.)).flex_none().truncate().text_color(if ok { Theme::success() } else { Theme::danger() }).child(match row.exit_code { Some(code) if !ok => format!("{} / {code}", t(tools::status_label(&row.status))), _ => t(tools::status_label(&row.status)).to_string() }))
                    .child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_color(Theme::text_secondary()).child(row.command.lines().next().unwrap_or("").to_string()))
            }));
            div().flex().flex_col().flex_1().min_h_0().child(head).child(list).into_any_element()
        };
        div().flex().flex_col().size_full().child(self.page_head(t("操作审计"), tf!("最近的 {} 条远程命令：谁执行的、风险、怎么授权的、结果如何", "The latest {} remote commands: who ran them, their risk, how they were authorized, how they ended", rows.len()), actions)).child(body).into_any_element()
    }
}
