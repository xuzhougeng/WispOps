//! 安全: how each server is being attacked. A triage reads the SSH log of
//! the last day and counts the logins that failed: how many, from which
//! addresses, with which account names, hour by hour; and beside them the
//! logins that succeeded and the other leads the triage found (miners,
//! deleted binaries, changed keys). The auth log is root's to read: where
//! the window may use root (a root login, passwordless sudo, or a linked
//! sudo credential) it does; elsewhere the row says what could not be read.

use crate::app::{Cmd, MenuKind, Page, Workspace};
use crate::i18n::t;
use crate::servers::state_color;
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_collect::attacks::SecuritySnapshot;
use wisp_ops_collect::inspect::Severity;
use wisp_ops_collect::security::SourceCount;
use wisp_ops_collect::util::n;
use wisp_ops_core::time;

/// The window the page's triage looks back over, in hours.
pub const WINDOW_HOURS: u32 = 24;
/// The hours a row's chart shows.
const CHART_HOURS: usize = 36;

/// The worst of a triage's findings: `crit`, `warn`, `info` or `ok`.
pub fn worst(row: &SecuritySnapshot) -> &'static str {
    wisp_ops_collect::inspect::worst_severity(row.report.findings.iter()).map_or("ok", Severity::as_str)
}

/// Failed logins of a triage: counted per attempt where the tail ran, else what the sources add up to.
fn failed(row: &SecuritySnapshot) -> f64 {
    if row.attacks.failed > 0. { row.attacks.failed } else { row.report.failed_by_source.iter().map(|source| source.count).sum() }
}

fn sources(row: &SecuritySnapshot) -> f64 {
    row.attacks.sources.max(row.report.failed_by_source.len() as f64)
}

impl Workspace {
    /// Triage the selected servers off the main thread, as root where the window may.
    pub fn scan_attacks(&mut self, selector: String, cx: &mut Context<Self>) {
        let names: Vec<String> = match self.fleet.select_names(&selector) {
            Ok(names) => names.into_iter().filter(|name| !self.attack_working.contains(name)).collect(),
            Err(error) => return self.fail(error, cx),
        };
        if names.is_empty() { return }
        self.attack_working.extend(names.iter().cloned());
        let fleet = self.fleet.clone();
        let selector = names.join(",");
        let work = cx.background_executor().spawn(async move { fleet.attack_scan(&selector, WINDOW_HOURS) });
        cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                for name in &names { this.attack_working.remove(name); }
                this.reload(cx);
                match result {
                    Ok(words) => this.say(words, cx),
                    Err(error) => this.fail(error, cx),
                }
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    pub fn render_security(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let busy = !self.attack_working.is_empty();
        let actions = vec![
            ui::secondary_button("attack-report", t("让助手分析")).child(ui::icon("sparkle", 13., Theme::accent())).on_click(self.on(Cmd::Suggest("/security all".into()), cx)).into_any_element(),
            ui::primary_button("attack-scan", if busy { t("正在排查…") } else { t("排查全部") }).when(busy, |b| b.opacity(0.6)).on_click(self.on(Cmd::ScanAttacks("all".into()), cx)).into_any_element(),
        ];
        let head = self.page_head(t("安全"), t("最近 24 小时每台服务器受到的登录攻击和可疑迹象；认证日志要 root 才能读"), actions, cx);
        if self.view.hosts.is_empty() {
            return div().flex().flex_col().size_full().child(head).child(ui::empty_state("shield", t("清单里还没有服务器"), t("先在「服务器」里添加，或从 ~/.ssh/config 导入。")).child(ui::primary_button("attack-add", t("去添加服务器")).on_click(self.on(Cmd::SetPage(Page::Servers), cx)))).into_any_element();
        }
        let rows = &self.view.attacks;
        let total: f64 = rows.values().map(failed).sum();
        let from: f64 = rows.values().map(sources).sum();
        let broken = rows.values().filter(|row| row.report.findings.iter().any(|finding| finding.code == "login-after-bruteforce")).count();
        let serious = rows.values().filter(|row| worst(row) == "crit").count();
        let tile = |label: &str, value: String, colour: Hsla| div().flex().flex_col().flex_1().gap(px(2.)).px(px(14.)).py(px(10.)).rounded(px(10.)).border_1().border_color(Theme::line()).child(div().text_size(text_px(12.)).text_color(Theme::text_secondary()).child(label.to_string())).child(div().text_size(text_px(22.)).line_height(text_px(28.)).font_weight(FontWeight::SEMIBOLD).text_color(colour).child(value));
        let calm = |count: f64, alarm: Hsla| if count == 0. { Theme::text_placeholder() } else { alarm };
        let tiles = div()
            .flex()
            .gap(px(10.))
            .child(tile(t("失败登录（24 小时）"), n(total), calm(total, Theme::text())))
            .child(tile(t("攻击来源地址"), n(from), calm(from, Theme::text())))
            .child(tile(t("爆破后登录成功"), broken.to_string(), calm(broken as f64, Theme::danger())))
            .child(tile(t("有严重发现的服务器"), serious.to_string(), calm(serious as f64, Theme::danger())));
        // The servers under the most fire first; those never triaged last.
        let mut hosts: Vec<&str> = self.view.hosts.iter().map(|host| host.name.as_str()).collect();
        let rank = |name: &str| rows.get(name).map(|row| (match worst(row) { "crit" => 0, "warn" => 1, _ => 2 }, -failed(row)));
        hosts.sort_by(|a, b| match (rank(a), rank(b)) {
            (Some(a), Some(b)) => a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(head)
            .child(
                div()
                    .id("attack-body")
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
                    .child(div().flex().flex_col().children(hosts.into_iter().map(|host| self.render_attack_row(host, cx)))),
            )
            .into_any_element()
    }

    fn render_attack_row(&self, host: &str, cx: &mut Context<Self>) -> AnyElement {
        let row = self.view.attacks.get(host);
        // A server whose logins are paused cannot be triaged: the row says so instead of "not triaged".
        let paused = self.view.hosts.iter().find(|shown| shown.name == host).filter(|shown| shown.blocked_until.is_some());
        let working = self.attack_working.contains(host);
        let open = self.open_attack.as_deref() == Some(host);
        // A triage that could not read the auth log has not cleared the server of anything.
        let state = row.map_or("none", |row| match worst(row) { "ok" | "info" if !row.report.auth_log_readable => "none", state => state });
        // Failed logins hour by hour, the latest at the right; the tallest hour sets the scale.
        let chart = div().flex().flex_none().items_end().justify_end().gap(px(1.)).w(px((CHART_HOURS * 4) as f32)).h(px(20.)).children(row.into_iter().flat_map(|row| {
            let hours = &row.attacks.hours[row.attacks.hours.len().saturating_sub(CHART_HOURS)..];
            let top = hours.iter().map(|hour| hour.count).fold(1., f64::max);
            hours.iter().enumerate().map(move |(at, hour)| {
                div()
                    .id(SharedString::from(format!("attack-hour-{host}-{at}")))
                    .flex_none()
                    .w(px(3.))
                    .h(px(if hour.count > 0. { (hour.count / top * 20.).max(2.) as f32 } else { 1. }))
                    .rounded(px(1.))
                    .bg(if hour.count > 0. { Theme::danger().opacity(0.75) } else { Theme::line_strong() })
                    .tooltip(ui::tip(tf!("{} 时：失败 {} 次", "{}h: {} failed", hour.hour, n(hour.count))))
            })
        }));
        let words = match row {
            None => t("未排查").to_string(),
            Some(row) if !row.report.auth_log_readable => t("读不到认证日志").to_string(),
            Some(row) => tf!("失败登录 {} 次 · {} 个来源", "{} failed logins · {} sources", n(failed(row)), n(sources(row))),
        };
        let line = div()
            .id(SharedString::from(format!("attack-row-{host}")))
            .flex()
            .items_center()
            .gap(px(12.))
            .h(text_px(44.))
            .cursor_pointer()
            .hover(|s| s.bg(Theme::hover()))
            .on_click(self.on(Cmd::OpenAttack(host.to_string()), cx))
            .on_mouse_down(MouseButton::Right, self.on_context(MenuKind::AttackHost(host.to_string()), cx))
            .child(if working { ui::spinner(SharedString::from(format!("attack-working-{host}")), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(9.)).m(px(1.5)).rounded_full().bg(state_color(state)).into_any_element() })
            .child(div().w(px(150.)).flex_none().truncate().font_weight(FontWeight::MEDIUM).child(host.to_string()))
            .child(chart)
            .child(div().flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(if row.is_some_and(|row| failed(row) > 0.) { Theme::text() } else { Theme::text_tertiary() }).child(words))
            .children(paused.map(|_| ui::status_chip("deny", t("登录已暂停"))))
            .children(row.filter(|row| !row.report.full_visibility).map(|_| div().id(SharedString::from(format!("attack-partial-{host}"))).flex_none().tooltip(ui::tip(t("这次排查不是以 root 运行的：其他用户的进程和连接可能看不到。关联 sudo 凭据后重新排查。"))).child(ui::status_chip("warn", t("非 root")))))
            .children(row.filter(|row| !row.attacks.banned.is_empty()).map(|row| ui::status_chip("info", &tf!("已封禁 {}", "{} banned", row.attacks.banned.len()))))
            .children(row.map(|row| div().flex_none().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(time::short_time(&row.at))))
            .child(ui::icon_action(SharedString::from(format!("attack-scan-{host}")), "loader", Theme::text_tertiary(), t("重新排查")).on_click({
                let scan = self.on(Cmd::ScanAttacks(host.to_string()), cx);
                move |event, window, cx| {
                    cx.stop_propagation();
                    scan(event, window, cx);
                }
            }));
        div().flex().flex_col().border_b_1().border_color(Theme::line()).child(line).children(paused.filter(|_| open || row.is_none()).and_then(|shown| self.render_blocked(shown, "attack", cx)).map(|banner| banner.ml(px(21.)).mb(px(10.)))).children(row.filter(|_| open).map(|row| self.render_attack_detail(host, row, cx))).into_any_element()
    }

    /// A triage laid open: who attacks, with which names, who got in, and the other leads.
    fn render_attack_detail(&self, host: &str, row: &SecuritySnapshot, cx: &mut Context<Self>) -> AnyElement {
        let report = &row.report;
        let accepted_from = |source: &str| report.accepted.iter().any(|login| login.source == source);
        // A list of counted things, each with a bar to the scale of the largest.
        let counted = |title: String, rows: &[SourceCount], danger: &dyn Fn(&str) -> bool, mono: bool| {
            let top = rows.iter().map(|row| row.count).fold(1., f64::max);
            div().flex().flex_col().flex_1().min_w_0().gap(px(3.)).child(ui::caption(title)).children(rows.iter().take(8).map(|item| {
                let alarm = danger(&item.source);
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .h(text_px(22.))
                    .child(div().w(px(150.)).flex_none().truncate().when(mono, |d| d.font_family(theme::MONO_FONT)).text_color(if alarm { Theme::danger() } else { Theme::text() }).child(item.source.clone()))
                    .child(div().flex_1().min_w_0().h(px(5.)).rounded_full().bg(Theme::groove()).child(div().h_full().w(relative((item.count / top) as f32)).rounded_full().bg(if alarm { Theme::danger() } else { Theme::text_tertiary() })))
                    .child(div().w(px(52.)).flex_none().text_right().text_color(Theme::text_secondary()).child(n(item.count)))
            }))
            .when(rows.is_empty(), |d| d.child(div().text_color(Theme::text_tertiary()).child(t("没有"))))
        };
        let by_source: &[SourceCount] = if row.attacks.by_source.is_empty() { &report.failed_by_source } else { &row.attacks.by_source };
        let logins = div().flex().flex_col().flex_1().min_w_0().gap(px(3.)).child(ui::caption(t("登录成功"))).children(report.accepted.iter().take(8).enumerate().map(|(at, login)| {
            let alarm = report.failed_by_source.iter().any(|source| source.source == login.source && source.count >= 20.);
            let (who, how) = (format!("{} ← {}", login.user, login.source), format!("{} × {}", login.method, n(login.count)));
            // Who got in and from where is what must be read whole: the method gives way to it.
            div().id(SharedString::from(format!("attack-login-{host}-{at}"))).flex().items_center().gap(px(8.)).h(text_px(22.)).tooltip(ui::tip(format!("{who} · {how}"))).child(div().flex_shrink_0().max_w_full().truncate().text_color(if alarm { Theme::danger() } else { Theme::text() }).child(who)).child(div().flex_1().min_w_0().truncate().text_right().text_color(Theme::text_tertiary()).child(how))
        }))
        .when(report.accepted.is_empty(), |d| d.child(div().text_color(Theme::text_tertiary()).child(t("没有"))));
        let findings: Vec<_> = report.findings.iter().filter(|finding| finding.severity != Severity::Info).collect();
        let sshd: Vec<String> = report.sshd.iter().map(|(key, value)| format!("{key} {value}")).collect();
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .ml(px(21.))
            .mb(px(10.))
            .px(px(14.))
            .py(px(12.))
            .rounded(px(8.))
            .bg(Theme::bg_sunken())
            .text_size(text_px(12.))
            .line_height(text_px(18.))
            .when(!report.auth_log_readable, |d| {
                d.child(div().flex().items_center().gap(px(10.)).child(div().flex_1().min_w_0().text_color(Theme::warning()).child(t("这次排查不是以 root 运行的，读不到 SSH 认证日志，所以没有登录失败的统计。给这台服务器关联 sudo 凭据（或用 root 登录、配置免密 sudo 后重新探测），再排查一次。"))).child(ui::secondary_button("attack-bind", t("关联 sudo 凭据")).h(text_px(26.)).on_click(self.on(Cmd::BindCredential(host.to_string(), true), cx))))
            })
            .when(report.auth_log_readable, |d| d.child(div().flex().gap(px(24.)).child(counted(t("攻击来源").to_string(), by_source, &accepted_from, true)).child(counted(t("尝试的账号").to_string(), &row.attacks.by_user, &|_| false, true)).child(logins)))
            .when(!findings.is_empty(), |d| d.child(div().flex().flex_col().gap(px(4.)).child(ui::caption(t("发现"))).children(findings.iter().map(|finding| div().flex().items_start().gap(px(6.)).child(div().flex_none().mt(px(6.)).size(px(6.)).rounded_full().bg(state_color(finding.severity.as_str()))).child(div().flex_1().min_w_0().child(crate::findings::words(&finding.code, &finding.message)))))))
            .when(findings.is_empty() && report.auth_log_readable, |d| d.child(div().text_color(Theme::text_tertiary()).child(t("除登录尝试外，这次排查没有发现可疑迹象。"))))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(14.))
                    .text_color(Theme::text_tertiary())
                    .when(!sshd.is_empty(), |d| d.child(div().flex_1().min_w_0().truncate().child(format!("sshd: {}", sshd.join(" · ")))))
                    .when(sshd.is_empty(), |d| d.child(div().flex_1()))
                    .child(div().flex_none().child(if report.fail2ban.is_empty() { t("fail2ban 未启用").to_string() } else { format!("fail2ban: {}", report.fail2ban.join(" · ")) }))
                    .child(ui::secondary_button(SharedString::from(format!("attack-ask-{host}")), t("让助手分析")).h(text_px(26.)).child(ui::icon("sparkle", 12., Theme::accent())).on_click(self.on(Cmd::Suggest(format!("/security {host}")), cx))),
            )
            .into_any_element()
    }
}
