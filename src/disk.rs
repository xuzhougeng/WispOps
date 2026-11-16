//! 磁盘: what fills each disk of a server, as a map of blocks. Every block is
//! a directory, its area the space it takes; a large block shows the next
//! level inside, and a click opens it. The first scan of a server measures
//! either the login's own home directory or, as root, every local
//! filesystem; after that the same is measured again on a timer, and the
//! page says what grew since the scan before. Scans only read (`du`), are
//! recorded in the audit, and are kept in the data folder.

use crate::app::{Cmd, MenuKind, Page, SIDEBAR_W, Workspace};
use crate::dialogs::{Modal, segmented};
use crate::i18n::t;
use crate::ops::HostView;
use crate::scans::{DiskPlan, ScanView, Scope};
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use std::collections::HashSet;
use wisp_ops_collect::sections::format_kb;
use wisp_ops_collect::space::{SpaceNode, find_space_node};
use wisp_ops_core::time;

/// What the page holds: the server on show, its stored scans, and where in them the reader is.
#[derive(Default)]
pub struct DiskState {
    pub host: Option<String>,
    pub scans: Vec<ScanView>,
    pub plan: Option<DiskPlan>,
    /// The scanned path on show; empty is the first.
    pub path: String,
    /// The directory opened in the map; empty is the scan's root.
    pub zoom: String,
    pub list: bool,
    pub hide_free: bool,
    /// The servers being scanned right now.
    pub scanning: HashSet<String>,
}

/// An interval of the follow-up scans in words.
pub fn rescan_label(minutes: u32) -> String {
    match minutes {
        0 => t("关闭").to_string(),
        1440 => t("每天").to_string(),
        10080 => t("每周").to_string(),
        m => tf!("每 {} 小时", "Every {} h", m / 60),
    }
}

/// A change of size in words: `+3.2G`, `−1.1G`.
fn delta_words(delta: f64) -> String {
    format!("{}{}", if delta >= 0. { "+" } else { "−" }, format_kb(delta.abs()))
}

fn share(part: f64, whole: f64) -> String {
    let value = if whole > 0. { part / whole * 100. } else { 0. };
    if value >= 10. || value == 0. { format!("{value:.0}%") } else { format!("{value:.1}%") }
}

// ---- the layout

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

fn flush(row: &mut Vec<(usize, f64)>, rect: &mut Rect, out: &mut Vec<(usize, Rect)>) {
    let sum: f64 = row.iter().map(|(_, area)| area).sum();
    if rect.w <= 0. || rect.h <= 0. || sum <= 0. { return row.clear() }
    if rect.w >= rect.h {
        let w = ((sum / f64::from(rect.h)) as f32).min(rect.w);
        let mut y = rect.y;
        for (item, area) in row.drain(..) {
            let h = (area / f64::from(w)) as f32;
            out.push((item, Rect { x: rect.x, y, w, h }));
            y += h;
        }
        *rect = Rect { x: rect.x + w, y: rect.y, w: rect.w - w, h: rect.h };
    } else {
        let h = ((sum / f64::from(rect.w)) as f32).min(rect.h);
        let mut x = rect.x;
        for (item, area) in row.drain(..) {
            let w = (area / f64::from(h)) as f32;
            out.push((item, Rect { x, y: rect.y, w, h }));
            x += w;
        }
        *rect = Rect { x: rect.x, y: rect.y + h, w: rect.w, h: rect.h - h };
    }
}

/// Squarified treemap (Bruls, Huizing and van Wijk): fills `bounds` with one rectangle per
/// positive value, in the order given, keeping each close to square. Values come largest first;
/// each rectangle is given with the place of its value.
pub fn squarify(values: &[f64], bounds: Rect) -> Vec<(usize, Rect)> {
    let total: f64 = values.iter().map(|value| value.max(0.)).sum();
    if total <= 0. || bounds.w <= 0. || bounds.h <= 0. { return vec![] }
    let scale = f64::from(bounds.w) * f64::from(bounds.h) / total;
    // The most elongated rectangle if these areas share one strip along `side`.
    let worst = |row: &[(usize, f64)], more: Option<f64>, side: f64| {
        let sum: f64 = row.iter().map(|(_, area)| *area).chain(more).sum();
        row.iter().map(|(_, area)| *area).chain(more).map(|area| (side * side * area / (sum * sum)).max(sum * sum / (side * side * area))).fold(0., f64::max)
    };
    let (mut out, mut rect, mut row) = (vec![], bounds, Vec::<(usize, f64)>::new());
    for (item, value) in values.iter().enumerate() {
        if value.partial_cmp(&0.) != Some(std::cmp::Ordering::Greater) { continue }
        let area = value * scale;
        let side = f64::from(rect.w.min(rect.h));
        if !row.is_empty() && worst(&row, Some(area), side) > worst(&row, None, side) { flush(&mut row, &mut rect, &mut out) }
        row.push((item, area));
    }
    flush(&mut row, &mut rect, &mut out);
    out
}

// ---- the blocks

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Dir,
    /// Files directly in the open directory.
    Files,
    /// The directories too small to be drawn each.
    Other,
    Free,
}

struct Block<'a> {
    key: String,
    kind: Kind,
    kb: f64,
    /// What the share is a part of: the open directory, or the filesystem for free space.
    of: f64,
    label: String,
    /// Its place among the hues; none draws it neutral.
    hue: Option<usize>,
    node: Option<&'a SpaceNode>,
}

impl Block<'_> {
    fn colour(&self) -> Hsla {
        self.hue.map_or_else(theme::map_neutral, theme::map_hue)
    }

    /// The directory a click opens: one that lists subdirectories.
    fn opens(&self) -> Option<String> {
        self.node.filter(|node| !node.children.is_empty()).map(|node| node.path.clone())
    }
}

/// Blocks drawn per level; the smaller directories merge into one.
const MAX_BLOCKS: usize = 24;
const MAX_NESTED: usize = 12;
const MAX_ROWS: usize = 200;
const GAP: f32 = 4.;
const HEADER: f32 = 40.;
const PAD: f32 = 6.;
const HOSTS_W: f32 = 210.;

/// The blocks of one directory: its largest subdirectories, the rest merged, the files directly in it, and free space last.
fn blocks_of<'a>(node: &'a SpaceNode, limit: usize, hue: impl Fn(usize) -> Option<usize>, free: Option<(f64, f64)>) -> Vec<Block<'a>> {
    let shown = &node.children[..node.children.len().min(limit)];
    let hidden = &node.children[shown.len()..];
    let mut blocks: Vec<Block> = shown.iter().enumerate().map(|(at, child)| Block { key: child.path.clone(), kind: Kind::Dir, kb: child.kb, of: node.kb, label: child.name.clone(), hue: hue(at), node: Some(child) }).collect();
    let other: f64 = hidden.iter().map(|child| child.kb).sum();
    if other > 0. { blocks.push(Block { key: format!("{}//other", node.path), kind: Kind::Other, kb: other, of: node.kb, label: tf!("其余 {} 个目录", "{} more directories", hidden.len()), hue: None, node: None }) }
    if node.rest_kb > 0. { blocks.push(Block { key: format!("{}//files", node.path), kind: Kind::Files, kb: node.rest_kb, of: node.kb, label: t("此目录下的文件").to_string(), hue: None, node: None }) }
    blocks.sort_by(|a, b| b.kb.total_cmp(&a.kb));
    // Free space goes last, so it fills what the directories leave.
    if let Some((kb, of)) = free.filter(|(kb, _)| *kb > 0.) { blocks.push(Block { key: "//free".into(), kind: Kind::Free, kb, of, label: t("剩余空间").to_string(), hue: None, node: None }) }
    blocks
}

impl Workspace {
    /// Read the stored scans of the server on show. Called when the page opens, another server is picked, or a scan ends: never while drawing.
    pub fn load_disk(&mut self, cx: &mut Context<Self>) {
        if self.disk.host.as_ref().is_none_or(|name| !self.view.hosts.iter().any(|host| &host.name == name)) {
            self.disk.host = self.selected_host.clone().or_else(|| self.view.hosts.first().map(|host| host.name.clone()));
        }
        (self.disk.scans, self.disk.plan) = match &self.disk.host {
            Some(name) => (self.fleet.disk_scans(name), self.fleet.disk_plans().remove(name)),
            None => (vec![], None),
        };
        if !self.disk.scans.iter().any(|scan| scan.path == self.disk.path) {
            self.disk.path = self.disk.scans.first().map(|scan| scan.path.clone()).unwrap_or_default();
            self.disk.zoom.clear();
        }
        cx.notify();
    }

    pub fn run_disk(&mut self, cmd: Cmd, cx: &mut Context<Self>) {
        match cmd {
            Cmd::DiskHost(name) => {
                if self.disk.host.as_ref() != Some(&name) { (self.disk.path, self.disk.zoom) = (String::new(), String::new()) }
                self.disk.host = Some(name);
                self.page = Page::Disk;
                self.load_disk(cx);
            }
            Cmd::AskFullScan(name) => {
                // Said before anything runs: what root is needed for, and how to give it.
                let ready = self.fleet.inventory().host(&name).cloned().ok_or_else(|| tf!("清单里没有 {name}。", "{name} is not in the inventory.")).and_then(|host| self.fleet.root_way(&host));
                match ready {
                    Err(error) => self.fail(error, cx),
                    Ok(_) => self.open_modal(Modal::Confirm { title: t("全盘扫描").to_string(), message: tf!("以 root 在 {name} 的每个本地文件系统上运行 du，统计 5 层以内的目录大小。只读，但目录很多时要读几分钟到十几分钟磁盘，并写入操作审计。之后会按设定的间隔自动做增量扫描。", "Run du as root on every local filesystem of {name}, sizing directories five levels deep. It only reads, but with many directories it reads the disks for minutes, and it is recorded in the audit. Follow-up scans then run at the chosen interval."), label: t("开始扫描").to_string(), danger: false, cmd: Cmd::DiskScan(name, Scope::Full) }, cx),
                }
            }
            Cmd::DiskScan(name, scope) => self.scan_disk(name, scope, false, cx),
            Cmd::DiskPath(path) => {
                self.disk.path = path;
                self.disk.zoom.clear();
            }
            Cmd::DiskZoom(path) => self.disk.zoom = path,
            Cmd::DiskList(list) => self.disk.list = list,
            Cmd::ToggleDiskFree => self.disk.hide_free = !self.disk.hide_free,
            _ => {}
        }
    }

    /// Scan a server's disks off the main thread. A scan on the timer is quiet: what went wrong is shown on the page.
    pub fn scan_disk(&mut self, name: String, scope: Scope, timed: bool, cx: &mut Context<Self>) {
        if !self.disk.scanning.insert(name.clone()) { return }
        let fleet = self.fleet.clone();
        let work = cx.background_executor().spawn({
            let name = name.clone();
            async move { fleet.scan_disk(&name, scope, timed) }
        });
        cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                this.disk.scanning.remove(&name);
                if this.disk.host.as_ref() == Some(&name) && this.page == Page::Disk { this.load_disk(cx) }
                match result {
                    _ if timed => {}
                    Ok(words) => this.say(words, cx),
                    Err(error) => this.fail(error, cx),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// The follow-up scans whose time has come (called every minute by `watch_fleet`), two servers at a time at most.
    pub fn run_due_disk_scans(&mut self, cx: &mut Context<Self>) {
        for name in self.fleet.disk_due(self.settings.disk_scan_minutes) {
            if self.disk.scanning.len() >= 2 { break }
            self.scan_disk(name, Scope::Again, true, cx);
        }
    }

    // ---- drawing

    pub fn render_disk(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let actions = vec![ui::ghost_button("disk-auto", Some("history"), Some(tf!("增量扫描：{}", "Follow-up scans: {}", rescan_label(self.settings.disk_scan_minutes)).into())).on_click(self.on_menu(MenuKind::DiskScan, cx)).into_any_element()];
        let head = self.page_head(t("磁盘"), t("每块磁盘被什么占着：方块越大占得越多，点方块进入目录"), actions, cx);
        if self.view.hosts.is_empty() {
            return div().flex().flex_col().size_full().child(head).child(ui::empty_state("hard-drive", t("清单里还没有服务器"), t("先在「服务器」里添加，或从 ~/.ssh/config 导入。")).child(ui::primary_button("disk-add", t("去添加服务器")).on_click(self.on(Cmd::SetPage(Page::Servers), cx)))).into_any_element();
        }
        let hosts = div().id("disk-hosts").flex().flex_col().flex_none().w(px(HOSTS_W)).h_full().overflow_y_scroll().px(px(8.)).py(px(10.)).gap(px(1.)).border_r_1().border_color(Theme::line()).children(self.view.hosts.iter().map(|host| {
            let active = self.disk.host.as_ref() == Some(&host.name);
            let fullest = host.runs.last().and_then(|run| run.disk_max.as_ref()).map(|(_, pct)| *pct);
            let colour = match fullest {
                Some(pct) if pct >= 90. => Theme::danger(),
                Some(pct) if pct >= 80. => Theme::star(),
                Some(_) => Theme::success(),
                None => Theme::line_strong(),
            };
            div()
                .id(SharedString::from(format!("disk-host-{}", host.name)))
                .flex()
                .flex_none()
                .items_center()
                .gap(px(8.))
                .h(text_px(34.))
                .px(px(10.))
                .rounded(px(7.))
                .cursor_pointer()
                .when(active, |d| d.bg(Theme::accent_soft()).font_weight(FontWeight::MEDIUM))
                .hover(|s| s.bg(Theme::hover()))
                .on_click(self.on(Cmd::DiskHost(host.name.clone()), cx))
                .child(if self.disk.scanning.contains(&host.name) { ui::spinner(SharedString::from(format!("disk-scanning-{}", host.name)), 12., Theme::accent()).into_any_element() } else { div().flex_none().size(px(8.)).m(px(2.)).rounded_full().bg(colour).into_any_element() })
                .child(div().flex_1().min_w_0().truncate().child(host.name.clone()))
                .children(fullest.map(|pct| div().flex_none().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(format!("{pct:.0}%"))))
        }));
        let host = self.disk.host.as_ref().and_then(|name| self.view.hosts.iter().find(|host| &host.name == name));
        let detail = match host {
            Some(host) => self.render_disk_host(host, window, cx),
            None => div().into_any_element(),
        };
        div().flex().flex_col().size_full().child(head).child(div().flex().flex_1().min_h_0().child(hosts).child(detail)).into_any_element()
    }

    fn render_disk_host(&self, host: &HostView, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let name = host.name.clone();
        let scanning = self.disk.scanning.contains(&name);
        let plan = self.disk.plan.as_ref();
        let about = match plan {
            Some(plan) => {
                let scope = if plan.scope == "full" { t("全盘（root）") } else { t("用户目录") };
                tf!("{scope} · 首次扫描 {} · 最近 {}", "{scope} · first scan {} · latest {}", time::short_time(&plan.first_at), time::short_time(&plan.last_at))
            }
            None => t("还没有做过第一次扫描").to_string(),
        };
        let buttons = div()
            .flex()
            .flex_none()
            .items_center()
            .gap(px(6.))
            .when(scanning, |d| d.child(div().flex().items_center().gap(px(6.)).mr(px(6.)).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(ui::spinner("disk-working", 12., Theme::accent())).child(t("正在扫描，目录多时需要几分钟…"))))
            .when(plan.is_some() && !scanning, |d| d.child(ui::primary_button("disk-again", t("增量扫描")).h(text_px(28.)).on_click(self.on(Cmd::DiskScan(name.clone(), Scope::Again), cx))))
            .when(!scanning, |d| d.child(ui::secondary_button("disk-home", t("扫描用户目录")).h(text_px(28.)).on_click(self.on(Cmd::DiskScan(name.clone(), Scope::Home), cx))).child(ui::secondary_button("disk-full", t("全盘扫描（root）")).h(text_px(28.)).on_click(self.on(Cmd::AskFullScan(name.clone()), cx))));
        let top = div().flex().flex_col().gap(px(2.)).child(div().flex().items_center().gap(px(12.)).child(div().flex_1().min_w_0().truncate().text_size(text_px(15.)).font_weight(FontWeight::SEMIBOLD).child(name.clone())).child(buttons)).child(div().truncate().text_size(text_px(12.)).line_height(text_px(17.)).text_color(Theme::text_tertiary()).child(about));
        let column = div().id("disk-detail").flex().flex_col().flex_1().min_w_0().h_full().overflow_y_scroll().track_scroll(&self.page_scroll).px(px(24.)).py(px(16.)).gap(px(12.)).child(top).when_some(plan.and_then(|plan| plan.last_error.as_ref()), |d, error| d.child(ui::error_line(error)));
        let Some(scan) = self.disk.scans.iter().find(|scan| scan.path == self.disk.path).or(self.disk.scans.first()) else {
            return column
                .child(ui::empty_state("hard-drive", t("还没有扫描过这台服务器"), t("第一次扫描建立基线：「扫描用户目录」统计登录账号自己的 home，不需要 root；「全盘扫描」以 root 统计每个本地文件系统。之后按间隔自动增量扫描，并标出哪些目录在增长。")).when(!scanning, |d| d.child(div().flex().gap(px(8.)).child(ui::primary_button("disk-first-home", t("扫描用户目录")).on_click(self.on(Cmd::DiskScan(name.clone(), Scope::Home), cx))).child(ui::secondary_button("disk-first-full", t("全盘扫描（root）")).on_click(self.on(Cmd::AskFullScan(name.clone()), cx))))))
                .into_any_element();
        };
        let tree = &scan.tree;
        let current = find_space_node(tree, &self.disk.zoom).unwrap_or(tree);
        let at_root = current.path == tree.path;
        let filesystem = scan.report.filesystem.as_ref();
        let whole_mount = filesystem.filter(|fs| fs.mount == scan.path);
        let free = whole_mount.filter(|_| at_root && !self.disk.hide_free).map(|fs| (fs.avail_kb, fs.size_kb));

        // The scanned paths of this server: its disks, or the home directory.
        let paths = div().flex().flex_wrap().gap(px(8.)).children(self.disk.scans.iter().map(|other| {
            let chosen = other.path == scan.path;
            let line = match other.report.filesystem.as_ref().filter(|fs| fs.mount == other.path) {
                Some(fs) => tf!("已用 {:.0}% · 剩 {}", "{:.0}% used · {} free", fs.use_pct, format_kb(fs.avail_kb)),
                None => format_kb(other.tree.kb),
            };
            let full = other.report.filesystem.as_ref().filter(|fs| fs.mount == other.path).map(|fs| fs.use_pct);
            div()
                .id(SharedString::from(format!("disk-path-{}", other.path)))
                .flex()
                .flex_col()
                .min_w(px(132.))
                .max_w(px(260.))
                .px(px(10.))
                .py(px(6.))
                .rounded(px(8.))
                .border_1()
                .border_color(if chosen { Theme::accent() } else { Theme::line() })
                .when(chosen, |d| d.bg(Theme::accent_soft()))
                .cursor_pointer()
                .hover(|s| s.bg(Theme::hover()))
                .on_click(self.on(Cmd::DiskPath(other.path.clone()), cx))
                .child(div().truncate().font_weight(FontWeight::MEDIUM).child(other.path.clone()))
                .child(div().truncate().text_size(text_px(11.)).line_height(text_px(15.)).text_color(Theme::text_tertiary()).child(line))
                // How full the filesystem is, as a line under its name.
                .children(full.map(|pct| div().mt(px(4.)).h(px(3.)).rounded_full().bg(Theme::groove()).child(div().h_full().w(relative((pct as f32 / 100.).clamp(0., 1.))).rounded_full().bg(if pct >= 90. { Theme::danger() } else if pct >= 80. { Theme::star() } else { Theme::accent() }))))
        }));

        let mut facts = vec![tf!("已统计 {}", "{} counted", format_kb(tree.kb))];
        if let Some(fs) = filesystem { facts.push(tf!("文件系统 {}（{}）已用 {:.0}%，剩 {} / 共 {}", "filesystem {} ({}) {:.0}% used, {} free of {}", fs.mount, fs.fs_type.as_deref().unwrap_or(&fs.filesystem), fs.use_pct, format_kb(fs.avail_kb), format_kb(fs.size_kb))) }
        facts.push(tf!("扫描于 {}，{} 层", "scanned {}, {} levels", time::short_time(&scan.at), scan.report.depth));
        if let Some(previous) = &scan.previous_at { facts.push(tf!("对比 {}", "compared with {}", time::short_time(previous))) }
        let mut flags = vec![];
        if scan.report.walk_incomplete { flags.push(t("扫描超时，未走完的目录按已列出的子目录估算，数值偏小").to_string()) }
        if scan.report.permission_denied { flags.push(if scan.report.full_visibility { t("有目录读不了，数值偏小").to_string() } else { t("非 root：无权读取的目录没有计入，数值偏小").to_string() }) }
        if scan.report.dir_count > scan.report.dirs.len() as f64 { flags.push(tf!("只保留最大的 {} 个目录（共 {} 个不小于 {}）", "only the {} largest directories are kept (of {} at least {})", scan.report.dirs.len(), scan.report.dir_count, format_kb(scan.report.min_kb))) }
        let summary = div().flex().flex_wrap().gap_x(px(14.)).gap_y(px(2.)).text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_secondary()).children(facts.into_iter().enumerate().map(|(at, fact)| div().when(at == 0, |d| d.font_weight(FontWeight::MEDIUM).text_color(Theme::text())).child(fact)));

        // From the scan's root down to the open directory; each step goes back to it.
        let mut trail: Vec<&SpaceNode> = vec![tree];
        while let Some(last) = trail.last().copied().filter(|last| last.path != current.path) {
            let Some(next) = last.children.iter().find(|child| current.path == child.path || current.path.strip_prefix(child.path.as_str()).is_some_and(|rest| rest.starts_with('/'))) else { break };
            trail.push(next);
        }
        let steps = trail.len();
        let crumbs = div().flex().flex_wrap().items_center().flex_1().min_w_0().children(trail.into_iter().enumerate().map(|(at, node)| {
            let last = at + 1 == steps;
            div()
                .flex()
                .items_center()
                .when(at > 0, |d| d.child(div().px(px(6.)).text_color(Theme::text_placeholder()).child("›")))
                .child(if last { div().font_weight(FontWeight::SEMIBOLD).child(node.name.clone()).into_any_element() } else { div().id(SharedString::from(format!("disk-crumb-{at}"))).text_color(Theme::accent()).cursor_pointer().hover(|s| s.opacity(0.75)).on_click(self.on(Cmd::DiskZoom(node.path.clone()), cx)).child(node.name.clone()).into_any_element() })
        }));
        let total = div().flex_none().font_weight(FontWeight::SEMIBOLD).child(format!("{}{}{}", format_kb(current.kb), if at_root { String::new() } else { format!(" · {}", share(current.kb, tree.kb)) }, scan.delta(current).map(|delta| format!(" · {}", delta_words(delta))).unwrap_or_default()));
        let modes = segmented(vec![(div().id("disk-mode-map").child(t("方块图")).on_click(self.on(Cmd::DiskList(false), cx)), !self.disk.list), (div().id("disk-mode-list").child(t("列表")).on_click(self.on(Cmd::DiskList(true), cx)), self.disk.list)]).w(px(132.)).flex_none();
        let bar = div()
            .flex()
            .items_center()
            .gap(px(12.))
            .child(crumbs)
            .child(total)
            .when(whole_mount.is_some() && at_root, |d| d.child(div().id("disk-free").flex().flex_none().items_center().gap(px(6.)).cursor_pointer().text_size(text_px(12.)).text_color(Theme::text_secondary()).on_click(self.on(Cmd::ToggleDiskFree, cx)).child(crate::settings::switch(!self.disk.hide_free)).child(t("剩余空间"))))
            .child(modes);

        let body: AnyElement = if current.kb == 0. {
            div().py(px(40.)).text_color(Theme::text_tertiary()).child(t("这里没有不小于 1 MB 的目录。")).into_any_element()
        } else if self.disk.list {
            self.render_disk_list(scan, current, free, cx)
        } else {
            let viewport = window.viewport_size();
            let chat = if self.settings.chat_hidden { 0. } else { self.chat_width() + 1. };
            let width = (f32::from(viewport.width) - SIDEBAR_W - HOSTS_W - chat - 51.).max(260.);
            let height = (f32::from(viewport.height) - 420.).clamp(280., 620.);
            let blocks = blocks_of(current, MAX_BLOCKS, Some, free);
            // Laid out one gap beyond the edges, so the outer blocks sit flush with the frame.
            let layout = squarify(&blocks.iter().map(|block| block.kb).collect::<Vec<_>>(), Rect { x: 0., y: 0., w: width + GAP, h: height + GAP });
            div().relative().flex_none().w(px(width)).h(px(height)).overflow_hidden().children(layout.into_iter().filter_map(|(at, rect)| self.map_block(scan, &blocks[at], Rect { w: (rect.w - GAP).max(0.), h: (rect.h - GAP).max(0.), ..rect }, false, cx))).into_any_element()
        };

        let grown = scan.grown(6);
        let growth = (!grown.is_empty()).then(|| {
            div().flex().flex_col().gap(px(4.)).child(ui::caption(tf!("自上次扫描（{}）增长最多", "Grew most since the scan before ({})", scan.previous_at.as_deref().map(time::short_time).unwrap_or_default()))).children(grown.into_iter().enumerate().map(|(at, (path, delta))| {
                // A directory with nothing listed inside opens at its parent, where it is a block.
                let opens = find_space_node(tree, &path).map(|node| if node.children.is_empty() { path.rsplit_once('/').map(|(parent, _)| if parent.is_empty() { "/" } else { parent }).unwrap_or(&tree.path).to_string() } else { node.path.clone() });
                div()
                    .id(("disk-grown", at))
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .h(text_px(26.))
                    .px(px(8.))
                    .rounded(px(6.))
                    .text_size(text_px(12.))
                    .when_some(opens, |d, opens| d.cursor_pointer().hover(|s| s.bg(Theme::hover())).on_click(self.on(Cmd::DiskZoom(opens), cx)))
                    .child(div().w(px(72.)).flex_none().font_weight(FontWeight::MEDIUM).text_color(Theme::warning()).child(delta_words(delta)))
                    .child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_color(Theme::text_secondary()).child(path))
            }))
        });

        column
            .child(paths)
            .child(summary)
            .when(!flags.is_empty(), |d| d.child(div().flex().flex_wrap().gap(px(6.)).children(flags.into_iter().map(|flag| ui::status_chip("warn", &flag)))))
            .child(bar)
            .child(body)
            .children(growth)
            .when(scan.previous_at.is_none() && plan.is_some(), |d| d.child(div().text_size(text_px(12.)).text_color(Theme::text_placeholder()).child(t("这是第一次扫描；下一次增量扫描之后，这里会标出增长的目录。"))))
            .into_any_element()
    }

    /// One block of the map; a large directory shows its next level inside.
    fn map_block(&self, scan: &ScanView, block: &Block, rect: Rect, inner: bool, cx: &mut Context<Self>) -> Option<AnyElement> {
        // Slivers are skipped, so no block draws outside its own rectangle.
        if rect.w < 3. || rect.h < 3. { return None }
        let colour = block.colour();
        let opens = block.opens();
        let size = format_kb(block.kb);
        let part = share(block.kb, block.of);
        let delta = block.node.and_then(|node| scan.delta(node)).map(delta_words);
        let tip = format!("{} · {size} · {part}{}", block.node.map_or(block.label.as_str(), |node| node.path.as_str()), delta.as_ref().map(|delta| tf!(" · 较上次 {delta}", " · {delta} since the scan before")).unwrap_or_default());
        let mut element = div().id(SharedString::from(format!("disk-block-{}", block.key))).absolute().left(px(rect.x)).top(px(rect.y)).w(px(rect.w)).h(px(rect.h)).overflow_hidden().rounded(px(if inner { 5. } else { 7. })).border_1().tooltip(ui::tip(tip));
        element = match block.kind {
            Kind::Free => element.border_dashed().border_color(Theme::line_strong()).text_color(Theme::text_tertiary()),
            Kind::Files | Kind::Other => element.border_dashed().border_color(colour.opacity(0.38)).bg(colour.opacity(if inner { 0.05 } else { 0.08 })).text_color(colour),
            Kind::Dir => element.border_color(colour.opacity(0.38)).bg(colour.opacity(if inner { 0.16 } else { 0.10 })).text_color(colour),
        };
        if let Some(path) = &opens {
            let open = self.on(Cmd::DiskZoom(path.clone()), cx);
            element = element.cursor_pointer().hover(move |s| s.border_color(colour.opacity(0.75))).on_click(move |event, window, cx| {
                cx.stop_propagation();
                open(event, window, cx);
            });
        }
        let name = |size: f32| div().w_full().truncate().text_size(text_px(size)).line_height(text_px(size + 4.)).font_weight(FontWeight::MEDIUM).child(block.label.clone());
        let note = |words: String| div().w_full().truncate().text_size(text_px(11.)).line_height(text_px(15.)).opacity(0.8).child(words);
        let words = format!("{size} · {part}{}", delta.as_ref().map(|delta| format!(" · {delta}")).unwrap_or_default());
        if let (false, Some(node), true) = (inner, block.node.filter(|_| opens.is_some()), rect.w >= 120. && rect.h >= 96.) {
            // The 2px is the block's own border.
            let nested = blocks_of(node, MAX_NESTED, |_| block.hue, None);
            let layout = squarify(&nested.iter().map(|block| block.kb).collect::<Vec<_>>(), Rect { x: PAD, y: HEADER, w: rect.w - 2. * PAD - 2. + GAP, h: rect.h - HEADER - PAD - 2. + GAP });
            return Some(element.child(div().absolute().top_0().left_0().w_full().h(px(HEADER)).px(px(9.)).py(px(5.)).child(name(12.)).child(note(words))).children(layout.into_iter().filter_map(|(at, inside)| self.map_block(scan, &nested[at], Rect { w: (inside.w - GAP).max(0.), h: (inside.h - GAP).max(0.), ..inside }, true, cx))).into_any_element());
        }
        let (label_w, label_h, note_h) = if inner { (50., 24., 40.) } else { (56., 28., 46.) };
        if rect.w >= label_w && rect.h >= label_h {
            element = element.px(px(if inner { 6. } else { 9. })).py(px(if inner { 3. } else { 6. })).child(name(if inner { 11. } else { 12. })).when(rect.h >= note_h && (inner || rect.w >= 70.), |d| d.child(note(if inner { size.clone() } else { words.clone() })));
        }
        Some(element.into_any_element())
    }

    /// The open directory as rows: for exact numbers, and for more entries than a map can show.
    fn render_disk_list(&self, scan: &ScanView, current: &SpaceNode, free: Option<(f64, f64)>, cx: &mut Context<Self>) -> AnyElement {
        let blocks = blocks_of(current, MAX_ROWS, Some, free);
        let cell = |width: f32| div().w(px(width)).flex_none().text_right();
        let head = div().flex().items_center().gap(px(10.)).h(text_px(26.)).px(px(8.)).border_b_1().border_color(Theme::line()).text_size(text_px(11.)).text_color(Theme::text_tertiary()).child(div().flex_1().child(t("名称"))).child(cell(84.).child(t("较上次"))).child(cell(70.).child(t("大小"))).child(cell(150.).child(t("占比")));
        div()
            .flex()
            .flex_col()
            .child(head)
            .children(blocks.iter().enumerate().map(|(at, block)| {
                let colour = block.colour();
                let opens = block.opens();
                let delta = block.node.and_then(|node| scan.delta(node));
                let portion = if block.of > 0. { (block.kb / block.of) as f32 } else { 0. };
                div()
                    .id(("disk-row", at))
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .h(text_px(30.))
                    .px(px(8.))
                    .border_b_1()
                    .border_color(Theme::line())
                    .text_size(text_px(12.))
                    .when_some(opens, |d, path| d.cursor_pointer().hover(|s| s.bg(Theme::hover())).on_click(self.on(Cmd::DiskZoom(path), cx)))
                    .child(div().flex_none().size(px(10.)).rounded(px(3.)).when(block.kind == Kind::Free, |d| d.border_1().border_dashed().border_color(Theme::line_strong())).when(block.kind != Kind::Free, |d| d.bg(colour.opacity(0.7))))
                    .child(div().flex().flex_1().min_w_0().gap(px(6.)).child(div().truncate().when(block.kind == Kind::Dir, |d| d.text_size(text_px(13.))).when(block.kind != Kind::Dir, |d| d.text_color(Theme::text_secondary())).child(block.label.clone())).children(block.node.filter(|node| !node.children.is_empty()).map(|node| div().flex_none().text_color(Theme::text_placeholder()).child(tf!("{} 个子目录", "{} subdirectories", node.children.len())))))
                    .child(cell(84.).text_color(if delta.is_some_and(|delta| delta > 0.) { Theme::warning() } else { Theme::success() }).children(delta.map(delta_words)))
                    .child(cell(70.).font_family(theme::MONO_FONT).child(format_kb(block.kb)))
                    .child(div().flex().flex_none().items_center().justify_end().gap(px(8.)).w(px(150.)).child(div().w(px(90.)).h(px(6.)).rounded_full().bg(Theme::groove()).child(div().h_full().w(relative(portion.clamp(0., 1.))).rounded_full().bg(colour.opacity(0.7)))).child(div().w(px(44.)).text_right().child(share(block.kb, block.of))))
            }))
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::{Rect, blocks_of, squarify};
    use wisp_ops_collect::space::build_space_tree;

    #[test]
    fn the_map_fills_its_frame_with_areas_in_proportion() {
        let bounds = Rect { x: 0., y: 0., w: 600., h: 400. };
        let values = [6., 6., 4., 3., 2., 2., 1., 0., -1.];
        let layout = squarify(&values, bounds);
        assert_eq!(layout.iter().map(|(at, _)| *at).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 5, 6]);
        let unit = 600. * 400. / 24.;
        for (at, rect) in &layout {
            assert!((rect.w * rect.h - values[*at] as f32 * unit).abs() < 1., "{at}: {rect:?}");
            assert!(rect.x >= -0.01 && rect.y >= -0.01 && rect.x + rect.w <= 600.01 && rect.y + rect.h <= 400.01, "{rect:?}");
            assert!(rect.w / rect.h < 4. && rect.h / rect.w < 4., "{rect:?}");
        }
        assert!(squarify(&[0., 0.], bounds).is_empty() && squarify(&[1.], Rect { w: 0., ..bounds }).is_empty());
    }

    #[test]
    fn a_directory_becomes_its_subdirectories_the_rest_and_free_space_last() {
        let rows: Vec<(String, f64)> = [("/d", 100.), ("/d/a", 50.), ("/d/b", 20.), ("/d/c", 5.), ("/d/e", 4.)].iter().map(|(path, kb)| (path.to_string(), *kb)).collect();
        let tree = build_space_tree("/d", &rows);
        let blocks = blocks_of(&tree, 2, Some, Some((300., 400.)));
        assert_eq!(blocks.iter().map(|block| (block.kb, block.of, block.hue)).collect::<Vec<_>>(), [(50., 100., Some(0)), (21., 100., None), (20., 100., Some(1)), (9., 100., None), (300., 400., None)]);
        assert!(blocks[0].opens().is_none() && blocks[1].node.is_none());
    }
}
