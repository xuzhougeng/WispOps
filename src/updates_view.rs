//! The update check in the window: the check at start and once a day, the
//! quiet notice above 设置 in the sidebar, and the 更新 section of 设置 › 通用.
//! The checking and downloading itself is `updates.rs`.

use crate::app::{Cmd, Page, Workspace};
use crate::i18n::t;
use crate::settings::{Tab, switch};
use crate::theme::{Theme, text_px};
use crate::ui;
use crate::updates::{self, State, Status};
use gpui::{prelude::FluentBuilder, *};
use std::path::PathBuf;

/// What the window knows of updates; read from `updates.json` once at start.
pub struct UpdateState {
    pub status: Status,
    pub dismissed: String,
    pub checking: bool,
    pub downloading: bool,
}

impl Default for UpdateState {
    fn default() -> Self {
        UpdateState { status: Status::unchecked(), dismissed: String::new(), checking: false, downloading: false }
    }
}

/// How often the window asks itself whether a check is due; `updates::due` keeps it to once a day.
const LOOK_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

impl Workspace {
    /// At start: what the last check found, and a check now and whenever one is due while the window is open.
    pub fn start_updates(&mut self, cx: &mut Context<Self>) {
        let saved = updates::load(self.fleet.data_dir());
        self.updates.status = updates::reconcile(saved.status.unwrap_or_else(Status::unchecked), updates::RUNNING);
        self.updates.dismissed = saved.dismissed;
        cx.spawn(async move |this, cx| {
            loop {
                let alive = this.update(cx, |this, cx| {
                    if !this.updates.checking && updates::due(&this.updates.status, this.settings.auto_update_check, chrono::Utc::now()) { this.check_updates(false, cx) }
                });
                if alive.is_err() { break }
                cx.background_executor().timer(LOOK_EVERY).await;
            }
        })
        .detach();
    }

    /// Ask GitHub off the main thread. Only a check asked for from 设置 says how it went; an automatic one that fails is only recorded.
    fn check_updates(&mut self, asked: bool, cx: &mut Context<Self>) {
        if self.updates.checking { return }
        self.updates.checking = true;
        let data_dir = self.fleet.data_dir().to_path_buf();
        let task = cx.background_executor().spawn(async move { updates::check(&data_dir, updates::LATEST_URL, "") });
        cx.spawn(async move |this, cx| {
            let status = task.await;
            this.update(cx, |this, cx| {
                this.updates.checking = false;
                if asked {
                    match status.state {
                        State::Failed => this.fail(tf!("检查更新失败：{}", "Update check failed: {}", t(&status.detail)), cx),
                        State::Available => this.say(tf!("有新版本 {}", "Version {} is available", status.latest), cx),
                        _ => this.say(t("已是最新版本"), cx),
                    }
                }
                this.updates.status = status;
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    fn keep_updates(&mut self, cx: &mut Context<Self>) {
        let saved = updates::Saved { status: Some(self.updates.status.clone()), dismissed: self.updates.dismissed.clone() };
        if let Err(err) = updates::save(self.fleet.data_dir(), &saved) { self.fail(err, cx) }
    }

    pub fn run_updates(&mut self, cmd: Cmd, cx: &mut Context<Self>) {
        match cmd {
            Cmd::CheckUpdate => self.check_updates(true, cx),
            Cmd::ToggleUpdateCheck => {
                self.settings.auto_update_check = !self.settings.auto_update_check;
                self.save_settings(cx);
            }
            Cmd::DismissUpdate => {
                self.updates.dismissed = self.updates.status.latest.clone();
                self.keep_updates(cx);
            }
            Cmd::ShowUpdate => {
                self.page = Page::Settings;
                self.settings_view.tab = Tab::Data;
            }
            // The person may have moved or deleted it since: then it can be downloaded again.
            Cmd::RevealUpdate(path) if !path.is_file() => {
                self.updates.status.downloaded.clear();
                self.keep_updates(cx);
                self.fail(t("下载的安装包已经不在了，可以重新下载。"), cx);
            }
            Cmd::RevealUpdate(path) => cx.reveal_path(&path),
            Cmd::DownloadUpdate => self.download_update(cx),
            _ => {}
        }
        cx.notify();
    }

    /// Fetch and verify the package for this platform, then show it in the file manager. Never opened or run from here.
    fn download_update(&mut self, cx: &mut Context<Self>) {
        if self.updates.downloading { return }
        self.updates.downloading = true;
        let status = self.updates.status.clone();
        let folder = updates::downloads_folder();
        let task = cx.background_executor().spawn(async move { updates::download(&status, &folder, "") });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                this.updates.downloading = false;
                match result {
                    Ok(path) => {
                        this.updates.status.downloaded = path.display().to_string();
                        this.keep_updates(cx);
                        cx.reveal_path(&path);
                        this.say(tf!("已下载并校验 {}；请自己安装。", "Downloaded and verified {}; install it yourself.", path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()), cx);
                    }
                    Err(err) => this.fail(t(&err).to_string(), cx),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// Above 设置 in the sidebar while a newer version is known and its notice was not put away.
    pub fn render_update_notice(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let status = &self.updates.status;
        if !status.update_known() || self.updates.dismissed == status.latest { return None }
        Some(
            div()
                .id("update-notice")
                .flex()
                .items_center()
                .gap(px(6.))
                .mx(px(2.))
                .mb(px(4.))
                .pl(px(10.))
                .pr(px(4.))
                .py(px(4.))
                .rounded(px(7.))
                .border_1()
                .border_color(Theme::line())
                .cursor_pointer()
                .hover(|s| s.bg(Theme::hover()))
                .on_click(self.on(Cmd::ShowUpdate, cx))
                .child(div().flex().flex_col().flex_1().min_w_0().child(div().truncate().text_size(text_px(12.)).font_weight(FontWeight::MEDIUM).child(tf!("新版本 {}", "Version {}", status.latest))).child(div().truncate().text_size(text_px(11.)).line_height(text_px(15.)).text_color(Theme::text_tertiary()).child(t("在设置里查看"))))
                .child(ui::icon_action("update-dismiss", "x", Theme::text_tertiary(), t("不再提示这个版本")).on_click(self.on_within(Cmd::DismissUpdate, cx)))
                .into_any_element(),
        )
    }

    /// 设置 › 通用 › 更新.
    pub fn render_update_section(&self, cx: &mut Context<Self>) -> Div {
        let state = &self.updates;
        let status = &state.status;
        let row = |label: &str, control: AnyElement| div().flex().items_center().gap(px(16.)).child(div().w(px(120.)).flex_none().text_color(Theme::text_secondary()).child(label.to_string())).child(control);
        let automatic = div().id("update-auto").flex().items_center().gap(px(8.)).cursor_pointer().on_click(self.on(Cmd::ToggleUpdateCheck, cx)).child(switch(self.settings.auto_update_check)).child(t("启动时检查，之后每天最多一次"));
        let when = status.checked_at.map(|at| at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string());
        let found = match status.state {
            State::Unchecked => t("还没有检查过").to_string(),
            State::NoRelease => t("还没有发布的版本").to_string(),
            State::Current => t("已是最新版本").to_string(),
            State::Available => tf!("有新版本 {}", "Version {} is available", status.latest),
            State::Failed => tf!("检查失败：{}", "Check failed: {}", t(&status.detail)),
        };
        let last = div()
            .flex()
            .items_center()
            .gap(px(10.))
            .child(div().min_w_0().truncate().text_color(if status.state == State::Failed { Theme::warning() } else { Theme::text() }).child(match when { Some(when) => format!("{when} · {found}"), None => found }))
            .child(ui::secondary_button("update-check", if state.checking { t("正在检查…") } else { t("立即检查") }).h(text_px(28.)).when(!state.checking, |d| d.on_click(self.on(Cmd::CheckUpdate, cx))));
        let mut section = Self::section(t("更新"), t("从 GitHub 查看 WispOps 有没有新的正式版本。只请求公开的发布信息，不带任何个人信息，也不上传数据。安装包没有签名，所以不会自动替换或打开它：下载并校验后由你自己安装。"))
            .child(row(t("自动检查更新"), automatic.into_any_element()))
            .child(row(t("当前版本"), div().child(updates::RUNNING).into_any_element()))
            .child(row(t("上次检查"), last.into_any_element()));
        if status.update_known() {
            let downloaded = (!status.downloaded.is_empty()).then(|| PathBuf::from(&status.downloaded));
            let get: AnyElement = match (&status.asset, downloaded) {
                (_, Some(path)) => ui::primary_button("update-reveal", t("在文件夹中显示")).on_click(self.on(Cmd::RevealUpdate(path), cx)).into_any_element(),
                (Some(_), None) => ui::primary_button("update-download", if state.downloading { t("正在下载并校验…") } else { t("下载并校验") }).when(!state.downloading, |d| d.on_click(self.on(Cmd::DownloadUpdate, cx))).into_any_element(),
                (None, None) => div().into_any_element(),
            };
            let how = match (&status.asset, std::env::consts::OS) {
                (None, _) => t("这个平台没有现成的安装包，请到发布页面查看。"),
                (Some(_), "macos") => t("下载 .dmg 到「下载」文件夹，按 SHA256SUMS 校验后在访达里显示。退出 WispOps，打开它，把 WispOps 拖进「应用程序」替换旧版本。"),
                (Some(_), "windows") => t("下载 .zip 到「下载」文件夹，按 SHA256SUMS 校验后在资源管理器里显示。退出 WispOps，解压后用新的 WispOps.exe 替换旧的。"),
                (Some(_), _) => t("下载 .tar.gz 到「下载」文件夹，按 SHA256SUMS 校验后在文件管理器里显示。退出 WispOps，解压后替换原来的文件夹。"),
            };
            section = section.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .p(px(12.))
                    .rounded(px(10.))
                    .border_1()
                    .border_color(Theme::accent())
                    .child(div().font_weight(FontWeight::MEDIUM).child(tf!("WispOps {} 可以下载了", "WispOps {} is available", status.latest)))
                    .child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_secondary()).child(how))
                    .child(div().flex().items_center().gap(px(8.)).child(get).child(ui::secondary_button("update-notes", t("发布说明")).on_click(self.on(Cmd::OpenUrl(status.release_url.clone()), cx)))),
            );
        }
        section
    }
}
