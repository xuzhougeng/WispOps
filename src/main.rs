//! WispOps: an AI-native desk for a fleet of servers. A list of SSH hosts,
//! read-only inspection and diagnosis, and an assistant that works through
//! the same gated tools a person would: every change, sudo and destructive
//! command is settled per host before it runs. The engine is
//! `wisp_ops_engine` (inventory, SSH, permissions, vault, audit) with
//! `wisp_ops_collect` (collectors); this crate is the GPUI application.
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

#[macro_use]
mod i18n;
mod app;
mod assets;
mod assistant;
mod audit;
mod chat;
mod dialogs;
mod disk;
mod findings;
mod input;
mod longrun;
mod markdown;
mod ops;
mod overview;
mod scans;
mod security;
mod servers;
mod settings;
mod tasks;
mod theme;
mod tools;
mod ui;
mod updates;
mod updates_view;
mod vault;

use gpui::*;

pub(crate) const APP_ID: &str = "com.wisp.ops";

fn main() {
    let app = Application::new().with_assets(assets::Assets);
    app.run(|cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(1400.), px(880.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                app_id: Some(APP_ID.into()),
                titlebar: Some(TitlebarOptions { title: Some("WispOps".into()), appears_transparent: ui::custom_titlebar(), traffic_light_position: Some(point(px(14.), px(11.))) }),
                window_min_size: Some(size(px(960.), px(600.))),
                focus: std::env::var_os("WISP_OPS_DEV").is_none(),
                ..Default::default()
            },
            |window, cx| cx.new(|cx| app::Workspace::new(window, cx)),
        )
        .expect("open window")
        .update(cx, |workspace, window, cx| {
            workspace.start(window, cx);
            #[cfg(debug_assertions)]
            workspace.dev_start(window, cx);
        })
        .ok();
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() { cx.quit() }
        })
        .detach();
        if std::env::var_os("WISP_OPS_DEV").is_none() { cx.activate(true) }
    });
}
