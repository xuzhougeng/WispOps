//! Staying in the background (设置 › 后台运行). The timers that look after the
//! fleet belong to the window's `Workspace`, so the window is never really
//! closed while this is on: on macOS the program is hidden and its Dock icon
//! brings it back, elsewhere (GPUI has no tray icon) the window is minimised.
//! Quitting is then its own act: ⌘Q or the Dock on macOS, the button beside
//! the switch elsewhere.

use crate::i18n::t;
use gpui::{App, KeyBinding, Menu, MenuItem, Window, actions};

actions!(wisp_ops, [Quit]);

/// Once at start: quitting from the menu bar and the keyboard.
pub fn install(cx: &mut App) {
    cx.on_action(|_: &Quit, cx| cx.quit());
    set_menus(cx);
}

/// Again after `clear_key_bindings`.
pub fn bind_keys(cx: &mut App) {
    if cfg!(target_os = "macos") { cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]) }
}

/// The menu bar's one menu, in the language of the window (set again when that changes).
pub fn set_menus(cx: &mut App) {
    if cfg!(target_os = "macos") { cx.set_menus(vec![Menu { name: "WispOps".into(), items: vec![MenuItem::action(t("退出 WispOps"), Quit)] }]) }
}

/// The window was asked to close while the program is to keep running: put it away instead.
pub fn put_away(window: &mut Window, cx: &mut App) {
    if cfg!(target_os = "macos") { cx.hide() } else { window.minimize_window() }
}

/// macOS slows the timers of a program nobody can see (App Nap); a held activity keeps
/// them on time while the program is meant to work unseen. The machine may still sleep.
#[cfg(target_os = "macos")]
#[allow(unexpected_cfgs)] // objc 0.2's `sel!` asks for a `cargo-clippy` feature
pub fn stay_awake(on: bool) {
    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};
    use std::sync::atomic::{AtomicUsize, Ordering};
    // NSActivityUserInitiatedAllowingIdleSystemSleep
    const OPTIONS: u64 = 0x00FF_FFFF & !(1 << 20);
    static HELD: AtomicUsize = AtomicUsize::new(0);
    // Only ever called on the main thread (from `Workspace`), so load-then-store is enough.
    let held = HELD.load(Ordering::Relaxed) as *mut Object;
    if on == !held.is_null() { return }
    unsafe {
        let info: *mut Object = msg_send![class!(NSProcessInfo), processInfo];
        if on {
            let reason: *mut Object = msg_send![class!(NSString), stringWithUTF8String: c"Routine checks of the fleet run on a timer".as_ptr()];
            let activity: *mut Object = msg_send![info, beginActivityWithOptions: OPTIONS reason: reason];
            let activity: *mut Object = msg_send![activity, retain];
            HELD.store(activity as usize, Ordering::Relaxed);
        } else {
            let _: () = msg_send![info, endActivity: held];
            let _: () = msg_send![held, release];
            HELD.store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn stay_awake(_: bool) {}

/// Debug builds (`WISP_OPS_DEV=close,2@hidden`): press the window's close button the way a person
/// does, through the system and after this step has returned (the answer to "should it close"
/// is asked of the application, which this step is inside of); `hidden` says what became of it.
#[cfg(all(debug_assertions, target_os = "macos"))]
#[allow(unexpected_cfgs)]
pub fn dev_close(report: bool) {
    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};
    unsafe {
        let app: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        let windows: *mut Object = msg_send![app, windows];
        if report {
            let hidden: bool = msg_send![app, isHidden];
            let count: usize = msg_send![windows, count];
            return println!("hidden: {hidden}, windows: {count}");
        }
        let window: *mut Object = msg_send![windows, firstObject];
        let _: () = msg_send![window, performSelector: sel!(performClose:) withObject: std::ptr::null_mut::<Object>() afterDelay: 0f64];
    }
}

#[cfg(all(debug_assertions, not(target_os = "macos")))]
pub fn dev_close(_: bool) {}
