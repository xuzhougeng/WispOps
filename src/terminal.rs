//! 终端: a login shell on a server in the panel under the pages. The session is the system
//! `ssh` in a pseudo-terminal (`portable-pty`; ConPTY on Windows), started by
//! `Fleet::terminal`, so it logs in as the engine does: the inventory's address, port, jump
//! host and key, and for a password host the stored password through askpass. What it prints
//! goes through `vt100` into a grid of cells, which `TerminalElement` draws cell by cell.
//!
//! Keys: printable text (and what an input method composes) arrives through the input handler;
//! everything else is turned into the bytes a terminal sends by `key_bytes`. Tab, Escape and the
//! window's own shortcuts that a shell needs are bound in the `Terminal` context, so the window
//! does not take them. Copy and paste are ⌘C/⌘V on macOS, Ctrl+Shift+C/V elsewhere.

use crate::app::{Cmd, Edge, Page, Workspace};
use crate::i18n::t;
use crate::ops::Fleet;
use crate::ui;
use gpui::prelude::FluentBuilder;
use crate::theme::{self, Theme, text_px};
use gpui::*;
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::num::NonZeroU16;
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wisp_ops_engine::ssh::Interactive;

actions!(terminal, [TermTab, TermBackTab, TermEscape, TermCopy, TermPaste, TermCtrlJ, TermCtrlN, TermCtrlR, TermCtrlComma]);

/// Lines kept above the screen.
const SCROLLBACK: usize = 5000;
/// Room around the grid.
const PAD: f32 = 8.;
/// How long the password helper stays after the session starts: long enough to log in.
const ASKPASS_FOR: Duration = Duration::from_secs(90);

pub fn bind_keys(cx: &mut App) {
    let c = Some("Terminal");
    cx.bind_keys([KeyBinding::new("tab", TermTab, c), KeyBinding::new("shift-tab", TermBackTab, c), KeyBinding::new("escape", TermEscape, c)]);
    if cfg!(target_os = "macos") {
        cx.bind_keys([KeyBinding::new("cmd-c", TermCopy, c), KeyBinding::new("cmd-v", TermPaste, c)]);
    } else {
        // The window's Ctrl shortcuts are the shell's in here.
        cx.bind_keys([
            KeyBinding::new("ctrl-shift-c", TermCopy, c),
            KeyBinding::new("ctrl-shift-v", TermPaste, c),
            KeyBinding::new("ctrl-j", TermCtrlJ, c),
            KeyBinding::new("ctrl-n", TermCtrlN, c),
            KeyBinding::new("ctrl-r", TermCtrlR, c),
            KeyBinding::new("ctrl-,", TermCtrlComma, c),
        ]);
    }
}

/// The bytes a terminal sends for a key that is not plain text, or `None` for text (which comes
/// through the input handler) and for keys it leaves to the window (⌘ on macOS).
/// `app_cursor` is the application cursor mode, in which the arrows send `ESC O`.
pub fn key_bytes(keystroke: &Keystroke, app_cursor: bool) -> Option<Vec<u8>> {
    let m = &keystroke.modifiers;
    if m.platform || m.function && keystroke.key.len() == 1 { return None }
    let key = keystroke.key.as_str();
    // Alt as Meta: not on macOS, where Option writes letters of its own.
    let meta = m.alt && !cfg!(target_os = "macos");
    let with_meta = |bytes: Vec<u8>| if meta { [vec![0x1b], bytes].concat() } else { bytes };
    // xterm's modifier parameter: 1 + Shift 1 + Alt 2 + Ctrl 4.
    let param = 1 + u8::from(m.shift) + 2 * u8::from(m.alt) + 4 * u8::from(m.control);
    let cursor = |end: char| -> Vec<u8> {
        if param > 1 { format!("\x1b[1;{param}{end}").into_bytes() } else if app_cursor { format!("\x1bO{end}").into_bytes() } else { format!("\x1b[{end}").into_bytes() }
    };
    let tilde = |code: u8| -> Vec<u8> { if param > 1 { format!("\x1b[{code};{param}~").into_bytes() } else { format!("\x1b[{code}~").into_bytes() } };
    let bytes = match key {
        "enter" => with_meta(b"\r".to_vec()),
        "backspace" if m.control => with_meta(vec![0x08]),
        "backspace" => with_meta(vec![0x7f]),
        "tab" if m.shift => b"\x1b[Z".to_vec(),
        "tab" => b"\t".to_vec(),
        "escape" => vec![0x1b],
        "up" => cursor('A'),
        "down" => cursor('B'),
        "right" => cursor('C'),
        "left" => cursor('D'),
        "home" => cursor('H'),
        "end" => cursor('F'),
        "insert" => tilde(2),
        "delete" => tilde(3),
        "pageup" => tilde(5),
        "pagedown" => tilde(6),
        "f1" | "f2" | "f3" | "f4" => {
            let end = ['P', 'Q', 'R', 'S'][usize::from(key.as_bytes()[1] - b'1')];
            if param > 1 { format!("\x1b[1;{param}{end}").into_bytes() } else { format!("\x1bO{end}").into_bytes() }
        }
        "f5" => tilde(15),
        "f6" => tilde(17),
        "f7" => tilde(18),
        "f8" => tilde(19),
        "f9" => tilde(20),
        "f10" => tilde(21),
        "f11" => tilde(23),
        "f12" => tilde(24),
        "space" if m.control => with_meta(vec![0]),
        "space" if meta => vec![0x1b, b' '],
        _ if m.control => {
            let mut chars = key.chars();
            let (Some(c), None) = (chars.next(), chars.next()) else { return None };
            let byte = match c.to_ascii_lowercase() {
                c @ 'a'..='z' => c as u8 - b'a' + 1,
                '@' | '2' | ' ' => 0,
                '[' | '3' => 0x1b,
                '\\' | '4' => 0x1c,
                ']' | '5' => 0x1d,
                '^' | '6' => 0x1e,
                '_' | '-' | '/' | '7' => 0x1f,
                '?' | '8' => 0x7f,
                _ => return None,
            };
            with_meta(vec![byte])
        }
        _ if meta => {
            let text = keystroke.key_char.clone().unwrap_or_else(|| key.to_string());
            if text.chars().count() != 1 { return None }
            [vec![0x1b], text.into_bytes()].concat()
        }
        _ => return None,
    };
    Some(bytes)
}

/// Pasted text as the shell is to receive it: line breaks as Enter, and inside the bracketed
/// paste markers when the program asked for them (so a pasted command is not run line by line).
pub fn paste_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    let text = text.replace("\r\n", "\r").replace('\n', "\r");
    if bracketed { format!("\x1b[200~{}\x1b[201~", text.replace("\x1b[201~", "")).into_bytes() } else { text.into_bytes() }
}

/// The font of the grid, its size, what a cell measures and how many cells fit in `area`.
fn grid(window: &mut Window, area: Size<Pixels>) -> (Font, Pixels, Size<Pixels>, u16, u16) {
    let font_size = text_px(13.);
    let font = gpui::font(theme::MONO_FONT);
    let font_id = window.text_system().resolve_font(&font);
    let cell_width = window.text_system().advance(font_id, font_size, 'm').map(|advance| advance.width).unwrap_or(font_size * 0.6);
    let line_height = (font_size * 1.35).round();
    let rows = (((area.height - px(2. * PAD)) / line_height).floor() as i32).clamp(1, 500) as u16;
    let cols = (((area.width - px(2. * PAD)) / cell_width).floor() as i32).clamp(2, 1000) as u16;
    (font, font_size, size(cell_width, line_height), rows, cols)
}

/// What is wrong, or what ended the session.
#[derive(Clone, Debug, PartialEq)]
pub enum Ended {
    /// It never started: why.
    Failed(String),
    /// It ran and ended, with this exit status.
    Exited(u32),
}

/// One session: the server's shell, its screen, and what the window needs to draw and type into it.
pub struct TerminalView {
    pub host: String,
    focus: FocusHandle,
    parser: Arc<Mutex<vt100::Parser>>,
    writer: Option<Box<dyn Write + Send>>,
    master: Option<Box<dyn MasterPty + Send>>,
    killer: Option<Box<dyn ChildKiller + Send + Sync>>,
    status: Arc<Mutex<Option<u32>>>,
    pub ended: Option<Ended>,
    /// The size of the grid, rows and columns, as the shell was last told.
    size: (u16, u16),
    /// What a cell measures, and where the grid's top left corner was last drawn.
    cell: Size<Pixels>,
    origin: Point<Pixels>,
    /// Text an input method is composing, drawn at the cursor until it is committed.
    marked: Option<String>,
    /// A stretch selected with the mouse: anchor and end, (row, column) on the screen as shown.
    selection: Option<((u16, u16), (u16, u16))>,
    selecting: bool,
    _reading: Option<Task<()>>,
}

impl TerminalView {
    /// Open a session on `host`. One that cannot start is a view that says why.
    /// `area` is where it will be drawn, so the shell starts at the size it is shown at.
    pub fn open(host: &str, fleet: &Arc<Fleet>, area: Size<Pixels>, window: &mut Window, cx: &mut Context<Self>) -> TerminalView {
        let (_, _, _, rows, cols) = grid(window, area);
        let parser = Arc::new(Mutex::new(vt100::Parser::new(NonZeroU16::new(rows).unwrap(), NonZeroU16::new(cols).unwrap(), SCROLLBACK)));
        let mut view = TerminalView { host: host.to_string(), focus: cx.focus_handle(), parser, writer: None, master: None, killer: None, status: Arc::new(Mutex::new(None)), ended: None, size: (rows, cols), cell: size(px(8.), px(16.)), origin: Point::default(), marked: None, selection: None, selecting: false, _reading: None };
        match fleet.terminal(host).and_then(|spec| view.start(spec, cx)) {
            Ok(()) => {}
            Err(error) => view.ended = Some(Ended::Failed(error)),
        }
        view
    }

    fn start(&mut self, spec: Interactive, cx: &mut Context<Self>) -> Result<(), String> {
        let pair = native_pty_system().openpty(PtySize { rows: self.size.0, cols: self.size.1, pixel_width: 0, pixel_height: 0 }).map_err(|error| tf!("打不开终端：{error}", "Cannot open a terminal: {error}"))?;
        let mut command = CommandBuilder::new(&spec.program);
        command.args(&spec.args);
        for (key, value) in &spec.env { command.env(key, value) }
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        // A window started from the Dock or the Start menu has no locale: the server would fall back to ASCII.
        if std::env::var_os("LANG").is_none() && std::env::var_os("LC_ALL").is_none() { command.env("LANG", "en_US.UTF-8") }
        let mut child = pair.slave.spawn_command(command).map_err(|error| tf!("启动 ssh 失败：{error}", "Could not start ssh: {error}"))?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(|error| error.to_string())?;
        self.writer = Some(pair.master.take_writer().map_err(|error| error.to_string())?);
        self.killer = Some(child.clone_killer());
        self.master = Some(pair.master);
        // The password helper goes once the login is over, or with the session if that is sooner.
        let spec = Arc::new(Mutex::new(Some(spec)));
        let (later, on_exit) = (spec.clone(), spec);
        std::thread::spawn(move || {
            std::thread::sleep(ASKPASS_FOR);
            drop(later.lock().unwrap().take());
        });
        // Each read wakes the window once; reads that arrive while it is awake are drawn together.
        let (wake, woken) = async_channel::bounded::<()>(1);
        let parser = self.parser.clone();
        let reading_wake = wake.clone();
        std::thread::spawn(move || {
            let mut buffer = vec![0u8; 32 * 1024];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 { break }
                parser.lock().unwrap().process(&buffer[..read]);
                let _ = reading_wake.try_send(());
            }
        });
        let status = self.status.clone();
        std::thread::spawn(move || {
            let code = child.wait().map(|status| status.exit_code()).unwrap_or(1);
            *status.lock().unwrap() = Some(code);
            drop(on_exit.lock().unwrap().take());
            let _ = wake.try_send(());
            drop(wake);
        });
        self._reading = Some(cx.spawn(async move |this, cx| {
            while woken.recv().await.is_ok() {
                let alive = this.update(cx, |this, cx| {
                    if let Some(code) = *this.status.lock().unwrap() && this.ended.is_none() {
                        this.ended = Some(Ended::Exited(code));
                        this.writer = None;
                        cx.emit(TerminalEvent::Ended);
                    }
                    cx.notify();
                });
                if alive.is_err() { break }
            }
        }));
        Ok(())
    }

    pub fn focus(&self, window: &mut Window) {
        window.focus(&self.focus);
    }

    /// Whether the session is still on.
    pub fn running(&self) -> bool {
        self.ended.is_none()
    }

    /// Send text as if it were typed (the window's scripted runs use it).
    pub fn type_text(&mut self, text: &str, cx: &mut Context<Self>) {
        self.write(text.as_bytes(), cx);
    }

    fn write(&mut self, bytes: &[u8], cx: &mut Context<Self>) {
        let Some(writer) = self.writer.as_mut() else { return };
        if writer.write_all(bytes).and_then(|()| writer.flush()).is_err() { return }
        // Typing brings the screen back from the scrollback, and ends a selection.
        let mut parser = self.parser.lock().unwrap();
        if parser.screen().scrollback() > 0 { parser.screen_mut().set_scrollback(0) }
        drop(parser);
        self.selection = None;
        cx.notify();
    }

    /// Tell the shell the grid's new size.
    fn resize(&mut self, rows: u16, cols: u16) {
        if self.size == (rows, cols) { return }
        self.size = (rows, cols);
        if let (Some(rows), Some(cols)) = (NonZeroU16::new(rows), NonZeroU16::new(cols)) { self.parser.lock().unwrap().set_size(rows, cols) }
        if let Some(master) = &self.master { let _ = master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }); }
    }

    /// The cell under a point of the window, kept inside the grid.
    fn cell_at(&self, position: Point<Pixels>) -> (u16, u16) {
        let x = ((position.x - self.origin.x) / self.cell.width).floor().max(0.) as u16;
        let y = ((position.y - self.origin.y) / self.cell.height).floor().max(0.) as u16;
        (y.min(self.size.0.saturating_sub(1)), x.min(self.size.1.saturating_sub(1)))
    }

    /// The selection in reading order, the end column included.
    fn ordered(&self) -> Option<((u16, u16), (u16, u16))> {
        let (a, b) = self.selection?;
        if a == b { return None }
        Some(if a <= b { (a, b) } else { (b, a) })
    }

    fn copy(&mut self, _: &TermCopy, _: &mut Window, cx: &mut Context<Self>) {
        let Some((start, end)) = self.ordered() else { return };
        let text = self.parser.lock().unwrap().screen().contents_between(start.0, start.1, end.0, end.1 + 1);
        cx.write_to_clipboard(ClipboardItem::new_string(text));
    }

    fn paste(&mut self, _: &TermPaste, _: &mut Window, cx: &mut Context<Self>) {
        let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) else { return };
        let bracketed = self.parser.lock().unwrap().screen().bracketed_paste();
        self.write(&paste_bytes(&text, bracketed), cx);
    }

    fn on_key(&mut self, event: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        // While an input method composes, the keys are its own.
        if self.marked.is_some() { return }
        let app_cursor = self.parser.lock().unwrap().screen().application_cursor();
        if let Some(bytes) = key_bytes(&event.keystroke, app_cursor) {
            self.write(&bytes, cx);
            cx.stop_propagation();
        }
    }

    fn on_down(&mut self, event: &MouseDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.focus);
        let at = self.cell_at(event.position);
        self.selection = Some((at, at));
        self.selecting = true;
        cx.notify();
    }

    fn on_move(&mut self, event: &MouseMoveEvent, _: &mut Window, cx: &mut Context<Self>) {
        if !self.selecting || event.pressed_button != Some(MouseButton::Left) { return }
        let at = self.cell_at(event.position);
        if let Some((_, end)) = self.selection.as_mut() && *end != at {
            *end = at;
            cx.notify();
        }
    }

    fn on_up(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.selecting = false;
        if self.ordered().is_none() { self.selection = None }
        cx.notify();
    }

    /// The wheel moves through the scrollback; in a full-screen program (less, vim) it is the arrow keys, as in other terminals.
    fn on_scroll(&mut self, event: &ScrollWheelEvent, _: &mut Window, cx: &mut Context<Self>) {
        let lines = match event.delta {
            ScrollDelta::Lines(delta) => delta.y.round() as i32,
            ScrollDelta::Pixels(delta) => (delta.y / self.cell.height).round() as i32,
        };
        if lines == 0 { return }
        let mut parser = self.parser.lock().unwrap();
        if parser.screen().alternate_screen() {
            let key = if lines > 0 { if parser.screen().application_cursor() { "\x1bOA" } else { "\x1b[A" } } else if parser.screen().application_cursor() { "\x1bOB" } else { "\x1b[B" };
            drop(parser);
            self.write(&key.repeat(lines.unsigned_abs().min(10) as usize).into_bytes(), cx);
            return;
        }
        let at = parser.screen().scrollback() as i32;
        parser.screen_mut().set_scrollback((at + lines).max(0) as usize);
        drop(parser);
        self.selection = None;
        cx.notify();
    }
}

/// What the panel hears from a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalEvent {
    /// The session ended (or never started): its tab says so.
    Ended,
    /// The person asked for the same server again in its place.
    Reconnect,
}

impl EventEmitter<TerminalEvent> for TerminalView {}

impl Drop for TerminalView {
    fn drop(&mut self) {
        if let Some(killer) = self.killer.as_mut() && self.ended.is_none() { let _ = killer.kill(); }
    }
}

impl Focusable for TerminalView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl EntityInputHandler for TerminalView {
    fn text_for_range(&mut self, range: Range<usize>, actual: &mut Option<Range<usize>>, _: &mut Window, _: &mut Context<Self>) -> Option<String> {
        let marked: Vec<u16> = self.marked.as_deref().unwrap_or("").encode_utf16().collect();
        let range = range.start.min(marked.len())..range.end.min(marked.len());
        actual.replace(range.clone());
        Some(String::from_utf16_lossy(&marked[range]))
    }

    fn selected_text_range(&mut self, _: bool, _: &mut Window, _: &mut Context<Self>) -> Option<UTF16Selection> {
        let end = self.marked.as_deref().map_or(0, |text| text.encode_utf16().count());
        Some(UTF16Selection { range: end..end, reversed: false })
    }

    fn marked_text_range(&self, _: &mut Window, _: &mut Context<Self>) -> Option<Range<usize>> {
        self.marked.as_deref().map(|text| 0..text.encode_utf16().count())
    }

    fn unmark_text(&mut self, _: &mut Window, _: &mut Context<Self>) {
        self.marked = None;
    }

    fn replace_text_in_range(&mut self, _: Option<Range<usize>>, text: &str, _: &mut Window, cx: &mut Context<Self>) {
        self.marked = None;
        if !text.is_empty() { self.write(text.as_bytes(), cx) }
        cx.notify();
    }

    fn replace_and_mark_text_in_range(&mut self, _: Option<Range<usize>>, text: &str, _: Option<Range<usize>>, _: &mut Window, cx: &mut Context<Self>) {
        self.marked = (!text.is_empty()).then(|| text.to_string());
        cx.notify();
    }

    fn bounds_for_range(&mut self, _: Range<usize>, _: Bounds<Pixels>, _: &mut Window, _: &mut Context<Self>) -> Option<Bounds<Pixels>> {
        let (row, col) = self.parser.lock().unwrap().screen().cursor_position();
        Some(Bounds::new(self.origin + point(self.cell.width * f32::from(col), self.cell.height * f32::from(row)), size(self.cell.width, self.cell.height)))
    }

    fn character_index_for_point(&mut self, _: Point<Pixels>, _: &mut Window, _: &mut Context<Self>) -> Option<usize> {
        None
    }
}

impl Render for TerminalView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("terminal")
            .key_context("Terminal")
            .track_focus(&self.focus)
            .size_full()
            .bg(Theme::term_bg())
            .cursor(CursorStyle::IBeam)
            .on_key_down(cx.listener(Self::on_key))
            .on_action(cx.listener(|this, _: &TermTab, _, cx| this.write(b"\t", cx)))
            .on_action(cx.listener(|this, _: &TermBackTab, _, cx| this.write(b"\x1b[Z", cx)))
            .on_action(cx.listener(|this, _: &TermEscape, _, cx| this.write(b"\x1b", cx)))
            .on_action(cx.listener(|this, _: &TermCtrlJ, _, cx| this.write(&[0x0a], cx)))
            .on_action(cx.listener(|this, _: &TermCtrlN, _, cx| this.write(&[0x0e], cx)))
            .on_action(cx.listener(|this, _: &TermCtrlR, _, cx| this.write(&[0x12], cx)))
            .on_action(cx.listener(|this, _: &TermCtrlComma, _, cx| this.write(b",", cx)))
            .on_action(cx.listener(Self::copy))
            .on_action(cx.listener(Self::paste))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_down))
            .on_mouse_move(cx.listener(Self::on_move))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::on_up))
            .on_scroll_wheel(cx.listener(Self::on_scroll))
            .relative()
            .child(TerminalElement { view: cx.entity() })
            .children(self.ended.as_ref().map(|ended| {
                let (words, failed) = match ended {
                    Ended::Failed(why) => (tf!("没有连上：{why}", "Not connected: {why}"), true),
                    Ended::Exited(0) => (t("会话已结束").to_string(), false),
                    Ended::Exited(code) => (tf!("会话已结束（退出码 {code}）", "The session ended (exit status {code})"), true),
                };
                div()
                    .absolute()
                    .left_0()
                    .right_0()
                    .bottom_0()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .px(px(12.))
                    .py(px(6.))
                    .border_t_1()
                    .border_color(Theme::line())
                    .bg(Theme::bg_sunken())
                    .text_size(text_px(12.))
                    .child(ui::icon("info", 13., if failed { Theme::danger() } else { Theme::text_tertiary() }))
                    .child(div().flex_1().min_w_0().truncate().text_color(if failed { Theme::danger() } else { Theme::text_secondary() }).child(words))
                    .child(ui::secondary_button("terminal-again", t("重新连接")).h(text_px(26.)).on_click(cx.listener(|_, _, _, cx| cx.emit(TerminalEvent::Reconnect))))
            }))
    }
}

/// The panel under the pages: the sessions, one tab each, and the one on show.
#[derive(Default)]
pub struct TerminalPanel {
    pub open: bool,
    pub tabs: Vec<(Entity<TerminalView>, Subscription)>,
    pub active: usize,
}

/// The height the panel comes with, and the least room it leaves the page above it.
const PANEL_H: f32 = 300.;
const PAGE_MIN: f32 = 220.;

impl Workspace {
    pub fn terminal_height(&self, window: &Window) -> f32 {
        let room = f32::from(window.viewport_size().height) - ui::strip_h() - PAGE_MIN;
        (if self.settings.terminal_height > 0. { self.settings.terminal_height } else { PANEL_H }).clamp(140., room.max(140.))
    }

    pub fn run_terminal(&mut self, cmd: Cmd, window: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            Cmd::OpenTerminal(host) => {
                let view = self.new_terminal(&host, window, cx);
                self.terminal.tabs.push(view);
                self.terminal.active = self.terminal.tabs.len() - 1;
                self.terminal.open = true;
                self.focus_terminal(window, cx);
            }
            Cmd::ToggleTerminal => {
                self.terminal.open = !self.terminal.open;
                if self.terminal.open { self.focus_terminal(window, cx) } else { window.focus(&self.focus) }
            }
            Cmd::TerminalTab(at) => {
                self.terminal.active = at.min(self.terminal.tabs.len().saturating_sub(1));
                self.focus_terminal(window, cx);
            }
            Cmd::CloseTerminal(at) => {
                if at < self.terminal.tabs.len() { drop(self.terminal.tabs.remove(at)) }
                if self.terminal.active >= self.terminal.tabs.len() { self.terminal.active = self.terminal.tabs.len().saturating_sub(1) }
                if self.terminal.tabs.is_empty() { window.focus(&self.focus) } else { self.focus_terminal(window, cx) }
            }
            _ => {}
        }
        cx.notify();
    }

    /// A session on `host`, with the panel listening for its end.
    fn new_terminal(&mut self, host: &str, window: &mut Window, cx: &mut Context<Self>) -> (Entity<TerminalView>, Subscription) {
        let fleet = self.fleet.clone();
        // The panel's body: the page column's width under its tab bar.
        let viewport = window.viewport_size();
        let beside = if self.settings.chat_docked && !self.settings.chat_hidden && self.page != Page::Assistant { self.chat_width() } else { 0. };
        let area = size(viewport.width - px(crate::app::SIDEBAR_W + beside + 1.), px(self.terminal_height(window) - 37.));
        let view = cx.new(|cx| TerminalView::open(host, &fleet, area, window, cx));
        let subscription = cx.subscribe_in(&view, window, |this: &mut Self, view, event: &TerminalEvent, window, cx| match event {
            TerminalEvent::Ended => cx.notify(),
            TerminalEvent::Reconnect => {
                let Some(at) = this.terminal.tabs.iter().position(|(tab, _)| tab == view) else { return };
                let host = view.read(cx).host.clone();
                this.terminal.tabs[at] = this.new_terminal(&host, window, cx);
                this.terminal.active = at;
                this.terminal_needs_focus = true;
                cx.notify();
            }
        });
        (view, subscription)
    }

    fn focus_terminal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some((view, _)) = self.terminal.tabs.get(self.terminal.active) { view.read(cx).focus(window) }
    }

    /// The panel: its tabs over the session on show, and the edge above it to drag.
    pub fn render_terminal(&mut self, window: &mut Window, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.terminal.open { return None }
        if std::mem::take(&mut self.terminal_needs_focus) { self.focus_terminal(window, cx) }
        let height = self.terminal_height(window);
        let tabs = self.terminal.tabs.iter().enumerate().map(|(at, (view, _))| {
            let (host, colour) = {
                let view = view.read(cx);
                (view.host.clone(), match &view.ended { None => Theme::success(), Some(Ended::Exited(0)) => Theme::line_strong(), Some(_) => Theme::danger() })
            };
            let active = at == self.terminal.active;
            div()
                .id(("terminal-tab", at))
                .group("terminal-tab")
                .flex()
                .flex_none()
                .items_center()
                .gap(px(6.))
                .h(text_px(26.))
                .pl(px(10.))
                .pr(px(4.))
                .rounded(px(6.))
                .cursor_pointer()
                .text_size(text_px(12.))
                .when(active, |d| d.bg(Theme::pressed()).font_weight(FontWeight::MEDIUM))
                .when(!active, |d| d.text_color(Theme::text_secondary()))
                .hover(|s| s.bg(Theme::hover()))
                .on_click(self.on(Cmd::TerminalTab(at), cx))
                .child(div().flex_none().size(px(7.)).rounded_full().bg(colour))
                .child(host)
                .child(ui::icon_action(("terminal-close", at), "x", Theme::text_tertiary(), t("关闭这个终端")).size(px(20.)).on_click(self.on_within(Cmd::CloseTerminal(at), cx)))
        });
        let tabs: Vec<Stateful<Div>> = tabs.collect();
        let head = div()
            .flex()
            .flex_none()
            .items_center()
            .gap(px(4.))
            .h(text_px(36.))
            .px(px(8.))
            .border_b_1()
            .border_color(Theme::line())
            .child(div().flex().flex_none().items_center().gap(px(6.)).px(px(6.)).text_size(text_px(12.)).font_weight(FontWeight::MEDIUM).text_color(Theme::text_secondary()).child(ui::icon("square-terminal", 13., Theme::text_secondary())).child(t("终端")))
            .child(div().id("terminal-tabs").flex().flex_1().min_w_0().items_center().gap(px(2.)).overflow_x_scroll().children(tabs))
            .child(ui::icon_action("terminal-hide", "chevron-down", Theme::text_tertiary(), t("收起终端")).on_click(self.on(Cmd::ToggleTerminal, cx)));
        let body = match self.terminal.tabs.get(self.terminal.active) {
            Some((view, _)) => div().flex().flex_1().min_h_0().child(view.clone()).into_any_element(),
            None => ui::empty_state("square-terminal", t("还没有打开终端"), t("在「服务器」里选一台，点「终端」：用清单里的地址和密码库里的登录凭据连接，会话不经过助手。")).child(ui::primary_button("terminal-servers", t("去选服务器")).on_click(self.on(Cmd::SetPage(Page::Servers), cx))).into_any_element(),
        };
        Some(
            div()
                .relative()
                .flex()
                .flex_col()
                .flex_none()
                .h(px(height))
                .border_t_1()
                .border_color(Theme::line())
                .bg(Theme::bg_body())
                .child(head)
                .child(body)
                // The edge between the page and the panel, to be dragged.
                .child(div().id("terminal-edge").absolute().top(px(-3.)).left_0().w_full().h(px(6.)).cursor_row_resize().on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                    this.resizing = Some(Edge::Terminal);
                    cx.notify();
                })))
                .into_any_element(),
        )
    }

    /// The two buttons at the top right, as an editor has them: the panel under the pages, the assistant's column beside them.
    pub fn render_panel_toggles(&self, cx: &mut Context<Self>) -> Div {
        let column = self.settings.chat_docked && !self.settings.chat_hidden;
        let toggle = |id: &'static str, icon: &str, on: bool, tip: &str, cmd: Cmd, this: &Self, cx: &mut Context<Self>| {
            div()
                .id(id)
                .flex()
                .flex_none()
                .items_center()
                .justify_center()
                .size(px(26.))
                .rounded(px(6.))
                .cursor_pointer()
                .occlude()
                .when(on, |d| d.bg(Theme::pressed()))
                .hover(|s| s.bg(Theme::hover()))
                // Not the strip's: a press here does not move the window.
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .on_click(this.on(cmd, cx))
                .tooltip(ui::tip(t(tip)))
                .child(ui::icon(icon, 15., if on { Theme::accent() } else { Theme::text_secondary() }))
        };
        div()
            .flex()
            .items_center()
            .gap(px(2.))
            .child(toggle("toggle-terminal", "panel-bottom", self.terminal.open, "终端面板", Cmd::ToggleTerminal, self, cx))
            .child(toggle("toggle-column", "panel-right", column, "右侧助手栏", if column { Cmd::ToggleChat } else { Cmd::DockChat(true) }, self, cx))
    }
}

/// A colour of the grid; `None` is the default one.
fn colour(value: vt100::Color) -> Option<Hsla> {
    match value {
        vt100::Color::Default => None,
        vt100::Color::Idx(index) => Some(Theme::term_ansi(index)),
        vt100::Color::Rgb(r, g, b) => Some(Rgba { r: f32::from(r) / 255., g: f32::from(g) / 255., b: f32::from(b) / 255., a: 1. }.into()),
    }
}

/// A run of cells drawn alike: where it starts, how many cells it takes, what it says and how.
struct Piece {
    row: u16,
    col: u16,
    cells: u16,
    text: String,
    fg: Hsla,
    bg: Option<Hsla>,
    bold: bool,
    italic: bool,
    underline: bool,
    wide: bool,
}

/// The pieces of one row of the screen: alike cells together, a wide (CJK) character alone.
fn row_pieces(screen: &vt100::Screen, row: u16, cols: u16) -> Vec<Piece> {
    let mut pieces: Vec<Piece> = vec![];
    for col in 0..cols {
        let Some(cell) = screen.cell(row, col) else { continue };
        if cell.is_wide_continuation() { continue }
        let (mut fg, mut bg) = (colour(cell.fgcolor()), colour(cell.bgcolor()));
        if cell.inverse() { (fg, bg) = (Some(bg.unwrap_or_else(Theme::term_bg)), Some(fg.unwrap_or_else(Theme::term_fg))) }
        let mut fg = fg.unwrap_or_else(Theme::term_fg);
        if cell.dim() { fg = fg.opacity(0.6) }
        let text = if cell.has_contents() { cell.contents().to_string() } else { " ".to_string() };
        let wide = cell.is_wide();
        let alike = |piece: &Piece| !wide && !piece.wide && piece.fg == fg && piece.bg == bg && piece.bold == cell.bold() && piece.italic == cell.italic() && piece.underline == cell.underline() && piece.col + piece.cells == col;
        match pieces.last_mut() {
            Some(piece) if alike(piece) => {
                piece.text.push_str(&text);
                piece.cells += 1;
            }
            _ => pieces.push(Piece { row, col, cells: if wide { 2 } else { 1 }, text, fg, bg, bold: cell.bold(), italic: cell.italic(), underline: cell.underline(), wide }),
        }
    }
    pieces
}

struct TerminalElement {
    view: Entity<TerminalView>,
}

impl IntoElement for TerminalElement {
    type Element = Self;

    fn into_element(self) -> Self {
        self
    }
}

/// What prepaint laid out for paint.
struct Frame {
    backgrounds: Vec<PaintQuad>,
    lines: Vec<(Point<Pixels>, ShapedLine)>,
    cursor: Option<PaintQuad>,
    marked: Option<(Point<Pixels>, ShapedLine, PaintQuad)>,
    line_height: Pixels,
}

impl Element for TerminalElement {
    type RequestLayoutState = ();
    type PrepaintState = Frame;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(&mut self, _: Option<&GlobalElementId>, _: Option<&InspectorElementId>, window: &mut Window, cx: &mut App) -> (LayoutId, ()) {
        let mut style = Style::default();
        style.size.width = relative(1.).into();
        style.size.height = relative(1.).into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(&mut self, _: Option<&GlobalElementId>, _: Option<&InspectorElementId>, bounds: Bounds<Pixels>, _: &mut (), window: &mut Window, cx: &mut App) -> Frame {
        let (font, font_size, cell, rows, cols) = grid(window, bounds.size);
        let (cell_width, line_height) = (cell.width, cell.height);
        let origin = bounds.origin + point(px(PAD), px(PAD));
        let focused = self.view.read(cx).focus.is_focused(window);
        let (parser, selection, marked) = self.view.update(cx, |view, _| {
            view.resize(rows, cols);
            view.cell = size(cell_width, line_height);
            view.origin = origin;
            (view.parser.clone(), view.ordered(), view.marked.clone())
        });
        let parser = parser.lock().unwrap();
        let screen = parser.screen();
        let at = |row: u16, col: u16| origin + point(cell_width * f32::from(col), line_height * f32::from(row));
        let mut backgrounds = vec![];
        let mut lines = vec![];
        for row in 0..rows {
            for piece in row_pieces(screen, row, cols) {
                let width = cell_width * f32::from(piece.cells);
                if let Some(bg) = piece.bg { backgrounds.push(fill(Bounds::new(at(piece.row, piece.col), size(width, line_height)), bg)) }
                if piece.text.trim().is_empty() && !piece.underline { continue }
                let mut font = font.clone();
                if piece.bold { font.weight = FontWeight::BOLD }
                if piece.italic { font.style = FontStyle::Italic }
                let run = TextRun { len: piece.text.len(), font, color: piece.fg, background_color: None, underline: piece.underline.then(|| UnderlineStyle { color: Some(piece.fg), thickness: px(1.), wavy: false }), strikethrough: None };
                let shaped = window.text_system().shape_line(piece.text.into(), font_size, &[run], Some(if piece.wide { cell_width * 2. } else { cell_width }));
                lines.push((at(piece.row, piece.col), shaped));
            }
        }
        // The selection over the text, line by line.
        if let Some((start, end)) = selection {
            for row in start.0..=end.0.min(rows.saturating_sub(1)) {
                let from = if row == start.0 { start.1 } else { 0 };
                let to = if row == end.0 { end.1 + 1 } else { cols };
                if to > from { backgrounds.push(fill(Bounds::new(at(row, from), size(cell_width * f32::from(to - from), line_height)), Theme::selection())) }
            }
        }
        let (row, col) = screen.cursor_position();
        let live = screen.scrollback() == 0 && !screen.hide_cursor() && self.view.read(cx).running();
        let wide = screen.cell(row, col).is_some_and(|cell| cell.is_wide());
        let cursor_size = size(cell_width * if wide { 2. } else { 1. }, line_height);
        let cursor = live.then(|| if focused { fill(Bounds::new(at(row, col), cursor_size), Theme::term_cursor()) } else { outline(Bounds::new(at(row, col), cursor_size), Theme::term_cursor(), BorderStyle::Solid) });
        let marked = marked.filter(|_| live).map(|text| {
            let run = TextRun { len: text.len(), font: font.clone(), color: Theme::term_fg(), background_color: None, underline: Some(UnderlineStyle { color: Some(Theme::accent()), thickness: px(1.), wavy: false }), strikethrough: None };
            let shaped = window.text_system().shape_line(text.into(), font_size, &[run], None);
            let ground = fill(Bounds::new(at(row, col), size(shaped.width, line_height)), Theme::term_bg());
            (at(row, col), shaped, ground)
        });
        Frame { backgrounds, lines, cursor, marked, line_height }
    }

    fn paint(&mut self, _: Option<&GlobalElementId>, _: Option<&InspectorElementId>, bounds: Bounds<Pixels>, _: &mut (), frame: &mut Frame, window: &mut Window, cx: &mut App) {
        let focus = self.view.read(cx).focus.clone();
        window.handle_input(&focus, ElementInputHandler::new(bounds, self.view.clone()), cx);
        window.with_content_mask(Some(ContentMask { bounds }), |window| {
            for quad in frame.backgrounds.drain(..) { window.paint_quad(quad) }
            if let Some(cursor) = frame.cursor.take() { window.paint_quad(cursor) }
            for (origin, line) in &frame.lines { let _ = line.paint(*origin, frame.line_height, window, cx); }
            if let Some((origin, line, ground)) = frame.marked.take() {
                window.paint_quad(ground);
                let _ = line.paint(origin, frame.line_height, window, cx);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{Keystroke, key_bytes, paste_bytes};

    fn key(text: &str) -> Option<Vec<u8>> {
        key_bytes(&Keystroke::parse(text).unwrap(), false)
    }

    #[test]
    fn keys_become_what_a_terminal_sends() {
        assert_eq!(key("enter"), Some(b"\r".to_vec()));
        assert_eq!(key("backspace"), Some(vec![0x7f]));
        assert_eq!(key("ctrl-c"), Some(vec![3]));
        assert_eq!(key("ctrl-d"), Some(vec![4]));
        assert_eq!(key("ctrl-["), Some(vec![0x1b]));
        assert_eq!(key("up"), Some(b"\x1b[A".to_vec()));
        assert_eq!(key_bytes(&Keystroke::parse("up").unwrap(), true), Some(b"\x1bOA".to_vec()));
        assert_eq!(key("ctrl-right"), Some(b"\x1b[1;5C".to_vec()));
        assert_eq!(key("shift-tab"), Some(b"\x1b[Z".to_vec()));
        assert_eq!(key("delete"), Some(b"\x1b[3~".to_vec()));
        assert_eq!(key("f1"), Some(b"\x1bOP".to_vec()));
        assert_eq!(key("f12"), Some(b"\x1b[24~".to_vec()));
        // Plain letters come through the input handler; ⌘ is the window's.
        assert_eq!(key("a"), None);
        assert_eq!(key("space"), None);
        assert_eq!(key("cmd-c"), None);
    }

    #[test]
    fn pasted_lines_are_enters_and_bracketed_when_asked() {
        assert_eq!(paste_bytes("ls\npwd\n", false), b"ls\rpwd\r".to_vec());
        assert_eq!(paste_bytes("rm x\n", true), b"\x1b[200~rm x\r\x1b[201~".to_vec());
        // A paste cannot end the bracket early and run what follows.
        assert_eq!(paste_bytes("a\x1b[201~b", true), b"\x1b[200~ab\x1b[201~".to_vec());
    }
}
