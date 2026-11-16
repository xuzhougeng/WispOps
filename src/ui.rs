//! Small shared UI pieces: icons, buttons, chips, field shells, popover and dialog shells.

// Taken whole from Wisp Paper: the parts this app does not use yet are kept, so the two stay alike.
#![allow(dead_code)]

use crate::input::TextInput;
use crate::theme::{self, Theme, text_px};
use gpui::{prelude::FluentBuilder, *};
use std::time::Duration;

pub fn icon(name: &str, size: f32, color: Hsla) -> Svg {
    svg().path(SharedString::from(format!("icons/{name}.svg"))).size(px(size)).flex_none().text_color(color)
}

/// A turning mark: something is being waited for.
pub fn spinner(id: impl Into<ElementId>, size: f32, color: Hsla) -> impl IntoElement {
    icon("loader", size, color).with_animation(id, Animation::new(Duration::from_millis(900)).repeat(), |mark, turn| mark.with_transformation(Transformation::rotate(percentage(turn))))
}

/// The element appears over a moment instead of at once. It plays once,
/// when the element with this id is first drawn.
pub fn fade_in(id: impl Into<ElementId>, element: Div) -> impl IntoElement {
    element.with_animation(id, Animation::new(Duration::from_millis(400)).with_easing(ease_out_quint()), |element, shown| element.opacity(shown))
}

/// The filled button of a dialog or toolbar, in the accent.
pub fn primary_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .gap(px(6.))
        .h(text_px(32.))
        .px(px(14.))
        .rounded(px(8.))
        .bg(Theme::accent())
        .text_color(Theme::on_accent())
        .text_size(text_px(13.))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .hover(|s| s.opacity(0.9))
        .active(|s| s.opacity(0.8))
        .child(label.into())
}

pub fn secondary_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .gap(px(6.))
        .h(text_px(32.))
        .px(px(12.))
        .rounded(px(8.))
        .border_1()
        .border_color(Theme::line_strong())
        .bg(Theme::bg_body())
        .text_color(Theme::text())
        .text_size(text_px(13.))
        .cursor_pointer()
        .hover(|s| s.bg(Theme::bg_sunken()))
        .active(|s| s.bg(Theme::pressed()))
        .child(label.into())
}

/// A borderless button: an icon, a label, or both.
pub fn ghost_button(id: impl Into<ElementId>, icon_name: Option<&str>, label: Option<SharedString>) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .gap(px(5.))
        .h(text_px(28.))
        .min_w(px(28.))
        .when(label.is_some(), |d| d.px(px(8.)))
        .rounded(px(6.))
        .text_color(Theme::text_secondary())
        .text_size(text_px(13.))
        .cursor_pointer()
        .hover(|s| s.bg(Theme::hover()))
        .active(|s| s.bg(Theme::pressed()))
        .when_some(icon_name, |d, name| d.child(icon(name, 16., Theme::text_secondary())))
        .when_some(label, |d, label| d.child(label))
}

/// A small rounded label: statuses, tags, field values.
pub fn chip(label: impl Into<SharedString>, text: Hsla, fill: Hsla) -> Div {
    div().flex().flex_none().items_center().h(text_px(22.)).px(px(8.)).rounded(px(11.)).bg(fill).text_color(text).text_size(text_px(12.)).whitespace_nowrap().child(label.into())
}

pub fn status_chip(value: &str, label: &str) -> Div {
    let (text, fill) = theme::status_colors(value);
    chip(label.to_string(), text, fill)
}

/// A key as it is on the keyboard, beside what it does.
pub fn keycap(key: impl Into<SharedString>) -> Div {
    div().flex().flex_none().items_center().justify_center().min_w(px(18.)).h(text_px(18.)).px(px(4.)).rounded(px(4.)).border_1().border_color(Theme::line_strong()).bg(Theme::bg_sunken()).text_size(text_px(11.)).line_height(text_px(14.)).font_weight(FontWeight::MEDIUM).text_color(Theme::text_secondary()).child(key.into())
}

/// The bordered shell around a text input.
pub fn field(input: &Entity<TextInput>, window: &Window, cx: &App) -> Div {
    let focused = input.focus_handle(cx).is_focused(window);
    let multiline = input.read(cx).multiline;
    div()
        .flex()
        .w_full()
        .px(px(10.))
        .py(px(if multiline { 8. } else { 6. }))
        .rounded(px(8.))
        .border_1()
        .border_color(if focused { Theme::accent() } else { Theme::line_strong() })
        .bg(Theme::bg_body())
        .text_size(text_px(13.))
        .line_height(text_px(20.))
        .text_color(Theme::text())
        .child(input.clone())
}

/// A labelled row of a form.
pub fn form_row(label: impl Into<SharedString>, content: impl IntoElement) -> Div {
    div().flex().flex_col().gap(px(5.)).child(div().text_size(text_px(12.)).text_color(Theme::text_secondary()).child(label.into())).child(content)
}

/// The floating shell of a menu.
pub fn popover() -> Div {
    div()
        .occlude()
        .flex()
        .flex_col()
        .min_w(px(168.))
        .max_w(px(320.))
        .p(px(4.))
        .rounded(px(10.))
        .bg(Theme::bg_body())
        .border_1()
        .border_color(Theme::line())
        .shadow(theme::shadow_panel())
        .font(theme::ui_font())
        .text_size(text_px(13.))
        .text_color(Theme::text())
}

pub fn menu_row(id: impl Into<ElementId>, label: impl Into<SharedString>, checked: bool, note: Option<SharedString>) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .items_center()
        .gap(px(8.))
        .h(text_px(30.))
        .px(px(8.))
        .rounded(px(6.))
        .cursor_pointer()
        .hover(|s| s.bg(Theme::hover()))
        .child(div().w(px(14.)).flex_none().when(checked, |d| d.child(icon("check", 14., Theme::accent()))))
        .child(div().flex_1().min_w_0().truncate().child(label.into()))
        .when_some(note, |d, note| d.child(div().flex_none().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(note)))
}

/// The white card of a dialog, centred by the caller over a scrim.
pub fn dialog(width: f32) -> Div {
    div()
        .occlude()
        .flex()
        .flex_col()
        .w(px(width))
        .max_w(relative(0.92))
        .max_h(relative(0.9))
        .rounded(px(14.))
        .bg(Theme::bg_body())
        .shadow(theme::shadow_panel())
        .font(theme::ui_font())
        .text_color(Theme::text())
        .text_size(text_px(13.))
}

pub fn dialog_title(title: impl Into<SharedString>) -> Div {
    div().px(px(20.)).pt(px(18.)).pb(px(6.)).text_size(text_px(16.)).font_weight(FontWeight::SEMIBOLD).child(title.into())
}

pub fn error_line(message: &str) -> Div {
    div().when(!message.is_empty(), |d| d.px(px(10.)).py(px(7.)).rounded(px(8.)).bg(Theme::danger_soft()).text_color(Theme::danger()).text_size(text_px(12.)).child(message.to_string()))
}

/// The centred message of an empty list.
pub fn empty_state(icon_name: &str, title: &str, hint: &str) -> Div {
    div()
        .flex()
        .flex_col()
        .flex_1()
        .items_center()
        .justify_center()
        .gap(px(8.))
        .p(px(24.))
        .min_w_0()
        .max_w_full()
        .child(icon(icon_name, 30., Theme::text_placeholder()))
        .child(div().text_size(text_px(14.)).text_color(Theme::text_secondary()).child(title.to_string()))
        .child(div().max_w(px(360.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(hint.to_string()))
}

/// A section caption inside a panel.
pub fn caption(text: impl Into<SharedString>) -> Div {
    div().text_size(text_px(11.)).font_weight(FontWeight::MEDIUM).text_color(Theme::text_tertiary()).child(text.into())
}

// ---- panels, meters and small charts

/// A card on a page: a white plane with a hairline and a little lift.
pub fn panel() -> Div {
    div().flex().flex_col().rounded(px(12.)).border_1().border_color(Theme::line()).bg(Theme::bg_body()).shadow(theme::shadow_card())
}

/// A panel's heading: what it holds, and a quieter note beside it.
pub fn panel_head(title: impl Into<SharedString>, note: impl Into<SharedString>) -> Div {
    div().flex().items_center().gap(px(8.)).child(div().flex_none().text_size(text_px(13.)).font_weight(FontWeight::SEMIBOLD).child(title.into())).child(div().flex_1().min_w_0().truncate().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(note.into()))
}

/// A share of a whole as a thin bar; it takes the width left to it.
pub fn meter(pct: f64, color: Hsla) -> Div {
    div().flex_1().min_w(px(20.)).h(px(6.)).rounded_full().bg(Theme::groove()).overflow_hidden().child(div().h_full().min_w(px(3.)).rounded_full().bg(color).w(relative((pct / 100.).clamp(0., 1.) as f32)))
}

/// One measure over the inspections, the oldest at the left, from 0 to `top`: a line over a
/// soft fill, broken where there was no value. Each inspection has a column that says its
/// own value on hover (`tips`, as many as `values`).
pub fn trend(id: &str, values: Vec<Option<f64>>, tips: Vec<String>, top: f64, color: Hsla, height: f32) -> Div {
    let columns = tips.into_iter().enumerate().map(|(n, words)| div().id(SharedString::from(format!("{id}-{n}"))).flex_1().h_full().rounded(px(2.)).hover(|s| s.bg(Theme::hover())).tooltip(tip(words))).collect::<Vec<_>>();
    let ring = Theme::bg_body();
    let line = canvas(|_, _, _| (), move |bounds, _, window, _| {
        let count = values.len();
        if count == 0 || top <= 0. { return }
        let (left, bottom) = (f32::from(bounds.origin.x), f32::from(bounds.origin.y + bounds.size.height));
        let (width, height) = (f32::from(bounds.size.width), f32::from(bounds.size.height) - 4.);
        let place = |n: usize, value: f64| point(px(left + (n as f32 + 0.5) * width / count as f32), px(bottom - 1. - (value / top).clamp(0., 1.) as f32 * (height - 1.)));
        let mut runs: Vec<Vec<Point<Pixels>>> = vec![vec![]];
        for (n, value) in values.iter().enumerate() {
            match value {
                Some(value) => runs.last_mut().unwrap().push(place(n, *value)),
                None => if !runs.last().unwrap().is_empty() { runs.push(vec![]) },
            }
        }
        let dot = |at: Point<Pixels>, radius: f32, colour: Hsla, window: &mut Window| window.paint_quad(fill(Bounds::new(point(at.x - px(radius), at.y - px(radius)), size(px(radius * 2.), px(radius * 2.))), colour).corner_radii(px(radius)));
        for run in &runs {
            let (Some(first), Some(last)) = (run.first(), run.last()) else { continue };
            if run.len() == 1 {
                dot(*first, 2., color, window);
                continue;
            }
            let mut area = PathBuilder::fill();
            area.move_to(point(first.x, px(bottom)));
            for at in run { area.line_to(*at) }
            area.line_to(point(last.x, px(bottom)));
            area.close();
            if let Ok(path) = area.build() { window.paint_path(path, color.opacity(0.13)) }
            let mut stroke = PathBuilder::stroke(px(1.5));
            stroke.move_to(*first);
            for at in &run[1..] { stroke.line_to(*at) }
            if let Ok(path) = stroke.build() { window.paint_path(path, color) }
        }
        // Where it stands now.
        if values.last().is_some_and(Option::is_some) && let Some(last) = runs.last().and_then(|run| run.last()) {
            dot(*last, 4.5, ring, window);
            dot(*last, 2.5, color, window);
        }
    });
    div().relative().w_full().h(px(height)).child(line.absolute().top_0().left_0().size_full()).child(div().absolute().top_0().left_0().size_full().flex().children(columns))
}

// ---- window chrome
//
// On Windows and macOS the window has no separate title bar: the top strip
// of each column drags the window, and on Windows the minimise / maximise /
// close buttons are drawn at the top right. They are native hit-test areas,
// so Snap Layouts and the system's close handling keep working.

pub const TITLE_H: f32 = 36.;
pub const CONTROL_W: f32 = 46.;

/// The band under the title strip that a column's header fills, ending in a line: the
/// page's and the assistant's share it, so the lines under them run on from column to column.
pub fn head_h() -> Pixels {
    text_px(56.)
}

/// The size of a column header's title.
pub const HEAD_TITLE: f32 = 15.;

/// A column's header: one row in `head_h`, a line under it.
pub fn column_head() -> Div {
    div().flex().flex_none().items_center().gap(px(4.)).h(head_h()).px(px(16.)).border_b_1().border_color(Theme::line())
}

/// The height of `title_strip`: none where the system draws the title bar.
pub fn strip_h() -> f32 {
    if custom_titlebar() { TITLE_H } else { 0. }
}

/// For a column of its own colour in a page under the main column's title strip: its colour
/// and left line carried up through the strip, so it reaches the top like the sidebar and the
/// paper do. The column is `relative`; the cap hears nothing, so the strip still drags the window.
pub fn strip_cap(colour: Hsla) -> Div {
    // From the column's outer left edge, where its own line is drawn, not inside it.
    div().absolute().top(px(-strip_h())).left(px(-1.)).right_0().h(px(strip_h())).bg(colour).border_l_1().border_color(Theme::line())
}

pub fn custom_titlebar() -> bool {
    cfg!(any(target_os = "windows", target_os = "macos"))
}

/// Room to leave at the top left for macOS's traffic lights.
pub fn traffic_lights_width() -> f32 {
    if cfg!(target_os = "macos") { 72. } else { 0. }
}

/// A strip that works like a title bar: a press drags the window, a double
/// press zooms it. Buttons placed on it call `.occlude()` to stay clickable.
pub fn title_strip() -> Div {
    let strip = div().flex().flex_none().items_center().w_full().h(px(strip_h()));
    if cfg!(target_os = "windows") {
        // Keep the workspace's focus handler from preventing the native caption action
        // (activation, dragging and double-click maximising) on mouse down.
        strip.occlude().window_control_area(WindowControlArea::Drag)
    } else if cfg!(target_os = "macos") {
        strip.on_mouse_down(MouseButton::Left, |ev, window, _| match ev.click_count {
            1 => window.start_window_move(),
            2 => window.titlebar_double_click(),
            _ => {}
        })
    } else {
        strip
    }
}

/// The minimise, maximise and close buttons (Windows only).
pub fn window_controls(window: &Window) -> Option<Div> {
    if !cfg!(target_os = "windows") { return None }
    let button = |id: &'static str, area: WindowControlArea, icon_name: &'static str, close: bool| {
        div()
            .id(id)
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .w(px(CONTROL_W))
            .h(px(TITLE_H))
            .occlude()
            .window_control_area(area)
            .group(id)
            .hover(move |s| if close { s.bg(Theme::danger()) } else { s.bg(Theme::hover()) })
            .child(icon(icon_name, 15., Theme::text_secondary()).when(close, |i| i.group_hover(id, |s| s.text_color(gpui::white()))))
    };
    Some(
        div()
            .absolute()
            .top_0()
            .right_0()
            .flex()
            .child(button("window-minimize", WindowControlArea::Min, "minus", false))
            .child(button("window-maximize", WindowControlArea::Max, if window.is_maximized() { "copy" } else { "expand" }, false))
            .child(button("window-close", WindowControlArea::Close, "x", true)),
    )
}

/// A small ⓘ that says on hover what a part of the page is for: an
/// explanation kept out of the way of what it explains.
pub fn hint(id: impl Into<ElementId>, text: impl Into<String>) -> Stateful<Div> {
    div().id(id).flex().flex_none().items_center().justify_center().size(px(18.)).rounded(px(9.)).cursor_default().hover(|s| s.bg(Theme::hover())).child(icon("info", 13., Theme::text_tertiary())).tooltip(tip(text))
}

/// The small card a tooltip is.
pub struct Tip(pub String);

impl Render for Tip {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div().max_w(px(320.)).px(px(8.)).py(px(5.)).rounded(px(6.)).border_1().border_color(Theme::line()).bg(Theme::bg_body()).font(theme::ui_font()).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(self.0.clone())
    }
}

/// What a control does, said on hover: for `.tooltip`.
pub fn tip(text: impl Into<String>) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
    let text = text.into();
    move |_, cx| cx.new(|_| Tip(text.clone())).into()
}

/// A toolbar's button in a place too narrow for its words: the icon in the button's frame, the words on hover.
pub fn tool_button(id: impl Into<ElementId>, name: &str, words: impl Into<String>) -> Stateful<Div> {
    div().id(id).flex().flex_none().items_center().justify_center().size(text_px(32.)).rounded(px(8.)).border_1().border_color(Theme::line_strong()).bg(Theme::bg_body()).cursor_pointer().hover(|s| s.bg(Theme::bg_sunken())).active(|s| s.bg(Theme::pressed())).child(icon(name, 14., Theme::text_secondary())).tooltip(tip(words))
}

/// A button that is only an icon, with what it does said on hover; the
/// sparkle of what a model does is one of these.
pub fn icon_action(id: impl Into<ElementId>, name: &str, color: Hsla, tip: impl Into<String>) -> Stateful<Div> {
    div().id(id).flex().flex_none().items_center().justify_center().size(px(24.)).rounded(px(6.)).cursor_pointer().hover(|s| s.bg(Theme::hover())).active(|s| s.bg(Theme::pressed())).child(icon(name, 14., color)).tooltip(self::tip(tip))
}

