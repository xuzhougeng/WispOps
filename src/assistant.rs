//! 助手 as a page of its own: the kept conversations at the left, newest
//! first and filtered by title, the conversation itself at the right in a
//! column of readable width. There is one conversation and one composer, so
//! while this page is open the panel beside the pages is not drawn; leaving
//! the page brings it back as it was. The list is read from disk when the
//! page is entered and after a conversation is saved, opened or deleted
//! (`Workspace::relist`), never while drawing.

use crate::app::{Cmd, SIDEBAR_W, Workspace};
use crate::chat::{ChatInfo, list_conversations};
use crate::i18n::t;
use crate::theme::{Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::time;

/// The width of the list of conversations.
const LIST_W: f32 = 272.;
/// The widest the conversation's text runs.
const COLUMN_W: f32 = 760.;

/// Where a conversation falls in the list, by the local day it was last spoken in.
fn day_group(info: &ChatInfo) -> &'static str {
    match time::days_ago(&info.updated_at) {
        Some(0) => "今天",
        Some(1) => "昨天",
        Some(days) if days < 7 => "最近 7 天",
        _ => "更早",
    }
}

impl Workspace {
    /// The page is entered: the panel's own list is closed, the kept conversations are read, the caret goes to the box.
    pub fn enter_assistant(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.chat.history = None;
        self.chat.conversations = list_conversations(&self.fleet);
        self.focus_composer(window, cx);
    }

    pub fn focus_composer(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.chat.input.update(cx, |input, _| input.focus(window));
    }

    pub fn render_assistant(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        // The model is named only once it can be asked: one without a key is not in use.
        let model = self.settings.chat_profile().filter(|profile| !profile.key().is_empty()).map(|profile| profile.title()).unwrap_or_default();
        let about = if model.is_empty() { self.chat_scope() } else { format!("{model} · {}", self.chat_scope()) };
        let head = self.page_head(t("助手"), about, vec![], cx);
        // The text column: what is left beside the sidebar and the list, with margins, at most `COLUMN_W`.
        let room = f32::from(window.viewport_size().width) - SIDEBAR_W - LIST_W - 2.;
        let column = (room - 64.).clamp(280., COLUMN_W);
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(head)
            .child(div().flex().flex_1().min_h_0().child(self.render_conversation_list(window, cx)).child(div().flex().flex_col().flex_1().min_w_0().child(self.render_conversation(Some(column), window, cx))))
            .into_any_element()
    }

    fn render_conversation_list(&self, window: &mut Window, cx: &mut Context<Self>) -> Div {
        let chat = &self.chat;
        let query = chat.search.read(cx).text().trim().to_lowercase();
        let shown: Vec<&ChatInfo> = chat.conversations.iter().filter(|info| query.is_empty() || info.title.to_lowercase().contains(&query)).collect();
        let mut rows: Vec<AnyElement> = vec![];
        let mut group = "";
        for info in &shown {
            let day = day_group(info);
            if day != group {
                group = day;
                rows.push(div().px(px(10.)).pt(px(if rows.is_empty() { 4. } else { 14. })).pb(px(4.)).child(ui::caption(t(day))).into_any_element());
            }
            rows.push(self.conversation_row(info, true, cx).into_any_element());
        }
        let list = if chat.conversations.is_empty() {
            ui::empty_state("history", t("还没有历史对话"), t("和助手说过的话会留在这里，可以点开接着说。")).into_any_element()
        } else if shown.is_empty() {
            div().px(px(18.)).py(px(12.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("没有符合的对话")).into_any_element()
        } else {
            div().id("assistant-conversations").flex().flex_col().flex_1().min_h_0().overflow_y_scroll().px(px(8.)).pb(px(10.)).children(rows).into_any_element()
        };
        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(LIST_W))
            .h_full()
            .bg(Theme::bg_sunken())
            .border_r_1()
            .border_color(Theme::line())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_none()
                    .gap(px(8.))
                    .px(px(16.))
                    .pt(px(12.))
                    .pb(px(8.))
                    .child(ui::secondary_button("assistant-new", "").w_full().child(ui::icon("plus", 14., Theme::text_secondary())).child(t("新对话")).on_click(self.on(Cmd::NewChat, cx)))
                    .when(!chat.conversations.is_empty(), |d| d.child(ui::field(&chat.search, window, cx))),
            )
            .child(list)
    }
}
