//! 助手 as a page of its own: the conversation in a column of readable width,
//! and, from its header, the kept conversations as a view of the same page
//! (`chat.history`): newest first, by day, filtered by title, each opened or
//! deleted there. There is one conversation and one composer, so while this
//! page is open the assistant beside the pages (floating or as a column) is
//! not drawn; going back to the page it was opened over brings it back as it
//! was (over any other page the floating one is put away). The list is read
//! from disk when the page is entered and after a conversation is saved,
//! opened or deleted (`Workspace::relist`), never while drawing.

use crate::app::{Cmd, SIDEBAR_W, Workspace};
use crate::chat::{ChatInfo, list_conversations};
use crate::i18n::t;
use crate::theme::{Theme, text_px};
use crate::ui;
use gpui::*;
use wisp_ops_core::time;

/// The widest the conversation's text, and the list of conversations, run.
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
    /// The page is entered: on the conversation, with the kept ones read and the caret in the box.
    pub fn enter_assistant(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.chat.history = false;
        self.chat.conversations = list_conversations(&self.fleet);
        self.focus_composer(window, cx);
    }

    pub fn focus_composer(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.chat.input.update(cx, |input, _| input.focus(window));
    }

    pub fn render_assistant(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        // The column: what is left beside the sidebar, with margins, at most `COLUMN_W`.
        let room = f32::from(window.viewport_size().width) - SIDEBAR_W - 2.;
        let column = (room - 64.).clamp(280., COLUMN_W);
        let new = ui::secondary_button("assistant-new", "").child(ui::icon("plus", 14., Theme::text_secondary())).child(t("新对话")).on_click(self.on(Cmd::NewChat, cx)).into_any_element();
        if self.chat.history {
            let count = self.chat.conversations.len();
            let about = if count == 0 { t("和助手说过的话会留在这里，可以点开接着说。").to_string() } else { tf!("{count} 次对话 · 点开一次可以接着说", "{count} conversations · open one to continue it") };
            let back = ui::ghost_button("assistant-back", Some("arrow-left"), Some(t("返回对话").into())).on_click(self.on(Cmd::ToggleHistory, cx)).into_any_element();
            let head = self.page_head(t("历史对话"), about, vec![back, new], cx);
            return div().flex().flex_col().size_full().child(head).child(self.render_conversation_list(column, window, cx)).into_any_element();
        }
        // The model is named only once it can be asked: one without a key is not in use.
        let model = self.settings.chat_profile().filter(|profile| !profile.key().is_empty()).map(|profile| profile.title()).unwrap_or_default();
        let about = if model.is_empty() { self.chat_scope() } else { format!("{model} · {}", self.chat_scope()) };
        let behind = self.chat.behind_at_work();
        let history = if behind > 0 { tf!("历史对话 · {behind} 个在后台进行", "Conversations · {behind} going on in the background") } else { t("历史对话").to_string() };
        let mut actions = vec![ui::ghost_button("assistant-history", Some("history"), Some(history.into())).on_click(self.on(Cmd::ToggleHistory, cx)).into_any_element()];
        if !self.chat.current.messages.is_empty() { actions.push(new) }
        let head = self.page_head(t("助手"), about, actions, cx);
        div().flex().flex_col().size_full().child(head).child(self.render_conversation(Some(column), window, cx)).into_any_element()
    }

    /// The kept conversations, `column` wide in the middle of the page: a field to find one by its title, then the days.
    fn render_conversation_list(&self, column: f32, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let chat = &self.chat;
        if chat.conversations.is_empty() { return ui::empty_state("history", t("还没有历史对话"), t("和助手说过的话会留在这里，可以点开接着说。")).into_any_element() }
        let query = chat.search.read(cx).text().trim().to_lowercase();
        let shown: Vec<&ChatInfo> = chat.conversations.iter().filter(|info| query.is_empty() || info.title.to_lowercase().contains(&query)).collect();
        let mut rows: Vec<AnyElement> = vec![];
        let mut group = "";
        for info in &shown {
            let day = day_group(info);
            if day != group {
                group = day;
                rows.push(div().px(px(10.)).pt(px(16.)).pb(px(4.)).child(ui::caption(t(day))).into_any_element());
            }
            rows.push(self.conversation_row(info, cx).into_any_element());
        }
        if shown.is_empty() { rows.push(div().px(px(10.)).py(px(16.)).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(t("没有符合的对话")).into_any_element()) }
        // The scroll runs the full width, so the wheel works beside the list too.
        div()
            .id("assistant-conversations")
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .items_center()
            .overflow_y_scroll()
            .px(px(16.))
            .pt(px(20.))
            .pb(px(24.))
            .child(div().flex().flex_col().flex_none().w(px(column)).child(div().px(px(2.)).child(ui::field(&chat.search, window, cx))).children(rows))
            .into_any_element()
    }
}
