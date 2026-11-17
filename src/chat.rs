//! 助手: the conversation beside every page. The model is told what the
//! fleet is and works through the `ops_*` tools (`tools.rs`); between the
//! pieces of its answer stand the tools it called, folded into one line once
//! they are done. A call a host's policy asks about waits on a card for the
//! person: this once, for a while (a grant), or not at all. A policy that
//! denies is answered to the model without asking anyone.
//!
//! The steps of one request: `ask` → `chat_step` (the streamed turn) →
//! `run_tools` (each call settled by the gate) → `execute_tools` (off the
//! main thread) → `chat_step` again, until a turn ends without calls.

use crate::app::{Cmd, Consent, MenuKind, Page, Workspace};
use crate::i18n::t;
use crate::input::{InputEvent, TextInput};
use crate::theme::{self, Theme, text_px};
use crate::tools::{self, Gate};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use wisp_ops_core::ai::{self, ChatEvent, Protocol, Said, ToolCall, Transcript};
use wisp_ops_core::time;

/// The steps one request may take. Each is a request to the model; all but
/// the last end in tool calls. With the results before the last one the
/// model is told to answer from what it has (`ai::LAST_STEP_NOTE`).
const MAX_CHAT_STEPS: usize = 32;

/// What a conversation shows, in order.
pub enum ChatItem {
    /// A request as typed, and what went to the model where that is not the text (a slash command written out).
    User { text: String, prompt: String },
    /// Text of the model; one answer may come in several pieces with tool calls between them.
    Answer(String),
    /// A tool the model called, what came of it (summary, failed) once it has run, and what it returned in full.
    Tool { call: String, result: Option<(String, bool)>, output: String },
}

/// A tool call made ready to run: what the gate said of it.
pub struct PreparedCall {
    id: String,
    name: String,
    args: Result<Value, String>,
    pub gate: Gate,
}

/// The calls of a turn that wait for the person's consent, and where their lines stand in the conversation.
pub struct PendingTools {
    pub calls: Vec<PreparedCall>,
    first: usize,
}

/// A kept conversation as its list shows it.
pub struct ChatInfo {
    pub id: String,
    pub title: String,
    pub updated_at: String,
    pub requests: usize,
}

pub struct Chat {
    pub input: Entity<TextInput>,
    pub messages: Vec<ChatItem>,
    /// The conversation as the model's protocol carries it: requests, the
    /// model's turns as it sent them, tool results. Only ever appended to.
    wire: Vec<Value>,
    /// The protocol `wire` is written in.
    protocol: Option<Protocol>,
    /// Requests made to the model for the one being answered.
    pub steps: usize,
    /// What the model was told of the fleet, built with the first request.
    ctx: Option<ai::Context>,
    pub busy: bool,
    pub error: String,
    /// Why the last answer ended early, if it did; while one is awaited, what it is waiting for.
    pub note: String,
    pub scroll: ScrollHandle,
    /// Bumped by 新对话 and by stopping, so what still arrives for the old run is dropped.
    pub generation: u64,
    /// The conversation's id on disk; empty until a request was made.
    pub id: String,
    created_at: String,
    /// Whose grants these are: one conversation's, gone with it.
    pub session: String,
    /// Which of the slash commands on offer is picked.
    pub slash: usize,
    slash_closed: bool,
    /// On the assistant's page, the kept conversations are on show in place of the conversation.
    pub history: bool,
    /// The kept conversations as that list shows them: read when the page is entered and after each change.
    pub conversations: Vec<ChatInfo>,
    /// What the list is filtered by.
    pub search: Entity<TextInput>,
    /// The page the assistant's page was entered from: where its shortcut goes back to.
    pub back: Page,
    /// The page the conversation was opened over: floating, it is put away when another page is
    /// gone to, and opened there the assistant starts a conversation of that page's own.
    pub page: Page,
    /// The tool calls waiting for the person's consent.
    pub pending: Option<PendingTools>,
    /// The calls running now, which get an answer of their own if the person stops.
    running: Vec<String>,
    /// Raised by stopping: the SSH commands in flight are ended.
    cancel: Arc<AtomicBool>,
    /// The groups of tool lines (by the place of their first) that are unfolded.
    pub tools_open: HashSet<usize>,
    /// When the request being answered was made.
    pub started: Option<Instant>,
}

fn new_session() -> String {
    format!("s{:x}", time::now_millis())
}

impl Chat {
    pub fn new(cx: &mut App) -> Chat {
        let input = cx.new(|cx| {
            let mut input = TextInput::new("让助手巡检、诊断或处理服务器… 输入 / 查看命令", cx).multiline(1);
            input.submit_on_enter = true;
            input
        });
        let search = cx.new(|cx| TextInput::new("搜索对话", cx));
        Chat { input, messages: vec![], wire: vec![], protocol: None, steps: 0, ctx: None, busy: false, error: String::new(), note: String::new(), scroll: ScrollHandle::new(), generation: 0, id: String::new(), created_at: String::new(), session: new_session(), slash: 0, slash_closed: false, history: false, conversations: vec![], search, back: Page::Overview, page: Page::Overview, pending: None, running: vec![], cancel: Arc::new(AtomicBool::new(false)), tools_open: Default::default(), started: None }
    }

    /// The slash commands to offer for what is in the box right now.
    pub fn slash_list(&self, own: &[ai::Command], cx: &App) -> Vec<ai::Offer> {
        if self.slash_closed { vec![] } else { ai::slash_matches(self.input.read(cx).text(), own) }
    }

    /// An answer piece that never got any text leaves no empty line behind.
    fn drop_empty_answer(&mut self) {
        if matches!(self.messages.last(), Some(ChatItem::Answer(text)) if text.is_empty()) { self.messages.pop(); }
    }

    /// The request has been answered, or given up on.
    fn end_run(&mut self) {
        self.busy = false;
        self.started = None;
        self.pending = None;
        self.running.clear();
        self.drop_empty_answer();
        if self.note.is_empty() && self.error.is_empty() && !matches!(self.messages.last(), Some(ChatItem::Answer(_))) { self.note = t("模型没有返回内容。").into() }
    }

    fn transcript(&self) -> Transcript {
        let items = self
            .messages
            .iter()
            .filter_map(|item| match item {
                ChatItem::User { text, prompt } => Some(Said::User { text: text.clone(), prompt: prompt.clone() }),
                ChatItem::Answer(text) if !text.is_empty() => Some(Said::Answer { text: text.clone() }),
                ChatItem::Answer(_) => None,
                ChatItem::Tool { call, result, output } => Some(Said::Tool { call: call.clone(), result: result.as_ref().map(|(shown, _)| shown.clone()).unwrap_or_default(), failed: result.as_ref().is_some_and(|(_, failed)| *failed), output: output.clone() }),
            })
            .collect();
        Transcript { id: self.id.clone(), created_at: self.created_at.clone(), updated_at: time::now_iso(), items }
    }
}

// ---- conversations on disk: one JSON file each under `conversations/`.

fn conversations_dir(fleet: &crate::ops::Fleet) -> std::path::PathBuf {
    fleet.data_dir().join("conversations")
}

pub fn list_conversations(fleet: &crate::ops::Fleet) -> Vec<ChatInfo> {
    let mut all: Vec<ChatInfo> = std::fs::read_dir(conversations_dir(fleet))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let transcript: Transcript = serde_json::from_str(&std::fs::read_to_string(entry.path()).ok()?).ok()?;
            Some(ChatInfo { title: transcript.title(), requests: transcript.items.iter().filter(|item| matches!(item, Said::User { .. })).count(), id: transcript.id, updated_at: transcript.updated_at })
        })
        .collect();
    all.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    all
}

/// How long an answer has been awaited: `8s`, `1m 05s`.
fn elapsed(chat: &Chat) -> String {
    let seconds = chat.started.map_or(0, |at| at.elapsed().as_secs());
    if seconds < 60 { format!("{seconds}s") } else { format!("{}m {:02}s", seconds / 60, seconds % 60) }
}

/// The tools of a run of calls in a few words: 「巡检 ×2 · 批量命令」.
fn tools_summary(calls: &[&str]) -> String {
    let mut counted: Vec<(&str, usize)> = vec![];
    for call in calls {
        // A call is worded 「批量命令：df -h」; what stands before the colon is the tool.
        let title = call.split('：').next().unwrap_or(call);
        match counted.iter_mut().find(|(known, _)| *known == title) {
            Some((_, count)) => *count += 1,
            None => counted.push((title, 1)),
        }
    }
    counted.into_iter().map(|(title, count)| if count > 1 { format!("{title} ×{count}") } else { title.to_string() }).collect::<Vec<_>>().join(" · ")
}

impl Workspace {
    pub fn chat_input(&mut self, event: InputEvent, cx: &mut Context<Self>) {
        let chat = &mut self.chat;
        let (offered, picked) = (chat.slash_list(&self.settings.commands, cx).len(), chat.slash);
        match event {
            // Enter on a command in the list takes it; otherwise the message goes.
            InputEvent::Submit if offered > 0 => return self.pick_slash(picked, cx),
            InputEvent::Submit => return self.ask(cx),
            InputEvent::Tab if offered > 0 => return self.pick_slash(picked, cx),
            InputEvent::Changed => {
                chat.slash_closed = false;
                chat.slash = 0;
            }
            InputEvent::Up if offered > 0 => chat.slash = (chat.slash + offered - 1) % offered,
            InputEvent::Down if offered > 0 => chat.slash = (chat.slash + 1) % offered,
            InputEvent::Cancel => chat.slash_closed = true,
            _ => {}
        }
        // While the list is on show the arrow keys and Tab are its keys.
        let choosing = !chat.slash_list(&self.settings.commands, cx).is_empty();
        chat.input.update(cx, |input, _| input.choosing = choosing);
        cx.notify();
    }

    /// Take one of the slash commands on offer: `/new` runs, the others are
    /// written out for what they work on to follow.
    pub fn pick_slash(&mut self, at: usize, cx: &mut Context<Self>) {
        let offers = self.chat.slash_list(&self.settings.commands, cx);
        let Some(offer) = offers.get(at) else { return };
        if offer.runs {
            self.chat.input.update(cx, |input, cx| input.set_text("", cx));
            return self.new_chat(cx);
        }
        let text = format!("/{} ", offer.name);
        self.chat.input.update(cx, |input, cx| {
            input.set_text(&text, cx);
            input.choosing = false;
        });
        cx.notify();
    }

    pub fn new_chat(&mut self, cx: &mut Context<Self>) {
        if self.chat.busy { self.stop_chat(cx) }
        // The grants were this conversation's: they end with it.
        self.fleet.revoke_grants(&self.chat.session);
        let chat = &mut self.chat;
        chat.generation += 1;
        chat.messages.clear();
        chat.wire.clear();
        chat.protocol = None;
        chat.ctx = None;
        chat.error.clear();
        chat.note.clear();
        chat.id.clear();
        chat.created_at.clear();
        chat.session = new_session();
        chat.history = false;
        chat.pending = None;
        chat.tools_open.clear();
        self.show_chat(cx);
        cx.notify();
    }

    pub fn ask(&mut self, cx: &mut Context<Self>) {
        let Some(profile) = self.settings.chat_profile() else {
            self.chat.error = t("还没有配置模型。在「设置 › 模型」里添加一个模型服务。").into();
            return cx.notify();
        };
        let chat = &mut self.chat;
        let question = chat.input.read(cx).text().trim().to_string();
        if question.is_empty() || chat.busy { return }
        chat.error.clear();
        chat.note.clear();
        let prompt = match ai::read_input(&question, &self.settings.commands) {
            Ok(ai::Input::Ask(prompt)) => prompt,
            Ok(ai::Input::NewChat) => {
                chat.input.update(cx, |input, cx| input.set_text("", cx));
                return self.new_chat(cx);
            }
            Err(err) => {
                chat.error = err;
                return cx.notify();
            }
        };
        chat.history = false;
        // A changed protocol starts the wire again from the text of what was said:
        // the model's own turns are only valid in the conversation that produced them.
        let replay = chat.ctx.is_none() || chat.protocol != Some(profile.protocol);
        if chat.ctx.is_none() {
            // The fleet as it stands now: what there is, and what each host's policy says.
            self.fleet.refresh();
            self.view = self.fleet.view();
            self.chat.ctx = Some(tools::context(&self.view, &self.skills_on()));
        }
        let chat = &mut self.chat;
        if replay {
            let mut wire: Vec<Value> = vec![];
            let mut answer = String::new();
            for item in &chat.messages {
                match item {
                    ChatItem::User { text, prompt } => {
                        if !answer.is_empty() { wire.push(ai::assistant_message(&std::mem::take(&mut answer))) }
                        wire.push(ai::user_message(if prompt.is_empty() { text } else { prompt }));
                    }
                    ChatItem::Answer(text) if !text.is_empty() => {
                        if !answer.is_empty() { answer.push_str("\n\n") }
                        answer.push_str(text);
                    }
                    // What a tool found is not replayed: the answer that followed says it.
                    _ => {}
                }
            }
            if !answer.is_empty() { wire.push(ai::assistant_message(&answer)) }
            chat.wire = wire;
            chat.protocol = Some(profile.protocol);
        }
        chat.wire.push(ai::user_message(&prompt));
        let sent = if prompt == question { String::new() } else { prompt };
        chat.messages.push(ChatItem::User { text: question, prompt: sent });
        chat.steps = 0;
        chat.started = Some(Instant::now());
        chat.cancel = Arc::new(AtomicBool::new(false));
        if chat.created_at.is_empty() {
            chat.created_at = time::now_iso();
            chat.id = format!("c{:x}", time::now_millis());
        }
        let sent = self.chat_step(cx);
        let chat = &mut self.chat;
        if sent {
            chat.input.update(cx, |input, cx| input.set_text("", cx));
            self.save_chat(cx);
            self.tick_elapsed(cx);
        } else {
            // Nothing was sent: the request stays in the box, to be made again.
            chat.wire.pop();
            chat.messages.pop();
            if chat.messages.is_empty() { chat.ctx = None }
        }
        cx.notify();
    }

    /// The skills that are switched on.
    pub fn skills_on(&self) -> Vec<wisp_ops_core::skill::Skill> {
        self.skills.iter().filter(|skill| !self.settings.skills_off.contains(&skill.name)).cloned().collect()
    }

    /// While an answer is awaited, the seconds beside the turning mark go on.
    fn tick_elapsed(&mut self, cx: &mut Context<Self>) {
        let generation = self.chat.generation;
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(std::time::Duration::from_secs(1)).await;
                let going = this.update(cx, |this, cx| {
                    cx.notify();
                    this.chat.busy && this.chat.generation == generation
                });
                if !matches!(going, Ok(true)) { break }
            }
        })
        .detach();
    }

    /// Send the conversation to the model and follow its turn: the text as
    /// it arrives, then either the end of the answer or the tools it asked
    /// for. False when the request could not be made.
    fn chat_step(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(profile) = self.settings.chat_profile() else { return false };
        let mut catalog = tools::catalog();
        catalog.extend(wisp_ops_core::skill::tool(&self.skills_on()));
        let chat = &mut self.chat;
        let Some(ctx) = chat.ctx.as_ref() else { return false };
        let request = match ai::chat_request(&profile, ctx, &chat.wire, &catalog) {
            Ok(request) => request,
            Err(err) => {
                chat.error = err;
                chat.end_run();
                return false;
            }
        };
        chat.messages.push(ChatItem::Answer(String::new()));
        chat.busy = true;
        chat.steps += 1;
        chat.scroll.scroll_to_bottom();
        let generation = chat.generation;

        let (sender, events) = async_channel::unbounded();
        let protocol = profile.protocol;
        cx.background_executor().spawn(async move { wisp_ops_net::stream_chat(request, protocol, sender) }).detach();
        cx.spawn(async move |this, cx| {
            while let Ok(event) = events.recv().await {
                let alive = this.update(cx, |this, cx| {
                    let chat = &mut this.chat;
                    if chat.generation != generation { return false }
                    // Keep following the answer while the reader is at the bottom.
                    let at_bottom = chat.scroll.offset().y <= -chat.scroll.max_offset().height + px(40.);
                    let mut calls = None;
                    let more = match event {
                        ChatEvent::Text(text) => {
                            chat.note.clear();
                            if let Some(ChatItem::Answer(answer)) = chat.messages.last_mut() { answer.push_str(&text) }
                            true
                        }
                        ChatEvent::Retrying(attempt, why) => {
                            chat.note = tf!("模型服务暂时没有回应（{why}），正在重试，第 {attempt} 次…", "The model service has not responded ({why}). Retrying, attempt {attempt}…");
                            true
                        }
                        ChatEvent::Error(error) => {
                            chat.note.clear();
                            chat.error = error;
                            chat.end_run();
                            false
                        }
                        ChatEvent::Done(turn) => {
                            chat.note.clear();
                            chat.wire.extend(turn.wire());
                            if turn.calls.is_empty() {
                                chat.note = ai::stop_note(&turn.stop).unwrap_or_default().to_string();
                                chat.end_run();
                            } else if !turn.runnable() || chat.steps >= MAX_CHAT_STEPS {
                                // The calls still get an answer: a conversation that ends on an unanswered call cannot continue.
                                let (why, note) = if turn.runnable() { (t("已达到单次请求的步数上限，工具没有执行。"), t("已达到单次请求的步数上限。可以继续说，让它接着做。")) } else { (t("回答被截断，工具没有执行。"), ai::stop_note(&turn.stop).unwrap_or(t("回答没有正常结束。"))) };
                                let results: Vec<(String, String, bool)> = turn.calls.iter().map(|call| (call.id.clone(), why.to_string(), true)).collect();
                                chat.wire.extend(ai::tool_results(protocol, &results));
                                chat.note = note.to_string();
                                chat.end_run();
                            } else {
                                chat.drop_empty_answer();
                                calls = Some(turn.calls);
                            }
                            false
                        }
                    };
                    if at_bottom { chat.scroll.scroll_to_bottom() }
                    let ended = !chat.busy;
                    if let Some(calls) = calls { this.run_tools(calls, cx) }
                    if ended { this.save_chat(cx) }
                    cx.notify();
                    more
                });
                if !matches!(alive, Ok(true)) { break }
            }
        })
        .detach();
        true
    }

    /// Settle the tools a turn asked for, show them, and run them: at once
    /// when policy allows (or a grant covers them), after the person's
    /// consent when a host's policy asks. What policy denies is not asked about.
    fn run_tools(&mut self, calls: Vec<ToolCall>, cx: &mut Context<Self>) {
        // The inventory may have been edited since the last call.
        self.fleet.refresh();
        let skills = self.skills_on();
        let chat = &mut self.chat;
        let first = chat.messages.len();
        let mut prepared = vec![];
        for call in calls {
            let args = call.args.as_ref().unwrap_or(&Value::Null);
            let line = if call.name == wisp_ops_core::skill::TOOL { tf!("读取技能：{}", "Read skill: {}", args["name"].as_str().unwrap_or("?")) } else { tools::describe_call(&call.name, args) };
            let gate = match &call.args {
                Err(err) => Gate::Refuse(err.clone()),
                Ok(args) if call.name == wisp_ops_core::skill::TOOL => Gate::Said(wisp_ops_core::skill::read(&skills, args["name"].as_str().unwrap_or(""))),
                Ok(args) => tools::gate(&self.fleet, &chat.session, &call.name, args),
            };
            chat.messages.push(ChatItem::Tool { call: line, result: None, output: String::new() });
            prepared.push(PreparedCall { id: call.id, name: call.name, args: call.args, gate });
        }
        chat.scroll.scroll_to_bottom();
        if prepared.iter().any(|call| matches!(call.gate, Gate::Ask(..))) {
            chat.pending = Some(PendingTools { calls: prepared, first });
            return cx.notify();
        }
        self.execute_tools(prepared, first, true, cx);
    }

    /// The person answered the card: run the calls, or tell the model they were not allowed.
    pub fn answer_tools(&mut self, consent: Consent, cx: &mut Context<Self>) {
        let Some(pending) = self.chat.pending.take() else { return };
        if consent == Consent::Grant {
            for call in &pending.calls {
                if let Gate::Ask(_, ask) = &call.gate { self.fleet.grant(&self.chat.session, ask) }
            }
        }
        if consent == Consent::Full { self.fleet.grant_full(&self.chat.session) }
        self.execute_tools(pending.calls, pending.first, consent != Consent::Deny, cx);
    }

    /// Run a turn's tools off the main thread, then hand the results to the
    /// model with the next step. Calls that only read run side by side; a
    /// turn with a call that changes something runs in the order it was
    /// given. Without the person's consent (`allowed`) the calls that asked
    /// for it are answered with a refusal and the others still run.
    fn execute_tools(&mut self, calls: Vec<PreparedCall>, first: usize, allowed: bool, cx: &mut Context<Self>) {
        let chat = &mut self.chat;
        let Some(protocol) = chat.protocol else { return };
        let generation = chat.generation;
        chat.running = calls.iter().map(|call| call.id.clone()).collect();
        let (fleet, session, cancel) = (self.fleet.clone(), chat.session.clone(), chat.cancel.clone());
        let ordered = calls.len() == 1 || calls.iter().any(|call| !matches!(call.gate, Gate::Run(ref ticket) if ticket.read_only()) && !matches!(call.gate, Gate::Said(_) | Gate::Refuse(_)));
        let executor = cx.background_executor().clone();
        let run = move |fleet: &crate::ops::Fleet, session: &str, cancel: &Arc<AtomicBool>, call: PreparedCall| -> (String, Result<String, String>) {
            let result = match call.gate {
                Gate::Refuse(why) => Err(why),
                Gate::Said(said) => said,
                Gate::Ask(..) if !allowed => Err("用户没有同意这次操作，它没有执行。不要重试，也不要换一种写法绕过；向用户说明它会做什么、为什么需要，由用户决定。".to_string()),
                Gate::Ask(ticket, _) | Gate::Run(ticket) => call.args.and_then(|args| tools::run(fleet, session, &call.name, &args, ticket, cancel)),
            };
            (call.id, result)
        };
        let tasks: Vec<gpui::Task<Vec<(String, Result<String, String>)>>> = if ordered {
            vec![executor.spawn(async move { calls.into_iter().map(|call| run(&fleet, &session, &cancel, call)).collect() })]
        } else {
            calls
                .into_iter()
                .map(|call| {
                    let (fleet, session, cancel) = (fleet.clone(), session.clone(), cancel.clone());
                    executor.spawn(async move { vec![run(&fleet, &session, &cancel, call)] })
                })
                .collect()
        };
        cx.spawn(async move |this, cx| {
            let mut done = vec![];
            for task in tasks {
                done.extend(task.await);
            }
            this.update(cx, |this, cx| {
                // Whatever the calls did (an inspection, a probe, a change), the pages read it again.
                this.reload(cx);
                let chat = &mut this.chat;
                if chat.generation == generation {
                    for (n, (_, result)) in done.iter().enumerate() {
                        if let Some(ChatItem::Tool { result: shown, output, .. }) = chat.messages.get_mut(first + n) {
                            *shown = Some((tools::summary(result), result.is_err()));
                            *output = match result { Ok(text) | Err(text) => text.clone() };
                        }
                    }
                    let results: Vec<(String, String, bool)> = done.into_iter().map(|(id, result)| match result { Ok(text) => (id, text, false), Err(text) => (id, text, true) }).collect();
                    let mut results = ai::tool_results(protocol, &results);
                    // One step is left: the model is told to answer with what it has.
                    if chat.steps + 1 >= MAX_CHAT_STEPS { results = ai::with_note(protocol, results, ai::LAST_STEP_NOTE) }
                    chat.wire.extend(results);
                    chat.running.clear();
                    if !this.chat_step(cx) { this.save_chat(cx) }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// Stop the answer being given. What still arrives for it is dropped and
    /// the SSH commands in flight are ended; the conversation stays one that
    /// can go on: the calls in flight are answered as stopped, and the text
    /// so far stays as the model's turn.
    pub fn stop_chat(&mut self, cx: &mut Context<Self>) {
        let chat = &mut self.chat;
        if !chat.busy { return }
        chat.generation += 1;
        chat.cancel.store(true, Ordering::Relaxed);
        let unanswered: Vec<String> = match chat.pending.take() {
            Some(pending) => pending.calls.into_iter().map(|call| call.id).collect(),
            None => std::mem::take(&mut chat.running),
        };
        if let Some(protocol) = chat.protocol {
            if !unanswered.is_empty() {
                let results: Vec<(String, String, bool)> = unanswered.into_iter().map(|id| (id, "用户中止了这次请求。这个工具的结果没有交回；远端命令可能已经执行了一部分，继续之前先检查状态。".to_string(), true)).collect();
                chat.wire.extend(ai::tool_results(protocol, &results));
            } else if let Some(ChatItem::Answer(text)) = chat.messages.last() && !text.is_empty() {
                chat.wire.push(ai::assistant_message(text));
            }
        }
        for item in chat.messages.iter_mut() {
            if let ChatItem::Tool { result, .. } = item && result.is_none() { *result = Some((t("已中止").into(), true)) }
        }
        chat.note = t("已停止。").into();
        chat.end_run();
        self.save_chat(cx);
        cx.notify();
    }

    /// Keep the conversation on disk, as it stands.
    pub fn save_chat(&mut self, cx: &mut Context<Self>) {
        let chat = &self.chat;
        if chat.id.is_empty() || !chat.messages.iter().any(|item| matches!(item, ChatItem::User { .. })) { return }
        let dir = conversations_dir(&self.fleet);
        let result = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(dir.join(format!("{}.json", chat.id)), serde_json::to_string(&chat.transcript()).unwrap_or_default()));
        if let Err(err) = result { self.fail(tf!("这次对话没能保存：{err}", "Conversation not saved: {err}"), cx) }
        self.relist();
    }

    /// Read the kept conversations again, where their list can be shown: on the assistant's page.
    pub fn relist(&mut self) {
        if self.page == Page::Assistant { self.chat.conversations = list_conversations(&self.fleet) }
    }

    /// Take up a kept conversation: what was said is shown again, and the
    /// next request continues it with the fleet as it is now.
    pub fn open_chat(&mut self, id: &str, cx: &mut Context<Self>) {
        let path = conversations_dir(&self.fleet).join(format!("{id}.json"));
        let Some(transcript) = std::fs::read_to_string(path).ok().and_then(|text| serde_json::from_str::<Transcript>(&text).ok()) else { return self.fail(t("这次对话读不出来了。"), cx) };
        self.new_chat(cx);
        let chat = &mut self.chat;
        chat.id = transcript.id;
        chat.created_at = transcript.created_at;
        chat.messages = transcript
            .items
            .into_iter()
            .map(|item| match item {
                Said::User { text, prompt } => ChatItem::User { text, prompt },
                Said::Answer { text } => ChatItem::Answer(text),
                Said::Tool { call, result, failed, output } => ChatItem::Tool { call, result: Some((result, failed)), output },
            })
            .collect();
        chat.scroll.scroll_to_bottom();
        self.relist();
        cx.notify();
    }

    pub fn delete_chat(&mut self, id: &str, cx: &mut Context<Self>) {
        let _ = std::fs::remove_file(conversations_dir(&self.fleet).join(format!("{id}.json")));
        // The list stays open: deleting the open conversation starts a new one, which closes it.
        let listing = self.chat.history;
        if self.chat.id == id { self.new_chat(cx) }
        self.chat.history = listing;
        self.relist();
        cx.notify();
    }

    /// What a tool returned, in full, in a dialog: the evidence behind a line of the conversation.
    pub fn show_output(&mut self, at: usize, _: &mut Window, cx: &mut Context<Self>) {
        let Some(ChatItem::Tool { call, output, .. }) = self.chat.messages.get(at) else { return };
        self.modal = Some(crate::dialogs::Modal::Text { title: call.clone(), text: output.clone(), scroll: ScrollHandle::new() });
        cx.notify();
    }

    // ---- drawing

    /// What the assistant may work on, said under its title.
    pub fn chat_scope(&self) -> String {
        if self.view.hosts.is_empty() {
            t("清单里还没有服务器").to_string()
        } else {
            tf!("可操作清单里的 {} 台服务器；变更、sudo 和破坏性操作按每台的权限裁决", "Works on the {} servers of the inventory; changes, sudo and destructive commands are settled per host", self.view.hosts.len())
        }
    }

    /// The assistant over or beside a page: its header and the conversation. The kept conversations are on its own page.
    pub fn render_chat(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let scope = self.chat_scope();
        let docked = self.settings.chat_docked;
        let body = self.render_conversation(None, window, cx);
        let chat = &self.chat;
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(
                ui::column_head()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(div().truncate().text_size(text_px(ui::HEAD_TITLE)).font_weight(FontWeight::SEMIBOLD).child(t("助手")))
                            .child(div().id("chat-scope").truncate().text_size(text_px(12.)).line_height(text_px(17.)).text_color(Theme::text_tertiary()).tooltip(ui::tip(scope.clone())).child(scope)),
                    )
                    .when(!chat.messages.is_empty(), |d| d.child(ui::ghost_button("chat-new", Some("plus"), None).tooltip(ui::tip(t("新对话"))).on_click(self.on(Cmd::NewChat, cx))))
                    .child(ui::ghost_button("chat-history", Some("history"), None).tooltip(ui::tip(t("历史对话"))).on_click(self.on(Cmd::ToggleHistory, cx)))
                    .child(ui::ghost_button("chat-dock", Some(if docked { "picture-in-picture" } else { "panel-right" }), None).tooltip(ui::tip(if docked { t("改为悬浮窗") } else { t("停靠到右侧") })).on_click(self.on(Cmd::DockChat(!docked), cx)))
                    .child(ui::ghost_button("chat-page", Some("expand"), None).tooltip(ui::tip(t("在页面中打开"))).on_click(self.on(Cmd::SetPage(Page::Assistant), cx)))
                    .child(ui::ghost_button("chat-hide", Some("x"), None).tooltip(ui::tip(t("收起助手"))).on_click(self.on(Cmd::ToggleChat, cx))),
            )
            .child(body)
            .into_any_element()
    }

    /// The conversation itself: the grants strip, the messages (or the start), the consent card and the composer.
    /// Drawn once a frame: floating, in the column or on the assistant's page; there `column` is the width its text is kept to.
    pub fn render_conversation(&self, column: Option<f32>, window: &mut Window, cx: &mut Context<Self>) -> Div {
        let chat = &self.chat;
        let profile = self.settings.chat_profile();
        let configured = profile.as_ref().is_some_and(|profile| !profile.key().is_empty());
        // A service that is listed but has no key is not "no model": say which one, and what it lacks.
        let keyless = profile.as_ref().filter(|_| !configured).map(|profile| profile.labelled());
        let model = profile.map(|profile| profile.title()).unwrap_or_default();
        let grants = self.fleet.grants(&chat.session);
        let full = self.fleet.grant_store().is_full(&chat.session);
        let body = if let Some(model) = keyless.filter(|_| chat.messages.is_empty()) {
            ui::empty_state("sparkle", &tf!("{model} 还缺 API Key", "{model} has no API key yet"), t("模型服务已经列好，但还没有填 API Key（对应的环境变量也没有设置），助手问不了它。API Key 只保存在本机。不配置模型也可以用左边的页面巡检和管理服务器。")).child(ui::primary_button("chat-settings", t("去填 API Key")).on_click(self.on(Cmd::SetPage(Page::Settings), cx))).into_any_element()
        } else if !configured && chat.messages.is_empty() {
            ui::empty_state("sparkle", t("还没有配置模型"), t("助手需要一个模型服务：Claude API，或任何 OpenAI 兼容的服务。API Key 只保存在本机。不配置模型也可以用左边的页面巡检和管理服务器。")).child(ui::primary_button("chat-settings", t("打开设置")).on_click(self.on(Cmd::SetPage(Page::Settings), cx))).into_any_element()
        } else if chat.messages.is_empty() && chat.error.is_empty() {
            self.render_start(cx)
        } else {
            let messages = div().id("chat").flex().flex_col().flex_1().min_h_0().overflow_y_scroll().track_scroll(&chat.scroll).px(px(16.));
            match column {
                None => messages.py(px(14.)).gap(px(14.)).children(self.render_messages(cx)).into_any_element(),
                // The scroll runs the full width, so the wheel works beside the text too; the text keeps to its column.
                Some(width) => messages.items_center().py(px(20.)).child(div().flex().flex_col().flex_none().w(px(width)).gap(px(16.)).children(self.render_messages(cx))).into_any_element(),
            }
        };
        let composer = configured.then(|| match column {
            None => self.render_composer(&model, self.chat_width(), window, cx),
            Some(width) => div().flex().flex_none().justify_center().pb(px(8.)).child(div().w(px(width + 32.)).child(self.render_composer(&model, width + 32., window, cx))).into_any_element(),
        });
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            // The grants of this conversation: what the assistant may do without asking, until when, and a way to take it back.
            .when(full || !grants.is_empty(), |d| {
                d.child(
                    div()
                        .flex()
                        .flex_none()
                        .items_center()
                        .gap(px(8.))
                        .px(px(16.))
                        .py(px(6.))
                        .border_b_1()
                        .border_color(Theme::line())
                        .bg(Theme::bg_sunken())
                        .text_size(text_px(12.))
                        .child(ui::icon("info", 13., if full { Theme::danger() } else { Theme::warning() }))
                        .child(div().flex_1().min_w_0().truncate().text_color(Theme::text_secondary()).child(if full { t("完全授权：这次对话里助手的操作不再询问").to_string() } else { tf!("限时授权：{}", "Grants: {}", grants.join("；")) }))
                        .child(ui::secondary_button("grants-revoke", t("撤销")).h(text_px(24.)).on_click(self.on(Cmd::RevokeGrants, cx))),
                )
            })
            .child(div().relative().flex().flex_col().flex_1().min_h_0().child(body).children(composer))
    }

    /// The assistant before anything is said: what it can be asked to do.
    fn render_start(&self, cx: &mut Context<Self>) -> AnyElement {
        let empty = self.view.hosts.is_empty();
        let ideas: Vec<(&str, &str, Cmd)> = if empty {
            vec![("library", "先添加服务器", Cmd::SetPage(Page::Servers))]
        } else {
            vec![
                ("scan-text", "巡检全部服务器，告诉我哪些需要处理", Cmd::Suggest("/inspect all".into())),
                ("search", "哪台服务器磁盘快满了？是什么占的？", Cmd::Suggest("哪台服务器的磁盘快满了？先巡检，再对最紧张的那台做磁盘诊断，告诉我是什么占用的、哪些可以清理。".into())),
                ("eye", "排查有没有被攻击的迹象", Cmd::Suggest("/security all".into())),
                ("history", "最近 24 小时在这些服务器上做过什么", Cmd::Suggest("/history all".into())),
                ("pen-line", "在某台服务器上执行命令…", Cmd::Draft("在 <服务器> 上执行：".into())),
            ]
        };
        ui::empty_state("sparkle", t("让助手照看服务器"), t("助手通过和你一样的工具工作：只读的巡检和诊断直接执行；变更、sudo 和破坏性操作按每台服务器的权限裁决，需要时在这里等你批准。密码只交给 SSH，助手看不到。"))
            .id("chat-empty")
            .w_full()
            .min_h_0()
            .overflow_y_scroll()
            .children(ideas.into_iter().enumerate().map(|(n, (icon, text, cmd))| ui::secondary_button(("suggest", n), "").w_full().max_w(px(380.)).h_auto().min_h(text_px(34.)).py(px(7.)).justify_start().child(ui::icon(icon, 14., Theme::accent())).child(div().flex_1().min_w_0().child(t(text).to_string())).on_click(self.on(cmd, cx))))
            .into_any_element()
    }

    fn render_messages(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let chat = &self.chat;
        let mut items: Vec<AnyElement> = vec![];
        let mut i = 0;
        while i < chat.messages.len() {
            let content = match &chat.messages[i] {
                ChatItem::User { text, .. } => {
                    items.push(div().flex().flex_col().items_end().child(div().max_w(relative(0.88)).px(px(14.)).py(px(9.)).rounded(px(16.)).bg(Theme::groove()).line_height(theme::body_line(21.)).child(text.clone())).into_any_element());
                    i += 1;
                    continue;
                }
                // What the assistant did between two pieces of its answer: one line for the run of calls, the calls themselves on request.
                ChatItem::Tool { .. } => {
                    let first = i;
                    while matches!(chat.messages.get(i), Some(ChatItem::Tool { .. })) { i += 1 }
                    items.push(self.render_tools(first, i, cx));
                    continue;
                }
                ChatItem::Answer(text) => text,
            };
            // The last piece, still without text: the model is reading or thinking.
            if content.is_empty() {
                items.push(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .h(text_px(22.))
                        .text_color(Theme::text_tertiary())
                        .child(ui::spinner("thinking", 14., Theme::accent()))
                        .child(if chat.steps > 1 { t("正在看结果…") } else { t("正在思考…") })
                        .child(div().text_size(text_px(12.)).text_color(Theme::text_placeholder()).child(elapsed(chat)))
                        .into_any_element(),
                );
                i += 1;
                continue;
            }
            // Under the last piece of a finished answer: a button that copies the whole of it, pieces between tool calls included.
            let last = i + 1 == chat.messages.len();
            let whole = ((last && !chat.busy) || matches!(chat.messages.get(i + 1), Some(ChatItem::User { .. }))).then(|| {
                let from = chat.messages[..i].iter().rposition(|item| matches!(item, ChatItem::User { .. })).map_or(0, |at| at + 1);
                chat.messages[from..=i].iter().filter_map(|item| if let ChatItem::Answer(text) = item { Some(text.as_str()) } else { None }).collect::<Vec<_>>().join("\n\n")
            });
            items.push(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(crate::markdown::render(&format!("answer-{i}"), content, None))
                    .when_some(whole, |d, whole| d.child(div().flex().child(ui::ghost_button(("copy", i), Some("copy"), None).h(text_px(24.)).min_w(px(24.)).opacity(0.7).tooltip(ui::tip(t("复制回答"))).on_click(self.on(Cmd::CopyText(whole), cx)))))
                    .into_any_element(),
            );
            i += 1;
        }
        // Text has arrived and more is on its way (a tool call being written, the next piece): the mark keeps turning under it.
        if chat.busy && chat.pending.is_none() && matches!(chat.messages.last(), Some(ChatItem::Answer(text)) if !text.is_empty()) {
            items.push(div().flex().items_center().gap(px(8.)).h(text_px(18.)).child(ui::spinner("working", 13., Theme::accent())).child(div().text_size(text_px(12.)).text_color(Theme::text_placeholder()).child(elapsed(chat))).into_any_element());
        }
        if let Some(pending) = &chat.pending { items.push(self.render_consent(pending, cx)) }
        if !chat.note.is_empty() { items.push(div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(chat.note.clone()).into_any_element()) }
        if !chat.error.is_empty() { items.push(ui::error_line(&chat.error).into_any_element()) }
        items
    }

    /// The card that asks: which hosts, which capabilities, the exact command, and why the model wants it.
    fn render_consent(&self, pending: &PendingTools, cx: &mut Context<Self>) -> AnyElement {
        let button = |name: &'static str, label: &'static str, consent: Consent, this: &Self, cx: &mut Context<Self>| {
            let shell = if consent == Consent::Once { ui::primary_button(name, label) } else { ui::secondary_button(name, label) };
            shell.h(text_px(28.)).on_click(this.on(Cmd::AnswerTools(consent), cx))
        };
        let asks: Vec<&tools::Ask> = pending.calls.iter().filter_map(|call| if let Gate::Ask(_, ask) = &call.gate { Some(ask) } else { None }).collect();
        // A grant never covers a destructive command: that is named each time.
        let grantable = asks.iter().all(|ask| ask.grantable);
        let minutes = self.fleet.grant_minutes();
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .p(px(12.))
            .rounded(px(12.))
            .border_1()
            .border_color(Theme::warning())
            .bg(Theme::bg_sunken())
            .child(div().flex().items_center().gap(px(6.)).font_weight(FontWeight::MEDIUM).child(ui::icon("info", 14., Theme::warning())).child(t("助手想执行下面的操作，等你批准")))
            .children(asks.iter().enumerate().map(|(n, ask)| {
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(6.))
                            .children(ask.needs.iter().map(|need| ui::status_chip(need, t(tools::capability_label(need)))))
                            .child(div().min_w_0().text_size(text_px(12.)).text_color(Theme::text_secondary()).child(tf!("在 {}", "on {}", ask.hosts_line()))),
                    )
                    .child(div().id(("consent-command", n)).max_h(px(220.)).overflow_y_scroll().px(px(10.)).py(px(8.)).rounded(px(8.)).bg(Theme::bg_body()).border_1().border_color(Theme::line()).font_family(theme::MONO_FONT).text_size(text_px(12.)).line_height(text_px(18.)).child(ask.command.clone()))
                    .when(!ask.reason.is_empty(), |d| d.child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_secondary()).child(tf!("目的：{}", "Purpose: {}", ask.reason))))
                    .when(!ask.risks.is_empty(), |d| d.child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::warning()).child(tf!("风险：{}", "Risk: {}", ask.risks.join("；")))))
            }))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap(px(8.))
                    .child(button("consent-once", t("允许这一次"), Consent::Once, self, cx))
                    .when(grantable, |d| d.child(button("consent-grant", if crate::i18n::is_english() { "Allow for a while" } else { "限时允许同类操作" }, Consent::Grant, self, cx).tooltip(ui::tip(tf!("允许这一次，并在接下来 {minutes} 分钟内，对这些服务器上同样级别的操作不再询问（仅这次对话）。", "Allow this once, and for the next {minutes} minutes do not ask again about operations of the same level on these servers (this conversation only).")))))
                    .child(ui::secondary_button("consent-full", t("完全授权")).h(text_px(28.)).on_click(self.on(Cmd::AskFullPermission, cx)).tooltip(ui::tip(t("允许这一次，并且这次对话里不再询问任何操作，包括破坏性操作；会先提醒你确认。"))))
                    .child(button("consent-deny", t("不允许"), Consent::Deny, self, cx)),
            )
            .into_any_element()
    }

    /// A run of tool calls: those done as one line that unfolds, those
    /// still running each with a turning mark.
    fn render_tools(&self, first: usize, end: usize, cx: &mut Context<Self>) -> AnyElement {
        let chat = &self.chat;
        let run: Vec<(usize, &str, &Option<(String, bool)>)> = (first..end).filter_map(|at| if let ChatItem::Tool { call, result, .. } = &chat.messages[at] { Some((at, call.as_str(), result)) } else { None }).collect();
        let done: Vec<(usize, &str, &(String, bool))> = run.iter().filter_map(|(at, call, result)| result.as_ref().map(|result| (*at, *call, result))).collect();
        let failed = done.iter().filter(|(_, _, (_, failed))| *failed).count();
        let open = chat.tools_open.contains(&first);
        let waiting = chat.pending.is_some();
        div()
            .flex()
            .flex_col()
            .gap(px(4.))
            .text_size(text_px(12.))
            .when(!done.is_empty(), |d| {
                d.child(
                    div()
                        .id(("tools", first))
                        .flex()
                        .items_center()
                        .gap(px(4.))
                        .h(text_px(22.))
                        .cursor_pointer()
                        .text_color(Theme::text_tertiary())
                        .hover(|s| s.text_color(Theme::text_secondary()))
                        .on_click(self.on(Cmd::ToggleTools(first), cx))
                        .child(div().min_w_0().truncate().child(tools_summary(&done.iter().map(|(_, call, _)| *call).collect::<Vec<_>>())))
                        .when(failed > 0, |d| d.child(div().flex_none().text_color(Theme::danger()).child(tf!("· {failed} 项没有成功", "· {failed} failed"))))
                        .child(ui::icon(if open { "chevron-down" } else { "chevron-right" }, 12., Theme::text_tertiary())),
                )
                .when(open, |d| {
                    d.child(div().flex().flex_col().gap(px(3.)).pl(px(10.)).ml(px(3.)).border_l_1().border_color(Theme::line()).children(done.iter().map(|(at, call, (outcome, failed))| {
                        div()
                            .id(("tool-line", *at))
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .h(text_px(20.))
                            .cursor_pointer()
                            .hover(|s| s.bg(Theme::hover()))
                            .tooltip(ui::tip(t("查看返回的全部内容")))
                            .on_click(self.on(Cmd::ShowOutput(*at), cx))
                            .child(div().flex_none().max_w(relative(0.62)).truncate().text_color(Theme::text_secondary()).child(call.to_string()))
                            .child(div().min_w_0().truncate().text_color(if *failed { Theme::danger() } else { Theme::text_tertiary() }).child(outcome.clone()))
                    })))
                })
            })
            // The calls still running; those waiting for consent are named on the card that asks for it.
            .children(run.iter().filter(|(_, _, result)| result.is_none() && !waiting).map(|(at, call, _)| {
                div().flex().items_center().gap(px(8.)).h(text_px(22.)).text_color(Theme::text_secondary()).child(ui::spinner(("tool", *at), 13., Theme::accent())).child(div().min_w_0().truncate().child(call.to_string())).child(div().flex_none().text_color(Theme::text_placeholder()).child(elapsed(chat)))
            }))
            .into_any_element()
    }

    /// A kept conversation in the list: its title, when and how often it was asked, and a way to delete it
    /// under the pointer. The open one is lit.
    pub fn conversation_row(&self, info: &ChatInfo, cx: &mut Context<Self>) -> Stateful<Div> {
        let current = info.id == self.chat.id;
        div()
            .id(SharedString::from(format!("conversation-{}", info.id)))
            .group("conversation")
            .flex()
            .items_center()
            .gap(px(8.))
            .px(px(10.))
            .py(px(8.))
            .rounded(px(8.))
            .cursor_pointer()
            .when(current, |d| d.bg(Theme::pressed()))
            .hover(|s| s.bg(Theme::hover()))
            .on_click(self.on(Cmd::OpenChat(info.id.clone()), cx))
            .child(div().flex().flex_col().flex_1().min_w_0().child(div().truncate().when(current, |d| d.font_weight(FontWeight::MEDIUM)).child(info.title.clone())).child(div().text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(tf!("{} · {} 次请求", "{} · {} requests", time::short_time(&info.updated_at), info.requests))))
            .child(ui::icon_action(SharedString::from(format!("conversation-delete-{}", info.id)), "bin", Theme::text_tertiary(), t("删除这次对话")).opacity(0.).group_hover("conversation", |s| s.opacity(1.)).on_click(self.on_within(Cmd::DeleteChat(info.id.clone()), cx)))
    }

    /// The box a request is written in, `width` wide with its margins.
    fn render_composer(&self, model: &str, width: f32, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let chat = &self.chat;
        let focused = chat.input.focus_handle(cx).is_focused(window);
        let commands = if focused { chat.slash_list(&self.settings.commands, cx) } else { vec![] };
        let ready = !chat.input.read(cx).text().trim().is_empty();
        let round = |id: &'static str, icon_name: &'static str, lit: bool| {
            div().id(id).flex().flex_none().items_center().justify_center().size(px(30.)).rounded(px(15.)).bg(if lit { Theme::accent() } else { Theme::groove() }).cursor_pointer().hover(|s| s.opacity(0.88)).child(ui::icon(icon_name, 15., if lit { Theme::on_accent() } else { Theme::text_tertiary() }))
        };
        div()
            .relative()
            .flex()
            .flex_col()
            .flex_none()
            .gap(px(5.))
            .px(px(16.))
            .pb(px(10.))
            .pt(px(6.))
            .when(!commands.is_empty(), |d| {
                d.child(
                    ui::popover()
                        .absolute()
                        .left(px(16.))
                        .right(px(16.))
                        .bottom_full()
                        .max_w(px(520.))
                        .children(commands.iter().enumerate().map(|(n, command)| {
                            div()
                                .id(SharedString::from(format!("slash-{}", command.name)))
                                .flex()
                                .items_center()
                                .gap(px(10.))
                                .h(text_px(32.))
                                .px(px(8.))
                                .rounded(px(6.))
                                .cursor_pointer()
                                .when(n == chat.slash, |d| d.bg(Theme::hover()))
                                .hover(|s| s.bg(Theme::hover()))
                                .on_click(self.on(Cmd::PickSlash(n), cx))
                                .child(div().flex_none().font_weight(FontWeight::MEDIUM).text_color(Theme::accent()).child(format!("/{}", command.name)))
                                .child(div().flex_1().min_w_0().truncate().text_color(Theme::text_secondary()).child(if command.custom { command.about.clone() } else { t(&command.about).to_string() }))
                                .when(command.custom, |d| d.child(div().flex_none().px(px(6.)).rounded(px(5.)).bg(Theme::groove()).text_size(text_px(11.)).text_color(Theme::text_tertiary()).child(t("自定义"))))
                        }))
                        .child(div().px(px(8.)).pt(px(5.)).pb(px(2.)).mt(px(3.)).border_t_1().border_color(Theme::line()).text_size(text_px(11.)).text_color(Theme::text_placeholder()).child(t("↑↓ 选择 · Enter 或 Tab 确认 · Esc 关闭"))),
                )
            })
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(6.))
                    .p(px(8.))
                    .pl(px(12.))
                    .rounded(px(16.))
                    .border_1()
                    .border_color(if focused { Theme::accent() } else { Theme::line_strong() })
                    .bg(Theme::bg_body())
                    .shadow(theme::shadow_card())
                    // A pixel width: a wrapping input under ancestors whose widths are all relative is measured too narrow.
                    .child(div().flex().w(px(width - 32. - 22. - 36.)).py(px(5.)).max_h(px(170.)).overflow_hidden().text_size(text_px(13.)).line_height(text_px(20.)).text_color(Theme::text()).child(chat.input.clone()))
                    .child(div().flex_1())
                    .child(if chat.busy { round("chat-stop", "square", true).on_click(self.on(Cmd::StopChat, cx)) } else { round("chat-send", "send", ready).on_click(self.on(Cmd::Ask, cx)) }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .px(px(4.))
                    .text_size(text_px(11.))
                    .text_color(Theme::text_placeholder())
                    .child(div().flex_1().min_w_0().truncate().child(t("Enter 发送，Shift+Enter 换行 · 执行前请核对命令")))
                    .child(div().id("chat-model").flex().flex_none().items_center().gap(px(3.)).max_w(relative(0.5)).cursor_pointer().hover(|s| s.text_color(Theme::text_secondary())).on_click(self.on_menu(MenuKind::Models, cx)).child(div().min_w_0().truncate().child(model.to_string())).child(ui::icon("chevron-down", 11., Theme::text_placeholder()))),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    // Not `super::*`: that would bring in gpui's own `test` attribute.
    use super::tools_summary;

    #[test]
    fn tool_runs_in_a_line() {
        assert_eq!(tools_summary(&["巡检：all", "批量命令：df -h", "巡检：@gpu"]), "巡检 ×2 · 批量命令");
    }
}
