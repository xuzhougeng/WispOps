//! The assistant's side of a conversation: the request for each protocol,
//! reading the streamed answer, slash commands and what a conversation
//! leaves behind. No HTTP here; `wisp_ops_net` sends the request.
//!
//! The model is given the fleet as instructions (the inventory summary, the
//! permission model) and works through the `ops_*` tools; a turn that ends
//! in tool calls is answered with their results and the conversation goes on.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// The Claude Messages API.
    #[default]
    Anthropic,
    /// Any service speaking OpenAI's chat completions.
    OpenAI,
    /// OpenAI's Responses API (`/responses`).
    Responses,
}

/// One model configuration from the settings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Profile {
    /// What the task bindings in the settings point at. Given once, when the
    /// profile is added or first read from an older settings file.
    pub id: String,
    pub name: String,
    /// The name of the provider it belongs to, for where it is listed.
    pub provider: String,
    pub protocol: Protocol,
    pub base_url: String,
    /// Empty means the environment variable `key_env`, else ANTHROPIC_API_KEY / OPENAI_API_KEY.
    pub api_key: String,
    /// The environment variable the provider's key is read from when none is stored.
    pub key_env: String,
    pub model: String,
    /// How hard this model thinks, a key of `EFFORTS`: empty leaves it to the
    /// service, `off` asks for no thinking, the rest are levels.
    pub effort: String,
    /// A proxy for this service alone: empty uses the global one, `direct` none at all.
    pub proxy: String,
}

/// The thinking settings a profile may have, and what they are called.
pub const EFFORTS: [(&str, &str); 7] = [("", "默认"), ("off", "关闭"), ("low", "低"), ("medium", "中"), ("high", "高"), ("xhigh", "极高"), ("max", "最高")];

pub const ANTHROPIC_BASE: &str = "https://api.anthropic.com";
pub const DEFAULT_MODEL: &str = "claude-opus-5-5";

impl Default for Profile {
    fn default() -> Self {
        Profile { id: String::new(), name: "Claude".into(), provider: String::new(), protocol: Protocol::Anthropic, base_url: ANTHROPIC_BASE.into(), api_key: String::new(), key_env: String::new(), model: DEFAULT_MODEL.into(), effort: String::new(), proxy: String::new() }
    }
}

impl Profile {
    /// What the profile is called where it is listed or credited: its name, else its model.
    pub fn title(&self) -> String {
        let name = if self.name.trim().is_empty() { self.model.trim() } else { self.name.trim() };
        if name.is_empty() { "未命名模型".into() } else { name.to_string() }
    }

    /// The model with its provider: `deepseek-v4-pro · DeepSeek`.
    pub fn labelled(&self) -> String {
        if self.provider.trim().is_empty() { self.title() } else { format!("{} · {}", self.title(), self.provider.trim()) }
    }

    /// What is still missing before a request can be made, if anything.
    pub fn missing(&self) -> Option<&'static str> {
        if self.key().is_empty() { Some("还缺 API Key") } else if self.model.trim().is_empty() { Some("还缺模型名称") } else { None }
    }

    /// The key to send: the stored one, else the protocol's environment variable.
    pub fn key(&self) -> String {
        if !self.api_key.trim().is_empty() { return self.api_key.trim().to_string() }
        if !self.key_env.trim().is_empty() { return std::env::var(self.key_env.trim()).unwrap_or_default() }
        std::env::var(match self.protocol {
            Protocol::Anthropic => "ANTHROPIC_API_KEY",
            Protocol::OpenAI | Protocol::Responses => "OPENAI_API_KEY",
        })
        .unwrap_or_default()
    }
}

/// Everything the model is given for one conversation besides what is said:
/// the instructions, and the documents (the fleet as it stood when the
/// conversation began), kept apart so the prefix stays cacheable.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Context {
    pub instructions: String,
    pub documents: String,
}

/// A tool as the model is told of it.
#[derive(Clone, Debug, PartialEq)]
pub struct Tool {
    pub name: String,
    pub description: String,
    /// JSON Schema of the arguments object.
    pub input_schema: Value,
}

// ---- requests

#[derive(Clone, Debug, PartialEq)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
    /// The profile's own proxy setting, for whoever sends the request.
    pub proxy: String,
}

/// Models whose safety classifiers can decline a request, and for which the
/// API can then rerun it on another model inside the same call.
const FALLBACK_MODELS: [&str; 5] = ["claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"];

/// Claude models that cannot stop thinking: a request that tries is refused,
/// so "off" becomes the lowest effort for them.
const ALWAYS_THINKING: [&str; 3] = ["claude-fable", "claude-mythos", "claude-opus-5-5"];

/// Put the profile's thinking setting into a request body. Nothing is sent
/// for the default, so a service that knows none of these parameters still
/// answers. The three protocols, and the services behind the OpenAI one,
/// each spell it their own way.
fn apply_effort(profile: &Profile, base: &str, body: &mut Value) {
    let (effort, model) = (profile.effort.trim(), profile.model.trim());
    if effort.is_empty() || !EFFORTS.iter().any(|(key, _)| *key == effort) { return }
    // Chat completions and Responses know three levels; the two above them are the highest of those.
    let level = if matches!(effort, "xhigh" | "max") { "high" } else { effort };
    match (profile.protocol, effort) {
        (Protocol::Anthropic, "off") => {
            if ALWAYS_THINKING.iter().any(|name| model.contains(name)) {
                body["output_config"] = json!({"effort": "low"});
            } else if model.contains("claude-sonnet-5-5") {
                // Its way of not thinking; it takes no other field beside it.
                body["thinking"] = json!({"type": "between_tools"});
            } else {
                body["thinking"] = json!({"type": "disabled"});
            }
        }
        (Protocol::Anthropic, _) => {
            body["thinking"] = json!({"type": "adaptive"});
            body["output_config"] = json!({"effort": effort});
        }
        (Protocol::OpenAI, "off") => {
            if base.contains("api.openai.com") {
                body["reasoning_effort"] = json!("none");
            } else if base.contains("dashscope") || base.contains("siliconflow") {
                body["enable_thinking"] = json!(false);
            } else {
                // DeepSeek, 火山方舟, 智谱 and Kimi turn thinking off this way.
                body["thinking"] = json!({"type": "disabled"});
            }
        }
        (Protocol::OpenAI, _) => body["reasoning_effort"] = json!(level),
        (Protocol::Responses, _) => body["reasoning"] = json!({"effort": if effort == "off" { "none" } else { level }}),
    }
}

/// A question as it goes on the wire; the same for every protocol.
pub fn user_message(text: &str) -> Value {
    json!({"role": "user", "content": text})
}

/// An answer already given, when a conversation is replayed to another protocol.
pub fn assistant_message(text: &str) -> Value {
    json!({"role": "assistant", "content": text})
}

/// The streaming request for one step of a conversation. `wire` is the
/// conversation so far in the profile's protocol: questions, the model's
/// turns exactly as it sent them, and tool results. It only ever grows, so
/// the prefix stays cacheable and the model's thinking blocks stay valid.
pub fn chat_request(profile: &Profile, ctx: &Context, wire: &[Value], tools: &[Tool]) -> Result<HttpRequest, String> {
    let tools: Vec<(&str, &str, &Value)> = tools.iter().map(|t| (t.name.as_str(), t.description.as_str(), &t.input_schema)).collect();
    let key = profile.key();
    if key.is_empty() { return Err("还没有配置 API Key。请在「设置 › 模型」里填写，或设置对应的环境变量。".into()) }
    if profile.model.trim().is_empty() { return Err("请在「设置 › 模型」里填写模型名称。".into()) }
    let base = profile.base_url.trim().trim_end_matches('/');
    if !base.starts_with("https://") && !base.starts_with("http://") { return Err("模型服务地址应以 https:// 或 http:// 开头。".into()) }
    match profile.protocol {
        Protocol::Anthropic => {
            let mut headers = vec![("x-api-key".to_string(), key), ("anthropic-version".to_string(), "2026-10-21".to_string()), ("content-type".to_string(), "application/json".to_string())];
            let mut body = json!({
                "model": profile.model.trim(),
                // Streaming, so a long answer has room; thinking is the model's default unless the profile says otherwise.
                "max_tokens": 64000,
                "stream": true,
                // The documents come last in the system prompt with a cache breakpoint: follow-up
                // questions in the same conversation read them from the cache.
                "system": [
                    {"type": "text", "text": ctx.instructions},
                    {"type": "text", "text": if ctx.documents.is_empty() { "（清单为空）" } else { ctx.documents.as_str() }, "cache_control": {"type": "ephemeral"}},
                ],
                "messages": wire,
            });
            if !tools.is_empty() {
                body["tools"] = tools.iter().map(|(name, description, schema)| json!({"name": name, "description": description, "input_schema": schema})).collect();
            }
            apply_effort(profile, base, &mut body);
            // Only on Anthropic's own API: the other platforms and proxies reject these parameters.
            if base == ANTHROPIC_BASE {
                // The steps of a tool loop resend the conversation; cache it up to the last block.
                body["cache_control"] = json!({"type": "ephemeral"});
                if FALLBACK_MODELS.contains(&profile.model.trim()) {
                    headers.push(("anthropic-beta".to_string(), "server-side-fallback-2026-07-01".to_string()));
                    body["fallbacks"] = json!("default");
                }
            }
            Ok(HttpRequest { url: format!("{base}/v1/messages"), headers, body, proxy: profile.proxy.trim().to_string() })
        }
        Protocol::OpenAI => {
            let mut all = vec![json!({"role": "system", "content": format!("{}\n\n{}", ctx.instructions, ctx.documents)})];
            all.extend(wire.iter().cloned());
            let mut body = json!({"model": profile.model.trim(), "stream": true, "messages": all});
            if !tools.is_empty() {
                body["tools"] = tools.iter().map(|(name, description, schema)| json!({"type": "function", "function": {"name": name, "description": description, "parameters": schema}})).collect();
            }
            apply_effort(profile, base, &mut body);
            Ok(HttpRequest { url: format!("{base}/chat/completions"), headers: vec![("authorization".to_string(), format!("Bearer {key}")), ("content-type".to_string(), "application/json".to_string())], body, proxy: profile.proxy.trim().to_string() })
        }
        Protocol::Responses => {
            let mut body = json!({
                "model": profile.model.trim(),
                "stream": true,
                "instructions": format!("{}\n\n{}", ctx.instructions, ctx.documents),
                "input": wire,
                // Nothing is kept on the service: the conversation is sent whole each time, and the
                // model's reasoning comes back encrypted so that it can be handed in again with it.
                "store": false,
                "include": ["reasoning.encrypted_content"],
            });
            if !tools.is_empty() {
                body["tools"] = tools.iter().map(|(name, description, schema)| json!({"type": "function", "name": name, "description": description, "parameters": schema})).collect();
            }
            apply_effort(profile, base, &mut body);
            Ok(HttpRequest { url: format!("{base}/responses"), headers: vec![("authorization".to_string(), format!("Bearer {key}")), ("content-type".to_string(), "application/json".to_string())], body, proxy: profile.proxy.trim().to_string() })
        }
    }
}

// ---- the streamed turn

/// A tool the model asked for.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// The arguments; `Err` when what the model sent is not a JSON object.
    pub args: Result<Value, String>,
}

/// One turn of the model, read to its end.
#[derive(Clone, Debug, PartialEq)]
pub struct Turn {
    /// The turn as it goes back on the wire; `Null` when the model sent
    /// nothing. One message for Claude and chat completions; for the
    /// Responses API an array of output items (see `wire`).
    pub message: Value,
    pub calls: Vec<ToolCall>,
    /// The protocol's stop reason; "end" when the stream gave none.
    pub stop: String,
}

impl Turn {
    /// What the turn adds to the conversation on the wire.
    pub fn wire(&self) -> Vec<Value> {
        match &self.message {
            Value::Null => vec![],
            Value::Array(items) => items.clone(),
            message => vec![message.clone()],
        }
    }

    /// Whether the calls may run: not when the turn was cut off or declined,
    /// since a call's arguments may then be half written.
    pub fn runnable(&self) -> bool {
        !matches!(self.stop.as_str(), "max_tokens" | "length" | "refusal" | "content_filter" | "model_context_window_exceeded")
    }
}

/// What the app hears from a request in flight.
#[derive(Clone, Debug, PartialEq)]
pub enum ChatEvent {
    /// More of the answer's text.
    Text(String),
    /// The service was busy or unreachable and is being asked again: which try this is, and why.
    Retrying(usize, String),
    Done(Turn),
    Error(String),
}

fn push_text(value: &mut Value, more: &str) {
    match value {
        Value::String(text) => text.push_str(more),
        other => *other = json!(more),
    }
}

/// Reads the server-sent events of one turn. Every protocol puts a complete
/// JSON object on every `data:` line.
pub struct TurnReader {
    protocol: Protocol,
    /// Anthropic: the content blocks as they arrive, by index, with the
    /// pieces of each tool call's JSON beside them.
    blocks: Vec<Value>,
    inputs: Vec<String>,
    /// OpenAI: the text, and (id, name, arguments) of each tool call.
    text: String,
    calls: Vec<(String, String, String)>,
    stop: String,
}

impl TurnReader {
    pub fn new(protocol: Protocol) -> TurnReader {
        TurnReader { protocol, blocks: vec![], inputs: vec![], text: String::new(), calls: vec![], stop: String::new() }
    }

    /// One line of the stream: the answer text it adds, if any. `Err` is an
    /// error the service reported inside the stream.
    pub fn line(&mut self, line: &str) -> Result<Option<String>, String> {
        let Some(data) = line.strip_prefix("data:").map(str::trim) else { return Ok(None) };
        if data.is_empty() || data == "[DONE]" { return Ok(None) }
        let Ok(value) = serde_json::from_str::<Value>(data) else { return Ok(None) };
        if let Some(message) = value["error"]["message"].as_str() { return Err(message.to_string()) }
        match self.protocol {
            Protocol::Anthropic => {
                let index = value["index"].as_u64().unwrap_or(0) as usize;
                match value["type"].as_str() {
                    Some("content_block_start") => {
                        while self.blocks.len() <= index {
                            self.blocks.push(Value::Null);
                            self.inputs.push(String::new());
                        }
                        self.blocks[index] = value["content_block"].clone();
                    }
                    Some("content_block_delta") if index < self.blocks.len() => {
                        let delta = &value["delta"];
                        match delta["type"].as_str() {
                            Some("text_delta") => {
                                let text = delta["text"].as_str().unwrap_or("");
                                push_text(&mut self.blocks[index]["text"], text);
                                if !text.is_empty() { return Ok(Some(text.to_string())) }
                            }
                            Some("input_json_delta") => self.inputs[index].push_str(delta["partial_json"].as_str().unwrap_or("")),
                            // Thinking goes back to the model unchanged with the next step, signature included.
                            Some("thinking_delta") => push_text(&mut self.blocks[index]["thinking"], delta["thinking"].as_str().unwrap_or("")),
                            Some("signature_delta") => self.blocks[index]["signature"] = delta["signature"].clone(),
                            _ => {}
                        }
                    }
                    Some("message_delta") => {
                        if let Some(reason) = value["delta"]["stop_reason"].as_str() { self.stop = reason.to_string() }
                    }
                    _ => {}
                }
            }
            Protocol::Responses => match value["type"].as_str() {
                Some("response.output_text.delta") => {
                    if let Some(text) = value["delta"].as_str() && !text.is_empty() { return Ok(Some(text.to_string())) }
                }
                // Each finished item whole: a message, a function call with its arguments, a reasoning item.
                Some("response.output_item.done") => {
                    let index = value["output_index"].as_u64().unwrap_or(self.blocks.len() as u64) as usize;
                    while self.blocks.len() <= index { self.blocks.push(Value::Null) }
                    self.blocks[index] = value["item"].clone();
                }
                Some("response.completed") => self.stop = "stop".into(),
                Some("response.incomplete") => {
                    self.stop = match value["response"]["incomplete_details"]["reason"].as_str() {
                        Some("content_filter") => "content_filter",
                        _ => "length",
                    }
                    .into();
                }
                Some("response.failed") => return Err(value["response"]["error"]["message"].as_str().unwrap_or("模型服务没有完成这次回答。").to_string()),
                Some("error") => return Err(value["message"].as_str().unwrap_or("模型服务返回了错误。").to_string()),
                _ => {}
            },
            Protocol::OpenAI => {
                let choice = &value["choices"][0];
                if let Some(reason) = choice["finish_reason"].as_str() { self.stop = reason.to_string() }
                for call in choice["delta"]["tool_calls"].as_array().into_iter().flatten() {
                    let index = call["index"].as_u64().unwrap_or(self.calls.len().saturating_sub(1) as u64) as usize;
                    while self.calls.len() <= index { self.calls.push(Default::default()) }
                    let (id, name, arguments) = &mut self.calls[index];
                    if let Some(value) = call["id"].as_str() && !value.is_empty() { *id = value.to_string() }
                    name.push_str(call["function"]["name"].as_str().unwrap_or(""));
                    arguments.push_str(call["function"]["arguments"].as_str().unwrap_or(""));
                }
                if let Some(text) = choice["delta"]["content"].as_str() && !text.is_empty() {
                    self.text.push_str(text);
                    return Ok(Some(text.to_string()));
                }
            }
        }
        Ok(None)
    }

    /// The turn, once the stream has ended.
    pub fn finish(self) -> Turn {
        let parse = |raw: &str| -> Result<Value, String> {
            if raw.trim().is_empty() { return Ok(json!({})) }
            match serde_json::from_str::<Value>(raw) {
                Ok(value) if value.is_object() => Ok(value),
                Ok(_) => Err("工具参数应为一个 JSON 对象。".into()),
                Err(err) => Err(format!("工具参数不是有效的 JSON：{err}")),
            }
        };
        let stop = if self.stop.is_empty() { "end".to_string() } else { self.stop };
        let mut calls = vec![];
        match self.protocol {
            Protocol::Anthropic => {
                // When another model took over mid-answer, what the first one thought and
                // called before the `fallback` block is not sent back, and its calls do not run.
                let boundary = self.blocks.iter().rposition(|b| b["type"] == "fallback").unwrap_or(0);
                let mut kept = vec![];
                for (index, mut block) in self.blocks.into_iter().enumerate() {
                    let kind = block["type"].as_str().unwrap_or("").to_string();
                    if index < boundary && matches!(kind.as_str(), "thinking" | "redacted_thinking" | "tool_use") { continue }
                    match kind.as_str() {
                        "tool_use" => {
                            let args = parse(&self.inputs[index]);
                            block["input"] = args.clone().unwrap_or_else(|_| json!({}));
                            calls.push(ToolCall { id: block["id"].as_str().unwrap_or("").to_string(), name: block["name"].as_str().unwrap_or("").to_string(), args });
                        }
                        // The API rejects an empty text block when it is sent back.
                        "text" if block["text"].as_str().unwrap_or("").is_empty() => continue,
                        "" => continue,
                        _ => {}
                    }
                    kept.push(block);
                }
                let message = if kept.is_empty() { Value::Null } else { json!({"role": "assistant", "content": kept}) };
                Turn { message, calls, stop }
            }
            Protocol::Responses => {
                // The output items go back as they came, reasoning included: the service
                // wants a function call handed in again together with the reasoning before it.
                let items: Vec<Value> = self.blocks.into_iter().filter(|item| !item.is_null()).collect();
                for item in items.iter().filter(|item| item["type"] == "function_call") {
                    calls.push(ToolCall { id: item["call_id"].as_str().unwrap_or("").to_string(), name: item["name"].as_str().unwrap_or("").to_string(), args: parse(item["arguments"].as_str().unwrap_or("")) });
                }
                // The stream names no reason for stopping to call tools; the calls themselves say it.
                let stop = if stop == "stop" && !calls.is_empty() { "tool_calls".to_string() } else { stop };
                Turn { message: if items.is_empty() { Value::Null } else { Value::Array(items) }, calls, stop }
            }
            Protocol::OpenAI => {
                let mut wire_calls = vec![];
                for (n, (id, name, arguments)) in self.calls.into_iter().enumerate() {
                    if name.is_empty() { continue }
                    // Some compatible servers leave the id out.
                    let id = if id.is_empty() { format!("call_{n}") } else { id };
                    let args = parse(&arguments);
                    wire_calls.push(json!({"id": id, "type": "function", "function": {"name": name, "arguments": if args.is_ok() && !arguments.trim().is_empty() { arguments } else { "{}".to_string() }}}));
                    calls.push(ToolCall { id, name, args });
                }
                let message = if self.text.is_empty() && wire_calls.is_empty() {
                    Value::Null
                } else {
                    let mut message = json!({"role": "assistant", "content": if self.text.is_empty() { Value::Null } else { json!(self.text) }});
                    if !wire_calls.is_empty() { message["tool_calls"] = json!(wire_calls) }
                    message
                };
                Turn { message, calls, stop }
            }
        }
    }
}

/// The messages that answer a turn's tool calls: (call id, output, failed).
/// Anthropic takes every result of a turn in one user message.
pub fn tool_results(protocol: Protocol, results: &[(String, String, bool)]) -> Vec<Value> {
    match protocol {
        Protocol::Anthropic => vec![json!({"role": "user", "content": results.iter().map(|(id, output, failed)| json!({"type": "tool_result", "tool_use_id": id, "content": output, "is_error": failed})).collect::<Vec<_>>()})],
        Protocol::OpenAI => results.iter().map(|(id, output, _)| json!({"role": "tool", "tool_call_id": id, "content": output})).collect(),
        Protocol::Responses => results.iter().map(|(id, output, _)| json!({"type": "function_call_output", "call_id": id, "output": output})).collect(),
    }
}

/// Add a word from the app to the tool results that are about to go back,
/// without a turn of its own: for Claude a text block after the results in
/// the same message, for the other two a message after them.
pub fn with_note(protocol: Protocol, mut messages: Vec<Value>, note: &str) -> Vec<Value> {
    // `get_mut`, not an index: indexing would give a message without content (a Responses tool result) an empty one.
    match messages.last_mut().and_then(|last| last.get_mut("content")).and_then(Value::as_array_mut).filter(|_| protocol == Protocol::Anthropic) {
        Some(blocks) => blocks.push(json!({"type": "text", "text": note})),
        None => messages.push(user_message(note)),
    }
    messages
}

/// What the model is told with the results before the last step it gets for a question.
pub const LAST_STEP_NOTE: &str = "（系统提示）这次请求的步数快用完了：下一步请根据已经查到的内容直接回答，不要再调用工具。还没做完的部分在回答里说明，用户可以接着问。";

// ---- slash commands

/// A command typed at the start of a message.
pub struct Slash {
    /// What follows the slash.
    pub name: &'static str,
    pub about: &'static str,
    /// What to write after the name; empty when the command stands alone.
    pub hint: &'static str,
    /// The request it stands for (`{}` is what follows the name); empty for
    /// a command the window carries out itself.
    pub template: &'static str,
    /// What the command works on when nothing follows its name; empty when something must.
    pub alone: &'static str,
}

pub const SLASH: [Slash; 6] = [
    Slash {
        name: "inspect",
        about: "巡检服务器并汇报",
        hint: "选择器，如 all、@gpu、web-01；不写就是全部",
        template: "巡检这些服务器：{}\n\n调用 ops_inspect。先给一行总体状态（正常 / 警告 / 严重 / 不可达各几台），再按严重程度列出每台有问题的服务器和证据，与上次巡检相比的变化单独说明。最后给建议：哪些只需继续观察，哪些值得用只读工具进一步诊断，哪些需要变更（变更只提方案，不要执行）。",
        alone: "all",
    },
    Slash {
        name: "disk",
        about: "诊断一台服务器的磁盘占用",
        hint: "服务器名和路径，如 gpu-01 /data",
        template: "诊断这台服务器的磁盘：{}\n\n先读 wisp-disk-full 技能（如果有），调用 ops_disk（没写路径就诊断 /）。说明空间被什么占用、哪些正在被进程或作业使用不能动、哪些可以回收以及能回收多少。给出按回收量排序的清理方案，每一步写明命令、风险级别和先要做的检查；不要自行执行清理。",
        alone: "",
    },
    Slash {
        name: "security",
        about: "排查是否存在网络攻击",
        hint: "选择器；不写就是全部",
        template: "对这些服务器做安全排查：{}\n\n先读 wisp-security-triage 技能（如果有），调用 ops_security。把发现分成噪声、可疑、疑似失陷三类，每条给出证据；需要进一步确认的，写出要跑的只读命令。处置（封 IP、结束进程、改配置）只提方案，先保全证据，不要自行执行。",
        alone: "all",
    },
    Slash {
        name: "files",
        about: "分析近期新增的文件",
        hint: "服务器名和目录，如 nas-01 /data,/home",
        template: "分析这台服务器近期新增的文件：{}\n\n调用 ops_files（默认最近 7 天）。说明新增了多少、落在哪些目录、属于谁、是什么类型的数据，哪些是可再生的中间文件或被取代的冗余文件，并给出带前置检查的清理计划。不要删除任何东西。",
        alone: "",
    },
    Slash {
        name: "history",
        about: "查看最近的操作审计",
        hint: "选择器；不写就是全部",
        template: "列出这些服务器最近 24 小时的操作审计：{}\n\n调用 ops_history kind=operations sinceHours=24。按时间列出非只读的操作（风险、是否 sudo、授权方式、结果），只读采集只给出次数。有失败或被拒绝的操作时单独指出。",
        alone: "all",
    },
    Slash { name: "new", about: "开始一次新对话", hint: "", template: "", alone: "" },
];

/// A command the person wrote: a name and the request it stands for, kept
/// in `Settings::commands`. It is a prompt template and nothing more: it
/// runs nothing and reaches nothing a typed question could not.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Command {
    /// What follows the slash: letters, digits, `-` and `_`, in lower case.
    pub name: String,
    pub about: String,
    /// The request. `{}` is where what follows the name goes, and then
    /// something must follow; without it, what follows is added at the end.
    pub template: String,
}

impl Command {
    /// The request this command stands for with `argument` after its name.
    fn expand(&self, argument: &str) -> Result<String, String> {
        let (name, template) = (&self.name, self.template.trim());
        if template.is_empty() { return Err(format!("/{name} 还没有写模板。在设置文件的 commands 里补上。")) }
        match (template.contains("{}"), argument.is_empty()) {
            (true, true) => Err(format!("/{name} 后面写上内容：模板里的 {{}} 会换成它。")),
            (true, false) => Ok(template.replace("{}", argument)),
            (false, true) => Ok(template.to_string()),
            (false, false) => Ok(format!("{template}\n\n{argument}")),
        }
    }
}

/// What is wrong with a name for a command of one's own, if anything.
/// `others` are the names of the person's other commands.
pub fn command_name_problem<'a>(name: &str, mut others: impl Iterator<Item = &'a str>) -> Option<String> {
    if name.is_empty() { return Some("命令要有名称。".into()) }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') { return Some("名称只能用字母、数字、汉字、- 和 _，不能有空格。".into()) }
    if name.chars().count() > 32 { return Some("名称最多 32 个字。".into()) }
    if name.chars().any(char::is_uppercase) { return Some("名称里的字母用小写。".into()) }
    if SLASH.iter().any(|command| command.name == name) { return Some(format!("/{name} 是内置命令，换一个名称。")) }
    if others.any(|other| other == name) { return Some(format!("已经有一个 /{name} 了。")) }
    None
}

/// What a typed message asks for.
#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    /// A request for the model: the message itself, or what a slash command stands for.
    Ask(String),
    /// `/new`: leave this conversation and start another.
    NewChat,
}

/// Read a typed message; `custom` are the person's own commands, which a
/// built-in one of the same name comes before. The error is a sentence for
/// the person: an unknown command, or one that is missing what it works on.
pub fn read_input(input: &str, custom: &[Command]) -> Result<Input, String> {
    let input = input.trim();
    let Some(rest) = input.strip_prefix('/') else { return Ok(Input::Ask(input.to_string())) };
    let (name, argument) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    let Some(command) = SLASH.iter().find(|command| command.name == name) else {
        if let Some(command) = custom.iter().find(|command| command.name == name) { return command.expand(argument.trim()).map(Input::Ask) }
        let known = SLASH.iter().map(|command| (command.name, command.about)).chain(custom.iter().map(|command| (command.name.as_str(), command.about.as_str())));
        return Err(format!("没有 /{name} 这个命令。可用：{}", known.map(|(name, about)| if about.is_empty() { format!("/{name}") } else { format!("/{name}（{about}）") }).collect::<Vec<_>>().join("、")));
    };
    if command.template.is_empty() { return Ok(Input::NewChat) }
    let argument = if argument.trim().is_empty() { command.alone } else { argument.trim() };
    if argument.is_empty() { return Err(format!("/{name} 后面写上内容：{}。", command.about)) }
    Ok(Input::Ask(command.template.replace("{}", argument)))
}

/// A command on offer over the box.
#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
    pub name: String,
    pub about: String,
    /// What to write after the name.
    pub hint: String,
    /// One of the person's own.
    pub custom: bool,
    /// Taking it carries it out at once (`/new`); the others are written out for the person to go on.
    pub runs: bool,
}

/// The commands to offer while a message is still the beginning of one: a
/// slash and perhaps part of a name, nothing after it. Those whose name
/// starts with what was typed come first, then those described by it
/// (`/引` finds 「配引用」); the built-in ones before the person's own.
pub fn slash_matches(input: &str, custom: &[Command]) -> Vec<Offer> {
    let Some(typed) = input.strip_prefix('/') else { return vec![] };
    if typed.chars().any(char::is_whitespace) { return vec![] }
    let typed = typed.to_lowercase();
    let builtin = SLASH.iter().map(|command| Offer { name: command.name.into(), about: command.about.into(), hint: command.hint.into(), custom: false, runs: command.template.is_empty() });
    // One that a built-in command hides, or that has no name yet, cannot be called.
    let own = custom.iter().filter(|command| command_name_problem(&command.name, std::iter::empty()).is_none()).map(|command| Offer {
        name: command.name.clone(),
        about: command.about.clone(),
        hint: if command.template.contains("{}") { "要处理的内容" } else { "可以接着补充" }.into(),
        custom: true,
        runs: false,
    });
    let all: Vec<Offer> = builtin.chain(own).collect();
    let (mut found, rest): (Vec<Offer>, Vec<Offer>) = all.into_iter().partition(|offer| offer.name.starts_with(&typed));
    if !typed.is_empty() { found.extend(rest.into_iter().filter(|offer| offer.about.to_lowercase().contains(&typed))) }
    found
}

// ---- what a conversation leaves behind

/// One thing said in a conversation, as it is kept on disk.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Said {
    /// A request as typed, and what went to the model where that is not the
    /// text: what a slash command stood for when it was sent.
    User {
        text: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prompt: String,
    },
    Answer { text: String },
    /// A tool the assistant called, as the window described it, and what came back.
    Tool {
        call: String,
        #[serde(default)]
        result: String,
        #[serde(default)]
        failed: bool,
        /// What the tool returned in full, for the person to unfold; not sent again.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        output: String,
    },
}

/// A conversation as it is kept: what was said. What the model read through
/// its tools is not replayed: a conversation taken up again starts from the text.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Transcript {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub items: Vec<Said>,
}

impl Transcript {
    /// What the conversation is listed as: the start of its first request.
    pub fn title(&self) -> String {
        let first = self.items.iter().find_map(|item| match item {
            Said::User { text, .. } => Some(text.split_whitespace().collect::<Vec<_>>().join(" ")),
            _ => None,
        });
        match first {
            Some(text) if !text.is_empty() => {
                if text.chars().count() > 48 { format!("{}…", text.chars().take(48).collect::<String>()) } else { text }
            }
            _ => "未命名对话".into(),
        }
    }
}

// ---- one-off requests

/// A single question with its own instructions and no tools.
pub fn plain_request(profile: &Profile, system: &str, prompt: &str) -> Result<HttpRequest, String> {
    let mut request = chat_request(profile, &Context { instructions: system.into(), ..Default::default() }, &[user_message(prompt)], &[])?;
    match profile.protocol {
        // No documents to cache, and an empty text block would be refused.
        Protocol::Anthropic => {
            request.body["system"] = json!(system);
            if let Some(body) = request.body.as_object_mut() { body.remove("cache_control"); }
        }
        Protocol::OpenAI => request.body["messages"][0]["content"] = json!(system),
        Protocol::Responses => request.body["instructions"] = json!(system),
    }
    Ok(request)
}


/// What to tell the reader when a turn did not end normally.
pub fn stop_note(reason: &str) -> Option<&'static str> {
    match reason {
        "refusal" | "content_filter" => Some("模型拒绝回答这个问题。"),
        "max_tokens" | "length" => Some("回答达到长度上限，被截断了。"),
        "model_context_window_exceeded" => Some("材料超出了模型的上下文长度，回答可能不完整。请缩小提问范围。"),
        _ => None,
    }
}

/// The message inside an error response body; the body itself when it is not JSON.
pub fn error_message(status: u16, body: &str) -> String {
    // `error.message` is what most services say; `detail` (a sentence, or a list of what is wrong with which field) is TypeSafe's.
    let detail = serde_json::from_str::<Value>(body).ok().and_then(|v| v["error"]["message"].as_str().or(v["message"].as_str()).or(v["detail"].as_str()).or(v["detail"][0]["msg"].as_str()).map(String::from)).unwrap_or_else(|| body.chars().take(300).collect());
    let hint = match status {
        401 | 403 => "API Key 无效或没有权限",
        404 => "地址或模型名称不存在",
        429 => "请求过于频繁或额度不足",
        500..=599 => "模型服务暂时不可用",
        _ => "请求被拒绝",
    };
    format!("{hint}（HTTP {status}）：{}", detail.trim())
}

