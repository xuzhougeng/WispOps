//! The network: the streamed chat request to a model service. Everything
//! here blocks, so the app runs it on the background executor.

use std::io::{BufRead, BufReader};
use std::time::Duration;
use wisp_ops_core::ai::{self, ChatEvent, HttpRequest, Protocol, TurnReader};

pub mod fetch;
/// Webhook posts for the outgoing notifications.
pub mod webhook;

const USER_AGENT: &str = concat!("WispOps/", env!("CARGO_PKG_VERSION"));

/// The proxy every request of this process goes through, from the settings.
static PROXY: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

/// Set the global proxy (`http://…`, `socks5://…`); empty leaves the choice
/// to the environment (`ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`).
pub fn set_proxy(address: &str) {
    *PROXY.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = address.trim().to_string();
}

/// Which proxy a request takes. `own` is the setting of whoever asks (a
/// model profile): an address of its own, `direct` for none at all, or empty
/// for the global one, which when empty too is the environment's.
fn proxy_for(own: &str) -> Result<Option<ureq::Proxy>, String> {
    let own = own.trim();
    if own.eq_ignore_ascii_case("direct") { return Ok(None) }
    let global = PROXY.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
    let address = if own.is_empty() { global.as_str() } else { own };
    if address.is_empty() { return Ok(ureq::Proxy::try_from_env()) }
    ureq::Proxy::new(address).map(Some).map_err(|err| format!("代理地址 {address} 无法使用：{err}"))
}

fn agent(overall: Option<Duration>, proxy: &str) -> Result<ureq::Agent, String> {
    patient_agent(overall, proxy, Duration::from_secs(120))
}

/// An agent that waits `answer` for a response to begin.
fn patient_agent(overall: Option<Duration>, proxy: &str, answer: Duration) -> Result<ureq::Agent, String> {
    Ok(ureq::Agent::config_builder()
        // Error responses carry the reason in their body; read it rather than a bare status.
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_recv_response(Some(answer))
        .timeout_global(overall)
        .user_agent(USER_AGENT)
        .proxy(proxy_for(proxy)?)
        .build()
        .into())
}

fn network_error(err: ureq::Error) -> String {
    format!("网络请求失败：{err}")
}


/// How long to wait before each further try of a request the service could
/// not take: two more tries, as the model SDKs make.
const RETRY_WAITS: [u64; 2] = if cfg!(test) { [10, 10] } else { [1000, 3000] };

/// The longest a service's own `retry-after` is waited for, in milliseconds.
const RETRY_AFTER_CAP: u64 = 20_000;

/// Statuses that say "not now", not "not this": too many requests, a
/// service that is overloaded or failing, a request that timed out there.
fn retryable(status: u16) -> bool {
    matches!(status, 408 | 409 | 429 | 500..=599)
}

/// Send a chat request and forward the model's turn: its text as it
/// arrives, then the whole turn with any tool calls. A request the service
/// is too busy for, or that never reached it, is sent again a little later,
/// up to twice; nothing of an answer has arrived by then, so nothing is
/// repeated. Returns when the stream ends or the receiver is gone (the
/// conversation was reset or stopped).
pub fn stream_chat(request: HttpRequest, protocol: Protocol, events: async_channel::Sender<ChatEvent>) {
    let send = |event| events.send_blocking(event).is_ok();
    // The model service may have a proxy of its own, or be told to use none.
    let agent = match agent(None, &request.proxy) {
        Ok(agent) => agent,
        Err(err) => {
            send(ChatEvent::Error(err));
            return;
        }
    };
    // Compact JSON: the documents can be hundreds of kilobytes, and indentation only adds to them.
    let body = request.body.to_string();
    let mut tries = 0;
    let mut response = loop {
        let mut call = agent.post(&request.url);
        for (name, value) in &request.headers {
            call = call.header(name, value);
        }
        let last = tries >= RETRY_WAITS.len();
        let (why, wait) = match call.send(body.as_str()) {
            Ok(response) => {
                let status = response.status().as_u16();
                if last || !retryable(status) { break response }
                // The service may say how long it wants to be left alone.
                let asked = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<f64>().ok()).map(|seconds| ((seconds.max(0.) * 1000.) as u64).min(RETRY_AFTER_CAP));
                (format!("HTTP {status}"), asked)
            }
            // A request that waited two minutes for nothing is not worth two more waits.
            Err(err) if last || matches!(err, ureq::Error::Timeout(_)) => {
                send(ChatEvent::Error(network_error(err)));
                return;
            }
            Err(err) => (network_error(err), None),
        };
        let wait = wait.unwrap_or(RETRY_WAITS[tries]);
        tries += 1;
        if !send(ChatEvent::Retrying(tries, why)) { return }
        std::thread::sleep(Duration::from_millis(wait));
    };
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let body = response.body_mut().read_to_string().unwrap_or_default();
        send(ChatEvent::Error(ai::error_message(status, &body)));
        return;
    }
    let mut reader = TurnReader::new(protocol);
    for line in BufReader::new(response.body_mut().as_reader()).lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                send(ChatEvent::Error(format!("连接中断：{err}")));
                return;
            }
        };
        match reader.line(&line) {
            Ok(Some(text)) => {
                if !send(ChatEvent::Text(text)) { return }
            }
            Ok(None) => {}
            Err(error) => {
                send(ChatEvent::Error(error));
                return;
            }
        }
    }
    send(ChatEvent::Done(reader.finish()));
}

/// Send a request and wait for the whole answer as text: for a one-off
/// question whose reply is read by code, not shown as it arrives.
pub fn complete(request: HttpRequest, protocol: Protocol) -> Result<String, String> {
    let (sender, events) = async_channel::unbounded();
    stream_chat(request, protocol, sender);
    let mut text = String::new();
    while let Ok(event) = events.try_recv() {
        match event {
            ChatEvent::Text(more) => text.push_str(&more),
            ChatEvent::Retrying(..) => {}
            ChatEvent::Error(error) => return Err(error),
            // A reply that was cut off or declined is not one to parse.
            ChatEvent::Done(turn) => {
                if let Some(note) = ai::stop_note(&turn.stop) { return Err(note.to_string()) }
            }
        }
    }
    if text.trim().is_empty() { return Err("模型没有返回内容。".into()) }
    Ok(text)
}
