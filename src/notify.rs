//! 外部 webhook 通知: what the automatic inspection and the routine tasks
//! send to the webhooks of 设置 › 通用, as the plugin's notifier and its
//! automatic-inspection alerts did. The payloads and the send/skip rules are
//! `wisp_ops_engine::notify`; this is the glue: which channels, the states
//! last reported (`<data>/notify-state.json`), and the sending, always on a
//! thread of its own so an inspection or a task never waits for, or fails
//! because of, a webhook.
//!
//! What a task run sent is kept with its runs (`<data>/notifications/<task>.jsonl`),
//! as the plugin kept it; the latest send and the channels it could not
//! reach are said quietly on the settings page, never in a toast.

use crate::ops::{Fleet, TaskRunRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;
use wisp_ops_collect::inspect::Severity;
use wisp_ops_collect::types::FleetInspection;
use wisp_ops_core::settings::{Settings, Webhook};
use wisp_ops_engine::config::TaskSpec;
use wisp_ops_engine::notify::{self, Channel, Delivery, HostState, Kind, Request, Status, TaskRules};
use wisp_ops_engine::store::{OpsStore, StoreRetention};
use wisp_ops_engine::time;

/// How long one post may take, as the plugin allowed.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The webhooks and the task rule as last set in the window; the background work reads them.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub webhooks: Vec<Webhook>,
    /// `always`, `problems` or `change`.
    pub task_mode: String,
}

static CONFIG: RwLock<Config> = RwLock::new(Config { webhooks: Vec::new(), task_mode: String::new() });

/// The latest send, held in memory for the settings page (which must not read the disk).
static LAST: Mutex<Option<LastSend>> = Mutex::new(None);

/// One reader and writer of the state file at a time.
static STATE: Mutex<()> = Mutex::new(());

/// What the latest notification did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastSend {
    pub at: String,
    /// `inspection`, or the task's name.
    pub event: String,
    pub sent: Vec<String>,
    /// The channels it could not reach, with why (never the endpoint or a token).
    pub failed: Vec<(String, String)>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct NotifyState {
    /// The state last reported per server, so only changes are sent.
    reported: BTreeMap<String, HostState>,
    last: Option<LastSend>,
}

fn state_file(data_dir: &Path) -> PathBuf {
    data_dir.join("notify-state.json")
}

fn read_state(data_dir: &Path) -> NotifyState {
    std::fs::read_to_string(state_file(data_dir)).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
}

fn write_state(data_dir: &Path, state: &NotifyState) {
    let file = state_file(data_dir);
    let temporary = file.with_extension("json.tmp");
    if std::fs::write(&temporary, serde_json::to_string_pretty(state).unwrap_or_default()).is_ok() { let _ = std::fs::rename(&temporary, &file); }
}

/// Take the settings' webhooks for the background work; with `data_dir`, also read the latest send for the page.
pub fn configure(settings: &Settings, data_dir: Option<&Path>) {
    *CONFIG.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Config { webhooks: settings.webhooks.clone(), task_mode: settings.webhook_tasks.clone() };
    if let Some(dir) = data_dir {
        let last = { let _held = STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner()); read_state(dir).last };
        *LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = last;
    }
}

fn config() -> Config {
    CONFIG.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

/// The latest send, as remembered.
pub fn last() -> Option<LastSend> {
    LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

pub fn channel(webhook: &Webhook) -> Channel {
    Channel { name: webhook.name.clone(), kind: Kind::parse(&webhook.kind), url: webhook.url.clone(), secret: webhook.secret.clone() }
}

/// The network: one post, bounded by `TIMEOUT`.
pub fn post(request: &Request) -> Result<(u16, String), String> {
    wisp_ops_net::webhook::post_json(&request.url, &request.headers, &request.body.to_string(), TIMEOUT)
}

/// Keep what a send did: in the state file and for the page. Nothing is kept when nothing was tried.
fn remember(data_dir: &Path, event: &str, deliveries: &[Delivery]) {
    let tried: Vec<&Delivery> = deliveries.iter().filter(|delivery| delivery.status != Status::Skipped).collect();
    if tried.is_empty() { return }
    let last = LastSend {
        at: time::to_iso(time::now_ms()),
        event: event.to_string(),
        sent: tried.iter().filter(|d| d.status == Status::Sent).map(|d| d.channel.clone()).collect(),
        failed: tried.iter().filter(|d| d.status == Status::Failed).map(|d| (d.channel.clone(), d.detail.clone().unwrap_or_default())).collect(),
    };
    {
        let _held = STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = read_state(data_dir);
        state.last = Some(last.clone());
        write_state(data_dir, &state);
    }
    *LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(last);
}

/// After an automatic inspection: compare each server's state with the one last reported and send the changes.
pub fn after_inspection(data_dir: &Path, inspection: &FleetInspection) {
    let _ = inspection_with(&config(), data_dir, inspection, post);
}

fn inspection_with(config: &Config, data_dir: &Path, inspection: &FleetInspection, send: fn(&Request) -> Result<(u16, String), String>) -> Option<JoinHandle<()>> {
    let now: Vec<(String, HostState, Vec<String>)> = inspection.hosts.iter().map(|host| {
        let problems = host.findings.iter().filter(|finding| !finding.muted && matches!(finding.severity, Severity::Crit | Severity::Warn)).map(|finding| finding.message.clone()).collect();
        (host.host.clone(), HostState::from_severity(&host.severity), problems)
    }).collect();
    let changes = {
        let _held = STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = read_state(data_dir);
        let (reported, changes) = notify::state_changes(&state.reported, &now);
        if reported != state.reported {
            state.reported = reported;
            write_state(data_dir, &state);
        }
        changes
    };
    let channels: Vec<Channel> = config.webhooks.iter().filter(|webhook| webhook.inspection).map(channel).collect();
    if changes.is_empty() || channels.is_empty() { return None }
    let message = notify::alert_message(&changes, time::now_ms());
    let data_dir = data_dir.to_path_buf();
    Some(std::thread::spawn(move || {
        let deliveries: Vec<Delivery> = channels.iter().map(|channel| notify::deliver(channel, &message, time::now_ms(), &send)).collect();
        remember(&data_dir, "inspection", &deliveries);
    }))
}

/// After a task's run was recorded: send it to the task's channels if its rules say so.
/// A task written with `notify` names its channels; otherwise those set for routine tasks get it.
pub fn after_task(fleet: &Fleet, task: &TaskSpec, record: &TaskRunRecord, previous: Option<&TaskRunRecord>) {
    let _ = task_with(&config(), fleet.data_dir(), (&fleet.config.retention).into(), &fleet.config.time_zone, task, record, previous, post);
}

fn task_with(config: &Config, data_dir: &Path, retention: StoreRetention, default_zone: &str, task: &TaskSpec, record: &TaskRunRecord, previous: Option<&TaskRunRecord>, send: fn(&Request) -> Result<(u16, String), String>) -> Option<JoinHandle<()>> {
    let names: Vec<String> = if task.notify.is_empty() { config.webhooks.iter().filter(|webhook| webhook.tasks).map(|webhook| webhook.name.clone()).collect() } else { task.notify.clone() };
    if names.is_empty() { return None }
    let rules = TaskRules {
        only_problems: task.notify_only_problems.unwrap_or(config.task_mode == "problems"),
        on_change: task.notify_on_change.unwrap_or(config.task_mode == "change"),
        quiet_hours: task.quiet_hours.clone(),
        time_zone: task.schedule.as_ref().and_then(|schedule| schedule.time_zone.clone()).unwrap_or_else(|| default_zone.to_string()),
    };
    let at = time::parse_iso(&record.at).unwrap_or_else(time::now_ms);
    let skip = notify::task_skip(&rules, &record.counts, previous.map(|previous| &previous.counts), at);
    let message = notify::task_summary(&task.name, &record.at, &record.hosts, &record.counts, &record.excerpt);
    let channels: Vec<Channel> = config.webhooks.iter().map(channel).collect();
    let (data_dir, name, at_text) = (data_dir.to_path_buf(), task.name.clone(), record.at.clone());
    Some(std::thread::spawn(move || {
        let deliveries = notify::notify_task(&channels, &names, &message, skip.as_deref(), time::now_ms(), &send);
        let _ = OpsStore::new(&data_dir, retention).append_bounded("notifications", &name, &serde_json::json!({"at": at_text, "deliveries": deliveries}), 90);
        remember(&data_dir, &name, &deliveries);
    }))
}

/// 发送测试通知: post a test message to one webhook and say why it failed, if it did.
pub fn test(webhook: &Webhook) -> Result<(), String> {
    test_with(webhook, post)
}

fn test_with(webhook: &Webhook, send: fn(&Request) -> Result<(u16, String), String>) -> Result<(), String> {
    let delivery = notify::deliver(&channel(webhook), &notify::test_message(time::now_ms()), time::now_ms(), &send);
    if delivery.status == Status::Sent { Ok(()) } else { Err(delivery.detail.unwrap_or_default()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use wisp_ops_collect::inspect::Finding;
    use wisp_ops_collect::types::{FleetCounts, HostInspectionResult};

    fn dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wisp-ops-notify-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A receiver on 127.0.0.1 that answers `count` posts with `status` and hands over their bodies.
    fn receiver(count: usize, status: u16) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..count {
                let Ok((stream, _)) = listener.accept() else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 { break }
                    if let Some(value) = line.to_lowercase().strip_prefix("content-length:") { length = value.trim().parse().unwrap_or(0) }
                    if line == "\r\n" { break }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                let mut stream = stream;
                let _ = stream.write_all(format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
                let _ = tx.send(String::from_utf8_lossy(&body).into_owned());
            }
        });
        (url, rx)
    }

    fn hook(url: &str, inspection: bool, tasks: bool) -> Webhook {
        Webhook { name: "ops".into(), kind: "webhook".into(), url: url.into(), secret: "bearer-secret".into(), inspection, tasks }
    }

    fn host(name: &str, severity: &str, findings: Vec<Finding>) -> HostInspectionResult {
        HostInspectionResult { host: name.into(), status: "ok".into(), severity: severity.into(), findings, report: None, error: None, duration_ms: 1 }
    }

    fn pass(hosts: Vec<HostInspectionResult>) -> FleetInspection {
        FleetInspection { at: String::new(), hosts, counts: FleetCounts::default() }
    }

    #[test]
    fn the_inspection_sets_a_baseline_then_sends_changes_but_not_muted_problems() {
        let data = dir("inspection");
        let (url, bodies) = receiver(2, 200);
        let config = Config { webhooks: vec![hook(&url, true, false)], task_mode: "problems".into() };
        assert!(inspection_with(&config, &data, &pass(vec![host("a", "ok", vec![])]), post).is_none());
        let down = Finding::new(Severity::Crit, "unreachable", "ssh: connect timed out");
        inspection_with(&config, &data, &pass(vec![host("a", "unreachable", vec![down]), host("b", "ok", vec![])]), post).unwrap().join().unwrap();
        let body: serde_json::Value = serde_json::from_str(&bodies.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
        let text = body["markdown"].as_str().unwrap();
        assert!(text.contains("**a**: healthy → unreachable — ssh: connect timed out"), "{text}");
        assert!(!text.contains("**b**"));
        // A muted warning leaves b healthy: nothing to send.
        let muted = Finding { muted: true, ..Finding::new(Severity::Warn, "memory-low", "memory available 9%") };
        assert!(inspection_with(&config, &data, &pass(vec![host("b", "ok", vec![muted])]), post).is_none());
        inspection_with(&config, &data, &pass(vec![host("a", "ok", vec![])]), post).unwrap().join().unwrap();
        assert!(bodies.recv_timeout(Duration::from_secs(5)).unwrap().contains("**a**: unreachable → healthy"));
        let last = read_state(&data).last.unwrap();
        assert_eq!((last.event.as_str(), last.sent.clone()), ("inspection", vec!["ops".to_string()]));
        let _ = std::fs::remove_dir_all(data);
    }

    #[test]
    fn a_failed_send_is_remembered_without_the_endpoint_and_the_channels_without_events_are_left_out() {
        let data = dir("failed");
        let (url, _bodies) = receiver(1, 500);
        let config = Config { webhooks: vec![hook(&url, true, false), Webhook { name: "tasks-only".into(), ..hook(&url, false, true) }], task_mode: "always".into() };
        inspection_with(&config, &data, &pass(vec![host("a", "ok", vec![])]), post);
        inspection_with(&config, &data, &pass(vec![host("a", "crit", vec![Finding::new(Severity::Crit, "disk-full", "/ 99% used")])]), post).unwrap().join().unwrap();
        let last = read_state(&data).last.unwrap();
        assert_eq!(last.failed, vec![("ops".to_string(), "HTTP 500".to_string())]);
        let text = std::fs::read_to_string(state_file(&data)).unwrap();
        assert!(!text.contains(&url) && !text.contains("bearer-secret"));
        let _ = std::fs::remove_dir_all(data);
    }

    #[test]
    fn a_task_run_goes_to_the_task_channels_by_its_rules_and_is_kept_with_its_runs() {
        let data = dir("task");
        let (url, bodies) = receiver(2, 204);
        let config = Config { webhooks: vec![hook(&url, false, true)], task_mode: "problems".into() };
        let task = TaskSpec { name: "daily".into(), targets: "all".into(), ..Default::default() };
        let healthy = TaskRunRecord { at: "2026-10-27T00:00:00.000Z".into(), hosts: vec!["a".into()], playbook: "inspect".into(), counts: [("ok".to_string(), 1.)].into(), excerpt: "fine".into() };
        let retention = StoreRetention::default();
        task_with(&config, &data, retention, "UTC", &task, &healthy, None, post).unwrap().join().unwrap();
        let kept: Vec<serde_json::Value> = OpsStore::new(&data, retention).read_bounded("notifications", "daily").unwrap();
        assert_eq!(kept[0]["deliveries"][0]["status"], "skipped");
        let warned = TaskRunRecord { counts: [("warn".to_string(), 2.)].into(), excerpt: "disk 91%".into(), ..healthy.clone() };
        task_with(&config, &data, retention, "UTC", &task, &warned, Some(&healthy), post).unwrap().join().unwrap();
        let body: serde_json::Value = serde_json::from_str(&bodies.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
        assert!(body["markdown"].as_str().unwrap().starts_with("## WispOps: daily\n2026-10-27T00:00:00.000Z\nHosts: a\nwarn=2\n\ndisk 91%"));
        // The task's own rules come first: on-change skips a repeat even in "always" mode.
        let always = Config { task_mode: "always".into(), ..config.clone() };
        let changing = TaskSpec { notify_on_change: Some(true), ..task.clone() };
        task_with(&always, &data, retention, "UTC", &changing, &warned, Some(&warned), post).unwrap().join().unwrap();
        assert!(bodies.recv_timeout(Duration::from_millis(300)).is_err());
        // Without channels for tasks nothing starts.
        assert!(task_with(&Config { webhooks: vec![hook(&url, true, false)], ..config }, &data, retention, "UTC", &task, &warned, None, post).is_none());
        let _ = std::fs::remove_dir_all(data);
    }

    #[test]
    fn the_test_reports_success_or_why_not() {
        let (url, bodies) = receiver(1, 200);
        assert_eq!(test_with(&hook(&url, true, true), post), Ok(()));
        assert!(bodies.recv_timeout(Duration::from_secs(5)).unwrap().contains("test notification"));
        assert!(test_with(&hook("http://example.org/x", true, true), post).unwrap_err().contains("HTTPS"));
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let err = test_with(&hook(&format!("http://127.0.0.1:{port}/hook-token"), true, true), post).unwrap_err();
        assert!(!err.contains("hook-token"), "{err}");
    }
}
