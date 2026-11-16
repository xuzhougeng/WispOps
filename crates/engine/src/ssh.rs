//! Remote execution through the system OpenSSH client.
//!
//! Using the user's own `ssh` keeps ~/.ssh/config, agents, jump hosts, certificates, and
//! known_hosts exactly as the operator configured them. Scripts travel on stdin to `sh -s`, so no
//! remote quoting is involved and fish/csh login shells work. Key hosts use `BatchMode=yes` so
//! any prompt fails instead of hanging; password hosts answer exactly one prompt through a
//! one-shot askpass (OpenSSH ≥ 8.4). Repeated authentication failures block a host for a while,
//! because retried logins look like brute force and get operators' addresses banned.
//!
//! The API is blocking: [`SshRunner::run`] returns when the remote command finished, timed out or
//! was cancelled; [`SshRunner::run_many`] runs a fleet on a bounded number of threads.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use encoding_rs::Encoding;
use serde::{Deserialize, Serialize};

use crate::config::SshSpec;
use crate::fsutil::no_window;
use crate::diagnose::{Diagnosis, SshTarget, diagnose_target, parse_ssh_g};
use crate::fsutil::{create_private_dir, expand_home};
use crate::inventory::Host;
use crate::jsre::{js_re, js_trim};
use crate::time::{now_ms, to_iso};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    Ok,
    Failed,
    Unreachable,
    AuthFailed,
    Blocked,
    SudoRequired,
    Timeout,
    Cancelled,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Ok => "ok",
            RunStatus::Failed => "failed",
            RunStatus::Unreachable => "unreachable",
            RunStatus::AuthFailed => "auth-failed",
            RunStatus::Blocked => "blocked",
            RunStatus::SudoRequired => "sudo-required",
            RunStatus::Timeout => "timeout",
            RunStatus::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunResult {
    pub host: String,
    pub status: RunStatus,
    /// Remote exit status, or `None` when the command never reported one.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub duration_ms: u64,
    /// Milliseconds from starting ssh to the first byte on stdout; with `time_login`, the login itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_output_ms: Option<u64>,
}

impl RunResult {
    /// A result for a host that was never contacted.
    pub fn without_run(host: &str, status: RunStatus, stderr: impl Into<String>) -> Self {
        RunResult { host: host.to_string(), status, exit_code: None, stdout: String::new(), stderr: stderr.into(), truncated: false, duration_ms: 0, first_output_ms: None }
    }
}

#[derive(Clone)]
pub struct RunRequest {
    pub host: Host,
    pub script: String,
    pub sudo: bool,
    /// Password for sudo, supplied by the vault and never by the model. It travels as the first
    /// stdin line, is consumed by `read` in the remote wrapper, and is redacted from captured output.
    pub sudo_password: Option<String>,
    /// Login password for `auth: password` hosts, answered through askpass.
    pub login_password: Option<String>,
    pub timeout_ms: u64,
    /// Set to true to stop the run; the local ssh is killed and the result is `cancelled`.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Per-stream capture limit for built-in collectors whose output is bounded by construction.
    pub max_output_bytes: Option<usize>,
    /// Print `@@login` before the prelude, so `first_output_ms` measures the login rather than profile loading.
    pub time_login: bool,
}

impl RunRequest {
    /// A plain, unprivileged run with a 60-second limit.
    pub fn new(host: Host, script: impl Into<String>) -> Self {
        RunRequest { host, script: script.into(), sudo: false, sudo_password: None, login_password: None, timeout_ms: 60_000, cancel: None, max_output_bytes: None, time_login: false }
    }

    pub fn sudo(mut self, sudo: bool) -> Self {
        self.sudo = sudo;
        self
    }

    pub fn sudo_password(mut self, password: Option<String>) -> Self {
        self.sudo_password = password;
        self
    }

    pub fn login_password(mut self, password: Option<String>) -> Self {
        self.login_password = password;
        self
    }

    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    pub fn max_output_bytes(mut self, limit: usize) -> Self {
        self.max_output_bytes = Some(limit);
        self
    }

    pub fn time_login(mut self, time_login: bool) -> Self {
        self.time_login = time_login;
        self
    }
}

impl std::fmt::Debug for RunRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunRequest")
            .field("host", &self.host.name)
            .field("script", &self.script)
            .field("sudo", &self.sudo)
            .field("sudo_password", &self.sudo_password.as_ref().map(|_| "[REDACTED]"))
            .field("login_password", &self.login_password.as_ref().map(|_| "[REDACTED]"))
            .field("timeout_ms", &self.timeout_ms)
            .field("time_login", &self.time_login)
            .finish()
    }
}

/// Exit status the password wrapper uses when sudo rejects the password.
pub const SUDO_REJECTED_EXIT: i32 = 97;

/// Single-quote a value for POSIX sh.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn auth_failure() -> &'static regex::Regex {
    js_re!(r"Permission denied \(|Host key verification failed|Too many authentication failures|REMOTE HOST IDENTIFICATION HAS CHANGED|Authentication failed", "i")
}

/// Classify a finished ssh process.
pub fn classify_exit(code: Option<i32>, stderr: &str, sudo: bool, with_password: bool) -> RunStatus {
    if code == Some(0) { return RunStatus::Ok }
    if code == Some(255) && auth_failure().is_match(stderr) { return RunStatus::AuthFailed }
    let unreachable = js_re!(
        r"ssh: |Connection (?:refused|timed out|closed|reset)|Could not resolve hostname|No route to host|Network is unreachable|kex_exchange_identification|banner exchange|Operation timed out",
        "i"
    );
    if code == Some(255) && unreachable.is_match(stderr) { return RunStatus::Unreachable }
    if sudo && with_password && code == Some(SUDO_REJECTED_EXIT) { return RunStatus::SudoRequired }
    let sudo_required = js_re!(r"sudo: (?:a password is required|a terminal is required|no tty present|.*may not run sudo|.* is not in the sudoers file)", "i");
    if sudo && sudo_required.is_match(stderr) { return RunStatus::SudoRequired }
    RunStatus::Failed
}

/// The script a locale most likely writes in, for locales without an explicit one.
fn likely_script(language: &str, region: &str) -> &'static str {
    match language {
        "zh" => if matches!(region, "TW" | "HK" | "MO") { "Hant" } else { "Hans" },
        "ja" => "Jpan",
        "ko" => "Kore",
        "ru" | "uk" | "bg" | "be" | "mk" | "sr" | "kk" | "ky" | "mn" | "tg" => "Cyrl",
        "el" => "Grek",
        "he" | "iw" | "yi" => "Hebr",
        "ar" | "fa" | "ur" | "ps" => "Arab",
        "th" => "Thai",
        _ => "Latn",
    }
}

/// Windows ANSI code pages by locale `language-script`, language, or script; anything else is Western (1252).
fn ansi_code_page(language: &str, script: &str) -> &'static str {
    match (language, script) {
        ("zh", "Hans") => "gb18030",
        ("zh", "Hant") => "big5",
        ("tr", _) => "windows-1254",
        ("vi", _) => "windows-1258",
        ("cs" | "hr" | "hu" | "pl" | "ro" | "sk" | "sl", _) => "windows-1250",
        ("et" | "lt" | "lv", _) => "windows-1257",
        (_, "Jpan") => "shift_jis",
        (_, "Kore") => "euc-kr",
        (_, "Cyrl") => "windows-1251",
        (_, "Grek") => "windows-1253",
        (_, "Hebr") => "windows-1255",
        (_, "Arab") => "windows-1256",
        (_, "Thai") => "windows-874",
        _ => "windows-1252",
    }
}

/// Windows OpenSSH reports system errors such as "No such host is known" in the ANSI code page
/// (GBK on Chinese Windows); guess it from the user locale. `None` elsewhere: POSIX ssh speaks UTF-8.
pub fn legacy_decoder(platform: &str, locale: &str) -> Option<&'static Encoding> {
    if platform != "win32" { return None }
    let mut parts = locale.split(['-', '_']);
    let language = parts.next().unwrap_or("").to_lowercase();
    let mut script = String::new();
    let mut region = String::new();
    for part in parts {
        if part.len() == 4 && part.chars().all(|c| c.is_ascii_alphabetic()) {
            script = format!("{}{}", part[..1].to_uppercase(), part[1..].to_lowercase());
        } else if part.len() == 2 && region.is_empty() {
            region = part.to_uppercase();
        }
    }
    if script.is_empty() { script = likely_script(&language, &region).to_string() }
    Encoding::for_label(ansi_code_page(&language, &script).as_bytes())
}

/// The decoder for local ssh messages on this machine.
fn system_legacy_decoder() -> Option<&'static Encoding> {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            safe fn GetACP() -> u32;
        }
        let label = match GetACP() {
            936 | 54936 => "gb18030".to_string(),
            950 => "big5".to_string(),
            932 => "shift_jis".to_string(),
            949 => "euc-kr".to_string(),
            874 => "windows-874".to_string(),
            page @ 1250..=1258 => format!("windows-{page}"),
            65001 => return None,
            _ => "windows-1252".to_string(),
        };
        Encoding::for_label(label.as_bytes())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn decode_bytes(bytes: &[u8], legacy: Option<&'static Encoding>) -> Option<String> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text.to_string()),
        Err(_) => legacy.map(|encoding| encoding.decode_without_bom_handling(bytes).0.into_owned()),
    }
}

/// Decode ssh stderr line by line, so the remote's UTF-8 survives next to local messages in the
/// legacy code page. OpenSSH also writes non-ASCII bytes of its own messages as `\NNN` octal
/// escapes; those runs are decoded too.
pub fn decode_stderr(bytes: &[u8], legacy: Option<&'static Encoding>) -> String {
    let lines: Vec<String> = bytes.split(|b| *b == b'\n').map(|line| decode_bytes(line, legacy).unwrap_or_else(|| String::from_utf8_lossy(line).into_owned())).collect();
    let joined = lines.join("\n");
    js_re!(r"(?:\\[23][0-7]{2})+")
        .replace_all(&joined, |captures: &regex::Captures<'_>| {
            let run = &captures[0];
            let raw: Vec<u8> = run[1..].split('\\').filter_map(|digits| u8::from_str_radix(digits, 8).ok()).collect();
            decode_bytes(&raw, legacy).unwrap_or_else(|| run.to_string())
        })
        .into_owned()
}

/// Remote command that validates sudo with a password read from stdin, then runs the rest of
/// stdin through the cached credential. Both sudo calls keep the same parent shell: replacing it
/// with exec changes the ppid timestamp scope on sessions without a tty and loses the successful
/// authentication. The password reaches only the `read` builtin and sudo's own stdin: if sudo
/// needs no password (NOPASSWD or a cached timestamp) the piped line is discarded by sudo, so it
/// can never be executed as a script line.
pub fn password_sudo_command(sudo_user: Option<&str>) -> String {
    let as_user = sudo_user.map(|user| format!(" -u {user}")).unwrap_or_default();
    format!(
        "sh -c 'IFS= read -r p; printf \"%s\\n\" \"$p\" | sudo -S -p \"\" -v{as_user} 2>/dev/null; s=$?; unset p; [ \"$s\" -eq 0 ] || exit {SUDO_REJECTED_EXIT}; sudo -n{as_user} -- sh -s; s=$?; exit \"$s\"'"
    )
}

/// Script prelude: extend PATH with site directories and, optionally, adopt the PATH a login
/// shell would have. Profiles are sourced in a subshell with output discarded, so a profile that
/// prints, exits, or execs another shell cannot break the session.
pub fn prelude(load_profile: bool, extra_path: &[String]) -> String {
    let mut lines: Vec<String> = Vec::new();
    if load_profile {
        lines.push(r#"__wisp_path=$( { [ -r /etc/profile ] && . /etc/profile; [ -r "$HOME/.profile" ] && . "$HOME/.profile"; } >/dev/null 2>&1 </dev/null; printf '%s' "$PATH")"#.to_string());
        lines.push(r#"[ -n "$__wisp_path" ] && PATH="$__wisp_path"; unset __wisp_path"#.to_string());
    }
    if !extra_path.is_empty() { lines.push(format!("PATH=\"$PATH:{}\"", extra_path.join(":"))) }
    if lines.is_empty() { return String::new() }
    lines.push("export PATH".to_string());
    format!("{}\n", lines.join("\n"))
}

/// A host whose logins are paused, and until when (ISO time).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BlockedHost {
    pub host: String,
    pub until: String,
}

/// Per-host login backoff after authentication failures.
#[derive(Debug)]
pub struct AuthGuard {
    block_ms: i64,
    blocked: Mutex<Vec<(String, i64, String)>>,
}

impl AuthGuard {
    pub fn new(block_ms: i64) -> Self {
        AuthGuard { block_ms, blocked: Mutex::new(Vec::new()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<(String, i64, String)>> {
        self.blocked.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Why logins to this host are paused, or `None` when they are not.
    pub fn check(&self, host: &str) -> Option<String> {
        self.check_at(host, now_ms())
    }

    pub fn check_at(&self, host: &str, now: i64) -> Option<String> {
        let mut blocked = self.lock();
        let index = blocked.iter().position(|(name, _, _)| name == host)?;
        let (_, until, reason) = &blocked[index];
        if *until <= now {
            blocked.remove(index);
            return None;
        }
        Some(format!(
            "logins to {host} are paused until {} after an authentication failure ({reason}); fix the credentials or host key, then run /ops-unblock {host}",
            to_iso(*until)
        ))
    }

    /// Pause logins to a host after an authentication failure with this stderr.
    pub fn record(&self, host: &str, stderr: &str) {
        self.record_at(host, stderr, now_ms());
    }

    pub fn record_at(&self, host: &str, stderr: &str, now: i64) {
        if self.block_ms <= 0 { return }
        let reason = stderr.split('\n').find(|line| auth_failure().is_match(line)).map(js_trim).unwrap_or("authentication failed");
        let reason: String = reason.chars().take(200).collect();
        let mut blocked = self.lock();
        blocked.retain(|(name, _, _)| name != host);
        blocked.push((host.to_string(), now + self.block_ms, reason));
    }

    /// Resume logins to one host, or to every host with `all`; returns the hosts that were paused.
    pub fn clear(&self, host: &str) -> Vec<String> {
        let mut blocked = self.lock();
        let hosts: Vec<String> = blocked.iter().filter(|(name, _, _)| host == "all" || name == host).map(|(name, _, _)| name.clone()).collect();
        blocked.retain(|(name, _, _)| !hosts.contains(name));
        hosts
    }

    pub fn list(&self) -> Vec<BlockedHost> {
        self.list_at(now_ms())
    }

    pub fn list_at(&self, now: i64) -> Vec<BlockedHost> {
        self.lock().iter().filter(|(_, until, _)| *until > now).map(|(host, until, _)| BlockedHost { host: host.clone(), until: to_iso(*until) }).collect()
    }
}

/// A one-shot helper that answers ssh's password prompt, removed after ssh exits.
///
/// On Unix the password is never written to a file: the helper script reads it from a FIFO in an
/// owner-only directory, fed by a thread of this process, so it exists only in memory and in the
/// kernel's pipe buffer. It never appears in an argument list either.
struct Askpass {
    dir: PathBuf,
    env: Vec<(String, String)>,
    #[cfg(unix)]
    feeder: Option<(Arc<AtomicBool>, mpsc::Receiver<()>, PathBuf)>,
}

impl Askpass {
    fn base_env(script: &Path) -> Vec<(String, String)> {
        vec![
            ("SSH_ASKPASS".to_string(), script.to_string_lossy().into_owned()),
            ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
            ("DISPLAY".to_string(), std::env::var("DISPLAY").unwrap_or_else(|_| "wisp-ops:0".to_string())),
        ]
    }

    #[cfg(unix)]
    fn create(password: &str) -> std::io::Result<Askpass> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let token = crate::fsutil::random_hex::<8>().map_err(std::io::Error::other)?;
        let dir = std::env::temp_dir().join(format!("wisp-ops-askpass-{token}"));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let prepared = (|| -> std::io::Result<(PathBuf, PathBuf)> {
            let fifo = dir.join("pass");
            let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
            // SAFETY: `c_path` is a valid NUL-terminated path for the duration of the call.
            if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 { return Err(std::io::Error::last_os_error()) }
            let script = dir.join("askpass.sh");
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).open(&script)?;
            file.write_all(format!("#!/bin/sh\ncat {}\n", shell_quote(&fifo.to_string_lossy())).as_bytes())?;
            Ok((fifo, script))
        })();
        let (fifo, script) = match prepared {
            Ok(paths) => paths,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(error);
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = mpsc::channel();
        let line = format!("{password}\n");
        let (feeder_stop, feeder_fifo) = (stop.clone(), fifo.clone());
        std::thread::spawn(move || {
            // Each open blocks until a reader (one askpass invocation) opens the FIFO.
            while let Ok(mut pipe) = std::fs::OpenOptions::new().write(true).open(&feeder_fifo) {
                if feeder_stop.load(Ordering::SeqCst) { break }
                let _ = pipe.write_all(line.as_bytes());
                drop(pipe);
                // Let the reader see end-of-file before the next open can pair with it again.
                std::thread::sleep(Duration::from_millis(30));
                if feeder_stop.load(Ordering::SeqCst) { break }
            }
            let _ = done_tx.send(());
        });
        Ok(Askpass { env: Askpass::base_env(&script), dir, feeder: Some((stop, done_rx, fifo)) })
    }

    #[cfg(not(unix))]
    fn create(password: &str) -> std::io::Result<Askpass> {
        // Without FIFOs the password sits in an owner-only temporary file until ssh exits, as in the plugin.
        let token = crate::fsutil::random_hex::<8>().map_err(std::io::Error::other)?;
        let dir = std::env::temp_dir().join(format!("wisp-ops-askpass-{token}"));
        std::fs::create_dir(&dir)?;
        let passfile = dir.join("pass");
        let script = dir.join("askpass.cmd");
        let written = std::fs::write(&passfile, password).and_then(|()| std::fs::write(&script, format!("@type \"{}\"\r\n", passfile.display())));
        if let Err(error) = written {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(error);
        }
        Ok(Askpass { env: Askpass::base_env(&script), dir })
    }

    fn cleanup(self) {
        #[cfg(unix)]
        if let Some((stop, done, fifo)) = self.feeder {
            use std::os::unix::fs::OpenOptionsExt;
            stop.store(true, Ordering::SeqCst);
            // Opening the FIFO ourselves releases a feeder that is still waiting for a reader.
            let release = std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open(&fifo);
            let _ = done.recv_timeout(Duration::from_secs(1));
            drop(release);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Bounded output capture that keeps the head of the stream.
#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
    first_ms: Option<u64>,
}

fn capture_stream(mut stream: impl Read + Send + 'static, limit: usize, started: Instant, done: mpsc::Sender<()>) -> Arc<Mutex<Capture>> {
    let capture = Arc::new(Mutex::new(Capture::default()));
    let shared = capture.clone();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut capture = shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    if capture.first_ms.is_none() { capture.first_ms = Some(started.elapsed().as_millis() as u64) }
                    let room = limit.saturating_sub(capture.bytes.len());
                    if n > room { capture.truncated = true }
                    capture.bytes.extend_from_slice(&chunk[..n.min(room)]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = done.send(());
    });
    capture
}

/// Ask the process to stop: SIGTERM where there is one, so ssh can close its control socket.
fn terminate(child: &mut Child) {
    #[cfg(unix)]
    {
        // SAFETY: the child has not been reaped (the caller only stops a child that `try_wait` reported running),
        // so its pid still refers to it.
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

fn poll_interval(elapsed: Duration) -> Duration {
    if elapsed < Duration::from_millis(100) {
        Duration::from_millis(2)
    } else if elapsed < Duration::from_secs(2) {
        Duration::from_millis(5)
    } else {
        Duration::from_millis(20)
    }
}

/// The longest directory a ControlMaster socket fits in. A Unix socket path holds 104 bytes on
/// macOS (108 on Linux); `%C` is 40 and ssh adds a 17-byte suffix while the master starts.
const CONTROL_DIR_MAX: usize = 104 - 1 - 40 - 17 - 1;

/// The `ControlPath` of the ControlMaster sockets: `<data_dir>/cm/%C`, or, when the data
/// folder's path is too long for a socket (ssh then refuses every connection with "ControlPath
/// too long"), a name in the user's own directory under `/tmp` that starts with a digest of the
/// data folder, so two data folders never share a master. `None` gives up multiplexing rather
/// than connecting.
fn control_path_for(data_dir: &Path) -> Option<String> {
    let own = data_dir.join("cm");
    if cfg!(windows) || own.as_os_str().len() <= CONTROL_DIR_MAX {
        let _ = create_private_dir(&own);
        return Some(own.join("%C").to_string_lossy().into_owned());
    }
    short_control_path(data_dir)
}

#[cfg(unix)]
fn short_control_path(data_dir: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let uid = unsafe { libc::getuid() };
    let dir = PathBuf::from(format!("/tmp/wispops-{uid}"));
    create_private_dir(&dir).ok()?;
    // /tmp is everyone's: take the directory only if it is ours alone, and not a link to elsewhere.
    let meta = std::fs::symlink_metadata(&dir).ok()?;
    if !(meta.is_dir() && meta.uid() == uid && meta.mode() & 0o077 == 0) { return None }
    let digest = crate::fsutil::hex(&Sha256::digest(data_dir.to_string_lossy().as_bytes()));
    Some(format!("{}/{}-%C", dir.display(), &digest[..8]))
}

#[cfg(not(unix))]
fn short_control_path(_: &Path) -> Option<String> {
    None
}

pub struct SshRunner {
    spec: SshSpec,
    max_output_bytes: usize,
    control_path: Option<String>,
    legacy: Option<&'static Encoding>,
    guard: AuthGuard,
    env: HashMap<String, String>,
}

impl SshRunner {
    /// A runner for this transport configuration. `max_output_bytes` caps each captured stream;
    /// the ControlMaster sockets live in `<data_dir>/cm`, or under `/tmp/wispops-<uid>` when that path is too long for a socket.
    pub fn new(spec: SshSpec, max_output_bytes: usize, data_dir: &Path) -> Self {
        let control_path = if spec.control_persist_sec > 0 { control_path_for(data_dir) } else { None };
        let guard = AuthGuard::new(spec.auth_failure_block_minutes as i64 * 60_000);
        SshRunner { spec, max_output_bytes, control_path, legacy: system_legacy_decoder(), guard, env: HashMap::new() }
    }

    /// Extra environment variables for every ssh process this runner starts.
    pub fn with_env<K: Into<String>, V: Into<String>>(mut self, vars: impl IntoIterator<Item = (K, V)>) -> Self {
        self.env.extend(vars.into_iter().map(|(key, value)| (key.into(), value.into())));
        self
    }

    /// The login pauses of this runner.
    pub fn guard(&self) -> &AuthGuard {
        &self.guard
    }

    pub fn spec(&self) -> &SshSpec {
        &self.spec
    }

    /// Run `ssh -G` for a host: its configuration after ssh_config, without connecting.
    fn ssh_g(&self, host: &Host) -> Option<String> {
        let mut args = vec!["-G".to_string()];
        let argv = self.argv(host, false, false);
        args.extend_from_slice(&argv[..argv.len() - 1]);
        let mut child = no_window(&mut Command::new(&self.spec.binary)).args(&args).envs(&self.env).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
        let started = Instant::now();
        let (done_tx, done_rx) = mpsc::channel();
        let capture = capture_stream(child.stdout.take()?, 1024 * 1024, started, done_tx);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < Duration::from_secs(5) => std::thread::sleep(poll_interval(started.elapsed())),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        };
        let _ = done_rx.recv_timeout(Duration::from_millis(500));
        if !status.success() { return None }
        let capture = capture.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Some(String::from_utf8_lossy(&capture.bytes).into_owned())
    }

    /// Resolve ssh_config aliases locally, without opening a connection or decrypting a login password.
    pub fn login_user(&self, host: &Host) -> Result<String, String> {
        if let Some(user) = host.user.as_deref().filter(|user| !user.is_empty()) { return Ok(user.to_string()) }
        if let Some(ssh) = &host.ssh
            && let Some(at) = ssh.rfind('@')
        {
            return Ok(ssh[..at].to_string());
        }
        // Never expose ssh_config output or custom command diagnostics.
        if let Some(output) = self.ssh_g(host)
            && let Some(captures) = js_re!(r"^user\s+(\S+)\s*$", "m").captures(&output)
        {
            return Ok(captures[1].to_string());
        }
        Err("无法确定 SSH 登录用户，请在服务器配置中显式填写用户名。".to_string())
    }

    /// Where ssh would connect for this host after ssh_config, without connecting; falls back to the inventory fields.
    pub fn resolve_target(&self, host: &Host) -> SshTarget {
        let destination = host.destination();
        let hostname = match destination.find('@') {
            Some(at) => &destination[at + 1..],
            None => destination,
        };
        let port = host.port.and_then(|port| u16::try_from(port).ok());
        match self.ssh_g(host) {
            Some(output) => parse_ssh_g(&output, hostname, port),
            None => SshTarget::direct(hostname, port.unwrap_or(22)),
        }
    }

    /// Diagnose the path to a host (DNS, TCP connect, SSH banner) without logging in.
    pub fn diagnose(&self, host: &Host, timeout_ms: u64) -> Diagnosis {
        diagnose_target(&host.name, &self.resolve_target(host), timeout_ms)
    }

    /// The argv for one host; the destination always follows `--`, so it cannot be parsed as an option.
    pub fn argv(&self, host: &Host, sudo: bool, with_password: bool) -> Vec<String> {
        let mut args: Vec<String> = vec!["-T".into(), "-o".into(), format!("ConnectTimeout={}", self.spec.connect_timeout_sec)];
        let option = |args: &mut Vec<String>, value: String| {
            args.push("-o".into());
            args.push(value);
        };
        if host.uses_password() {
            // StrictHostKeyChecking=accept-new: with forced askpass, a host-key question would receive the password as its answer.
            for value in ["BatchMode=no", "PreferredAuthentications=password,keyboard-interactive", "PubkeyAuthentication=no", "NumberOfPasswordPrompts=1", "StrictHostKeyChecking=accept-new"] {
                option(&mut args, value.to_string());
            }
        } else {
            option(&mut args, "BatchMode=yes".to_string());
        }
        if let Some(control_path) = &self.control_path {
            option(&mut args, "ControlMaster=auto".to_string());
            option(&mut args, format!("ControlPath={control_path}"));
            option(&mut args, format!("ControlPersist={}s", self.spec.control_persist_sec));
        }
        if let Some(identity) = &host.identity_file {
            args.push("-i".into());
            args.push(expand_home(identity));
            option(&mut args, "IdentitiesOnly=yes".to_string());
        }
        if let Some(jump) = &host.proxy_jump {
            args.push("-J".into());
            args.push(jump.clone());
        }
        if let Some(port) = host.port {
            args.push("-p".into());
            args.push(port.to_string());
        }
        if let Some(user) = &host.user {
            args.push("-l".into());
            args.push(user.clone());
        }
        args.extend(self.spec.extra_args.iter().cloned());
        args.push("--".into());
        args.push(host.destination().to_string());
        if !sudo {
            args.push("sh -s".into());
        } else if with_password {
            args.push(password_sudo_command(host.sudo_user.as_deref()));
        } else {
            args.push(format!("sudo -n{} -- sh -s", host.sudo_user.as_ref().map(|user| format!(" -u {}", shell_quote(user))).unwrap_or_default()));
        }
        args
    }

    /// Run one script on one host and wait for it. Never panics on a missing binary or a dead host:
    /// every outcome is a [`RunResult`].
    pub fn run(&self, request: RunRequest) -> RunResult {
        let host = &request.host;
        if let Some(blocked) = self.guard.check(&host.name) { return RunResult::without_run(&host.name, RunStatus::Blocked, blocked) }
        if host.uses_password() && request.login_password.is_none() {
            return RunResult::without_run(
                &host.name,
                RunStatus::AuthFailed,
                format!("{} uses password login but no password is available; set loginSecret to a Password Store entry or switch the host to key authentication", host.name),
            );
        }
        if request.cancel.as_ref().is_some_and(|cancel| cancel.load(Ordering::SeqCst)) { return RunResult::without_run(&host.name, RunStatus::Cancelled, "") }
        let askpass = match request.login_password.as_deref().filter(|_| host.uses_password()) {
            Some(password) => match Askpass::create(password) {
                Ok(askpass) => Some(askpass),
                Err(error) => return RunResult::without_run(&host.name, RunStatus::Failed, format!("cannot prepare the password login helper: {error}")),
            },
            None => None,
        };
        let result = self.spawn_once(&request, askpass.as_ref().map(|askpass| askpass.env.as_slice()));
        if result.status == RunStatus::AuthFailed { self.guard.record(&host.name, &result.stderr) }
        if let Some(askpass) = askpass { askpass.cleanup() }
        result
    }

    fn spawn_once(&self, request: &RunRequest, askpass_env: Option<&[(String, String)]>) -> RunResult {
        let started = Instant::now();
        let host = &request.host;
        let secrets: Vec<&str> = [&request.sudo_password, &request.login_password].into_iter().filter_map(|secret| secret.as_deref()).filter(|secret| !secret.is_empty()).collect();
        let redact = |text: String| secrets.iter().fold(text, |acc, secret| acc.replace(secret, "[REDACTED]"));
        let with_password = request.sudo && request.sudo_password.is_some();
        let mut command = Command::new(&self.spec.binary);
        no_window(&mut command).args(self.argv(host, request.sudo, with_password)).envs(&self.env).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(env) = askpass_env { command.envs(env.iter().map(|(key, value)| (key, value))); }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return RunResult {
                    duration_ms: started.elapsed().as_millis() as u64,
                    ..RunResult::without_run(&host.name, RunStatus::Unreachable, redact(format!("failed to start {}: {error}", self.spec.binary)))
                };
            }
        };
        let limit = request.max_output_bytes.unwrap_or(self.max_output_bytes);
        let (done_tx, done_rx) = mpsc::channel();
        let out = child.stdout.take().map(|stream| capture_stream(stream, limit, started, done_tx.clone()));
        let err = child.stderr.take().map(|stream| capture_stream(stream, limit, started, done_tx.clone()));
        let readers = usize::from(out.is_some()) + usize::from(err.is_some());
        drop(done_tx);

        let mut script = String::new();
        if with_password {
            script.push_str(request.sudo_password.as_deref().unwrap_or(""));
            script.push('\n');
        }
        if request.time_login { script.push_str("echo @@login\n") }
        script.push_str(&prelude(self.spec.load_profile, &self.spec.extra_path));
        // `sh` reads a CR before LF as part of the line (`LC_ALL=C\r`, `fi\r`): a script written or
        // checked out on Windows would fail on every host, so line ends go as LF.
        script.push_str(&request.script.replace("\r\n", "\n"));
        if !script.ends_with('\n') { script.push('\n') }
        if let Some(mut stdin) = child.stdin.take() {
            // A separate thread, so a remote that never reads cannot stall the wait loop below.
            std::thread::spawn(move || {
                let _ = stdin.write_all(script.as_bytes());
            });
        }

        let deadline = started + Duration::from_millis(request.timeout_ms);
        let stop_reason = || {
            if request.cancel.as_ref().is_some_and(|cancel| cancel.load(Ordering::SeqCst)) {
                Some(RunStatus::Cancelled)
            } else if Instant::now() >= deadline {
                Some(RunStatus::Timeout)
            } else {
                None
            }
        };
        let mut ended: Option<RunStatus> = None;
        let mut kill_at: Option<Instant> = None;
        let exit = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {}
                Err(_) => break None,
            }
            if ended.is_none() {
                if let Some(reason) = stop_reason() {
                    ended = Some(reason);
                    terminate(&mut child);
                    kill_at = Some(Instant::now() + Duration::from_secs(2));
                }
            } else if kill_at.is_some_and(|at| Instant::now() >= at) {
                let _ = child.kill();
                kill_at = None;
            }
            std::thread::sleep(poll_interval(started.elapsed()));
        };
        // Wait for the pipes to drain. A stopped ssh may leave a descendant holding them open; do not wait on it.
        let mut finished = 0;
        let stopped_at = Instant::now();
        while finished < readers {
            match done_rx.recv_timeout(Duration::from_millis(20)) {
                Ok(()) => finished += 1,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if ended.is_some() {
                        if stopped_at.elapsed() >= Duration::from_millis(500) { break }
                    } else if let Some(reason) = stop_reason() {
                        ended = Some(reason);
                        break;
                    }
                }
            }
        }
        let take = |capture: Option<Arc<Mutex<Capture>>>| -> (Vec<u8>, bool, Option<u64>) {
            match capture {
                Some(capture) => {
                    let capture = capture.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    (capture.bytes.clone(), capture.truncated, capture.first_ms)
                }
                None => (Vec::new(), false, None),
            }
        };
        let (out_bytes, out_truncated, first_output_ms) = take(out);
        let (err_bytes, err_truncated, _) = take(err);
        let code = exit.and_then(|status| status.code());
        let stderr = redact(decode_stderr(&err_bytes, self.legacy));
        RunResult {
            host: host.name.clone(),
            status: ended.unwrap_or_else(|| classify_exit(code, &stderr, request.sudo, with_password)),
            exit_code: if ended.is_none() { code } else { None },
            stdout: redact(String::from_utf8_lossy(&out_bytes).into_owned()),
            stderr,
            truncated: out_truncated || err_truncated,
            duration_ms: started.elapsed().as_millis() as u64,
            first_output_ms,
        }
    }

    fn workers(&self, jobs: usize) -> usize {
        (self.spec.concurrency.max(1) as usize).min(jobs)
    }

    /// Run every request, at most `ssh.concurrency` at once; results come back in input order.
    pub fn run_many(&self, requests: Vec<RunRequest>) -> Vec<RunResult> {
        let jobs: Vec<Mutex<Option<RunRequest>>> = requests.into_iter().map(|request| Mutex::new(Some(request))).collect();
        self.pooled(jobs.len(), |index| {
            let request = jobs[index].lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
            request.map(|request| self.run(request))
        })
    }

    /// Build and run one request per host with bounded parallelism, preserving host order. A build
    /// error (for example a secret lookup failure) is that host's failure, not the fleet's.
    pub fn run_many_with<F>(&self, hosts: &[Host], build: F) -> Vec<RunResult>
    where
        F: Fn(&Host) -> Result<RunRequest, String> + Sync,
    {
        self.pooled(hosts.len(), |index| {
            let host = &hosts[index];
            Some(match build(host) {
                Ok(request) => self.run(request),
                Err(error) => RunResult::without_run(&host.name, RunStatus::Failed, error),
            })
        })
    }

    fn pooled<F>(&self, jobs: usize, run: F) -> Vec<RunResult>
    where
        F: Fn(usize) -> Option<RunResult> + Sync,
    {
        let results: Vec<Mutex<Option<RunResult>>> = (0..jobs).map(|_| Mutex::new(None)).collect();
        let next = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..self.workers(jobs) {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    if index >= jobs { break }
                    let result = run(index);
                    *results[index].lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = result;
                });
            }
        });
        results
            .into_iter()
            .enumerate()
            .map(|(index, slot)| {
                slot.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner()).unwrap_or_else(|| RunResult::without_run(&format!("#{index}"), RunStatus::Failed, "the run did not complete"))
            })
            .collect()
    }
}
