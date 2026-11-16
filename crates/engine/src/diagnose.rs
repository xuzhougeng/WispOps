//! Connection diagnosis: where the path to a server breaks, without logging in.
//!
//! The destination is resolved the way ssh resolves it (`ssh -G`), then the name is looked up, a
//! TCP connection is opened to the SSH port (or the first ProxyJump hop) and the server's
//! identification line is read. Nothing is authenticated or run and no credential is touched; the
//! server only sees one connection that closes before key exchange.

use std::io::{ErrorKind, Read};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::jsre::js_trim;

/// Where ssh would connect for a host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshTarget {
    pub hostname: String,
    pub port: u16,
    /// First ProxyJump hop as `host[:port]`, when the connection goes through one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_jump: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub proxy_command: bool,
}

impl SshTarget {
    pub fn direct(hostname: &str, port: u16) -> Self {
        SshTarget { hostname: hostname.to_string(), port, proxy_jump: None, proxy_command: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosisStepName {
    Dns,
    Tcp,
    Banner,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosisStep {
    pub step: DiagnosisStepName,
    pub ok: bool,
    pub ms: u64,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Via {
    ProxyJump,
    ProxyCommand,
}

/// The first failing step, `proxy-command` when nothing can be tested directly, or `ok`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Ok,
    Dns,
    Tcp,
    Banner,
    ProxyCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnosis {
    pub host: String,
    /// What this machine actually connects to: the server, or the first jump host.
    pub target: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<Via>,
    pub steps: Vec<DiagnosisStep>,
    pub verdict: Verdict,
}

/// The destination fields of `ssh -G` output.
pub fn parse_ssh_g(output: &str, fallback_hostname: &str, fallback_port: Option<u16>) -> SshTarget {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in output.split('\n') {
        let line = js_trim(line);
        let Some(split) = line.find(crate::jsre::is_js_space) else { continue };
        let key = line[..split].to_lowercase();
        if !pairs.iter().any(|(known, _)| *known == key) { pairs.push((key, js_trim(&line[split..]).to_string())) }
    }
    let set = |key: &str| pairs.iter().find(|(known, _)| known == key).map(|(_, value)| value.as_str()).filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("none"));
    let port = set("port").and_then(|port| port.parse::<u32>().ok()).filter(|port| *port > 0 && *port < 65536).map(|port| port as u16);
    let jump = set("proxyjump").and_then(|jump| jump.split(',').next()).map(|hop| {
        let hop = hop.strip_prefix("ssh://").unwrap_or(hop);
        match hop.find('@') {
            Some(at) => hop[at + 1..].to_string(),
            None => hop.to_string(),
        }
    });
    SshTarget {
        hostname: set("hostname").unwrap_or(fallback_hostname).to_string(),
        port: port.or(fallback_port).unwrap_or(22),
        proxy_jump: jump.filter(|jump| !jump.is_empty()),
        proxy_command: set("proxycommand").is_some(),
    }
}

/// `host`, `host:port` or `[v6]:port` of a jump hop.
fn split_hop(hop: &str) -> (String, u16) {
    if let Some(rest) = hop.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        let after = &rest[close + 1..];
        if after.is_empty() { return (rest[..close].to_string(), 22) }
        if let Some(port) = after.strip_prefix(':')
            && !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
        {
            return (rest[..close].to_string(), port.parse().unwrap_or(22));
        }
    }
    if let Some(colon) = hop.rfind(':')
        && colon > 0
        && hop.find(':') == Some(colon)
    {
        let port = hop[colon + 1..].parse::<u16>().ok().filter(|port| *port > 0).unwrap_or(22);
        return (hop[..colon].to_string(), port);
    }
    (hop.to_string(), 22)
}

/// Keep a remote identification line printable and short before it reaches a person.
fn printable(line: &str) -> String {
    line.chars().filter(|c| (' '..='~').contains(c)).take(120).collect()
}

/// A short code for a socket error, in the vocabulary the plugin's records use.
fn error_code(error: &std::io::Error) -> String {
    match error.kind() {
        ErrorKind::ConnectionRefused => "ECONNREFUSED".to_string(),
        ErrorKind::TimedOut | ErrorKind::WouldBlock => "ETIMEDOUT".to_string(),
        ErrorKind::ConnectionReset => "ECONNRESET".to_string(),
        ErrorKind::HostUnreachable => "EHOSTUNREACH".to_string(),
        ErrorKind::NetworkUnreachable => "ENETUNREACH".to_string(),
        ErrorKind::ConnectionAborted => "ECONNABORTED".to_string(),
        ErrorKind::AddrNotAvailable => "EADDRNOTAVAIL".to_string(),
        _ => error.to_string(),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// Read until a line starting with `SSH-`; servers may print other lines first (RFC 4253 §4.2).
fn read_banner(mut socket: TcpStream, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err("no identification within the time limit".to_string()) }
        let _ = socket.set_read_timeout(Some(remaining));
        match socket.read(&mut chunk) {
            Ok(0) => return Err(if buffer.is_empty() { "closed without an identification line" } else { "no SSH identification line" }.to_string()),
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                // Latin-1: every byte is one character, so nothing is lost before filtering.
                let text: String = buffer.iter().map(|b| *b as char).collect();
                let mut lines: Vec<&str> = text.split('\n').collect();
                lines.pop();
                if let Some(line) = lines.iter().map(|line| line.strip_suffix('\r').unwrap_or(line)).find(|line| line.starts_with("SSH-")) {
                    return Ok(printable(line));
                }
                if buffer.len() > 8192 { return Err("no SSH identification line".to_string()) }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Err("no identification within the time limit".to_string()),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error_code(&error)),
        }
    }
}

/// Diagnose the path to one resolved target. Blocks for at most a few multiples of `timeout_ms`.
pub fn diagnose_target(host: &str, target: &SshTarget, timeout_ms: u64) -> Diagnosis {
    if target.proxy_command && target.proxy_jump.is_none() {
        return Diagnosis { host: host.to_string(), target: target.hostname.clone(), port: target.port, via: Some(Via::ProxyCommand), steps: Vec::new(), verdict: Verdict::ProxyCommand };
    }
    let (hop_host, hop_port) = match &target.proxy_jump {
        Some(jump) => split_hop(jump),
        None => (target.hostname.clone(), target.port),
    };
    let mut diagnosis = Diagnosis {
        host: host.to_string(),
        target: hop_host.clone(),
        port: hop_port,
        via: target.proxy_jump.as_ref().map(|_| Via::ProxyJump),
        steps: Vec::new(),
        verdict: Verdict::Ok,
    };
    let address: IpAddr = match hop_host.parse::<IpAddr>() {
        Ok(address) => address,
        Err(_) => {
            let started = Instant::now();
            match (hop_host.as_str(), hop_port).to_socket_addrs().ok().and_then(|mut addresses| addresses.next()) {
                Some(resolved) => {
                    diagnosis.steps.push(DiagnosisStep { step: DiagnosisStepName::Dns, ok: true, ms: elapsed_ms(started), detail: resolved.ip().to_string() });
                    resolved.ip()
                }
                None => {
                    diagnosis.steps.push(DiagnosisStep { step: DiagnosisStepName::Dns, ok: false, ms: elapsed_ms(started), detail: "ENOTFOUND".to_string() });
                    diagnosis.verdict = Verdict::Dns;
                    return diagnosis;
                }
            }
        }
    };
    let started = Instant::now();
    let socket = match TcpStream::connect_timeout(&SocketAddr::new(address, hop_port), Duration::from_millis(timeout_ms.max(1))) {
        Ok(socket) => socket,
        Err(error) => {
            diagnosis.steps.push(DiagnosisStep { step: DiagnosisStepName::Tcp, ok: false, ms: elapsed_ms(started), detail: error_code(&error) });
            diagnosis.verdict = Verdict::Tcp;
            return diagnosis;
        }
    };
    diagnosis.steps.push(DiagnosisStep { step: DiagnosisStepName::Tcp, ok: true, ms: elapsed_ms(started), detail: format!("{address}:{hop_port}") });
    let started = Instant::now();
    match read_banner(socket, Duration::from_millis(timeout_ms.clamp(1, 10_000))) {
        Ok(line) => diagnosis.steps.push(DiagnosisStep { step: DiagnosisStepName::Banner, ok: true, ms: elapsed_ms(started), detail: line }),
        Err(error) => {
            diagnosis.steps.push(DiagnosisStep { step: DiagnosisStepName::Banner, ok: false, ms: elapsed_ms(started), detail: error });
            diagnosis.verdict = Verdict::Banner;
        }
    }
    diagnosis
}
