//! Read host aliases out of OpenSSH client configuration so they can be added to the inventory.
//!
//! Only literal `Host` entries are offered; wildcard patterns and `Match` blocks are skipped.
//! Imported hosts connect through their alias, so the keys, jump hosts and options in
//! ssh_config keep applying.

use std::collections::{HashSet, VecDeque};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::{HostSpec, is_valid_name};
use crate::fsutil::expand_home;
use crate::inventory::glob_match;
use crate::jsre::{is_js_space, js_re, js_trim};

pub const DEFAULT_SSH_CONFIG: &str = "~/.ssh/config";
const MAX_FILES: usize = 30;
const MAX_DEPTH: usize = 3;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigHost {
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_jump: Option<String>,
    /// File the alias was read from.
    pub source: String,
}

/// One parsed file: its literal hosts and the `Include` arguments it names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedSshConfig {
    pub hosts: Vec<SshConfigHost>,
    pub includes: Vec<String>,
}

/// Keyword and arguments of one line; OpenSSH accepts `Key Value`, `Key=Value` and double quotes.
fn split_line(line: &str) -> Option<(String, Vec<String>)> {
    let trimmed = js_trim(line);
    if trimmed.is_empty() || trimmed.starts_with('#') { return None }
    let Some(captures) = js_re!(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$").captures(trimmed) else { return Some((trimmed.to_lowercase(), Vec::new())) };
    let args = js_re!(r#""([^"]*)"|(\S+)"#)
        .captures_iter(&captures[2])
        .map(|m| m.get(1).or_else(|| m.get(2)).map_or(String::new(), |g| g.as_str().to_string()))
        .collect();
    Some((captures[1].to_lowercase(), args))
}

/// Parse one file. The first block naming an alias wins, as in OpenSSH.
pub fn parse_ssh_config(text: &str, source: &str) -> ParsedSshConfig {
    let mut hosts: Vec<SshConfigHost> = Vec::new();
    let mut includes = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // Indexes into `hosts` of the block being read.
    let mut current: Vec<usize> = Vec::new();
    let mut skipping = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some((key, args)) = split_line(line) else { continue };
        match key.as_str() {
            "include" => {
                includes.extend(args);
                continue;
            }
            "match" => {
                current.clear();
                skipping = true;
                continue;
            }
            "host" => {
                current.clear();
                skipping = false;
                for pattern in args {
                    // Patterns, option-like words and names with whitespace cannot be inventory destinations.
                    if pattern.chars().any(|c| matches!(c, '*' | '?' | '!') || is_js_space(c)) || pattern.starts_with('-') || seen.contains(&pattern) { continue }
                    seen.insert(pattern.clone());
                    current.push(hosts.len());
                    hosts.push(SshConfigHost { alias: pattern, source: source.to_string(), ..SshConfigHost::default() });
                }
                continue;
            }
            _ => {}
        }
        if skipping || current.is_empty() { continue }
        let Some(value) = args.first().filter(|value| !value.is_empty()) else { continue };
        for index in &current {
            let host = &mut hosts[*index];
            match key.as_str() {
                "hostname" if host.host_name.is_none() => host.host_name = Some(value.clone()),
                "user" if host.user.is_none() => host.user = Some(value.clone()),
                "port" if host.port.is_none() => {
                    if value.len() <= 5 && value.bytes().all(|b| b.is_ascii_digit()) {
                        let port: u32 = value.parse().unwrap_or(0);
                        if port > 0 && port <= 65535 { host.port = Some(port) }
                    }
                }
                "identityfile" if host.identity_file.is_none() => host.identity_file = Some(value.clone()),
                "proxyjump" if host.proxy_jump.is_none() => host.proxy_jump = Some(value.clone()),
                _ => {}
            }
        }
    }
    ParsedSshConfig { hosts, includes }
}

/// The hosts of a configuration and the files it includes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshConfigHosts {
    /// The main file, with `~` expanded.
    pub path: String,
    pub hosts: Vec<SshConfigHost>,
}

fn has_glob(text: &str) -> bool {
    text.chars().any(|c| matches!(c, '*' | '?' | '[' | ']'))
}

/// Read a configuration and the files it includes (relative paths resolve against the main file's directory).
pub fn load_ssh_config_hosts(path: &str) -> Result<SshConfigHosts, String> {
    let root = expand_home(path);
    let root_dir = Path::new(&root).parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let mut hosts: Vec<SshConfigHost> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::from([(PathBuf::from(&root), 0)]);
    while visited.len() < MAX_FILES {
        let Some((file, depth)) = queue.pop_front() else { break };
        if !visited.insert(file.clone()) { continue }
        let text = match std::fs::read(&file) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::IsADirectory | ErrorKind::PermissionDenied) => continue,
            Err(error) => return Err(format!("cannot read {}: {error}", file.display())),
        };
        let parsed = parse_ssh_config(&text, &file.to_string_lossy());
        for host in parsed.hosts {
            if seen.insert(host.alias.clone()) { hosts.push(host) }
        }
        if depth >= MAX_DEPTH { continue }
        for pattern in parsed.includes {
            let expanded = if Path::new(&pattern).is_absolute() || pattern.starts_with('~') { PathBuf::from(expand_home(&pattern)) } else { root_dir.join(&pattern) };
            let dir = expanded.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
            let base = expanded.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
            if has_glob(&dir.to_string_lossy()) { continue }
            if has_glob(&base) {
                // Only `*` and `?` are wildcards here; brackets are matched literally.
                let mut names: Vec<String> = match std::fs::read_dir(&dir) {
                    Ok(entries) => entries.filter_map(|entry| entry.ok()).map(|entry| entry.file_name().to_string_lossy().into_owned()).collect(),
                    Err(_) => Vec::new(),
                };
                names.retain(|name| glob_match(&base, name));
                names.sort();
                for name in names {
                    queue.push_back((dir.join(name), depth + 1));
                }
            } else {
                queue.push_back((expanded, depth + 1));
            }
        }
    }
    Ok(SshConfigHosts { path: root, hosts })
}

/// An inventory name for an alias; OpenSSH allows characters the inventory does not, and `all` is a selector.
pub fn inventory_name_for(alias: &str) -> String {
    let replaced = js_re!(r"[^A-Za-z0-9._-]+").replace_all(alias, "-");
    let cleaned: String = js_re!(r"^[^A-Za-z0-9]+").replace(&replaced, "").chars().take(100).collect();
    if is_valid_name(&cleaned) && cleaned != "all" {
        cleaned
    } else {
        format!("host-{}", if cleaned.is_empty() { "x" } else { &cleaned }).chars().take(100).collect()
    }
}

/// Human-readable destination for a host list.
pub fn describe_ssh_config_host(host: &SshConfigHost) -> String {
    format!(
        "{}{}{}",
        host.user.as_ref().map(|user| format!("{user}@")).unwrap_or_default(),
        host.host_name.as_deref().unwrap_or(&host.alias),
        host.port.map(|port| format!(":{port}")).unwrap_or_default()
    )
}

/// The inventory entry for an alias. It connects through the alias itself, so ProxyJump,
/// IdentityFile and every other option stay in ssh_config; only display details are copied.
pub fn ssh_config_host_spec(host: &SshConfigHost) -> HostSpec {
    let name = inventory_name_for(&host.alias);
    let detail = if host.host_name.is_none() && host.user.is_none() && host.port.is_none() { String::new() } else { format!(" → {}", describe_ssh_config_host(host)) };
    HostSpec {
        ssh: if name == host.alias { None } else { Some(host.alias.clone()) },
        groups: vec!["ssh-config".to_string()],
        description: Some(format!("ssh_config {}{detail}", host.alias)),
        ..HostSpec::named(&name)
    }
}
