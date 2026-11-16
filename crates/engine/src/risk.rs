//! Shell command risk classification.
//!
//! The classifier is fail-closed: a command is `read` only when every simple command in it is a
//! known read-only program used in a read-only way and no output is redirected into a file.
//! Anything unrecognized is at least `change`. Pattern matching can never fully understand shell,
//! so this is a policy input, not a sandbox: approval and grants are the enforcement.
//!
//! The tables are the plugin's, pattern for pattern. Where the original used regular-expression
//! look-around the rule is rewritten by hand; each rewrite is noted and covered by a test.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::jsre::{compile, js_re, js_trim};

/// Ordered risk levels; each level includes everything below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Read,
    Change,
    Destructive,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Read => "read",
            RiskLevel::Change => "change",
            RiskLevel::Destructive => "destructive",
        }
    }
}

/// Classification of one command string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Highest level found in any segment.
    pub level: RiskLevel,
    /// Whether the command itself escalates privilege (sudo, su, doas, pkexec).
    pub elevates: bool,
    /// Human-readable reasons for every non-read finding, deduplicated.
    pub reasons: Vec<String>,
}

impl RiskAssessment {
    /// A read-only action with nothing to report.
    pub fn read() -> Self {
        RiskAssessment { level: RiskLevel::Read, elevates: false, reasons: Vec::new() }
    }
}

/// Destructive patterns are matched against the whole command text.
///
/// Three originals ended in look-ahead. `(?=\s|$)` at the very end of a pattern that is only
/// tested for a match is the same as consuming `(?:\s|$)`. In `-?1\b(?!\d)` the look-ahead is
/// implied by `\b`: after the word character `1`, a boundary already excludes a following digit.
const DESTRUCTIVE_PATTERNS: &[(&str, &str, &str)] = &[
    (r#"(?:^|[\s;&|(`'"])(?:rm|unlink|shred|rmdir)(?:\s|$)"#, "", "deletes files"),
    (r"\bfind\b[^;&|]*\s-delete\b", "", "bulk-deletes files with find -delete"),
    (r"\bfind\b[^;&|]*\s-exec(?:dir)?\s+(?:\S*\/)?(?:rm|unlink|shred)\b", "", "bulk-deletes files with find -exec rm"),
    (r"\bxargs\b[^;&|]*\b(?:rm|unlink|shred)\b", "", "bulk-deletes files with xargs rm"),
    (r"\b(?:python3?|perl|ruby|php|node)\b.*\b(?:unlink(?:Sync)?|rmtree|rmSync|os\.remove|shutil\.rmtree)\b", "", "deletes files from an interpreter"),
    (r"\b(?:mkfs(?:\.\w+)?|wipefs|fdisk|sfdisk|parted|sgdisk|mkswap)\b", "", "formats or repartitions a disk"),
    (r"\bdd\b[^;&|]*\bof=", "", "writes raw data with dd"),
    (r">\s*\/dev\/(?:sd|nvme|vd|xvd|hd|md|dm-|mapper\/)", "", "overwrites a block device"),
    (r"\btruncate\b[^;&|]*\s-s\b", "", "truncates files"),
    (r#"(?:^|[\s;&|(`'"])(?:reboot|shutdown|poweroff|halt)\b"#, "", "reboots or shuts down the host"),
    (r"\binit\s+[06]\b", "", "reboots or shuts down the host"),
    (r"\bsystemctl\s+(?:\S+\s+)*(?:reboot|poweroff|halt|kexec|rescue|emergency)\b", "", "reboots or shuts down the host"),
    (r"\bkill\s+(?:-\S+\s+)*-?1\b", "", "signals every process (kill -1 / kill 1)"),
    (r"\bdocker\s+(?:(?:container|image|volume|network|system|builder)\s+)?(?:rm|rmi|prune)\b", "", "removes containers, images, or volumes"),
    (r"\b(?:kubectl\s+delete|helm\s+(?:uninstall|delete)|terraform\s+destroy)\b", "", "destroys deployed resources"),
    (r"\b(?:drop\s+(?:database|schema|table|user)|truncate\s+table)\b", "i", "destroys database objects"),
    (r"\bgit\s+(?:clean\s+-\S*f|reset\s+--hard|push\s+(?:\S+\s+)*(?:-f|--force))\b", "", "irreversibly discards git state"),
    (r"\b(?:userdel|groupdel)\b", "", "deletes accounts"),
    (r"\bcrontab\s+(?:\S+\s+)*-r\b", "", "removes a crontab"),
    (r"\b(?:lvremove|vgremove|pvremove|zfs\s+destroy|zpool\s+destroy|btrfs\s+subvolume\s+delete)\b", "", "destroys storage volumes"),
    (r"\b(?:iptables|ip6tables|nft)\s+(?:\S+\s+)*(?:-F|--flush|flush)\b", "", "flushes firewall rules"),
    (r"\bchmod\s+(?:\S+\s+)*-R\s+(?:\S+\s+)?\/(?:\s|$)|\bchown\s+(?:\S+\s+)*-R\s+(?:\S+\s+)?\/(?:\s|$)", "", "recursively changes permissions on /"),
    (r"\b(?:chmod|chown|chgrp)\s+(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)\b|\b(?:chmod|chown|chgrp)\s+(?:\S+\s+)*(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)\s", "", "recursively changes ownership or permissions of a tree"),
    (r"\bjournalctl\b[^;&|]*--vacuum-", "", "deletes journal files"),
    (r"\b(?:apt-get|apt|yum|dnf|zypper|apk|pacman)\s+(?:\S+\s+)*(?:remove|purge|autoremove|erase|del)\b", "", "removes packages"),
    (r"\bscancel\b[^;&|]*(?:\s-u\b|--user|\s--all\b)", "", "cancels jobs in bulk"),
    (r"\brsync\b[^;&|]*\s--(?:delete(?:-\w+)?|remove-source-files)\b", "", "deletes files with rsync"),
    (r"\btar\b[^;&|]*\s--remove-files\b", "", "deletes source files with tar"),
    (r"\bcp\s+(?:-\S+\s+)*\/dev\/null\s+\S", "", "truncates a file by copying /dev/null over it"),
    (r"\bmv\s+(?:-\S+\s+)*(?:\S+\s+)+(?:\/tmp|\/var\/tmp|\/dev\/shm|\/dev\/null)(?:\/\S*)?(?:\s|$)", "", "moves data into volatile storage or /dev/null"),
    (r#"(?:^|[\s;&|(`'"])(?:pkill|killall)(?:\s|$)"#, "", "kills processes by name or pattern"),
    (r#"(?:^|[\s;&|(`'"])kill\s+(?:-\S+\s+)*(?:-9|-KILL|-SIGKILL|-s\s+(?:9|KILL|SIGKILL))\b"#, "", "force-kills processes (SIGKILL)"),
];

static DESTRUCTIVE: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    DESTRUCTIVE_PATTERNS
        .iter()
        .map(|(pattern, flags, reason)| (compile(pattern, flags).expect("valid built-in pattern"), *reason))
        .collect()
});

fn is_assignment(token: &str) -> bool {
    js_re!(r"^[A-Za-z_][A-Za-z0-9_]*=").is_match(token)
}

/// A segment that only truncates: `> file`, `: > file`, `true > file`, `cat /dev/null > file`, `echo -n > file`.
fn truncates_only(tokens: &[String]) -> bool {
    let Some(first) = tokens.iter().find(|token| !is_assignment(token)) else { return true };
    if first == ":" || first == "true" { return true }
    let rest = tokens.get(1..).unwrap_or(&[]);
    if first == "cat" { return rest.iter().all(|t| t == "/dev/null" || t.starts_with('-')) }
    if first == "echo" || first == "printf" {
        return rest.iter().all(|t| js_re!(r"^-[neE]+$").is_match(t) || t.is_empty() || t == "\"\"" || t == "''");
    }
    false
}

/// The file a `>` / `>|` redirection writes (not an append, a descriptor duplication, or /dev/null).
fn truncation_target(segment: &str) -> Option<String> {
    for captures in js_re!(r"(?:^|[^<>&0-9])(?:\d)?>\|?\s*(\S+)").captures_iter(segment) {
        let whole = captures.get(0).map_or("", |m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        if whole.contains(">>") { continue }
        if target.starts_with('&') || target.starts_with("/dev/null") || js_re!(r"^\/dev\/(?:std(?:out|err)|fd\/\d)$").is_match(target) { continue }
        return Some(target.to_string());
    }
    None
}

/// Programs that only read state when used without write flags.
const READ_PROGRAMS: &[&str] = &[
    "ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "zcat", "less", "more",
    "wc", "sort", "uniq", "cut", "tr", "column", "nl", "rev", "tac", "paste", "join", "comm", "diff", "cmp",
    "echo", "printf", "true", "false", "test", "[", "date", "cal", "sleep", "seq", "expr", "basename", "dirname",
    "readlink", "realpath", "stat", "file", "md5sum", "sha1sum", "sha256sum", "cksum", "tree", "pwd", "cd",
    "hostname", "hostnamectl", "uname", "whoami", "id", "groups", "who", "w", "last", "lastlog", "users", "getent",
    "uptime", "free", "df", "du", "ps", "pgrep", "pstree", "top", "htop", "vmstat", "iostat", "mpstat", "pidstat",
    "sar", "nproc", "lscpu", "lsblk", "blkid", "lsmem", "lspci", "lsusb", "lsmod", "lsof", "fuser", "findmnt",
    "dmesg", "journalctl", "systemctl", "service", "timedatectl", "loginctl", "ss", "netstat", "ip", "ifconfig",
    "route", "ping", "traceroute", "tracepath", "dig", "nslookup", "host", "curl", "which", "whereis", "type",
    "command", "env", "printenv", "locale", "getconf", "ulimit", "sysctl", "find", "sed", "awk", "gawk", "mawk",
    "jq", "xargs", "nvidia-smi", "nvtop", "gpustat", "rocm-smi", "sinfo", "squeue", "sacct", "sshare", "sprio",
    "sstat", "scontrol", "docker", "podman", "crictl", "kubectl", "crontab", "git", "apt", "dpkg", "dpkg-query",
    "rpm", "pip", "pip3", "conda", "mamba", "module", "smartctl", "mdadm", "zpool", "zfs", "mount", "quota",
    "repquota", "iotop", "tcpdump", "strings", "od", "hexdump", "xxd", "base64", "timeout", "nice", "ionice",
    "time", "stdbuf", "nohup", "exec", "watch", "openssl", "ldd", "cat", "python", "python3", "tmux", "screen",
];

/// Wrapper programs whose real command follows their own options.
const WRAPPERS: &[&str] = &["sudo", "doas", "timeout", "nice", "ionice", "time", "stdbuf", "nohup", "exec", "command", "env", "xargs", "watch"];

const ELEVATORS: &[&str] = &["sudo", "su", "doas", "pkexec", "run0"];

/// One simple-command span; `masked` has quoted operators blanked, same length as `text`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub text: String,
    pub masked: String,
}

/// Length of the shell separator starting at byte `i` of `bytes`, or 0.
///
/// Hand-written form of `\|\||&&|\|&?|;|(?<![<>])&(?!>)|\n|`|\$\(|[(){}]`: the alternatives are
/// tried in that order, and a lone `&` separates only when it is neither preceded by `<` or `>`
/// (`>&2`, `<&3`) nor followed by `>` (`&>file`).
fn separator_len(bytes: &[u8], i: usize) -> usize {
    let next = bytes.get(i + 1).copied();
    match bytes[i] {
        b'|' => if next == Some(b'|') || next == Some(b'&') { 2 } else { 1 },
        b'&' => {
            if next == Some(b'&') { return 2 }
            let after_redirect = i > 0 && (bytes[i - 1] == b'<' || bytes[i - 1] == b'>');
            if after_redirect || next == Some(b'>') { 0 } else { 1 }
        }
        b';' | b'\n' | b'`' | b'(' | b')' | b'{' | b'}' => 1,
        b'$' if next == Some(b'(') => 2,
        _ => 0,
    }
}

/// Split a command into simple-command segments on shell operators and substitutions.
pub fn split_segments(command: &str) -> Vec<Segment> {
    let source = command.replace("\\\n", "  ");
    let masked = mask_quoted(&source);
    let bytes = masked.as_bytes();
    let mut segments = Vec::new();
    let mut push = |start: usize, end: usize| {
        // Separators are ASCII and masking keeps every byte offset, so both slices are on boundaries.
        let text = &source[start..end];
        if !js_trim(text).is_empty() {
            segments.push(Segment { text: js_trim(text).to_string(), masked: js_trim(&masked[start..end]).to_string() });
        }
    };
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let len = separator_len(bytes, i);
        if len == 0 {
            i += 1;
            continue;
        }
        push(start, i);
        i += len;
        start = i;
    }
    push(start, source.len());
    segments
}

/// Whitespace tokenization that keeps quoted spans together and strips the quotes.
pub fn tokenize(segment: &str) -> Vec<String> {
    js_re!(r#""((?:\\.|[^"\\])*)"|'([^']*)'|(\S+)"#)
        .captures_iter(segment)
        .map(|captures| captures.get(1).or_else(|| captures.get(2)).or_else(|| captures.get(3)).map_or(String::new(), |m| m.as_str().to_string()))
        .collect()
}

/// Program name after leading assignments; the basename of a path.
fn program_of(tokens: &[String], start: usize) -> Option<(String, usize)> {
    let mut index = start;
    while index < tokens.len() && is_assignment(&tokens[index]) {
        index += 1;
    }
    let token = tokens.get(index)?;
    let program = match token.rfind('/') {
        Some(slash) => &token[slash + 1..],
        None => token.as_str(),
    };
    Some((program.to_string(), index))
}

/// Skip a wrapper's own options (and the duration argument of timeout).
fn skip_wrapper_args(program: &str, tokens: &[String], index: usize) -> usize {
    let valued: &[&str] = match program {
        "sudo" => &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"],
        "nice" => &["-n"],
        "ionice" => &["-c", "-n", "-p"],
        "timeout" => &["-s", "-k", "--signal", "--kill-after"],
        "xargs" => &["-n", "-P", "-I", "-L", "-s", "-d", "-E", "-a"],
        "watch" => &["-n", "-d"],
        "stdbuf" => &["-i", "-o", "-e"],
        _ => &[],
    };
    let mut i = index + 1;
    while i < tokens.len() {
        let token = tokens[i].as_str();
        if token == "--" {
            i += 1;
            break;
        }
        if !token.starts_with('-') { break }
        i += if valued.contains(&token) { 2 } else { 1 };
    }
    if program == "timeout" && i < tokens.len() { i += 1 }
    if program == "env" {
        while i < tokens.len() && is_assignment(&tokens[i]) {
            i += 1;
        }
    }
    i
}

/// Decide whether one known-read program is used in a writing way.
fn read_program_writes(program: &str, args: &[String]) -> Option<String> {
    let joined = format!(" {} ", args.join(" "));
    let joined = joined.as_str();
    let first = args.iter().find(|a| !a.starts_with('-')).map(String::as_str).unwrap_or("");
    let when = |writes: bool, reason: &str| if writes { Some(reason.to_string()) } else { None };
    match program {
        "systemctl" | "service" => {
            let verbs = js_re!(r"\s(start|stop|restart|reload|try-restart|reload-or-restart|enable|disable|mask|unmask|kill|isolate|daemon-reload|set-property|edit|link|revert|preset|reset-failed)\s");
            when(verbs.is_match(joined), &format!("{program} changes service state"))
        }
        "journalctl" => when(js_re!(r"\s--(?:rotate|flush|sync|relinquish-var|setup-keys)\b").is_match(joined), "journalctl maintenance"),
        "find" => when(js_re!(r"\s-(?:exec|execdir|ok|okdir|fprint|fprint0|fprintf|fls)\s").is_match(joined), "find runs commands or writes files"),
        "sed" => when(js_re!(r"\s(?:-i\S*|--in-place\S*)\s|\s-[a-zA-Z]*i[a-zA-Z]*\s").is_match(joined), "sed edits files in place"),
        "awk" | "gawk" | "mawk" => when(js_re!(r"system\s*\(|print[^;}]*>|\|\s*getline|-i\s+inplace").is_match(joined), "awk runs commands or writes files"),
        "curl" => when(
            js_re!(r"\s(?:-o|-O|--output|--remote-name|-T|--upload-file|-d|--data\S*|-F|--form)\s|\s-X\s*(?:POST|PUT|DELETE|PATCH)\b|\s--request\s+(?:POST|PUT|DELETE|PATCH)\b", "i").is_match(joined),
            "curl writes files or sends data",
        ),
        "ip" => when(js_re!(r"\s(?:add|del|delete|change|replace|set|flush|append)\s").is_match(joined), "ip changes network configuration"),
        "sysctl" => when(js_re!(r"\s-w\s|=|\s-p\b|\s--load\b|\s--system\b").is_match(joined), "sysctl writes kernel parameters"),
        "docker" | "podman" => {
            const READ_VERBS: &[&str] = &["ps", "images", "inspect", "logs", "info", "version", "stats", "top", "port", "history", "events", "df", "ls", "diff"];
            const NOUNS: &[&str] = &["system", "container", "image", "volume", "network", "compose", "buildx", "node", "service"];
            let words: Vec<&str> = args.iter().filter(|a| !a.starts_with('-')).map(String::as_str).collect();
            let verb = if NOUNS.contains(&words.first().copied().unwrap_or("")) { words.get(1).copied() } else { words.first().copied() };
            if words.first() == Some(&"stats") && !joined.contains("--no-stream") {
                return Some("docker stats streams forever; add --no-stream".to_string());
            }
            match verb {
                Some(verb) if READ_VERBS.contains(&verb) => None,
                _ => Some(format!("{program} {} changes containers", words.iter().take(2).copied().collect::<Vec<_>>().join(" "))),
            }
        }
        "crictl" => when(!["ps", "images", "inspect", "logs", "info", "version", "stats", "pods"].contains(&first), "crictl changes containers"),
        "kubectl" => when(
            !(["get", "describe", "logs", "top", "version", "explain", "api-resources", "cluster-info", "config"].contains(&first)
                && !js_re!(r"\sconfig\s+(?:set|use|delete|rename)").is_match(joined)),
            "kubectl changes cluster state",
        ),
        "scontrol" => when(!["show", "ping", "version", "listpids"].contains(&first), "scontrol changes Slurm state"),
        "crontab" => when(!js_re!(r"\s-l\s").is_match(joined), "crontab edits schedules"),
        "git" => when(
            !(["status", "log", "diff", "show", "branch", "remote", "rev-parse", "describe", "blame", "ls-files", "shortlog", "tag"].contains(&first)
                && !js_re!(r"\s(?:-d|-D|--delete|add|set-url|remove|rm)\s").is_match(joined)),
            "git changes the repository",
        ),
        "apt" => when(!["list", "show", "policy", "search", "depends", "rdepends"].contains(&first), "apt changes packages"),
        "dpkg" => when(js_re!(r"\s-(?:i|r|P|-install|-remove|-purge|-configure|-unpack)\b").is_match(joined), "dpkg changes packages"),
        "rpm" => when(js_re!(r"\s-(?:i|U|F|e)\S*|\s--(?:install|upgrade|freshen|erase|import|rebuilddb)\b").is_match(joined), "rpm changes packages"),
        "pip" | "pip3" => when(
            !(["list", "show", "freeze", "check", "config", "cache"].contains(&first) && !js_re!(r"\scache\s+(?:purge|remove)\b").is_match(joined)),
            "pip changes packages",
        ),
        "conda" | "mamba" => when(
            !(["list", "info", "search", "env"].contains(&first) && !js_re!(r"\senv\s+(?:create|remove|update)\b").is_match(joined)),
            "conda changes environments",
        ),
        "mount" => when(!(args.is_empty() || js_re!(r"^\s+(?:-l|-t\s+\S+)\s*$").is_match(joined)), "mount changes mounts"),
        "zpool" | "zfs" => when(!["list", "status", "get", "iostat", "history"].contains(&first), &format!("{program} changes storage")),
        "mdadm" => when(!js_re!(r"\s--(?:detail|examine|query)\b|\s-D\b|\s-E\b|\s-Q\b").is_match(joined), "mdadm changes arrays"),
        "nvidia-smi" => when(
            js_re!(r"\s(?:-pm|-r|--gpu-reset|-pl|--power-limit|-ac|--applications-clocks|-rac|-c|--compute-mode|-e|--ecc-config|-mig|-lgc|-rgc|-lmc|-rmc)\b").is_match(joined),
            "nvidia-smi changes GPU settings",
        ),
        "smartctl" => when(js_re!(r"\s(?:-s|--smart|-t|--test|-X|--abort|-o|--offlineauto)\b").is_match(joined), "smartctl changes drive settings"),
        "openssl" => when(js_re!(r"\s-out\s").is_match(joined), "openssl writes files"),
        "python" | "python3" => when(!(args.is_empty() || js_re!(r"^\s+(?:-V|--version)\s*$").is_match(joined)), "runs an interpreter script"),
        "tmux" | "screen" => when(!js_re!(r"\s(?:ls|list-sessions|-ls|-list)\s").is_match(joined), &format!("{program} starts or controls sessions")),
        "tcpdump" => when(js_re!(r"\s-w\s").is_match(joined), "tcpdump writes capture files"),
        _ => None,
    }
}

/// Output redirection into anything but /dev/null or another descriptor writes a file.
fn redirects_to_file(segment: &str) -> bool {
    for captures in js_re!(r"(?:^|[^<>&0-9])(?:\d|&)?>>?\|?\s*(\S+)?").captures_iter(segment) {
        let Some(target) = captures.get(1).map(|m| m.as_str()) else { return true };
        if target.starts_with('&') || target.starts_with("/dev/null") { continue }
        if js_re!(r"^(?:\/dev\/std(?:out|err)|\/dev\/fd\/\d)$").is_match(target) { continue }
        return true;
    }
    false
}

/// Blank shell operators inside quoted spans, preserving every offset.
pub fn mask_quoted(command: &str) -> String {
    js_re!(r#"'[^']*'|"(?:\\.|[^"\\])*""#)
        .replace_all(command, |captures: &regex::Captures<'_>| {
            captures[0]
                .chars()
                .map(|c| if matches!(c, ';' | '&' | '|' | '`' | '(' | ')' | '<' | '>' | '{' | '}' | '\n' | '$') { ' ' } else { c })
                .collect::<String>()
        })
        .into_owned()
}

const SKIPPED_WORDS: &[&str] = &["!", "then", "do", "else", "fi", "done", "esac"];
const SHELL_KEYWORDS: &[&str] = &[
    "for", "while", "until", "if", "case", "in", "function", "select", "local", "export", "readonly", "declare", "set", "shift", "return", "break",
    "continue", "unset", "read",
];

/// Classify one shell command string.
pub fn classify_command(command: &str, extra_read_programs: &HashSet<String>) -> RiskAssessment {
    let mut reasons: Vec<String> = Vec::new();
    let mut level = RiskLevel::Read;
    let mut elevates = false;
    let mut raise = |to: RiskLevel, reason: String| {
        if to > level { level = to }
        if !reasons.contains(&reason) { reasons.push(reason) }
    };

    // Quoted text is matched too: `sh -c 'rm -rf x'` must not hide a deletion,
    // at the cost of flagging `grep 'reboot' log` for approval.
    for (pattern, reason) in DESTRUCTIVE.iter() {
        if pattern.is_match(command) { raise(RiskLevel::Destructive, reason.to_string()) }
    }

    for segment in split_segments(command) {
        if redirects_to_file(&segment.masked) { raise(RiskLevel::Change, "redirects output into a file".to_string()) }
        let tokens = tokenize(&segment.text);
        // `> file` with nothing meaningful before it empties an existing file: as irreversible as deleting it.
        if let Some(truncated) = truncation_target(&segment.masked) {
            let without_redirects = js_re!(r"(?:^|[^<>&0-9])(?:\d)?>\|?\s*\S+").replace_all(&segment.masked, " ");
            if truncates_only(&tokenize(&without_redirects)) { raise(RiskLevel::Destructive, format!("truncates {truncated}")) }
        }
        let mut found = program_of(&tokens, 0);
        while let Some((program, index)) = found.clone() {
            if !WRAPPERS.contains(&program.as_str()) { break }
            if ELEVATORS.contains(&program.as_str()) { elevates = true }
            if program == "command" && js_re!(r"^-[vV]$").is_match(tokens.get(index + 1).map_or("", String::as_str)) {
                found = None;
                break;
            }
            if program == "env" && index + 1 >= tokens.len() {
                found = None;
                break;
            }
            found = program_of(&tokens, skip_wrapper_args(&program, &tokens, index));
        }
        let Some((program, index)) = found else { continue };
        let program = program.as_str();
        if ELEVATORS.contains(&program) {
            elevates = true;
            raise(RiskLevel::Change, format!("{program} opens a privileged shell"));
            continue;
        }
        if program.starts_with('-') || SKIPPED_WORDS.contains(&program) { continue }
        if SHELL_KEYWORDS.contains(&program) { continue }
        if is_assignment(program) { continue }
        if !READ_PROGRAMS.contains(&program) && !extra_read_programs.contains(program) {
            raise(RiskLevel::Change, format!("runs {program}"));
            continue;
        }
        if let Some(writes) = read_program_writes(program, &tokens[index + 1..]) { raise(RiskLevel::Change, writes) }
    }
    RiskAssessment { level, elevates, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(command: &str) -> Vec<String> {
        split_segments(command).into_iter().map(|s| s.text).collect()
    }

    #[test]
    fn splits_on_operators_but_not_on_descriptor_redirections() {
        assert_eq!(texts("a && b || c; d | e |& f"), ["a", "b", "c", "d", "e", "f"]);
        assert_eq!(texts("sleep 1 & echo done"), ["sleep 1", "echo done"]);
        // `&` next to a redirection operator is part of it, not a separator.
        assert_eq!(texts("lsof +L1 2>&1 | head"), ["lsof +L1 2>&1", "head"]);
        assert_eq!(texts("cmd &> out"), ["cmd &> out"]);
        assert_eq!(texts("cmd <&3"), ["cmd <&3"]);
        assert_eq!(texts("cmd >&2 && next"), ["cmd >&2", "next"]);
        assert_eq!(texts("echo $(date) `id` (x) { y; }"), ["echo", "date", "id", "x", "y"]);
        assert_eq!(texts("echo 'a; b' \"c && d\""), ["echo 'a; b' \"c && d\""]);
        assert_eq!(texts("a \\\n b\nc"), ["a    b", "c"]);
        assert_eq!(texts("echo $HOME"), ["echo $HOME"]);
    }

    #[test]
    fn masks_quoted_operators_and_keeps_offsets() {
        let command = "echo 'a;b' \"c|d\\\"e\" > f";
        let masked = mask_quoted(command);
        assert_eq!(masked, "echo 'a b' \"c d\\\"e\"   f".replace("   f", " > f"));
        assert_eq!(masked.len(), command.len());
        assert_eq!(tokenize("a 'b c' \"d \\\" e\" f"), ["a", "b c", "d \\\" e", "f"]);
    }

    #[test]
    fn look_ahead_rewrites_keep_their_meaning() {
        let level = |command: &str| classify_command(command, &HashSet::new()).level;
        // `(?:rm|…)(?=\s|$)`: the word must end at whitespace or the end of the text.
        assert_eq!(level("rm"), RiskLevel::Destructive);
        assert_eq!(level("echo x; rm -f y"), RiskLevel::Destructive);
        assert_eq!(level("rmdir /tmp/x"), RiskLevel::Destructive);
        assert_eq!(level("ls rm.txt"), RiskLevel::Read);
        assert_eq!(level("cat /tmp/rm-notes"), RiskLevel::Read);
        // `-?1\b(?!\d)`: pid 1 and -1, but not pids that merely start with 1.
        let reasons = |command: &str| classify_command(command, &HashSet::new()).reasons;
        assert!(reasons("kill -1").iter().any(|r| r.contains("signals every process")));
        assert!(reasons("kill -TERM 1").iter().any(|r| r.contains("signals every process")));
        assert_eq!(level("kill 1"), RiskLevel::Destructive);
        assert_eq!(level("kill 1234"), RiskLevel::Change);
        assert_eq!(level("kill 12"), RiskLevel::Change);
        // `(?:pkill|killall)(?=\s|$)`.
        assert_eq!(level("pkill"), RiskLevel::Destructive);
        assert_eq!(level("killall5x"), RiskLevel::Change);
    }
}
