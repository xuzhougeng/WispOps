//! How a finding reads in the window. The collectors word their findings in
//! English (the history, the audit and the model all keep that text); here a
//! Chinese window gets them in Chinese, and a long list of instances of one
//! systemd template is folded into a count. Anything not recognised is shown
//! as it was written.

use regex::Regex;
use std::sync::LazyLock;

/// A finding's code, the shape of its English message, and the Chinese it becomes.
const RULES: &[(&str, &str, &str)] = &[
    ("disk-full", r"^(\S+) (\S+)% used \((.+) free of (.+)\)$", "${1} 已用 ${2}%（剩 ${3}，共 ${4}）"),
    ("disk-high", r"^(\S+) (\S+)% used \((.+) free of (.+)\)$", "${1} 已用 ${2}%（剩 ${3}，共 ${4}）"),
    ("disk-growth", r"^(\S+) grew (\S+)% → (\S+)% since (.+)$", "${1} 从 ${2}% 涨到 ${3}%（自 ${4} 起）"),
    ("disk-forecast", r"^(\S+) grows (\S+) points a day and fills in less than a day$", "${1} 每天涨 ${2} 个百分点，不到一天就会写满"),
    ("disk-forecast", r"^(\S+) grows (\S+) points a day and fills in about (\S+) days$", "${1} 每天涨 ${2} 个百分点，约 ${3} 天后写满"),
    ("inodes-full", r"^(\S+) inodes (\S+)% used$", "${1} 的 inode 已用 ${2}%"),
    ("inodes-high", r"^(\S+) inodes (\S+)% used$", "${1} 的 inode 已用 ${2}%"),
    ("memory-low", r"^memory available (\S+)% \((.+) of (.+)\)$", "可用内存 ${1}%（${2}，共 ${3}）"),
    ("swap-high", r"^swap (\S+)% used$", "swap 已用 ${1}%"),
    ("load-high", r"^load (\S+) on (\S+) cores \((\S+) per core\)$", "负载 ${1}，${2} 核（每核 ${3}）"),
    ("units-failed", r"^failed systemd units: (.*)$", "失败的 systemd 单元：${1}"),
    ("zombies", r"^(\S+) zombie processes$", "${1} 个僵尸进程"),
    ("oom-kills", r"^(\S+) OOM-killer messages in the last 24h$", "最近 24 小时 OOM killer 出手 ${1} 次"),
    ("kernel-errors", r"^(\S+) kernel error lines in the last 24h$", "最近 24 小时内核报错 ${1} 行"),
    ("gpu-hot", r"^GPU (\S+) at (\S+)°C$", "GPU ${1} 温度 ${2}°C"),
    ("gpu-idle-held", r"^GPU (\S+) holds (\S+) MiB at 0% utilization \(pids (.*)\)$", "GPU ${1} 占着 ${2} MiB 显存，利用率却是 0%（进程 ${3}）"),
    ("slurm-nodes", r"^Slurm nodes need attention: (.*)$", "Slurm 节点需要处理：${1}"),
    ("login-slow", r"^SSH login took (\S+) s$", "SSH 登录用了 ${1} 秒"),
    ("tcp-retrans", r"^(\S+)% of TCP segments were retransmitted during the sample$", "采样期间 ${1}% 的 TCP 报文被重传"),
    ("port-new", r"^new listening TCP ports: (.*)$", "新开的 TCP 监听端口：${1}"),
    ("login-new-source", r"^new login sources: (.*)$", "新的登录来源：${1}"),
    ("ssh-failures", r"^(\S+) failed SSH logins in the last hour$", "最近一小时 SSH 登录失败 ${1} 次"),
    ("service-down", r"^port (\S+) is not listening$", "端口 ${1} 没有在监听"),
    ("service-down", r"^(.+) answered nothing$", "${1} 没有响应"),
    ("service-down", r"^(.+) answered (\S+)$", "${1} 返回 ${2}"),
    ("service-down", r"^(.+) is (\S+)$", "${1} 的状态是 ${2}"),
    ("ntp-unsynced", r"^system clock is not NTP-synchronized$", "系统时钟没有与 NTP 同步"),
    ("reboot-required", r"^a package update requires a reboot$", "有软件包更新需要重启才生效"),
    ("auth-log-unreadable", r"^SSH auth log not readable; run with sudo for login analysis$", "读不到 SSH 认证日志；用 sudo 运行才能分析登录"),
    ("partial-visibility", r"^not running as root: other users' processes and sockets may be hidden$", "不是以 root 运行：其他用户的进程和连接可能看不到"),
    ("ssh-bruteforce", r"^(\S+) failed SSH logins from (\S+) in (\S+)h$", "${3} 小时内来自 ${2} 的 SSH 登录失败 ${1} 次"),
    ("ssh-distributed", r"^failed SSH logins from at least (\S+) sources \((\S+) total\) in (\S+)h$", "${3} 小时内至少 ${1} 个来源的 SSH 登录失败，共 ${2} 次"),
    ("login-after-bruteforce", r"^successful (\S+) login as (\S+) from (\S+), which also had many failed attempts$", "${2} 从 ${3} 登录成功（${1}），而这个来源此前有大量失败尝试"),
    ("root-password-login", r"^root logged in with a password from (\S+)$", "root 从 ${1} 用密码登录"),
    ("public-logins", r"^logins from public addresses: (.*)$", "来自公网地址的登录：${1}"),
    ("syn-flood", r"^(\S+) half-open \(SYN-RECV\) connections: possible SYN flood$", "${1} 个半开（SYN-RECV）连接：可能是 SYN flood"),
    ("connection-flood", r"^(\S+) established connections from (\S+)$", "来自 ${2} 的已建立连接有 ${1} 个"),
    ("crypto-miner", r"^crypto-miner-like process (.*) \[pid (\d+), (\S+), (\S+)% CPU\]$", "疑似挖矿进程 ${1}（pid ${2}，用户 ${3}，CPU ${4}%）"),
    ("binary-replaced", r"^process (.+)\[(\d+)\] still runs a binary replaced since it started \((.*)\); usually an upgrade — restart it to pick up the new version$", "进程 ${1}[${2}] 运行的程序在它启动后被替换过（${3}）；通常是升级所致，重启它才用上新版本"),
    ("binary-removed", r"^process (.+)\[(\d+)\] runs (.*), removed by an upgrade or uninstall of a managed tool; restart it if it should keep running$", "进程 ${1}[${2}] 运行的 ${3} 已被升级或卸载移除；还要用的话重启它"),
    ("deleted-exe", r"^process (.+)\[(\d+)\] runs a binary that no longer exists on disk \((.*)\); malware often deletes itself after starting$", "进程 ${1}[${2}] 运行的程序已不在磁盘上（${3}）；恶意程序常在启动后删除自身"),
    ("suspicious-exe", r"^process (.+)\[(\d+)\] runs from a world-writable location: (.*)$", "进程 ${1}[${2}] 从人人可写的位置运行：${3}"),
    ("suspicious-outbound", r"^outbound connection (\S+) → (\S+) \(port often used by miners/C2\)$", "外连 ${1} → ${2}（这个端口常被挖矿程序和 C2 使用）"),
    ("extra-uid0", r"^accounts with UID 0 besides root: (.*)$", "除 root 外还有 UID 为 0 的账号：${1}"),
    ("authorized-keys-changed", r"^(.+) changed at (.+)$", "${1} 在 ${2} 被改动"),
    ("cron-changed", r"^cron files changed: (.*)$", "cron 文件有改动：${1}"),
    ("units-changed", r"^systemd units changed: (.*)$", "systemd 单元有改动：${1}"),
    ("sshd-weak", r"^sshd allows root login with passwords .*$", "sshd 允许 root 用密码登录（PermitRootLogin yes、PasswordAuthentication yes）"),
    ("no-fail2ban", r"^brute force is ongoing and fail2ban \(sshd jail\) is not active$", "暴力破解正在进行，而 fail2ban（sshd jail）没有启用"),
];

/// What a server whose logins are paused reports instead of an inspection, whatever its code.
static PAUSED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^logins to (\S+) are paused until (\S+) after an authentication failure \((.*)\); fix the credentials or host key, then run /ops-unblock \S+$").expect("a valid expression"));

static COMPILED: LazyLock<Vec<(&'static str, Regex, &'static str)>> = LazyLock::new(|| RULES.iter().map(|(code, shape, chinese)| (*code, Regex::new(shape).expect("a finding's shape is a valid expression"), *chinese)).collect());

const UNITS_PREFIX: &str = "failed systemd units: ";

/// A finding as the window words it, in the language given.
pub fn words_in(english: bool, code: &str, message: &str) -> String {
    // Thirty core dumps of one service are one thing to know, not thirty names to read.
    let folded = match (code, message.strip_prefix(UNITS_PREFIX)) {
        ("units-failed", Some(units)) => format!("{UNITS_PREFIX}{}", fold_units(units)),
        _ => message.to_string(),
    };
    if let Some(found) = PAUSED.captures(&folded) {
        let (until, reason) = (wisp_ops_core::time::short_time(&found[2]), &found[3]);
        return if english { format!("logins are paused until {until} after an authentication failure ({reason}); fix the user, key or credential, then resume them") } else { format!("认证失败，登录暂停到 {until}（{reason}）；修正用户名、密钥或凭据后解除暂停") };
    }
    if english { return folded }
    COMPILED.iter().find(|(known, shape, _)| *known == code && shape.is_match(&folded)).map_or(folded.clone(), |(_, shape, chinese)| shape.replace(&folded, *chinese).into_owned())
}

/// A finding as the window words it now.
pub fn words(code: &str, message: &str) -> String {
    words_in(crate::i18n::is_english(), code, message)
}

/// `a.service, x@1.service, x@2.service` as `a.service, x@… × 2`: instances of one template counted, the order kept.
fn fold_units(units: &str) -> String {
    let mut seen: Vec<(String, usize, &str)> = vec![];
    for unit in units.split(", ") {
        let template = unit.split_once('@').map_or(unit.to_string(), |(template, _)| format!("{template}@"));
        match seen.iter_mut().find(|(known, _, _)| *known == template) {
            Some(entry) => entry.1 += 1,
            None => seen.push((template, 1, unit)),
        }
    }
    seen.into_iter().map(|(template, count, first)| if count > 1 { format!("{template}… × {count}") } else { first.to_string() }).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::{COMPILED, words_in};

    #[test]
    fn every_shape_compiles() {
        assert!(!COMPILED.is_empty());
    }

    #[test]
    fn a_chinese_window_reads_findings_in_chinese_and_keeps_what_it_does_not_know() {
        assert_eq!(words_in(false, "disk-full", "/data1 100% used (107G free of 13.8T)"), "/data1 已用 100%（剩 107G，共 13.8T）");
        assert_eq!(words_in(false, "swap-high", "swap 100% used"), "swap 已用 100%");
        assert_eq!(words_in(false, "load-high", "load 12/11/9 on 8 cores (1.5 per core)"), "负载 12/11/9，8 核（每核 1.5）");
        assert_eq!(words_in(false, "service-down", "nginx.service is failed"), "nginx.service 的状态是 failed");
        assert_eq!(words_in(false, "service-down", "port 443 is not listening"), "端口 443 没有在监听");
        assert_eq!(words_in(false, "deleted-exe", "process server[1105341] runs a binary that no longer exists on disk (/tmp/x (deleted)); malware often deletes itself after starting"), "进程 server[1105341] 运行的程序已不在磁盘上（/tmp/x (deleted)）；恶意程序常在启动后删除自身");
        assert_eq!(words_in(false, "unreachable", "ssh: connect timed out"), "ssh: connect timed out");
        let paused = words_in(false, "blocked", "logins to node100 are paused until 2026-11-16T12:49:21.934Z after an authentication failure (ops@10.0.0.9: Permission denied (publickey,password).); fix the credentials or host key, then run /ops-unblock node100");
        assert!(paused.starts_with("认证失败，登录暂停到 ") && paused.ends_with("（ops@10.0.0.9: Permission denied (publickey,password).）；修正用户名、密钥或凭据后解除暂停"), "{paused}");
        assert_eq!(words_in(false, "disk-full", "something else"), "something else");
        assert_eq!(words_in(true, "disk-full", "/data1 100% used (107G free of 13.8T)"), "/data1 100% used (107G free of 13.8T)");
    }

    #[test]
    fn instances_of_one_unit_template_are_counted() {
        let units = "failed systemd units: access.service, systemd-coredump@1-2-0.service, nginx.service, systemd-coredump@3-4-0.service, getty@tty1.service";
        assert_eq!(words_in(true, "units-failed", units), "failed systemd units: access.service, systemd-coredump@… × 2, nginx.service, getty@tty1.service");
        assert_eq!(words_in(false, "units-failed", units), "失败的 systemd 单元：access.service, systemd-coredump@… × 2, nginx.service, getty@tty1.service");
    }
}
