//! The classifier cases of the plugin's `risk.spec.ts`, and a corpus classified by the original
//! TypeScript implementation (`fixtures/risk.golden.json`) that the port must reproduce exactly.

use std::collections::HashSet;

use serde::Deserialize;
use wisp_ops_engine::risk::{RiskLevel, classify_command, mask_quoted, split_segments, tokenize};

fn level(command: &str) -> RiskLevel {
    classify_command(command, &HashSet::new()).level
}

#[test]
fn read_commands() {
    for command in [
        "df -h",
        "du -xh -d1 /var 2>/dev/null | sort -rh | head -20",
        "journalctl -u nginx --since \"1 hour ago\" --no-pager | tail -n 50",
        "systemctl status nginx",
        "systemctl --failed",
        "ps aux --sort=-%mem | head",
        "nvidia-smi --query-gpu=index,utilization.gpu --format=csv",
        "docker ps -a",
        "docker system df",
        "find /var/log -type f -size +100M -mtime -1",
        "sinfo -N; squeue -u alice",
        "cat /etc/os-release && uname -a",
        "lsof +L1 2>&1 | head",
        "grep -c error /var/log/syslog",
        "timeout 10 du -sh /home/*",
        "awk '{print $1}' /proc/loadavg",
        "curl -s http://localhost:8080/health",
        "for f in /var/log/*.log; do wc -l \"$f\"; done",
        "command -v nvidia-smi",
    ] {
        assert_eq!(level(command), RiskLevel::Read, "{command}");
    }
}

#[test]
fn change_commands() {
    for command in [
        "systemctl restart nginx",
        "apt-get install -y htop",
        "echo \"vm.swappiness=10\" > /etc/sysctl.d/99.conf",
        "sed -i s/foo/bar/ /etc/app.conf",
        "kill 1234",
        "docker restart web",
        "mv /var/log/big.log /data/",
        "some-unknown-tool --flag",
        "find /tmp -name x -exec chmod 600 {} +",
        "awk '{print > \"out.txt\"}' in",
        "curl -o /tmp/x http://example.com/x",
        "sh -c \"ls\"",
        "tee /etc/motd",
        "scontrol update nodename=n1 state=resume",
        "sysctl -w vm.drop_caches=3",
    ] {
        assert_eq!(level(command), RiskLevel::Change, "{command}");
    }
}

#[test]
fn destructive_commands() {
    for command in [
        "rm -rf /data/tmp/*",
        "find /var/log -name \"*.gz\" -mtime +30 -delete",
        r"find . -type f -exec rm {} \;",
        "ls *.log | xargs rm",
        "journalctl --vacuum-size=500M",
        "docker image prune -a",
        "docker system prune",
        "reboot",
        "sudo shutdown -h now",
        "dd if=/dev/zero of=/dev/sdb bs=1M",
        "mkfs.ext4 /dev/sdb1",
        "truncate -s 0 /var/log/huge.log",
        "apt-get autoremove -y",
        "python3 -c \"import shutil; shutil.rmtree('/data/x')\"",
        "bash -c 'rm -f /tmp/a'",
        "git reset --hard HEAD~1",
        ": > /var/log/syslog",
        "> /var/log/nginx/access.log",
        "cat /dev/null > /var/log/syslog",
        "cp /dev/null /var/log/auth.log",
        "rsync -a --delete /src/ /dst/",
        "tar --remove-files -cf /backup/a.tar /data/a",
        "mv /data/project /tmp/",
        "pkill -9 -f python",
        "killall java",
        "kill -9 1234",
        "chmod -R 000 /data/shared",
        "chown -R alice:alice /home/alice",
    ] {
        assert_eq!(level(command), RiskLevel::Destructive, "{command}");
    }
}

#[test]
fn flags_privilege_escalation() {
    let classify = |command: &str| classify_command(command, &HashSet::new());
    assert!(classify("sudo du -sh /root").elevates);
    assert_eq!(classify("sudo du -sh /root").level, RiskLevel::Read);
    assert!(classify("sudo -u postgres psql").elevates);
    assert_eq!(classify("su -").level, RiskLevel::Change);
    assert!(!classify("df -h").elevates);
}

#[test]
fn keeps_ordinary_writes_at_change_rather_than_destructive() {
    for command in ["grep error log > /tmp/out.txt", "echo \"x\" > /etc/motd", "mv /var/log/big.log /data/", "kill 1234", "chmod 600 /etc/app.conf", "rsync -a /src/ /dst/", "tar -cf a.tar dir"] {
        assert_eq!(level(command), RiskLevel::Change, "{command}");
    }
    assert_eq!(level("cmd 2>/dev/null | head"), RiskLevel::Change);
    assert_eq!(level("du -sh /data 2>/dev/null"), RiskLevel::Read);
}

#[test]
fn accepts_deployment_configured_read_programs() {
    let extra: HashSet<String> = ["ncdu".to_string()].into();
    assert_eq!(classify_command("ncdu -o- /", &extra).level, RiskLevel::Read);
    assert_eq!(level("ncdu -o- /"), RiskLevel::Change);
}

#[derive(Deserialize)]
struct GoldenRow {
    command: String,
    level: RiskLevel,
    elevates: bool,
    reasons: Vec<String>,
    segments: Vec<(String, String)>,
    tokens: Option<Vec<String>>,
    masked: Option<String>,
}

#[test]
fn reproduces_the_original_classifier_on_a_corpus() {
    let rows: Vec<GoldenRow> = serde_json::from_str(include_str!("fixtures/risk.golden.json")).expect("golden corpus");
    assert!(rows.len() > 5000);
    let mut mismatches = Vec::new();
    for row in &rows {
        let got = classify_command(&row.command, &HashSet::new());
        let segments: Vec<(String, String)> = split_segments(&row.command).into_iter().map(|s| (s.text, s.masked)).collect();
        let same = got.level == row.level
            && got.elevates == row.elevates
            && got.reasons == row.reasons
            && segments == row.segments
            && row.tokens.as_ref().is_none_or(|tokens| *tokens == tokenize(&row.command))
            && row.masked.as_ref().is_none_or(|masked| *masked == mask_quoted(&row.command));
        if !same {
            mismatches.push(format!("{:?}: expected {:?}/{}/{:?}, got {:?}/{}/{:?}", row.command, row.level, row.elevates, row.reasons, got.level, got.elevates, got.reasons));
        }
    }
    assert!(mismatches.is_empty(), "{} of {} differ:\n{}", mismatches.len(), rows.len(), mismatches.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}
