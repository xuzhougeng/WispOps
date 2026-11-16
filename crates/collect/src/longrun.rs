//! Long-running user work on a host, read-only: the processes of ordinary accounts (and the
//! running Slurm jobs) that have been going for longer than a threshold. Session plumbing
//! (login shells, sshd, tmux, the user's systemd) is left out, and a process tree is reported
//! once, at its oldest member, with what its descendants add up to.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::sections::{format_kb, num, num_opt, parse_sections};
use crate::util::{desc, fill, n, to_fixed};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LongRunOptions {
    /// Only work that has run at least this long is reported.
    pub min_seconds: u64,
    /// The lowest UID that counts as a person; `None` reads `UID_MIN` of `/etc/login.defs` (1000 without it).
    pub min_uid: Option<u32>,
    /// Accounts that are never reported.
    pub ignore_users: Vec<String>,
    /// Program names that are never reported, besides the built-in session plumbing.
    pub ignore_commands: Vec<String>,
}

impl LongRunOptions {
    pub fn hours(hours: u32) -> Self {
        LongRunOptions { min_seconds: u64::from(hours) * 3600, min_uid: None, ignore_users: vec![], ignore_commands: vec![] }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LongKind {
    Process,
    Slurm,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LongJob {
    pub kind: LongKind,
    /// The PID, or the scheduler's job id.
    pub id: String,
    pub user: String,
    pub elapsed_sec: f64,
    /// CPU over the whole life of the process and of its long-running descendants, in percent of one core.
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub rss_kb: f64,
    /// `running`, `sleeping`, `stopped` or `zombie`; empty for a scheduler job.
    pub state: String,
    /// Long-running descendants folded into this row.
    pub children: u32,
    pub command: String,
}

impl LongJob {
    /// Alive for long and hardly ever on a CPU: likely forgotten rather than working.
    pub fn idle(&self) -> bool {
        self.kind == LongKind::Process && self.cpu_pct < 1.0
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LongRunReport {
    pub min_seconds: f64,
    pub uid_min: f64,
    /// Longest first.
    pub jobs: Vec<LongJob>,
    /// `ps` gave nothing to read (a restricted shell, or a `ps` without these columns).
    pub ps_failed: bool,
}

/// One stored check; the page draws the latest per host.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LongRunSnapshot {
    #[serde(flatten)]
    pub report: LongRunReport,
    pub at: String,
}

/// Shells count as session plumbing only while they run nothing of their own (`-bash`, `zsh -l`).
const SHELLS: [&str; 8] = ["bash", "sh", "zsh", "fish", "tcsh", "csh", "ksh", "dash"];

/// What a login leaves running that is nobody's task.
const PLUMBING: [&str; 30] = [
    "systemd", "(sd-pam)", "sshd", "sshd-session", "sftp-server", "login", "su", "sudo", "tmux", "screen", "dbus-daemon", "dbus-broker", "dbus-launch", "ssh-agent", "gpg-agent", "gnome-keyring-daemon", "pipewire", "pipewire-pulse", "wireplumber", "pulseaudio", "at-spi-bus-launcher", "at-spi2-registryd", "gvfsd", "gvfsd-fuse", "mosh-server",
    "xdg-desktop-portal", "xdg-document-portal", "xdg-permission-store", "dconf-service", "fusermount3",
];

pub fn longrun_script(o: &LongRunOptions) -> String {
    fill(include_str!("scripts/longrun.sh.tpl"), &[("o.minSeconds", &o.min_seconds.to_string()), ("o.minUid", &o.min_uid.map(|uid| uid.to_string()).unwrap_or_default())])
}

/// The program a command line runs: `-bash` → `bash`, `/usr/bin/python3 x.py` → `python3`, `sshd: a@pts/0` → `sshd`.
pub fn program_of(command: &str) -> &str {
    let first = command.split_whitespace().next().unwrap_or("");
    let first = first.strip_prefix('-').unwrap_or(first);
    let name = if first.starts_with('(') { first } else { first.rsplit('/').next().unwrap_or(first) };
    name.strip_suffix(':').unwrap_or(name)
}

fn is_plumbing(command: &str, extra: &[String]) -> bool {
    let program = program_of(command);
    let lower = program.to_lowercase();
    if PLUMBING.contains(&lower.as_str()) || extra.iter().any(|name| name.eq_ignore_ascii_case(program)) {
        return true;
    }
    // A shell with a script or `-c` text is somebody's job; a bare one is a terminal left open.
    SHELLS.contains(&lower.as_str()) && command.split_whitespace().skip(1).all(|word| word.starts_with('-'))
}

fn state_word(stat: &str) -> &'static str {
    match stat.chars().next() {
        Some('R') => "running",
        Some('T' | 't') => "stopped",
        Some('Z') => "zombie",
        _ => "sleeping",
    }
}

/// Slurm's elapsed time: `[days-][hours:]minutes:seconds`.
fn slurm_seconds(text: &str) -> Option<f64> {
    let (days, clock) = match text.split_once('-') {
        Some((days, clock)) => (num(days)?, clock),
        None => (0.0, text),
    };
    let parts: Vec<f64> = clock.split(':').map(num).collect::<Option<_>>()?;
    let seconds = match parts.as_slice() {
        [h, m, s] => h * 3600.0 + m * 60.0 + s,
        [m, s] => m * 60.0 + s,
        [s] => *s,
        _ => return None,
    };
    Some(days * 86400.0 + seconds)
}

struct Proc {
    pid: i64,
    ppid: i64,
    job: LongJob,
}

pub fn parse_longrun(output: &str, o: &LongRunOptions) -> LongRunReport {
    let s = parse_sections(output);
    let min = o.min_seconds as f64;
    let mut procs: Vec<Proc> = s
        .get("procs")
        .iter()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (pid, ppid, elapsed) = (num(f.first()?)?, num(f.get(1)?)?, num(f.get(4)?)?);
            let user = f.get(3)?.to_string();
            let command = f.get(9..)?.join(" ");
            if command.is_empty() || elapsed < min || o.ignore_users.contains(&user) || is_plumbing(&command, &o.ignore_commands) {
                return None;
            }
            let field = |at: usize| f.get(at).and_then(|value| num(value)).unwrap_or(0.0);
            Some(Proc { pid: pid as i64, ppid: ppid as i64, job: LongJob { kind: LongKind::Process, id: f[0].to_string(), user, elapsed_sec: elapsed, cpu_pct: field(5), mem_pct: field(6), rss_kb: field(7), state: state_word(f.get(8).copied().unwrap_or("")).into(), children: 0, command } })
        })
        .collect();
    // Fold every process into the oldest kept ancestor of the same user.
    let parent: HashMap<i64, i64> = procs.iter().map(|p| (p.pid, p.ppid)).collect();
    let owner: HashMap<i64, String> = procs.iter().map(|p| (p.pid, p.job.user.clone())).collect();
    let root_of = |pid: i64| -> i64 {
        let (mut at, mut seen) = (pid, HashSet::new());
        while let Some(up) = parent.get(&at).copied().filter(|up| owner.get(up) == owner.get(&pid) && seen.insert(*up)) {
            at = up;
        }
        at
    };
    let roots: Vec<i64> = procs.iter().map(|p| root_of(p.pid)).collect();
    let mut added: HashMap<i64, (u32, f64, f64, f64)> = HashMap::new();
    for (p, root) in procs.iter().zip(&roots) {
        if p.pid != *root {
            let sum = added.entry(*root).or_default();
            *sum = (sum.0 + 1, sum.1 + p.job.cpu_pct, sum.2 + p.job.mem_pct, sum.3 + p.job.rss_kb);
        }
    }
    let mut keep = roots.iter();
    procs.retain(|p| keep.next() == Some(&p.pid));
    let mut jobs: Vec<LongJob> = procs
        .into_iter()
        .map(|p| {
            let mut job = p.job;
            if let Some((children, cpu, mem, rss)) = added.get(&p.pid) {
                job.children = *children;
                job.cpu_pct += cpu;
                job.mem_pct += mem;
                job.rss_kb += rss;
            }
            job
        })
        .collect();
    jobs.extend(s.get("slurm").iter().filter_map(|line| {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let (id, user, elapsed) = (cells.first()?, cells.get(1)?, slurm_seconds(cells.get(2)?)?);
        if id.is_empty() || elapsed < min || o.ignore_users.iter().any(|name| name == user) {
            return None;
        }
        let nodes = cells.get(3).copied().unwrap_or("");
        let partition = cells.get(4).copied().unwrap_or("");
        let name = cells.get(5..).map(|rest| rest.join("|")).unwrap_or_default();
        Some(LongJob { kind: LongKind::Slurm, id: id.to_string(), user: user.to_string(), elapsed_sec: elapsed, cpu_pct: 0.0, mem_pct: 0.0, rss_kb: 0.0, state: String::new(), children: 0, command: format!("{name} ({partition}, {nodes} node(s))") })
    }));
    jobs.sort_by(|a, b| desc(a.elapsed_sec, b.elapsed_sec).then_with(|| a.id.cmp(&b.id)));
    LongRunReport { min_seconds: min, uid_min: num_opt(s.first("uidmin")).unwrap_or(1000.0), jobs, ps_failed: num_opt(s.first("ps_total")) == Some(0.0) }
}

/// `3d 4h`, `5h 12m`, `42m`.
pub fn format_elapsed(seconds: f64) -> String {
    let total = seconds.max(0.0) as u64;
    let (days, hours, minutes) = (total / 86400, total % 86400 / 3600, total % 3600 / 60);
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

/// Model-facing rendering.
pub fn render_longrun(host: &str, r: &LongRunReport) -> String {
    let threshold = format_elapsed(r.min_seconds);
    let mut lines = vec![format!("## {host} — user work running longer than {threshold}: {}", if r.jobs.is_empty() { "none".to_string() } else { format!("{} task(s)", r.jobs.len()) })];
    if r.ps_failed {
        lines.push("Note: ps returned nothing readable; the process list is missing.".into());
    }
    for job in r.jobs.iter().take(60) {
        lines.push(match job.kind {
            LongKind::Slurm => format!("- slurm job {} of {}: running {} — {}", job.id, job.user, format_elapsed(job.elapsed_sec), job.command),
            LongKind::Process => format!(
                "- pid {} of {}: running {}, {}, lifetime CPU {}%, memory {}{}{} — {}",
                job.id,
                job.user,
                format_elapsed(job.elapsed_sec),
                job.state,
                to_fixed(job.cpu_pct, 1),
                format_kb(job.rss_kb),
                if job.children > 0 { format!(", with {} long-running descendant(s)", job.children) } else { String::new() },
                if job.idle() { " [idle: almost no CPU over its life]" } else { "" },
                job.command
            ),
        });
    }
    if r.jobs.len() > 60 {
        lines.push(format!("… and {} more", n((r.jobs.len() - 60) as f64)));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTPUT: &str = "@@whoami\n1000\n@@uidmin\n1000\n@@procs\n\
  900     1 1000 alice 400000 0.0 0.1 5000 Ss /usr/lib/systemd/systemd --user\n\
  950   900 1000 alice 399000 0.0 0.0 3000 Ss -bash\n\
 1200   950 1000 alice 300000 380.5 2.0 2000000 Sl python train.py --epochs 90\n\
 1201  1200 1000 alice 299990 95.0 0.5 500000 Rl python train.py --epochs 90\n\
 1202  1200 1000 alice 299990 96.0 0.5 500000 Rl python train.py --epochs 90\n\
 2000     1 1001 bob 90000 0.0 0.0 800 S sleep infinity\n\
 2100     1 1001 bob 200000 0.2 0.1 9000 Ss tmux: server\n\
 2200  2100 1001 bob 190000 0.0 0.1 4000 T /bin/bash /home/bob/run all.sh\n\
 2300     1 1002 carol 100000 50.0 1.0 70000 Sl jupyter-lab\n\
 2400     1 1003 dave 3000 9.0 1.0 70000 Sl short-lived\n\
@@slurm\n8801|alice|2-03:00:00|4|gpu|align|v2\n8802|bob|10:00|1|cpu|quick\n@@end\n";

    #[test]
    fn folds_trees_drops_plumbing_and_reads_slurm_times() {
        let options = LongRunOptions { ignore_users: vec!["carol".into()], ..LongRunOptions::hours(24) };
        let report = parse_longrun(OUTPUT, &options);
        let rows: Vec<_> = report.jobs.iter().map(|job| (job.id.as_str(), job.user.as_str(), job.elapsed_sec, job.children)).collect();
        assert_eq!(rows, [("1200", "alice", 300000.0, 2), ("2200", "bob", 190000.0, 0), ("8801", "alice", 183600.0, 0), ("2000", "bob", 90000.0, 0)]);
        let tree = &report.jobs[0];
        assert_eq!((tree.cpu_pct, tree.rss_kb, tree.idle()), (571.5, 3_000_000.0, false));
        assert_eq!((report.jobs[1].state.as_str(), report.jobs[1].command.as_str()), ("stopped", "/bin/bash /home/bob/run all.sh"));
        assert_eq!(report.jobs[2].command, "align|v2 (gpu, 4 node(s))");
        assert!(report.jobs[3].idle() && !report.ps_failed);
        let text = render_longrun("gpu-01", &report);
        assert!(text.starts_with("## gpu-01 — user work running longer than 1d 0h: 4 task(s)"));
        assert!(text.contains("pid 1200 of alice: running 3d 11h, sleeping, lifetime CPU 571.5%, memory 2.9G, with 2 long-running descendant(s)"));
        assert!(text.contains("pid 2000 of bob") && text.contains("[idle: almost no CPU over its life]"));
        assert_eq!(serde_json::from_value::<LongRunSnapshot>(serde_json::to_value(LongRunSnapshot { report: report.clone(), at: "2026-11-16T00:00:00.000Z".into() }).unwrap()).unwrap().report, report);
    }

    #[test]
    fn names_programs_and_tells_idle_shells_from_scripts() {
        assert_eq!((program_of("-bash"), program_of("/usr/bin/python3 x.py"), program_of("sshd: alice@pts/0"), program_of("(sd-pam)")), ("bash", "python3", "sshd", "(sd-pam)"));
        assert!(is_plumbing("zsh -l", &[]) && is_plumbing("SCREEN -S work", &[]) && is_plumbing("code-server --port 1", &["code-server".into()]));
        assert!(!is_plumbing("bash -c 'while :; do :; done'", &[]) && !is_plumbing("sh run.sh", &[]));
        assert_eq!((slurm_seconds("1-00:00:01"), slurm_seconds("5:07"), slurm_seconds("x")), (Some(86401.0), Some(307.0), None));
        assert_eq!((format_elapsed(59.0), format_elapsed(3700.0), format_elapsed(90000.0)), ("0m".to_string(), "1h 1m".to_string(), "1d 1h".to_string()));
    }

    /// The script runs through the real shell and finds this very test's long-lived parent, if any;
    /// what must hold everywhere is that it ends and every row parses.
    #[cfg(unix)]
    #[test]
    fn runs_through_a_real_shell() {
        use std::io::Write;
        let options = LongRunOptions { min_seconds: 0, min_uid: Some(0), ignore_users: vec![], ignore_commands: vec![] };
        let mut child = std::process::Command::new("sh").arg("-s").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(longrun_script(&options).as_bytes()).unwrap();
        let output = String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).into_owned();
        assert!(output.contains("@@end"));
        let rows = parse_sections(&output).get("procs").len();
        let report = parse_longrun(&output, &options);
        assert!(rows > 0 && !report.jobs.is_empty() && !report.ps_failed, "{output}");
        assert!(report.jobs.iter().all(|job| job.elapsed_sec >= 0.0 && !job.command.is_empty()));
    }
}
