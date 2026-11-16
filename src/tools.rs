//! What the assistant can do with the fleet: the `ops_*` tools, the gate
//! every call passes before it runs, and running it.
//!
//! A call is first planned from its arguments alone (`plan`): which hosts,
//! which command text, what risk. The gate then settles each capability the
//! action needs on each host (policy → grant → ask) and hands back a
//! `Ticket` holding the voucher; `run` refuses to work without one and
//! checks that it still names the hosts the selector resolves to. The model
//! names hosts only by their inventory names and never sees a password.

use crate::ops::{Collect, Exec, Fleet, View, as_run};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use wisp_ops_collect::render::{render_inspection, render_runs};
use wisp_ops_collect::{HistoryRecord, disk, files, longrun, security, trends};
use wisp_ops_core::ai;
use wisp_ops_engine::change;
use wisp_ops_engine::inventory::Host;
use wisp_ops_engine::policy::{self, GateOutcome, Voucher};
use wisp_ops_engine::risk::{self, RiskAssessment, RiskLevel};
use wisp_ops_engine::store::{AuditFilter, ChangeOutcome, ChangeRecord};
use wisp_ops_engine::time;

/// The gate's leave for one call, consumed by running it.
#[derive(Clone)]
pub struct Ticket {
    voucher: Option<Voucher>,
}

impl Ticket {
    /// Whether the call only reads: such calls of one turn may run side by side.
    pub fn read_only(&self) -> bool {
        self.voucher.as_ref().is_none_or(|voucher| voucher.risk.level == RiskLevel::Read)
    }
}

/// What the person is asked before a call runs.
pub struct Ask {
    pub hosts: Vec<String>,
    /// The capabilities still to be allowed: `change`, `sudo`, `destructive`.
    pub needs: Vec<String>,
    pub command: String,
    /// Why the model wants it, in its words.
    pub reason: String,
    pub risks: Vec<String>,
    /// A grant for a while may cover it; never a destructive command.
    pub grantable: bool,
}

impl Ask {
    pub fn hosts_line(&self) -> String {
        policy::host_list(&self.hosts)
    }
}

pub enum Gate {
    Run(Ticket),
    Ask(Ticket, Ask),
    /// Not run, and nobody is asked: a deny rule, or arguments that cannot be read.
    Refuse(String),
    /// Answered without the fleet (a skill read out).
    Said(Result<String, String>),
}

const SELECTOR: &str = "Selector: host names, @group, tag:key=value, globs like gpu-*, all; comma separated; prefix ! to exclude.";

/// The tools, as the model is told of them.
pub fn catalog() -> Vec<ai::Tool> {
    let tool = |name: &str, description: &str, properties: Value, required: &[&str]| ai::Tool { name: name.into(), description: description.into(), input_schema: json!({"type": "object", "properties": properties, "required": required}) };
    vec![
        tool("ops_hosts", "List managed servers from the inventory: names, groups, tags, per-host permission policy (change/sudo/destructive = allow|ask|deny), whether passwords are stored, the last capability probe (OS, cores, GPUs, scheduler, privilege), login pauses, and the grants of this conversation. Set probe=true to (re)probe capabilities over SSH (read-only). Use this first to learn what exists before running anything.", json!({"targets": {"type": "string", "description": format!("{SELECTOR} Default all.")}, "probe": {"type": "boolean", "description": "Probe the selected hosts over SSH before listing (read-only)."}}), &[]),
        tool("ops_inspect", "Fleet health inspection (巡检), read-only: load, CPU, memory, swap, disk and inode usage, failed systemd units, top processes, NVIDIA GPUs and their processes, Slurm node and job states, OOM kills and kernel errors in the last 24h, NTP sync, pending reboot, network and login changes. Thresholds turn these into critical/warning findings, disk growth is compared with the previous inspection, and results are saved to history. Run this for any \"check the servers\" request, then drill down with ops_disk or ops_exec.", json!({"targets": {"type": "string", "description": "Selector; default all."}, "detail": {"type": "boolean", "description": "Include top processes, GPU processes, per-mount usage and kernel error samples."}, "sudo": {"type": "boolean", "description": "Run the collector as root for complete journal access (needs sudo permission)."}}), &[]),
        tool("ops_exec", "Run a POSIX shell command on one or more inventory servers over SSH (parallel for fleets; identical outputs are folded). The command is risk-classified (read / change / destructive, plus sudo); per-host policy and the user's grants decide whether it runs, asks the user to approve this exact call, or is refused. Set sudo=true instead of writing \"sudo\" in the command; passwords are supplied from the user's vault and never visible to you. Never ask the user for passwords. Prefer read-only diagnosis first, and explain the purpose in reason.", json!({"targets": {"type": "string", "description": SELECTOR}, "command": {"type": "string", "description": "Shell script run by sh on each host."}, "sudo": {"type": "boolean", "description": "Run as root (or the host's sudoUser)."}, "reason": {"type": "string", "description": "Why this is needed; shown to the user in the approval card and kept in the audit log. Required for anything that is not read-only."}, "timeoutMs": {"type": "integer", "description": "Per-host deadline in milliseconds; default 60000."}}), &["targets", "command"]),
        tool("ops_disk", "Diagnose a full or growing filesystem on one server, read-only: usage and inodes, largest directories (with growth since the previous diagnosis of the same path), largest and recently modified large files, which of them are held open by processes or sit inside running job directories, space pinned by deleted-but-open files, journal/docker/package/conda/pip caches, rotated logs. Every file gets a verdict (in-use, job-directory, rotated-log, core-dump, recently-written, review). Propose a cleanup plan from this, execute it with ops_exec (it will need approval), then run ops_disk again on the same path to verify the space was freed.", json!({"host": {"type": "string", "description": "One inventory host name."}, "path": {"type": "string", "description": "Absolute path on the filesystem to diagnose; default /."}, "depth": {"type": "integer", "description": "Directory depth for sizes; default 2."}, "top": {"type": "integer", "description": "Rows per list; default 15."}, "minFileMb": {"type": "integer", "description": "Large-file threshold in MiB; default 100."}, "sudo": {"type": "boolean", "description": "Run as root to see all directories and every process holding files (needs sudo permission)."}}), &["host"]),
        tool("ops_files", "Recent-file analysis (近期新增文件分析) on one server, read-only: files modified in the last N days under the given roots — total volume, where it landed (with growth since the previous scan), owners, what kind of data it is with sequencing/bioinformatics knowledge, which files are still open or inside running job directories, which are superseded by a processed or compressed sibling, and a cleanup plan ordered by reclaimable space with the checks to run first. Never deletes anything; execute chosen steps with ops_exec.", json!({"host": {"type": "string", "description": "One inventory host."}, "paths": {"type": "string", "description": "Absolute roots to scan, comma separated (e.g. /data,/home)."}, "days": {"type": "integer", "description": "Window in days; default 7."}, "sudo": {"type": "boolean", "description": "Scan as root to see every user's files (needs sudo permission)."}}), &["host", "paths"]),
        tool("ops_security", "Security triage (网络攻击排查) on servers, read-only: SSH brute force by source and successful logins, connection and SYN floods, listening services, crypto-miner-like processes, processes running deleted binaries or from /tmp and /dev/shm, outbound connections to common mining/C2 ports, extra UID-0 accounts, and recently changed authorized_keys, cron and systemd units. Use sudo=true for the auth log and all processes. Findings are leads to confirm, not verdicts; containment goes through ops_exec with approval.", json!({"targets": {"type": "string", "description": "Selector; default all."}, "hours": {"type": "integer", "description": "Look-back window in hours; default 24."}, "sudo": {"type": "boolean", "description": "Run as root (recommended; needs sudo permission)."}}), &[]),
        tool("ops_jobs", "Long-running user work (长时任务), read-only: the processes of ordinary accounts and the running Slurm jobs that are older than a threshold on each server — owner, how long, lifetime CPU, memory, state (stopped, zombie, idle) and command. Session plumbing (login shells, tmux, sshd) is left out and a process tree is reported once, at its oldest member. Use it to find forgotten or stuck work. It never ends anything: stopping a task goes through ops_exec with approval, and only when its owner or the user says so.", json!({"targets": {"type": "string", "description": "Selector; default all."}, "hours": {"type": "integer", "description": "Report work running at least this many hours; default 24."}}), &[]),
        tool("ops_change", "Managed change on one or more hosts with enforced backup, apply, verify and automatic restore on failure, rolled out host by host in inventory order and stopped at the first host that does not verify. List EVERY path the command can touch: files = existing regular files (copied), newFiles = paths that must not exist yet (deleted on failure), directories = existing directories (tar backup, replaced on failure). afterRollback reloads restored configuration if needed. Unlisted side effects (packages, databases) are not rolled back. An interrupted connection has an unknown outcome: inspect before retrying. Backups stay on the host; ops_history kind=changes lists them.", json!({"targets": {"type": "string", "description": "Selector. Hosts are changed one at a time; start with one canary host."}, "files": {"type": "array", "items": {"type": "string"}}, "newFiles": {"type": "array", "items": {"type": "string"}}, "directories": {"type": "array", "items": {"type": "string"}}, "command": {"type": "string", "description": "Apply the change; nonzero exit triggers rollback."}, "verify": {"type": "string", "description": "Verification script; nonzero exit triggers rollback."}, "afterRollback": {"type": "string"}, "reason": {"type": "string"}, "sudo": {"type": "boolean"}, "timeoutMs": {"type": "integer", "description": "Per-stage timeout, default 15000."}}), &["targets", "command", "verify", "reason"]),
        tool("ops_task", "Run a routine task the user defined (a read-only check bound to some servers) and get its data, the user's instruction for the report, and the previous run for comparison. Without name, lists the tasks. mode=\"last\" returns the most recent recorded run without running anything: use it when asked to report on a run the app already made. Write the report as instructed; do not change anything during a task.", json!({"name": {"type": "string", "description": "Task name; omit to list tasks."}, "mode": {"type": "string", "enum": ["run", "last"]}}), &[]),
        tool("ops_template_draft", "Submit a recurring-check template draft for the user to review in the WispOps window (Tasks → 从模板新建 / New from template → the assistant's drafts). It does not save to the task library, link servers, create, schedule or run anything: the user reviews and saves it there, and only they turn a template into a task by choosing servers. Templates never hold servers or sudo. Write instruction as the rules of a read-only check (what to look at, thresholds, how to judge and report); put values the user supplies when linking servers in {{key}} placeholders with matching parameters. A task of this app runs and records without you, so a custom check needs commands. Submitting again with the same id replaces the earlier draft.", json!({"id": {"type": "string", "description": "Letters, digits, dot, hyphen or underscore, e.g. nginx-health; must not exist in the task library."}, "title": {"type": "string"}, "category": {"type": "string", "description": "For example 基础运维, 安全, 应用服务, 数据管理, 计算集群."}, "description": {"type": "string", "description": "One line for the template card."}, "playbook": {"type": "string", "enum": ["inspect", "disk", "space", "new-files", "security", "custom"], "description": "inspect = health data; disk = disk diagnosis (paths); space = directory sizes level by level (paths); new-files = recent files (paths, days); security = security triage (hours); custom = checks driven by commands."}, "instruction": {"type": "string"}, "commands": {"type": "array", "items": {"type": "string"}, "description": format!("Up to {} read-only POSIX shell commands the task runs on every linked server after its collector (e.g. \"systemctl is-active {{{{service}}}}\"); {{{{key}}}} placeholders are inserted as one quoted word. Each must classify as read-only (no writes, deletes, service changes or sudo), or the draft is rejected. Required for custom.", wisp_ops_engine::config::MAX_TASK_COMMANDS)}, "paths": {"type": "array", "items": {"type": "string"}, "description": "Absolute default paths; required for disk, space and new-files."}, "days": {"type": "integer", "description": "new-files look-back days."}, "hours": {"type": "integer", "description": "security look-back hours."}, "daily": {"type": "string", "description": "Suggested daily run time HH:MM; default 08:30."}, "timeZone": {"type": "string", "description": "IANA time zone; default the app's."}, "parameters": {"type": "array", "description": "Values asked for when servers are linked, referenced as {{key}} in instruction and commands.", "items": {"type": "object", "additionalProperties": false, "properties": {"key": {"type": "string"}, "label": {"type": "string"}, "hint": {"type": "string"}, "required": {"type": "boolean"}, "defaultValue": {"type": "string"}}, "required": ["key", "label", "hint", "required"]}}}), &["id", "title", "category", "description", "playbook", "instruction"]),
        tool("ops_history", "Read past operations (the audit log of every remote command, with risk, authorization and result), past inspections (health findings and metrics over time), trends, or managed changes with their retained remote backups. Use it for \"what changed\", \"when did this start\", failure history and \"where is the backup\".", json!({"kind": {"type": "string", "enum": ["operations", "inspections", "trends", "changes"]}, "targets": {"type": "string", "description": "Selector; default all."}, "sinceHours": {"type": "number", "description": "Only entries newer than this; default 168."}, "limit": {"type": "integer", "description": "Maximum entries (per host for inspections); default 50."}}), &["kind"]),
        tool("ops_script_draft", &format!("Submit a check-script draft for the user to review in the WispOps window (Routine tasks → Check scripts). It does not save, schedule or run anything: the user reads the draft and accepts it into the script library, then uses it as the check of a routine task, which runs it unattended with sh -s on the task's servers. Write a read-only POSIX sh check that follows the output contract; the draft is refused unless the command classifier finds every line read-only, with no sudo (a task may run it as root instead) and nothing on the deny list. {} Keep it bounded (timeouts, line limits), never modify anything, never read credentials.", wisp_ops_engine::check_scripts::SCRIPT_CONTRACT), json!({"id": {"type": "string", "description": "Letters, digits, dot, hyphen or underscore, e.g. gpu-idle; must not exist in the script library."}, "title": {"type": "string"}, "description": {"type": "string", "description": "One line for the script card: what it checks and when it warns."}, "content": {"type": "string", "description": "POSIX sh script, at most 64 KB."}, "timeoutSec": {"type": "integer", "description": "Per-host timeout, 5 to 3600 seconds; default 120."}}), &["id", "title", "description", "content"]),
    ]
}

/// What the model is told before anything is said: its role, the rules, and the fleet as it stands.
pub fn context(view: &View, skills: &[wisp_ops_core::skill::Skill]) -> ai::Context {
    let mut instructions = String::from(
        "You are the operations assistant inside WispOps, a desktop app for looking after a fleet of Linux servers over SSH. You act only through the ops_* tools; you have no shell of your own.\n\n\
Rules that always hold:\n\
- Address servers only by their inventory names and selectors. Never invent hosts or SSH targets.\n\
- Every call is risk-classified. Read-only commands and the built-in inspection, diagnosis and triage run at once. Anything that changes state, uses sudo, or is destructive is settled per host by the user's policy: allowed, asked (the user sees a card with the hosts, the exact command and your reason, and approves or declines this one call), or denied. A denial by policy is final: do not rephrase the command to get around it, and say what was refused.\n\
- When the user declines a call, do not retry it. Explain what it would do and let them decide.\n\
- Passwords come from the user's vault and go straight to SSH and sudo. You never see them and must never ask for them. Use sudo=true rather than writing sudo in a command.\n\
- Diagnose before you change. Start with ops_inspect / ops_disk / ops_security / ops_jobs / read-only ops_exec, show the evidence (numbers, paths, processes), then propose a plan. For changes to configuration files prefer ops_change (backup, apply, verify, automatic rollback), one canary host first.\n\
- Give a reason for every call that is not read-only: it is shown to the user and kept in the audit log.\n\
- Never delete data whose owner or purpose is unclear; files in use or inside running job directories are left alone and reported to their owners.\n\
- After a change, verify it (run the same diagnosis again) and report what actually happened, including failures.\n\n\
Answer in the user's language, briefly: a status line first, then findings with evidence, then recommended next steps, each marked read-only or needing approval. Use Markdown; put commands in code blocks.",
    );
    if !skills.is_empty() { instructions.push_str("\n\nSkills (step-by-step guides for kinds of work) are available through use_skill; read the matching one before disk cleanups, security triage, managed changes, GPU/Slurm questions and task reports.") }
    let mut documents = format!("# Inventory ({} servers) as of {}\n", view.hosts.len(), wisp_ops_core::time::now_iso());
    if view.hosts.is_empty() { documents.push_str("The inventory is empty. The user adds servers on the Servers page (or imports them from ~/.ssh/config); you cannot add them.\n") }
    for host in &view.hosts {
        documents.push_str(&format!("- {}: {}", host.name, host.address));
        if !host.groups.is_empty() { documents.push_str(&format!("; groups {}", host.groups.join(","))) }
        documents.push_str(&format!("; policy change={} sudo={} destructive={}", host.policy[0], host.policy[1], host.policy[2]));
        if let Some(probe) = &host.probe { documents.push_str(&format!("; {} {}, {} cores, {} GPU, scheduler {}, {}", probe.os, probe.arch, probe.cores, probe.gpus, probe.scheduler, probe.privilege)) }
        if !host.sudo_secret.is_empty() { documents.push_str("; sudo password stored") }
        documents.push_str(&format!("; last inspection: {}", host.state()));
        if !host.description.is_empty() { documents.push_str(&format!(" ({})", host.description)) }
        documents.push('\n');
    }
    if !view.tasks.is_empty() {
        documents.push_str("\n# Routine tasks\n");
        for task in &view.tasks { documents.push_str(&format!("- {}: {} on {}, {}\n", task.name, task.draft.playbook, task.draft.targets, task.when)) }
    }
    documents.push_str("\nThis list was taken when the conversation began; call ops_hosts for the current state.");
    ai::Context { instructions, documents }
}

fn text<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args[key].as_str().filter(|value| !value.trim().is_empty())
}

fn number(args: &Value, key: &str, fallback: i64, min: i64, max: i64) -> i64 {
    args[key].as_i64().or_else(|| args[key].as_f64().map(|n| n as i64)).unwrap_or(fallback).clamp(min, max)
}

/// The call as the window words it: 「批量命令：df -h → web-01」.
pub fn describe_call(name: &str, args: &Value) -> String {
    let short = |value: &str| -> String {
        let line = value.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.chars().count() > 90 { format!("{}…", line.chars().take(90).collect::<String>()) } else { line }
    };
    let sudo = if args["sudo"] == true { "sudo " } else { "" };
    let t = crate::i18n::t;
    match name {
        "ops_hosts" if args["probe"] == true => format!("{}：{}", t("探测能力"), text(args, "targets").unwrap_or("all")),
        "ops_hosts" => format!("{}：{}", t("查看清单"), text(args, "targets").unwrap_or("all")),
        "ops_inspect" => format!("{}：{sudo}{}", t("巡检"), text(args, "targets").unwrap_or("all")),
        "ops_exec" => format!("{}：{sudo}{} → {}", t("批量命令"), short(text(args, "command").unwrap_or("")), text(args, "targets").unwrap_or("?")),
        "ops_disk" => format!("{}：{sudo}{} {}", t("磁盘诊断"), text(args, "host").unwrap_or("?"), text(args, "path").unwrap_or("/")),
        "ops_files" => format!("{}：{sudo}{} {}", t("新增文件分析"), text(args, "host").unwrap_or("?"), text(args, "paths").unwrap_or("?")),
        "ops_security" => format!("{}：{sudo}{}", t("安全排查"), text(args, "targets").unwrap_or("all")),
        "ops_jobs" => format!("{}：{}", t("长时任务"), text(args, "targets").unwrap_or("all")),
        "ops_change" => format!("{}：{sudo}{} → {}", t("安全变更"), short(text(args, "command").unwrap_or("")), text(args, "targets").or(text(args, "host")).unwrap_or("?")),
        "ops_task" => match text(args, "name") {
            Some(task) if args["mode"] == "last" => format!("{}：{task}", t("读取任务结果")),
            Some(task) => format!("{}：{task}", t("运行任务")),
            None => t("查看任务").to_string(),
        },
        "ops_template_draft" => format!("{}：{}", t("提议任务模板"), text(args, "title").or(text(args, "id")).unwrap_or("?")),
        "ops_history" => format!("{}：{} {}", t("查看历史"), text(args, "kind").unwrap_or("?"), text(args, "targets").unwrap_or("all")),
        "ops_script_draft" => format!("{}：{}", t("提交检查脚本草稿"), text(args, "id").unwrap_or("?")),
        other => other.to_string(),
    }
}

/// The remote action a call would perform, read from its arguments alone.
struct Planned {
    selector: String,
    /// What the card shows and the deny list reads.
    command: String,
    /// Every command text the action runs verbatim.
    commands: Vec<String>,
    risk: RiskAssessment,
    sudo: bool,
    task_sudo: bool,
}

/// `Ok(None)` for a call that touches no host.
fn plan(fleet: &Fleet, name: &str, args: &Value) -> Result<Option<Planned>, String> {
    let sudo = args["sudo"] == true;
    let built = |selector: &str, command: String| Planned { selector: selector.to_string(), commands: vec![command.clone()], command, risk: RiskAssessment::read(), sudo, task_sudo: false };
    Ok(Some(match name {
        "ops_exec" => {
            let command = text(args, "command").ok_or("command must not be empty")?.to_string();
            let risk = risk::classify_command(&command, &fleet.extra_read);
            Planned { risk, ..built(text(args, "targets").ok_or("targets is required")?, command) }
        }
        "ops_change" => {
            let plan = change::validate_change(args)?;
            Planned { selector: plan.targets.clone(), command: change::describe_change(&plan), commands: change::change_commands(&plan), risk: change::change_risk(&plan, &fleet.extra_read), sudo, task_sudo: false }
        }
        "ops_inspect" => built(text(args, "targets").unwrap_or("all"), "(built-in read-only inspection)".into()),
        "ops_hosts" if args["probe"] == true => Planned { sudo: false, ..built(text(args, "targets").unwrap_or("all"), "(built-in read-only capability probe)".into()) },
        "ops_disk" => built(text(args, "host").ok_or("host is required")?, format!("(built-in read-only disk diagnosis of {})", text(args, "path").unwrap_or("/"))),
        "ops_files" => built(text(args, "host").ok_or("host is required")?, format!("(built-in read-only recent-file analysis of {})", text(args, "paths").unwrap_or("?"))),
        "ops_security" => built(text(args, "targets").unwrap_or("all"), "(built-in read-only security triage)".into()),
        "ops_jobs" => Planned { sudo: false, ..built(text(args, "targets").unwrap_or("all"), "(built-in read-only check for long-running tasks)".into()) },
        "ops_task" => {
            let Some(task) = text(args, "name").and_then(|name| fleet.inventory().task(name).cloned()) else { return Ok(None) };
            if args["mode"] == "last" { return Ok(None) }
            let task_sudo = task.sudo == Some(true);
            let command = format!("(task {}: built-in {} playbook{})", task.name, task.playbook.as_str(), if task.commands.is_empty() { String::new() } else { format!(" + {} read-only command(s)", task.commands.len()) });
            let mut commands = vec![command.clone()];
            commands.extend(task.commands.iter().cloned());
            // A check script's lines meet the deny list here too; `run_script_task` checks it again before it runs.
            if let Some(id) = &task.script {
                let script = fleet.library_script(id)?.ok_or_else(|| format!("check script \"{id}\" is not in the script library; nothing was executed"))?;
                commands.extend(script.content.lines().map(String::from));
            }
            Planned { selector: task.targets.clone(), command, commands, risk: RiskAssessment::read(), sudo: task_sudo, task_sudo }
        }
        _ => return Ok(None),
    }))
}

/// Settle one call: run it, ask the person about it, or refuse it.
pub fn gate(fleet: &Fleet, session: &str, name: &str, args: &Value) -> Gate {
    let planned = match plan(fleet, name, args) {
        Ok(Some(planned)) => planned,
        Ok(None) => return Gate::Run(Ticket { voucher: None }),
        Err(error) => return Gate::Refuse(error),
    };
    let hosts = match fleet.select(&planned.selector) {
        Ok(hosts) => hosts,
        Err(error) => return Gate::Refuse(error),
    };
    if name == "ops_exec" && planned.risk.level != RiskLevel::Read && text(args, "reason").is_none() { return Gate::Refuse("reason is required for commands that change state; nothing was executed".into()) }
    match policy::gate(&hosts, &planned.risk, planned.sudo, planned.task_sudo, &planned.commands, Some(session), fleet.grant_store(), &fleet.deny) {
        GateOutcome::Deny { reason } => Gate::Refuse(reason.replace(" or /ops-allow", " or a grant")),
        GateOutcome::Allow { voucher } => Gate::Run(Ticket { voucher: Some(voucher) }),
        GateOutcome::Ask { voucher, pending } => {
            let mut needs: Vec<String> = vec![];
            for ruling in &pending {
                let need = ruling.capability.as_str().to_string();
                if !needs.contains(&need) { needs.push(need) }
            }
            let mut asked: Vec<String> = vec![];
            for ruling in &pending {
                if !asked.contains(&ruling.host) { asked.push(ruling.host.clone()) }
            }
            let grantable = !needs.iter().any(|need| need == "destructive");
            Gate::Ask(Ticket { voucher: Some(voucher) }, Ask { hosts: asked, needs, command: planned.command, reason: text(args, "reason").unwrap_or("").to_string(), risks: planned.risk.reasons.clone(), grantable })
        }
    }
}

/// The voucher of a call that touches hosts: there must be one, and it must name the hosts the selector resolves to now.
fn take(ticket: &Ticket, tool: &str, hosts: &[Host]) -> Result<Voucher, String> {
    let voucher = ticket.voucher.clone().ok_or_else(|| format!("{tool}: no authorization record for this call; the permission gate did not run, so nothing was executed"))?;
    if voucher.hosts.len() != hosts.len() || !hosts.iter().all(|host| voucher.hosts.contains(&host.name)) { return Err(format!("{tool}: the authorized host set differs from the resolved one (the inventory changed during the call); nothing was executed")) }
    Ok(voucher)
}

/// Run a call the gate let through. Blocks; called off the main thread.
pub fn run(fleet: &Fleet, session: &str, name: &str, args: &Value, ticket: Ticket, cancel: &Arc<AtomicBool>) -> Result<String, String> {
    let collect = |voucher: &Voucher| Collect { sudo: voucher.sudo && args["sudo"] == true, tool: name.to_string(), session: Some(session.to_string()), authorization: voucher.authorization, cancel: Some(cancel.clone()) };
    let one = |key: &str| -> Result<Host, String> {
        let mut hosts = fleet.select(text(args, key).ok_or_else(|| format!("{key} is required"))?)?;
        if hosts.len() != 1 { return Err(format!("{name} takes exactly one host")) }
        Ok(hosts.remove(0))
    };
    match name {
        "ops_hosts" => {
            let hosts = fleet.select(text(args, "targets").unwrap_or("all"))?;
            let mut failed = vec![];
            if args["probe"] == true {
                take(&ticket, name, &hosts)?;
                failed = fleet.probe_hosts(&hosts, name, Some(session.to_string()), Some(cancel.clone())).into_iter().filter_map(|(host, result)| result.err().map(|error| format!("{host}: {error}"))).collect();
            }
            let view = fleet.view();
            let policy = &fleet.config.default_policy;
            let mut lines = vec![format!("{} host(s). Policy defaults: change={}, sudo={}, destructive={}.", hosts.len(), policy.change.as_str(), policy.sudo.as_str(), policy.destructive.as_str())];
            for host in &hosts {
                let Some(shown) = view.hosts.iter().find(|shown| shown.name == host.name) else { continue };
                let mut parts = vec![format!("ssh {}{}", shown.address, if shown.jump.is_empty() { String::new() } else { format!(" via {}", shown.jump) })];
                if !host.groups.is_empty() { parts.push(format!("groups {}", host.groups.join(","))) }
                if !host.tags.is_empty() { parts.push(format!("tags {}", host.tags.iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join(","))) }
                parts.push(format!("policy change={} sudo={} destructive={}", shown.policy[0], shown.policy[1], shown.policy[2]));
                if host.uses_password() { parts.push("password login".into()) }
                if host.sudo_secret.is_some() { parts.push("sudo password stored".into()) }
                parts.push(match &shown.probe {
                    Some(probe) => format!("{} {}, {} cores, {} GPU, scheduler {}, {}, docker {} (probed {})", probe.os, probe.arch, probe.cores, probe.gpus, probe.scheduler, probe.privilege, probe.docker, probe.at),
                    None => "not probed".into(),
                });
                if let Some(until) = &shown.blocked_until { parts.push(format!("LOGIN PAUSED until {until} after an authentication failure (the user lifts it on the Servers page)")) }
                lines.push(format!("- {}{}: {}", host.name, host.description.as_ref().map(|d| format!(" ({d})")).unwrap_or_default(), parts.join("; ")));
            }
            if !failed.is_empty() { lines.push(format!("\nProbe failed: {}", failed.join("; "))) }
            let grants = fleet.grant_store().active(session);
            lines.push(String::new());
            lines.push(if fleet.grant_store().is_full(session) { "The user gave this conversation full permission: actions needing an \"ask\" capability (change, sudo, destructive) run without asking; \"deny\" and the deny list still refuse. Still prefer read-only diagnosis, explain each change in reason, and be careful with destructive commands.".into() } else if grants.is_empty() { "No grants in this conversation. Actions needing an \"ask\" capability show the user an approval card once per call.".into() } else { format!("Grants in this conversation: {}", grants.iter().map(|grant| format!("{} on {} until {}", grant.capability, grant.hosts.join(","), time::to_iso(grant.expires_at))).collect::<Vec<_>>().join("; ")) });
            Ok(lines.join("\n"))
        }
        "ops_exec" => {
            let command = text(args, "command").ok_or("command must not be empty")?;
            let hosts = fleet.select(text(args, "targets").ok_or("targets is required")?)?;
            let voucher = take(&ticket, name, &hosts)?;
            let exec = Exec { sudo: voucher.sudo && args["sudo"] == true, timeout_ms: fleet.clamp_timeout(args["timeoutMs"].as_u64()), max_output_bytes: None, tool: name.into(), session: Some(session.into()), risk: voucher.risk.level, authorization: voucher.authorization, reason: text(args, "reason").map(String::from), audit_command: None, time_login: false, cancel: Some(cancel.clone()) };
            let results = fleet.execute_one(&hosts, command, &exec);
            let distinct = results.iter().map(|result| result.stdout.as_str()).collect::<std::collections::HashSet<_>>().len().max(1);
            let runs: Vec<_> = results.iter().map(as_run).collect();
            Ok(format!("Risk: {}{}; authorized by {}.\n\n{}", voucher.risk.level.as_str(), if voucher.sudo { " + sudo" } else { "" }, authorization_word(&voucher), render_runs(&runs, (48_000 / distinct).max(2000))))
        }
        "ops_inspect" => {
            let hosts = fleet.select(text(args, "targets").unwrap_or("all"))?;
            let voucher = take(&ticket, name, &hosts)?;
            let fleet_report = fleet.inspect_hosts(&hosts, &collect(&voucher), "(built-in read-only inspection)");
            Ok(render_inspection(&fleet_report, args["detail"] == true))
        }
        "ops_disk" => {
            let host = one("host")?;
            let path = text(args, "path").unwrap_or("/");
            if !path.starts_with('/') { return Err("path must be absolute".into()) }
            let voucher = take(&ticket, name, std::slice::from_ref(&host))?;
            let min = number(args, "minFileMb", 100, 1, 1_000_000) as u64;
            let options = disk::DiskOptions { path: path.to_string(), depth: number(args, "depth", 2, 1, 6) as u32, top: number(args, "top", 15, 1, 100) as usize, min_file_mb: min, recent_min_file_mb: (min / 10).max(1), recent_minutes: number(args, "recentMinutes", 1440, 1, 60 * 24 * 90) as u64, walk_timeout_sec: number(args, "walkTimeoutSec", 60, 5, 1800) as u64 };
            let (report, result) = fleet.disk(&host, &options, &collect(&voucher));
            Ok(match report { Some(report) => disk::render_disk(&host.name, &report), None => render_runs(&[as_run(&result)], 4000) })
        }
        "ops_files" => {
            let host = one("host")?;
            let paths: Vec<String> = text(args, "paths").unwrap_or("").split(',').map(str::trim).filter(|path| !path.is_empty()).map(String::from).collect();
            if paths.is_empty() || paths.iter().any(|path| !path.starts_with('/')) { return Err("paths must be absolute".into()) }
            let voucher = take(&ticket, name, std::slice::from_ref(&host))?;
            let options = files::FilesOptions { paths, days: number(args, "days", 7, 1, 3650) as u32, depth: number(args, "depth", 3, 1, 8) as u32, list_min_mb: number(args, "listMinMb", 10, 1, 1_000_000) as u64, max_files: 5000, top: 20, walk_timeout_sec: number(args, "walkTimeoutSec", 300, 10, 3600) as u64 };
            let (report, result) = fleet.files(&host, &options, &collect(&voucher));
            Ok(match report { Some(report) => files::render_files(&host.name, &report), None => render_runs(&[as_run(&result)], 4000) })
        }
        "ops_security" => {
            let hosts = fleet.select(text(args, "targets").unwrap_or("all"))?;
            let voucher = take(&ticket, name, &hosts)?;
            let hours = number(args, "hours", 24, 1, 24 * 90) as u32;
            Ok(fleet.security(&hosts, hours, &collect(&voucher)).into_iter().map(|(host, report, result)| match report { Some(report) => security::render_security(&host, &report, hours), None => render_runs(&[as_run(&result)], 2000) }).collect::<Vec<_>>().join("\n\n"))
        }
        "ops_jobs" => {
            let hosts = fleet.select(text(args, "targets").unwrap_or("all"))?;
            let voucher = take(&ticket, name, &hosts)?;
            let hours = number(args, "hours", 24, 1, 24 * 365) as u32;
            let collect = Collect { sudo: false, ..collect(&voucher) };
            Ok(fleet.long_jobs_on(&hosts, hours, &collect).into_iter().map(|(host, report, result)| match report { Some(report) => longrun::render_longrun(&host, &report), None => render_runs(&[as_run(&result)], 2000) }).collect::<Vec<_>>().join("\n\n"))
        }
        "ops_change" => run_change(fleet, session, args, &ticket, cancel),
        // Touches no host (`plan` gives no voucher): it only queues a draft the person reviews in the window.
        "ops_template_draft" => fleet.draft_template(args),
        "ops_task" => {
            let inventory = fleet.inventory();
            let Some(task_name) = text(args, "name") else {
                let tasks = inventory.tasks();
                if tasks.is_empty() { return Ok("No tasks are defined. The user creates them on the Tasks page.".into()) }
                return Ok(tasks.iter().map(|task| format!("- {}: {} on {}, {}{}{}", task.name, task.playbook.as_str(), task.targets, wisp_ops_engine::schedule::describe_schedule(task.schedule.as_ref(), &fleet.config.time_zone), if task.sudo == Some(true) { ", sudo" } else { "" }, task.description.as_ref().map(|d| format!(" — {d}")).unwrap_or_default())).collect::<Vec<_>>().join("\n"));
            };
            let task = inventory.task(task_name).ok_or_else(|| format!("unknown task \"{task_name}\"; call ops_task without a name to list tasks"))?;
            if args["mode"] == "last" { return Ok(fleet.last_task_text(task)) }
            let hosts = fleet.select(&task.targets)?;
            let voucher = take(&ticket, name, &hosts)?;
            fleet.run_task_as(task, voucher.sudo && task.sudo == Some(true), voucher.authorization, Some(session.to_string()), Some(cancel.clone())).map(|(text, _)| text)
        }
        // Writes a draft for a person to review, nothing more: the model cannot accept it.
        "ops_script_draft" => fleet.draft_script(args),
        "ops_history" => {
            let hosts = fleet.select(text(args, "targets").unwrap_or("all"))?;
            let since_ms = time::now_ms() - (args["sinceHours"].as_f64().unwrap_or(168.) * 3_600_000.) as i64;
            let limit = number(args, "limit", 50, 1, 1000) as usize;
            match text(args, "kind").unwrap_or("") {
                "operations" => {
                    let rows = fleet.store.read_audit(&AuditFilter { hosts: Some(hosts.iter().map(|host| host.name.clone()).collect()), since_ms: Some(since_ms), limit })?;
                    if rows.is_empty() { return Ok("No recorded operations in this window.".into()) }
                    Ok(rows.iter().map(|row| format!("{} {} [{}{}, {}] {}{} {}: {}{}", row.at, row.host, row.risk.as_str(), if row.sudo { "+sudo" } else { "" }, serde_json::to_value(row.authorization).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(), row.status.as_str(), row.exit_code.map(|code| format!("/{code}")).unwrap_or_default(), row.tool, row.command.lines().next().unwrap_or("").chars().take(160).collect::<String>(), row.reason.as_ref().map(|reason| format!(" — {}", reason.chars().take(120).collect::<String>())).unwrap_or_default())).collect::<Vec<_>>().join("\n"))
                }
                "changes" => {
                    let mut lines = vec![];
                    for host in &hosts {
                        let rows: Vec<ChangeRecord> = fleet.store.read_changes(&host.name, limit)?.into_iter().filter(|row| wisp_ops_collect::util::date_parse(&row.at) as i64 >= since_ms).collect();
                        if rows.is_empty() { continue }
                        lines.push(format!("## {}", host.name));
                        for row in rows {
                            let paths: Vec<String> = row.files.iter().cloned().chain(row.new_files.iter().map(|file| format!("{file} (new)"))).chain(row.directories.iter().map(|dir| format!("{dir}/"))).collect();
                            lines.push(format!("{} {:?}{} {} — {}; {}", row.at, row.outcome, if row.sudo { " sudo" } else { "" }, paths.join(", "), row.reason.chars().take(120).collect::<String>(), row.backup_dir.as_ref().map(|dir| format!("backup {dir}")).unwrap_or_else(|| "no backup created".into())));
                        }
                    }
                    let retention = fleet.config.change.backup_retention_days;
                    let header = format!("Backup retention: {} under {} on each host.", if retention > 0 { format!("{retention} days") } else { "unlimited".into() }, fleet.config.change.backup_root);
                    Ok(if lines.is_empty() { format!("No managed changes recorded in this window. {header}") } else { format!("{header}\n{}", lines.join("\n")) })
                }
                kind @ ("inspections" | "trends") => {
                    let mut lines = vec![];
                    for host in &hosts {
                        let rows: Vec<HistoryRecord> = fleet.store.read_history::<HistoryRecord>(&host.name, limit).unwrap_or_default().into_iter().filter(|row| wisp_ops_collect::util::date_parse(&row.metrics.at) as i64 >= since_ms).collect();
                        if rows.is_empty() { continue }
                        lines.push(format!("## {}", host.name));
                        if kind == "trends" {
                            lines.extend(trends::render_trends(&rows));
                            continue;
                        }
                        for row in &rows {
                            let disks: Vec<String> = row.metrics.disk_pct.iter().map(|(mount, pct)| format!("{mount} {pct}%")).collect();
                            let problems: Vec<&str> = row.findings.iter().filter(|finding| finding.severity.as_str() != "info").map(|finding| finding.code.as_str()).collect();
                            lines.push(format!("{} {}{}{} {}{}", row.metrics.at, row.status, row.metrics.load1.map(|load| format!(" load {load}")).unwrap_or_default(), row.metrics.mem_avail_pct.map(|pct| format!(" mem {pct}%")).unwrap_or_default(), disks.join(" "), if problems.is_empty() { String::new() } else { format!(" | {}", problems.join(", ")) }));
                        }
                    }
                    Ok(if lines.is_empty() { "No inspections recorded in this window; run ops_inspect.".into() } else { lines.join("\n") })
                }
                _ => Err("kind must be one of operations, inspections, trends, changes".into()),
            }
        }
        other => Err(format!("unknown tool {other}")),
    }
}

fn authorization_word(voucher: &Voucher) -> String {
    serde_json::to_value(voucher.authorization).ok().and_then(|value| value.as_str().map(String::from)).unwrap_or_default()
}

/// A managed change: host by host in inventory order, stopped at the first that does not verify.
fn run_change(fleet: &Fleet, session: &str, args: &Value, ticket: &Ticket, cancel: &Arc<AtomicBool>) -> Result<String, String> {
    let plan = change::validate_change(args)?;
    let hosts = fleet.select(&plan.targets)?;
    let voucher = take(ticket, "ops_change", &hosts)?;
    let max = fleet.config.limits.max_timeout_ms;
    if max < 20_000 { return Err("ops_change requires maxTimeoutMs >= 20000 to reserve rollback time".into()) }
    let seconds = (plan.timeout_ms.unwrap_or(15_000).min((max - 15_000) / 3) / 1000).max(1);
    // Backups of directories run outside the staged timeouts; give them extra connection time.
    let timeout_ms = max.min(seconds * 3000 + 15_000 + plan.directories.len() as u64 * 60_000);
    let script = change::change_script(&plan, seconds, &change::ChangeScriptOptions { backup_root: fleet.config.change.backup_root.clone(), retention_days: fleet.config.change.backup_retention_days });
    let sudo = args["sudo"] == true && voucher.sudo;
    let described = change::describe_change(&plan);
    fleet.begin_change(&hosts)?;
    let mut rollout: Vec<String> = vec![];
    let mut runs = vec![];
    let mut skipped: Vec<&str> = vec![];
    for (index, host) in hosts.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            skipped = hosts[index..].iter().map(|host| host.name.as_str()).collect();
            break;
        }
        let exec = Exec { sudo, timeout_ms, max_output_bytes: None, tool: "ops_change".into(), session: Some(session.into()), risk: voucher.risk.level, authorization: voucher.authorization, reason: Some(plan.reason.clone()), audit_command: Some(described.clone()), time_login: false, cancel: Some(cancel.clone()) };
        let result = fleet.execute_one(std::slice::from_ref(host), &script, &exec).remove(0);
        let parsed = change::parse_change_output(&result.stdout, result.exit_code);
        let _ = fleet.store.record_change(&ChangeRecord { at: time::to_iso(time::now_ms()), session: Some(session.into()), host: host.name.clone(), outcome: parsed.outcome, status: result.status, exit_code: result.exit_code, backup_dir: parsed.backup_dir.clone(), files: plan.files.clone(), new_files: plan.new_files.clone(), directories: plan.directories.clone(), reason: plan.reason.clone(), sudo });
        let outcome = serde_json::to_value(parsed.outcome).ok().and_then(|value| value.as_str().map(String::from)).unwrap_or_default();
        rollout.push(format!("- {}: {outcome}{}{}", host.name, if parsed.outcome != ChangeOutcome::Verified && result.status.as_str() != "ok" { format!(" ({})", result.status.as_str()) } else { String::new() }, parsed.backup_dir.map(|dir| format!(" — backup {dir}")).unwrap_or_default()));
        runs.push(as_run(&result));
        if parsed.outcome != ChangeOutcome::Verified {
            skipped = hosts[index + 1..].iter().map(|host| host.name.as_str()).collect();
            break;
        }
    }
    fleet.end_change(&hosts);
    rollout.extend(skipped.iter().map(|host| format!("- {host}: skipped")));
    let mut note = vec![];
    if !skipped.is_empty() { note.push(format!("Rollout stopped at the first host that did not verify; not attempted: {}.", skipped.join(", "))) }
    note.push("Backups stay on the host; ops_history kind=changes lists them. If SSH timed out or disconnected, the final state of that host is unknown; inspect before retrying.".to_string());
    Ok(format!("{described}\n\nRollout ({} host(s), in order):\n{}\n\n{}\n{}", hosts.len(), rollout.join("\n"), render_runs(&runs, 12_000), note.join(" ")))
}

/// What came of a call, in a few words for its line in the conversation.
pub fn summary(result: &Result<String, String>) -> String {
    let line = |text: &str| -> String {
        let first = text.lines().find(|line| !line.trim().is_empty()).unwrap_or("").trim().trim_start_matches('#').trim();
        if first.chars().count() > 80 { format!("{}…", first.chars().take(80).collect::<String>()) } else { first.to_string() }
    };
    match result {
        Ok(text) => {
            let first = line(text);
            if first.is_empty() { crate::i18n::t("完成").to_string() } else { first }
        }
        Err(error) => line(error),
    }
}

// ---- the words of the interface (Chinese keys, looked up by `i18n::t` where shown)

pub fn capability_label(capability: &str) -> &'static str {
    match capability {
        "change" => "变更",
        "sudo" => "sudo 提权",
        "destructive" => "破坏性操作",
        _ => "只读",
    }
}

pub fn capability_about(capability: &str) -> &'static str {
    match capability {
        "change" => "重启服务、装包、改配置、写文件",
        "sudo" => "以 root 或其他账号执行",
        _ => "删除、格式化、重启、清理",
    }
}

pub fn permission_label(permission: &str) -> &'static str {
    match permission {
        "allow" => "允许",
        "deny" => "拒绝",
        _ => "询问",
    }
}

pub fn privilege_label(privilege: &str) -> &'static str {
    match privilege {
        "root" => "以 root 登录",
        "sudo-nopasswd" => "免密 sudo",
        "sudo-password" => "需要密码",
        _ => "不可用",
    }
}

pub fn risk_label(risk: &str) -> &'static str {
    match risk {
        "change" => "变更",
        "destructive" => "破坏性",
        _ => "只读",
    }
}

pub fn authorization_label(authorization: &str) -> &'static str {
    match authorization {
        "policy" => "策略允许",
        "grant" => "限时授权",
        "full" => "完全授权",
        "approval" => "逐次批准",
        "task" => "任务",
        _ => "只读",
    }
}

pub fn status_label(status: &str) -> &'static str {
    match status {
        "ok" => "成功",
        "failed" => "失败",
        "unreachable" => "不可达",
        "auth-failed" => "认证失败",
        "blocked" => "登录暂停",
        "sudo-required" => "sudo 被拒",
        "timeout" => "超时",
        "cancelled" => "已中止",
        _ => "未知",
    }
}

/// Who ran a command, from the audit's `tool`.
pub fn origin_label(tool: &str) -> &'static str {
    if tool.starts_with("ops_task") {
        "任务"
    } else if tool.starts_with("window:auto") {
        "自动巡检"
    } else if tool.starts_with("window:disk-auto") {
        "增量扫描"
    } else if tool.starts_with("window") {
        "窗口"
    } else {
        "助手"
    }
}
