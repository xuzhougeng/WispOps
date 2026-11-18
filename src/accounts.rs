//! What the 用户 page has the fleet do: read the accounts of servers (as root where the window
//! may, so that the password states show), create accounts on many servers at once, and give one
//! account a new password. The changes need root and are refused where a server's policy denies
//! changes or sudo, or the deny list refuses the script; nothing runs unless every server named
//! may. They are recorded in the audit as the person's own approval, without any password.
//!
//! A password the window makes up (`NewPassword::Random`, a reset without one written) is handed
//! back once, to be shown to the person who has to pass it on; it is kept nowhere.

use crate::ops::{Exec, Fleet};
use std::collections::{BTreeMap, HashMap};
use wisp_ops_collect::accounts::{self, AccountsSnapshot};
use wisp_ops_engine::accounts::{self as change, NewAccounts, NewPassword, Outcome};
use wisp_ops_engine::config::Permission;
use wisp_ops_engine::inventory::Host;
use wisp_ops_engine::risk::RiskLevel;
use wisp_ops_engine::ssh::{RunResult, RunStatus};
use wisp_ops_engine::store::Authorization;
use wisp_ops_engine::time;

/// What one server made of a creation: each account, what became of it and the password made
/// up for it; or why nothing could be done there.
pub struct HostOutcome {
    pub host: String,
    pub accounts: Vec<(String, Outcome, Option<String>)>,
    pub error: Option<String>,
}

/// A run that did not get to say anything, in a line.
fn run_error(result: &RunResult) -> String {
    let why = result.stderr.trim().lines().next().map(|line| format!("：{}", line.chars().take(240).collect::<String>())).unwrap_or_default();
    format!("{}{why}", crate::i18n::t(crate::tools::status_label(result.status.as_str())))
}

impl Fleet {
    /// Read the accounts of the selected servers and keep them: as root wherever the window may,
    /// without it elsewhere (then the password states are not known).
    pub fn read_accounts(&self, selector: &str) -> Result<String, String> {
        let hosts = self.select(selector)?;
        let (rooted, plain): (Vec<Host>, Vec<Host>) = hosts.into_iter().partition(|host| self.root_way(host) == Ok(true));
        let at = time::to_iso(time::now_ms());
        let (mut read, mut failed) = (0, vec![]);
        for (group, sudo) in [(rooted, true), (plain, false)] {
            if group.is_empty() { continue }
            let mut exec = Exec::read("window:accounts", if sudo { Authorization::Approval } else { Authorization::ReadOnly });
            exec.sudo = sudo;
            exec.timeout_ms = self.config.ssh.connect_timeout_sec * 1000 + 30_000;
            exec.max_output_bytes = Some(4 << 20);
            exec.audit_command = Some("(built-in read-only listing of accounts and groups)".into());
            for result in self.execute_one(&group, accounts::ACCOUNTS_SCRIPT, &exec) {
                match accounts::parse_accounts(&result.stdout) {
                    Some(report) => {
                        let _ = self.store.append_bounded("accounts", &result.host, &AccountsSnapshot { report, at: at.clone() }, 3);
                        read += 1;
                    }
                    None => failed.push(format!("{}（{}）", result.host, run_error(&result))),
                }
            }
        }
        let said = tf!("已读取 {read} 台服务器的账号", "Read the accounts of {read} servers");
        if failed.is_empty() { Ok(said) } else { Err(tf!("{said}；没有读到：{}", "{said}; not read: {}", failed.join("；"))) }
    }

    /// The accounts last read on every server that has been read.
    pub fn accounts(&self) -> BTreeMap<String, AccountsSnapshot> {
        self.inventory().hosts().iter().filter_map(|host| self.store.read_bounded::<AccountsSnapshot>("accounts", &host.name).ok().and_then(|mut rows| rows.pop()).map(|row| (host.name.clone(), row))).collect()
    }

    /// Whether the window may change accounts on this server, and whether that takes sudo.
    fn account_way(&self, host: &Host) -> Result<bool, String> {
        if host.policy.change == Permission::Deny { return Err(tf!("{} 的权限策略拒绝变更。", "The policy of {} denies changes.", host.name)) }
        self.root_way(host)
    }

    /// A script with its passwords blanked, line by line against the deny list.
    fn deny_check(&self, masked: &str) -> Result<(), String> {
        match masked.lines().find_map(|line| self.deny.matches(line)) {
            Some(pattern) => Err(tf!("拒绝清单拦下了这个操作（{pattern}）。", "The deny list refuses this ({pattern}).")),
            None => Ok(()),
        }
    }

    fn change_exec(&self, sudo: bool, audit: String, reason: &str, accounts: usize) -> Exec {
        let mut exec = Exec::read("window:accounts", Authorization::Approval);
        exec.sudo = sudo;
        exec.risk = RiskLevel::Change;
        exec.reason = Some(reason.into());
        exec.audit_command = Some(audit);
        exec.max_output_bytes = Some(1 << 20);
        exec.timeout_ms = self.clamp_timeout(Some(self.config.ssh.connect_timeout_sec * 1000 + 30_000 + accounts as u64 * 2_000));
        exec
    }

    /// Create the same accounts on every selected server. Nothing runs unless every one of them may.
    pub fn create_accounts(&self, selector: &str, spec: &NewAccounts, password: &NewPassword) -> Result<Vec<HostOutcome>, String> {
        if spec.names.is_empty() { return Err(t_owned("写上要创建的用户名。")) }
        let hosts = self.select(selector)?;
        let mut ways: Vec<(Host, bool)> = vec![];
        let mut refused: Vec<String> = vec![];
        for host in hosts {
            match self.account_way(&host) {
                Ok(sudo) => ways.push((host, sudo)),
                Err(error) => refused.push(error),
            }
        }
        if !refused.is_empty() { return Err(tf!("没有创建任何账号：{}", "No account was created: {}", refused.join(" "))) }
        let blank = || match password { NewPassword::Locked => None, _ => Some("********".to_string()) };
        self.deny_check(&change::create_script(spec, &vec![blank(); spec.names.len()]))?;
        // The passwords of each server, one per account; made up here when they are to be random.
        let mut passwords: HashMap<String, Vec<Option<String>>> = HashMap::new();
        for (host, _) in &ways {
            let list = spec.names.iter().map(|_| match password {
                NewPassword::Random => change::generate_password().map(Some),
                NewPassword::Same(text) => Ok(Some(text.clone())),
                NewPassword::Locked => Ok(None),
            }).collect::<Result<Vec<_>, String>>()?;
            passwords.insert(host.name.clone(), list);
        }
        let audit = change::describe_create(spec, password);
        let mut out = vec![];
        for sudo in [true, false] {
            let group: Vec<Host> = ways.iter().filter(|(_, way)| *way == sudo).map(|(host, _)| host.clone()).collect();
            if group.is_empty() { continue }
            let exec = self.change_exec(sudo, audit.clone(), "创建用户（窗口）", spec.names.len());
            let script = |host: &Host| change::create_script(spec, passwords.get(&host.name).map(Vec::as_slice).unwrap_or(&[]));
            for result in self.execute(&group, &script, &exec) {
                let made = passwords.get(&result.host).cloned().unwrap_or_default();
                let secrets: Vec<&str> = made.iter().flatten().map(String::as_str).collect();
                let stdout = change::redact(&result.stdout, &secrets);
                let outcomes = change::parse_outcomes(&stdout);
                let whole = outcomes.iter().find(|(name, _)| name == "*").map(|(_, outcome)| outcome.clone());
                let error = match whole {
                    Some(Outcome::Failed(why)) => Some(why),
                    _ if outcomes.is_empty() => Some(change::redact(&run_error(&result), &secrets)),
                    _ => None,
                };
                let accounts = outcomes.into_iter().filter(|(name, _)| name != "*").map(|(name, outcome)| {
                    // Only a password the window made up is shown again: the person knows one they wrote.
                    let shown = (outcome == Outcome::Created && *password == NewPassword::Random).then(|| spec.names.iter().position(|known| *known == name).and_then(|at| made.get(at).cloned().flatten())).flatten();
                    (name, outcome, shown)
                }).collect();
                out.push(HostOutcome { host: result.host.clone(), accounts, error });
            }
        }
        let names: Vec<&str> = out.iter().map(|outcome| outcome.host.as_str()).collect();
        let _ = self.read_accounts(&names.join(","));
        Ok(out)
    }

    /// Give one account of one server a new password: the one written, or one made up here, which
    /// is handed back. A locked account is unlocked by it.
    pub fn reset_account_password(&self, host_name: &str, account: &str, written: Option<String>, expire: bool) -> Result<Option<String>, String> {
        if let Some(problem) = change::name_problem(account) { return Err(problem) }
        let host = self.inventory().host(host_name).cloned().ok_or_else(|| tf!("清单里没有 {host_name}。", "{host_name} is not in the inventory."))?;
        let sudo = self.account_way(&host)?;
        if let Some(problem) = written.as_deref().and_then(change::password_problem) { return Err(problem) }
        self.deny_check(&change::reset_script(account, "********", expire))?;
        let generated = written.is_none();
        let password = match written {
            Some(text) => text,
            None => change::generate_password()?,
        };
        let exec = self.change_exec(sudo, change::describe_reset(account, generated, expire), "重置用户密码（窗口）", 1);
        let result = self.execute_one(std::slice::from_ref(&host), &change::reset_script(account, &password, expire), &exec).remove(0);
        let stdout = change::redact(&result.stdout, &[&password]);
        let outcome = change::parse_outcomes(&stdout).into_iter().find(|(name, _)| name == account).map(|(_, outcome)| outcome);
        let _ = self.read_accounts(host_name);
        match outcome {
            Some(Outcome::Reset) => Ok(generated.then_some(password)),
            Some(Outcome::Missing) => Err(tf!("{host_name} 上没有账号 {account}。", "There is no account {account} on {host_name}.")),
            Some(Outcome::Failed(why)) => Err(tf!("没有改成：{why}", "The password was not changed: {why}")),
            _ if result.status == RunStatus::Ok => Err(t_owned("没有改成：服务器没有回报结果。")),
            _ => Err(tf!("没有改成：{}", "The password was not changed: {}", change::redact(&run_error(&result), &[&password]))),
        }
    }
}

fn t_owned(key: &str) -> String {
    crate::i18n::t(key).to_string()
}
