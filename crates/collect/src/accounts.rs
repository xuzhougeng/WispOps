//! The accounts of a host, read-only: `passwd` and `group` (through `getent`, so directory
//! accounts count too), and, where the script runs as root, what state each password is in.
//! The hashes never leave the host: `awk` reduces each `shadow` line to a word before printing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::logins::{LoginReport, parse_logins};
use crate::quotas::{QuotaReport, parse_quotas};
use crate::sections::parse_sections;

/// The most lines of each database the script prints; a directory with more is cut there.
pub const MAX_LINES: usize = 5000;

/// The accounts, then their logins (`logins`) and their disk quotas (`quotas`), in one run.
pub const ACCOUNTS_SCRIPT: &str = concat!(
    r#"export LC_ALL=C
db() { if command -v getent >/dev/null 2>&1; then getent "$1"; else cat "/etc/$1"; fi 2>/dev/null | head -n 5000; }
echo @@whoami
id -u
echo @@login_uid_min
awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null
echo @@passwd
db passwd
echo @@group
db group
if [ -r /etc/shadow ]; then
  echo @@shadow
  awk -F: 'NF >= 2 { p = $2; if (p == "") s = "empty"; else if (p ~ /^[!*]+$/) s = "none"; else if (p ~ /^!/) s = "locked"; else s = "set"; print $1 ":" s ":" $3 ":" $8 }' /etc/shadow 2>/dev/null | head -n 5000
fi
echo @@who
who 2>/dev/null | awk '{ print $1 }' | head -n 2000
"#,
    include_str!("scripts/logins.sh"),
    include_str!("scripts/quotas.sh"),
    "echo @@end\n"
);

/// What a password is, as far as `shadow` tells.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordState {
    /// A password is set and can be used.
    Set,
    /// A password is set but locked (`!` before it).
    Locked,
    /// No password at all (`!`, `!!` or `*`): only a key or another method logs in.
    None,
    /// An empty field: anyone may log in without a password where that is allowed.
    Empty,
    /// `shadow` was not readable (not root), or the account is not in it.
    #[default]
    Unknown,
}

impl PasswordState {
    fn read(word: &str) -> PasswordState {
        match word {
            "set" => PasswordState::Set,
            "locked" => PasswordState::Locked,
            "none" => PasswordState::None,
            "empty" => PasswordState::Empty,
            _ => PasswordState::Unknown,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// The group of `gid`, when the group database names it.
    pub primary_group: String,
    /// The other groups it is a member of.
    pub groups: Vec<String>,
    pub gecos: String,
    pub home: String,
    pub shell: String,
    pub password: PasswordState,
    /// The day (since 1970) the password was last changed; 0 means it must be changed at the next login.
    pub changed_day: Option<i64>,
    /// The day (since 1970) the account expires.
    pub expires_day: Option<i64>,
    /// Sessions open now (`who`).
    pub sessions: u32,
}

impl Account {
    /// Root, or a member of a group that usually holds sudo.
    pub fn admin(&self) -> bool {
        self.uid == 0 || [self.primary_group.as_str()].into_iter().chain(self.groups.iter().map(String::as_str)).any(|group| matches!(group, "sudo" | "wheel" | "admin"))
    }

    /// Its shell lets it log in.
    pub fn can_log_in(&self) -> bool {
        !(self.shell.ends_with("/nologin") || self.shell.ends_with("/false") || self.shell == "/sbin/shutdown" || self.shell == "/bin/sync" || self.shell == "/sbin/halt")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AccountsReport {
    pub accounts: Vec<Account>,
    /// The lowest UID of a person's account (`UID_MIN` of `/etc/login.defs`, 1000 without it).
    pub uid_min: u32,
    /// The script ran as root.
    pub as_root: bool,
    /// The password states could be read.
    pub shadow_readable: bool,
    /// A database had more lines than the script prints.
    pub truncated: bool,
    pub logins: LoginReport,
    pub quotas: QuotaReport,
}

impl AccountsReport {
    /// A system account: below `UID_MIN` (root aside), or `nobody`.
    pub fn system(&self, account: &Account) -> bool {
        account.uid != 0 && (account.uid < self.uid_min || account.uid == 65534 || account.name == "nobody")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AccountsSnapshot {
    pub report: AccountsReport,
    pub at: String,
}

/// Read what `ACCOUNTS_SCRIPT` printed. `None` when it did not get to the end.
pub fn parse_accounts(output: &str) -> Option<AccountsReport> {
    let sections = parse_sections(output);
    if !sections.has("end") { return None }
    let uid_min = sections.first("login_uid_min").and_then(|value| value.trim().parse().ok()).unwrap_or(1000);
    let as_root = sections.first("whoami").map(str::trim) == Some("0");
    let mut group_names: HashMap<u32, String> = HashMap::new();
    let mut members: HashMap<&str, Vec<String>> = HashMap::new();
    for line in sections.get("group") {
        let parts: Vec<&str> = line.split(':').collect();
        let [name, _, gid, list] = parts[..] else { continue };
        if let Ok(gid) = gid.parse() { group_names.entry(gid).or_insert_with(|| name.to_string()); }
        for member in list.split(',').map(str::trim).filter(|member| !member.is_empty()) {
            let joined = members.entry(member).or_default();
            if !joined.iter().any(|group| group == name) { joined.push(name.to_string()) }
        }
    }
    let shadow: HashMap<&str, (PasswordState, Option<i64>, Option<i64>)> = sections
        .get("shadow")
        .iter()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            let [name, state, changed, expires] = parts[..] else { return None };
            Some((name, (PasswordState::read(state), changed.parse().ok(), expires.parse().ok())))
        })
        .collect();
    let mut sessions: HashMap<&str, u32> = HashMap::new();
    for line in sections.get("who") { *sessions.entry(line.trim()).or_default() += 1 }
    let mut accounts: Vec<Account> = vec![];
    for line in sections.get("passwd") {
        let parts: Vec<&str> = line.split(':').collect();
        let [name, _, uid, gid, gecos, home, shell] = parts[..] else { continue };
        let (Ok(uid), Ok(gid)) = (uid.parse(), gid.parse()) else { continue };
        // A directory can list an account that a local file lists too: the first one counts, as for the system.
        if name.is_empty() || accounts.iter().any(|account| account.name == name) { continue }
        let primary_group = group_names.get(&gid).cloned().unwrap_or_default();
        let groups = members.get(name).map(|groups| groups.iter().filter(|group| **group != primary_group).cloned().collect()).unwrap_or_default();
        let (password, changed_day, expires_day) = shadow.get(name).copied().unwrap_or((PasswordState::Unknown, None, None));
        accounts.push(Account { name: name.into(), uid, gid, primary_group, groups, gecos: gecos.split(',').next().unwrap_or("").into(), home: home.into(), shell: shell.into(), password, changed_day, expires_day, sessions: sessions.get(name).copied().unwrap_or(0) });
    }
    let truncated = [sections.get("passwd").len(), sections.get("group").len()].iter().any(|count| *count >= MAX_LINES);
    Some(AccountsReport { accounts, uid_min, as_root, shadow_readable: sections.has("shadow"), truncated, logins: parse_logins(&sections), quotas: parse_quotas(&sections) })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTPUT: &str = "@@whoami\n0\n@@login_uid_min\n1000\n@@passwd\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nalice:x:1001:1001:Alice Liu,,,:/home/alice:/bin/bash\nbob:x:1002:100::/home/bob:/bin/zsh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nalice:x:5001:5001:dup:/x:/bin/sh\n@@group\nroot:x:0:\nusers:x:100:\nalice:x:1001:\nsudo:x:27:alice\ndocker:x:998:alice,bob\n@@shadow\nroot:set:19800:\ndaemon:none:19000:\nalice:set:0:\nbob:locked:19850:20000\nnobody:empty:19000:\n@@who\nalice\nalice\nbob\n@@end\n";

    #[test]
    fn accounts_are_read_with_their_groups_and_password_state() {
        let report = parse_accounts(OUTPUT).unwrap();
        assert!(report.as_root && report.shadow_readable && !report.truncated);
        let names: Vec<&str> = report.accounts.iter().map(|account| account.name.as_str()).collect();
        assert_eq!(names, ["root", "daemon", "alice", "bob", "nobody"]);
        let alice = &report.accounts[2];
        assert_eq!((alice.gecos.as_str(), alice.primary_group.as_str(), alice.groups.clone()), ("Alice Liu", "alice", vec!["sudo".to_string(), "docker".to_string()]));
        assert_eq!((alice.password, alice.changed_day, alice.sessions), (PasswordState::Set, Some(0), 2));
        assert!(alice.admin() && alice.can_log_in());
        let bob = &report.accounts[3];
        assert_eq!((bob.primary_group.as_str(), bob.password, bob.expires_day, bob.admin()), ("users", PasswordState::Locked, Some(20000), false));
        assert!(report.system(&report.accounts[1]) && report.system(&report.accounts[4]) && !report.system(&report.accounts[0]));
        assert!(!report.accounts[1].can_log_in());
        assert_eq!(report.accounts[4].password, PasswordState::Empty);
    }

    #[test]
    fn without_root_the_passwords_are_unknown_and_a_cut_run_is_nothing() {
        let plain = OUTPUT.replace("@@whoami\n0", "@@whoami\n1000");
        let start = plain.find("@@shadow").unwrap();
        let end = plain.find("@@who\n").unwrap();
        let plain = format!("{}{}", &plain[..start], &plain[end..]);
        let report = parse_accounts(&plain).unwrap();
        assert!(!report.as_root && !report.shadow_readable);
        assert!(report.accounts.iter().all(|account| account.password == PasswordState::Unknown));
        assert_eq!(parse_accounts("@@whoami\n0\n@@passwd\nroot:x:0:0::/root:/bin/sh\n"), None);
    }

    #[test]
    fn the_script_never_prints_a_hash() {
        // The second field of shadow is reduced to a word inside awk; nothing else reads the file.
        assert_eq!(ACCOUNTS_SCRIPT.matches("/etc/shadow").count(), 2);
        assert_eq!(ACCOUNTS_SCRIPT.matches("echo @@end").count(), 1);
        assert!(ACCOUNTS_SCRIPT.ends_with("fi\necho @@end\n"));
        assert!(ACCOUNTS_SCRIPT.contains("print $1 \":\" s \":\" $3 \":\" $8"));
    }
}
