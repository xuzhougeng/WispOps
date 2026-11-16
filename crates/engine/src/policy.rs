//! Permission decisions, human-issued grants, and the gate that settles one planned action.
//!
//! Three sources can authorize a capability on a host: deployment policy (`allow`), a time-boxed
//! grant the human issued, or a one-shot approval of the exact call. `deny` in policy is
//! absolute: neither grants nor approvals override it. Grants are created only by the human;
//! nothing the model can call creates or widens one.

use std::sync::Mutex;

use regex::Regex;
use serde::Serialize;

use crate::config::{Capability, Permission};
use crate::fsutil::random_hex;
use crate::inventory::Host;
use crate::jsre::{compile, is_js_space, js_re, js_trim};
use crate::risk::{RiskAssessment, RiskLevel};
pub use crate::store::Authorization;
use crate::time::now_ms;

/// A human-issued, session-scoped, expiring permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub id: String,
    /// Session the grant belongs to.
    pub session: String,
    pub capability: Capability,
    /// Host names resolved when the grant was issued; later inventory additions are not covered.
    pub hosts: Vec<String>,
    /// The selector the human typed, for display.
    pub selector: String,
    /// Epoch milliseconds.
    pub created_at: i64,
    pub expires_at: i64,
}

/// What the human asked for; the store adds the id and creation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewGrant {
    pub session: String,
    pub capability: Capability,
    pub hosts: Vec<String>,
    pub selector: String,
    pub expires_at: i64,
}

/// In-memory grants. They are never persisted: a restart clears them, failing closed.
#[derive(Debug, Default)]
pub struct GrantStore {
    grants: Mutex<Vec<Grant>>,
}

impl GrantStore {
    pub fn new() -> Self {
        GrantStore::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Grant>> {
        self.grants.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn add(&self, grant: NewGrant) -> Grant {
        self.add_at(grant, now_ms())
    }

    pub fn add_at(&self, grant: NewGrant, now: i64) -> Grant {
        let id = random_hex::<4>().unwrap_or_else(|_| format!("{:08x}", now as u32));
        let full = Grant { id, session: grant.session, capability: grant.capability, hosts: grant.hosts, selector: grant.selector, created_at: now, expires_at: grant.expires_at };
        self.lock().push(full.clone());
        full
    }

    /// Active grants of one session, pruning expired ones.
    pub fn active(&self, session: &str) -> Vec<Grant> {
        self.active_at(session, now_ms())
    }

    pub fn active_at(&self, session: &str, now: i64) -> Vec<Grant> {
        let mut grants = self.lock();
        grants.retain(|grant| grant.expires_at > now);
        grants.iter().filter(|grant| grant.session == session).cloned().collect()
    }

    /// The grant covering one capability on one host, if any.
    pub fn find(&self, session: &str, host: &str, capability: Capability) -> Option<Grant> {
        self.find_at(session, host, capability, now_ms())
    }

    pub fn find_at(&self, session: &str, host: &str, capability: Capability, now: i64) -> Option<Grant> {
        self.active_at(session, now).into_iter().find(|grant| grant.capability == capability && grant.hosts.iter().any(|h| h == host))
    }

    /// Revoke one grant by id, or every grant of the session with `all`.
    pub fn revoke(&self, session: &str, id: &str) -> Vec<Grant> {
        self.revoke_at(session, id, now_ms())
    }

    pub fn revoke_at(&self, session: &str, id: &str, now: i64) -> Vec<Grant> {
        let revoked: Vec<Grant> = self.active_at(session, now).into_iter().filter(|grant| id == "all" || grant.id == id).collect();
        self.lock().retain(|grant| !revoked.iter().any(|gone| gone.id == grant.id));
        revoked
    }

    pub fn clear(&self) {
        self.lock().clear();
    }
}

/// Capabilities a classified action needs. Destructive actions are also changes.
pub fn required_capabilities(risk: &RiskAssessment, sudo: bool) -> Vec<Capability> {
    let mut capabilities = Vec::new();
    if risk.level != RiskLevel::Read { capabilities.push(Capability::Change) }
    if risk.level == RiskLevel::Destructive { capabilities.push(Capability::Destructive) }
    if sudo || risk.elevates { capabilities.push(Capability::Sudo) }
    capabilities
}

/// How one capability on one host was settled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRuling {
    pub host: String,
    pub capability: Capability,
    pub permission: Permission,
    /// Set when an active grant turned `ask` into `allow`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow { rulings: Vec<CapabilityRuling> },
    Ask { rulings: Vec<CapabilityRuling>, pending: Vec<CapabilityRuling> },
    Deny { rulings: Vec<CapabilityRuling>, denied: Vec<CapabilityRuling> },
}

/// Settle the capabilities of one action on a set of hosts. Deny beats ask beats allow.
pub fn decide(hosts: &[Host], capabilities: &[Capability], session: Option<&str>, grants: &GrantStore) -> Decision {
    decide_at(hosts, capabilities, session, grants, now_ms())
}

pub fn decide_at(hosts: &[Host], capabilities: &[Capability], session: Option<&str>, grants: &GrantStore, now: i64) -> Decision {
    let mut rulings = Vec::new();
    for host in hosts {
        for capability in capabilities {
            let permission = host.policy.get(*capability);
            if permission == Permission::Ask
                && let Some(session) = session
                && let Some(grant) = grants.find_at(session, &host.name, *capability, now)
            {
                rulings.push(CapabilityRuling { host: host.name.clone(), capability: *capability, permission: Permission::Allow, grant: Some(grant.id) });
                continue;
            }
            rulings.push(CapabilityRuling { host: host.name.clone(), capability: *capability, permission, grant: None });
        }
    }
    let denied: Vec<CapabilityRuling> = rulings.iter().filter(|ruling| ruling.permission == Permission::Deny).cloned().collect();
    if !denied.is_empty() { return Decision::Deny { rulings, denied } }
    let pending: Vec<CapabilityRuling> = rulings.iter().filter(|ruling| ruling.permission == Permission::Ask).cloned().collect();
    if !pending.is_empty() { return Decision::Ask { rulings, pending } }
    Decision::Allow { rulings }
}

/// Parse a human duration into milliseconds: `45` (minutes), `30m`, `2h`, `1h30m`.
pub fn parse_duration(text: &str) -> Option<u64> {
    let trimmed = js_trim(text).to_lowercase();
    if js_re!(r"^\d+$").is_match(&trimmed) { return trimmed.parse::<u64>().ok()?.checked_mul(60_000) }
    let captures = js_re!(r"^(?:(\d+)h)?(?:(\d+)m)?$").captures(&trimmed)?;
    if captures.get(1).is_none() && captures.get(2).is_none() { return None }
    let number = |index: usize| -> Option<u64> { captures.get(index).map_or(Some(0), |m| m.as_str().parse().ok()) };
    number(1)?.checked_mul(60)?.checked_add(number(2)?)?.checked_mul(60_000)
}

/// Compact a ruling list into `host: cap, cap` entries for prompts and results.
pub fn describe_rulings(rulings: &[CapabilityRuling]) -> String {
    let mut by_host: Vec<(String, Vec<String>)> = Vec::new();
    for ruling in rulings {
        let text = match &ruling.grant {
            None => ruling.capability.to_string(),
            Some(grant) => format!("{} (grant {grant})", ruling.capability),
        };
        match by_host.iter_mut().find(|(host, _)| *host == ruling.host) {
            Some((_, list)) => list.push(text),
            None => by_host.push((ruling.host.clone(), vec![text])),
        }
    }
    by_host.iter().map(|(host, caps)| format!("{host}: {}", caps.join(", "))).collect::<Vec<_>>().join("; ")
}

/// Grants a human may issue for a capability word.
pub fn grant_capabilities(word: &str) -> Option<Vec<Capability>> {
    match word {
        "change" => Some(vec![Capability::Change]),
        "sudo" => Some(vec![Capability::Sudo]),
        "destructive" => Some(vec![Capability::Destructive]),
        // `all` deliberately excludes destructive: that must always be named.
        "all" => Some(vec![Capability::Change, Capability::Sudo]),
        _ => None,
    }
}

/// Compile the deployment deny list (JavaScript-flavoured patterns, as the plugin's configuration wrote them).
pub fn compile_deny_patterns(patterns: &[String]) -> Result<Vec<Regex>, String> {
    patterns.iter().map(|pattern| compile(pattern, "").map_err(|error| format!("invalid deny pattern {pattern}: {error}"))).collect()
}

/// A compiled deny list that remembers each pattern as it was written, for refusal messages.
#[derive(Clone, Debug, Default)]
pub struct DenyList {
    patterns: Vec<(String, Regex)>,
}

impl DenyList {
    pub fn compile(patterns: &[String]) -> Result<DenyList, String> {
        let compiled = compile_deny_patterns(patterns)?;
        Ok(DenyList { patterns: patterns.iter().cloned().zip(compiled).collect() })
    }

    /// The pattern, as configured, that refuses this command.
    pub fn matches(&self, command: &str) -> Option<&str> {
        self.patterns.iter().find(|(_, re)| re.is_match(command)).map(|(source, _)| source.as_str())
    }
}

/// The configured deny pattern a command matches, if any.
pub fn denied_by_pattern<'a>(command: &str, patterns: &'a DenyList) -> Option<&'a str> {
    patterns.matches(command)
}

/// What the gate concluded for one action, to be consumed once by whatever executes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Voucher {
    pub hosts: Vec<String>,
    pub risk: RiskAssessment,
    /// Whether the action runs with sudo: requested, or implied by the command itself.
    pub sudo: bool,
    pub authorization: Authorization,
    /// Epoch milliseconds.
    pub issued_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateOutcome {
    /// Run it; the voucher says under which authorization.
    Allow { voucher: Voucher },
    /// Ask the human about this exact action. The voucher (authorization `approval`) is valid only if they agree.
    Ask { voucher: Voucher, pending: Vec<CapabilityRuling> },
    /// Never run; no approval or grant overrides this.
    Deny { reason: String },
}

/// Settle one planned action: deny list, then task sudo against policy, then policy → grant → ask.
///
/// `commands` is every command text the action runs verbatim (for a managed change: apply,
/// verify, after-rollback). `task_sudo` marks sudo pre-authorized by a human-written task; it is
/// still refused by a policy `deny`.
pub fn gate(
    hosts: &[Host],
    risk: &RiskAssessment,
    sudo: bool,
    task_sudo: bool,
    commands: &[String],
    session: Option<&str>,
    grants: &GrantStore,
    deny_patterns: &DenyList,
) -> GateOutcome {
    gate_at(hosts, risk, sudo, task_sudo, commands, session, grants, deny_patterns, now_ms())
}

pub fn gate_at(
    hosts: &[Host],
    risk: &RiskAssessment,
    sudo: bool,
    task_sudo: bool,
    commands: &[String],
    session: Option<&str>,
    grants: &GrantStore,
    deny_patterns: &DenyList,
    now: i64,
) -> GateOutcome {
    if let Some(pattern) = commands.iter().find_map(|command| deny_patterns.matches(command)) {
        return GateOutcome::Deny {
            reason: format!("Refused by the deployment deny list ({pattern}). This command is never run by the agent; a human must do it directly if it is really intended."),
        };
    }
    if task_sudo {
        let refused: Vec<&str> = hosts.iter().filter(|host| host.policy.sudo == Permission::Deny).map(|host| host.name.as_str()).collect();
        if !refused.is_empty() { return GateOutcome::Deny { reason: format!("Task needs sudo, but host policy denies sudo on {}.", refused.join(", ")) } }
    }
    // A task's sudo was authorized by the human who wrote the task.
    let capabilities = required_capabilities(risk, sudo && !task_sudo);
    let voucher = |authorization| Voucher { hosts: hosts.iter().map(|host| host.name.clone()).collect(), risk: risk.clone(), sudo: sudo || risk.elevates, authorization, issued_at: now };
    match decide_at(hosts, &capabilities, session, grants, now) {
        Decision::Deny { denied, .. } => GateOutcome::Deny {
            reason: format!(
                "Denied by host policy: {} is set to deny. Policy deny cannot be overridden by approval or /ops-allow; change the inventory policy if this is intended.",
                describe_rulings(&denied)
            ),
        },
        Decision::Allow { rulings } => {
            let authorization = if task_sudo {
                Authorization::Task
            } else if capabilities.is_empty() {
                Authorization::ReadOnly
            } else if rulings.iter().any(|ruling| ruling.grant.is_some()) {
                Authorization::Grant
            } else {
                Authorization::Policy
            };
            GateOutcome::Allow { voucher: voucher(authorization) }
        }
        Decision::Ask { pending, .. } => GateOutcome::Ask { voucher: voucher(Authorization::Approval), pending },
    }
}

/// The distinct capabilities still awaiting approval, as `change + sudo`.
pub fn pending_needs(pending: &[CapabilityRuling]) -> String {
    let mut needs: Vec<&str> = Vec::new();
    for ruling in pending {
        if !needs.contains(&ruling.capability.as_str()) { needs.push(ruling.capability.as_str()) }
    }
    needs.join(" + ")
}

/// Collapse whitespace and cap the length, for one-line prompts.
pub fn compact(text: &str, max: usize) -> String {
    let mut one_line = String::new();
    let mut gap = false;
    for c in text.chars() {
        if is_js_space(c) {
            gap = true;
        } else {
            if gap && !one_line.is_empty() { one_line.push(' ') }
            gap = false;
            one_line.push(c);
        }
    }
    if one_line.chars().count() > max { format!("{}…", one_line.chars().take(max).collect::<String>()) } else { one_line }
}

/// Host names for a prompt: the first twelve, then a count.
pub fn host_list(names: &[String]) -> String {
    if names.len() > 12 { format!("{} … (+{})", names[..12].join(", "), names.len() - 12) } else { names.join(", ") }
}
