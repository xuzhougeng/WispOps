//! Host inventory: membership, selectors, and the effective permission table of each host.
//! The model can only address hosts by inventory name, so it never supplies an SSH destination.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::ErrorKind;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{
    AuthMethod, CAPABILITIES, Config, GroupSpec, HostSpec, Playbook, Policy, PolicySpec, ReportMode, TaskSpec, stricter, validate_hosts,
    validate_tasks,
};
pub use crate::fsutil::expand_home;
use crate::jsre::is_js_space;
use crate::managed::{ManagedState, managed_store};
use crate::risk::{RiskLevel, classify_command};

/// A host with its effective policy resolved.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub groups: Vec<String>,
    pub tags: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Effective policy: host > strictest group > default, then the application's override.
    pub policy: Policy,
    /// Effective policy before the application's override, so a form can show what "inherit" means.
    pub inherited_policy: Policy,
    /// Capabilities overridden in the application; absent when nothing is overridden.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_override: Option<PolicySpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sudo_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_jump: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sudo_secret: Option<String>,
    /// Service checks, threshold overrides and muted findings set in the application (opaque here).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_checks: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_override: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutes: Option<Value>,
}

impl Host {
    /// The OpenSSH destination: `ssh`, or the name.
    pub fn destination(&self) -> &str {
        self.ssh.as_deref().unwrap_or(&self.name)
    }

    pub fn uses_password(&self) -> bool {
        self.auth == Some(AuthMethod::Password)
    }
}

/// An inventory entry before resolution: the spec plus what the application layered on it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostEntry {
    pub spec: HostSpec,
    pub policy_override: Option<PolicySpec>,
    pub service_checks: Option<Value>,
    pub threshold_override: Option<Value>,
    pub mutes: Option<Value>,
}

impl From<HostSpec> for HostEntry {
    fn from(spec: HostSpec) -> Self {
        HostEntry { spec, ..HostEntry::default() }
    }
}

/// The content of an inventory file.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct InventoryFile {
    pub hosts: Vec<HostSpec>,
    pub groups: BTreeMap<String, GroupSpec>,
    pub tasks: Vec<TaskSpec>,
}

/// Parse inventory text; YAML is a superset of JSON so one parser serves both.
pub fn parse_inventory(text: &str) -> Result<InventoryFile, String> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(text).map_err(|error| error.to_string())?;
    if parsed.is_null() { return Ok(InventoryFile::default()) }
    let file: InventoryFile = serde_yaml::from_value(parsed).map_err(|error| error.to_string())?;
    validate_hosts(&file.hosts)?;
    validate_tasks(&file.tasks)?;
    Ok(file)
}

/// Read an inventory file. A missing file is an empty inventory.
pub fn load_inventory_file(path: &str) -> Result<InventoryFile, String> {
    let text = match std::fs::read_to_string(expand_home(path)) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(InventoryFile::default()),
        Err(error) => return Err(format!("cannot read inventory file {path}: {error}")),
    };
    parse_inventory(&text).map_err(|error| format!("invalid inventory file {path}: {error}"))
}

/// `*` and `?` wildcard match over whole strings; every other character is literal.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

fn valid_zone(zone: &str) -> bool {
    chrono_tz::Tz::from_str(zone).is_ok() || chrono_tz::Tz::from_str_insensitive(zone).is_ok()
}

/// The resolved inventory: hosts with effective policies, groups, and validated tasks.
#[derive(Clone, Debug)]
pub struct Inventory {
    hosts: Vec<Host>,
    index: HashMap<String, usize>,
    groups: BTreeMap<String, GroupSpec>,
    tasks: Vec<TaskSpec>,
}

impl Inventory {
    /// Resolve entries into hosts and validate tasks. Duplicate names, tasks that are not
    /// read-only, and task targets that match nothing fail.
    pub fn new(
        hosts: Vec<HostEntry>,
        groups: BTreeMap<String, GroupSpec>,
        defaults: Policy,
        tasks: Vec<TaskSpec>,
        extra_read: &HashSet<String>,
    ) -> Result<Inventory, String> {
        let mut group_map = groups;
        let mut resolved: Vec<Host> = Vec::new();
        let mut index = HashMap::new();
        for entry in hosts {
            let spec = entry.spec;
            if index.contains_key(&spec.name) { return Err(format!("duplicate inventory host \"{}\"", spec.name)) }
            for name in &spec.groups {
                // A host may name a group that has no settings; it then exists only as a label.
                group_map.entry(name.clone()).or_default();
            }
            let mut effective = defaults;
            for capability in CAPABILITIES {
                if let Some(own) = spec.policy.get(capability) {
                    effective.set(capability, own);
                    continue;
                }
                let from_groups = spec.groups.iter().filter_map(|name| group_map.get(name).and_then(|group| group.policy.get(capability)));
                if let Some(strictest) = from_groups.reduce(stricter) { effective.set(capability, strictest) }
            }
            let mut policy = effective;
            if let Some(overrides) = &entry.policy_override {
                for capability in CAPABILITIES {
                    if let Some(permission) = overrides.get(capability) { policy.set(capability, permission) }
                }
            }
            index.insert(spec.name.clone(), resolved.len());
            resolved.push(Host {
                name: spec.name,
                ssh: spec.ssh,
                port: spec.port,
                user: spec.user,
                groups: spec.groups,
                tags: spec.tags,
                description: spec.description,
                policy,
                inherited_policy: effective,
                policy_override: entry.policy_override,
                sudo_user: spec.sudo_user,
                proxy_jump: spec.proxy_jump,
                identity_file: spec.identity_file,
                auth: spec.auth,
                login_secret: spec.login_secret,
                sudo_secret: spec.sudo_secret,
                service_checks: entry.service_checks,
                threshold_override: entry.threshold_override,
                mutes: entry.mutes,
            });
        }
        let mut inventory = Inventory { hosts: resolved, index, groups: group_map, tasks: Vec::new() };
        let mut names = HashSet::new();
        for raw in tasks {
            let task = inventory.check_task(raw, extra_read)?;
            if !names.insert(task.name.clone()) { return Err(format!("duplicate task \"{}\"", task.name)) }
            inventory.tasks.push(task);
        }
        Ok(inventory)
    }

    /// Hosts and groups only, with no tasks.
    pub fn from_specs(hosts: Vec<HostSpec>, groups: BTreeMap<String, GroupSpec>, defaults: Policy) -> Result<Inventory, String> {
        Inventory::new(hosts.into_iter().map(HostEntry::from).collect(), groups, defaults, Vec::new(), &HashSet::new())
    }

    /// Normalize one task and apply the cross-field rules.
    fn check_task(&self, mut task: TaskSpec, extra_read: &HashSet<String>) -> Result<TaskSpec, String> {
        // Absent optional objects may arrive as empty ones; normalize them away.
        if task.schedule.as_ref().is_some_and(|schedule| !schedule.is_timed()) { task.schedule = None }
        if task.quiet_hours.as_ref().is_some_and(|quiet| quiet.start.is_empty() && quiet.end.is_empty()) { task.quiet_hours = None }
        task.commands = task.commands.iter().map(|command| command.trim_matches(is_js_space).to_string()).collect();
        let name = task.name.clone();
        if task.playbook == Playbook::Custom && task.instruction.as_deref().is_none_or(|text| text.trim_matches(is_js_space).is_empty()) {
            return Err(format!("task \"{name}\" uses the custom playbook and needs an instruction"));
        }
        if task.playbook == Playbook::Script && task.script.is_none() { return Err(format!("task \"{name}\" uses the script playbook and needs a script id")) }
        if task.playbook != Playbook::Script && task.script.is_some() {
            return Err(format!("task \"{name}\" names a script but does not use the script playbook"));
        }
        if let Some(report) = task.report
            && report != ReportMode::Always
        {
            // Without a collector or commands the model is the only thing that gathers evidence.
            if task.playbook == Playbook::Custom && task.commands.is_empty() {
                return Err(format!(
                    "task \"{name}\" needs read-only commands or a built-in playbook before report \"{}\" can run without the agent",
                    report.as_str()
                ));
            }
        }
        // Commands run unattended under the task's authorization, so only commands the classifier
        // proves read-only are accepted; everything else must go through an approved execution.
        for command in &task.commands {
            if command.is_empty() || command.contains('\0') { return Err(format!("task \"{name}\" has an empty or invalid command")) }
            let risk = classify_command(command, extra_read);
            if risk.level != RiskLevel::Read || risk.elevates {
                let why = if risk.reasons.is_empty() { "privilege escalation".to_string() } else { risk.reasons.join("; ") };
                return Err(format!("task \"{name}\" command is not read-only ({why}): {}", command.chars().take(120).collect::<String>()));
            }
        }
        if let Some(quiet) = &task.quiet_hours {
            if quiet.start.is_empty() || quiet.end.is_empty() || quiet.start == quiet.end {
                return Err(format!("task \"{name}\" quietHours need different start and end times"));
            }
            if let Some(zone) = &quiet.time_zone
                && !valid_zone(zone)
            {
                return Err(format!("task \"{name}\" quietHours time zone \"{zone}\" is invalid"));
            }
        }
        if task.playbook == Playbook::NewFiles && task.paths.is_empty() {
            return Err(format!("task \"{name}\" uses the new-files playbook and needs paths"));
        }
        if let Some(schedule) = &task.schedule {
            let kinds = [schedule.daily.is_some(), schedule.cron.is_some(), schedule.every_minutes.is_some()].iter().filter(|set| **set).count();
            if kinds != 1 { return Err(format!("task \"{name}\" schedule needs exactly one of daily, cron, everyMinutes")) }
            if !schedule.weekdays.is_empty() && schedule.daily.is_none() { return Err(format!("task \"{name}\" schedule weekdays need daily")) }
        }
        // Fail loudly now rather than at 8 a.m.
        let matched = self.select(&task.targets).and_then(|hosts| if hosts.is_empty() { Err("matches no hosts".to_string()) } else { Ok(()) });
        if let Err(error) = matched { return Err(format!("task \"{name}\" targets \"{}\": {error}", task.targets)) }
        Ok(task)
    }

    /// Build from config: imported hosts first, then inline entries, then the inventory file, then
    /// hosts added in the application. A configured host replaces an imported one of the same
    /// name; two configured hosts with one name fail. `managed` defaults to `<dataDir>/managed.json`.
    pub fn load(config: &Config, imported: &[HostSpec], managed: Option<&ManagedState>) -> Result<Inventory, String> {
        let mut configured = config.hosts.clone();
        let mut groups = config.groups.clone();
        let mut tasks = config.tasks.clone();
        if let Some(path) = &config.inventory_file {
            let file = load_inventory_file(path)?;
            configured.extend(file.hosts);
            groups.extend(file.groups);
            tasks.extend(file.tasks);
        }
        let read;
        let state = match managed {
            Some(state) => state,
            None => {
                read = managed_store(&config.data_path()).read()?.value;
                &read
            }
        };
        let names: HashSet<&str> = configured.iter().map(|h| h.name.as_str()).collect();
        let excluded: HashSet<&str> = state.excluded_hosts.iter().map(String::as_str).collect();
        let mut entries = Vec::new();
        let all = imported.iter().filter(|h| !names.contains(h.name.as_str())).chain(configured.iter()).chain(state.hosts.iter());
        for host in all {
            if excluded.contains(host.name.as_str()) { continue }
            let mut spec = host.clone();
            if let Some(binding) = state.bindings.get(&spec.name) {
                // A binding is the whole truth about a host's credentials, not a partial overlay.
                spec.auth = Some(binding.auth);
                spec.login_secret = binding.login_secret.clone();
                spec.sudo_secret = binding.sudo_secret.clone();
            }
            entries.push(HostEntry {
                policy_override: state.policies.get(&spec.name).filter(|policy| !policy.is_empty()).cloned(),
                service_checks: state.checks.get(&spec.name).cloned(),
                threshold_override: state.thresholds.get(&spec.name).cloned(),
                mutes: state.mutes.get(&spec.name).cloned(),
                spec,
            });
        }
        tasks.extend(state.tasks.iter().cloned());
        let extra_read: HashSet<String> = config.extra_read_programs.iter().cloned().collect();
        Inventory::new(entries, groups, config.default_policy, tasks, &extra_read)
    }

    /// Every host, in inventory order.
    pub fn hosts(&self) -> &[Host] {
        &self.hosts
    }

    pub fn host(&self, name: &str) -> Option<&Host> {
        self.index.get(name).map(|i| &self.hosts[*i])
    }

    pub fn has_host(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    pub fn groups(&self) -> &BTreeMap<String, GroupSpec> {
        &self.groups
    }

    /// Every task, in definition order.
    pub fn tasks(&self) -> &[TaskSpec] {
        &self.tasks
    }

    pub fn task(&self, name: &str) -> Option<&TaskSpec> {
        self.tasks.iter().find(|task| task.name == name)
    }

    /// Resolve a selector list. Each comma- or space-separated term is a host name, `@group`,
    /// `tag:key=value`, a `*` glob over names, or `all`. A term prefixed with `!` removes matches.
    /// Unknown names fail loudly. Hosts come back in inventory order.
    pub fn select(&self, selector: &str) -> Result<Vec<Host>, String> {
        let terms: Vec<&str> = selector.split(|c: char| is_js_space(c) || c == ',').filter(|term| !term.is_empty()).collect();
        if terms.is_empty() { return Err("empty host selector".to_string()) }
        let mut chosen: HashSet<usize> = HashSet::new();
        for raw in terms {
            let (negate, term) = match raw.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, raw),
            };
            for i in self.matches(term)? {
                if negate { chosen.remove(&i); } else { chosen.insert(i); }
            }
        }
        Ok(self.hosts.iter().enumerate().filter(|(i, _)| chosen.contains(i)).map(|(_, host)| host.clone()).collect())
    }

    /// Names of the hosts a selector resolves to.
    pub fn select_names(&self, selector: &str) -> Result<Vec<String>, String> {
        Ok(self.select(selector)?.into_iter().map(|host| host.name).collect())
    }

    fn matches(&self, term: &str) -> Result<Vec<usize>, String> {
        let filter = |keep: &dyn Fn(&Host) -> bool| self.hosts.iter().enumerate().filter(|(_, host)| keep(host)).map(|(i, _)| i).collect::<Vec<_>>();
        if term == "all" || term == "*" { return Ok((0..self.hosts.len()).collect()) }
        if let Some(group) = term.strip_prefix('@') {
            if !self.groups.contains_key(group) {
                let known = self.groups.keys().cloned().collect::<Vec<_>>().join(", ");
                return Err(format!("unknown group \"{group}\"; known groups: {}", if known.is_empty() { "(none)" } else { &known }));
            }
            return Ok(filter(&|host| host.groups.iter().any(|g| g == group)));
        }
        if let Some(rest) = term.strip_prefix("tag:") {
            // Only the first two `=`-separated fields count, as in the original's `split('=', 2)`.
            let mut parts = rest.split('=');
            let key = parts.next().unwrap_or("");
            let value = parts.next();
            if key.is_empty() { return Err(format!("invalid tag selector \"{term}\"; use tag:key or tag:key=value")) }
            return Ok(filter(&|host| match value {
                None => host.tags.contains_key(key),
                Some(value) => host.tags.get(key).is_some_and(|v| v == value),
            }));
        }
        if term.contains('*') || term.contains('?') { return Ok(filter(&|host| glob_match(term, &host.name))) }
        match self.index.get(term) {
            Some(i) => Ok(vec![*i]),
            None => Err(format!("unknown host \"{term}\"; run ops_hosts to list the inventory")),
        }
    }

    /// Every token that would address an inventory host from a raw ssh command line.
    pub fn address_tokens(&self) -> HashSet<String> {
        let mut tokens = HashSet::new();
        for host in &self.hosts {
            tokens.insert(host.name.clone());
            if let Some(ssh) = &host.ssh {
                tokens.insert(ssh.clone());
                tokens.insert(match ssh.find('@') {
                    Some(at) => ssh[at + 1..].to_string(),
                    None => ssh.clone(),
                });
            }
        }
        tokens
    }
}
