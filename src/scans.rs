//! What the 磁盘, 长时任务 and 安全 pages have the fleet do: the first disk
//! scan of a server (the login's own home, or every local filesystem as
//! root) and the follow-up scans that say what grew; the check for user
//! tasks that have run too long; and the triage of login attacks. All of it
//! reads only, is recorded in the audit, and keeps its results in the data
//! folder for the pages to draw.

use crate::ops::{Collect, Exec, Fleet};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use wisp_ops_collect::attacks::SecuritySnapshot;
use wisp_ops_collect::longrun::{self, LongRunOptions, LongRunSnapshot};
use wisp_ops_collect::sections::{self, FsUsage};
use wisp_ops_collect::space::{self, SpaceNode, SpaceOptions, SpaceReport, SpaceSnapshot};
use wisp_ops_collect::util;
use wisp_ops_engine::config::Permission;
use wisp_ops_engine::inventory::Host;
use wisp_ops_engine::ssh::RunStatus;
use wisp_ops_engine::store::Authorization;
use wisp_ops_engine::time;

/// What a disk scan covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The home directory of the account that logs in; no root needed.
    Home,
    /// Every local filesystem, read as root.
    Full,
    /// What the server's first scan covered, measured again.
    Again,
}

/// What a server's first scan settled, so that the follow-up scans repeat it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DiskPlan {
    /// `home` or `full`.
    pub scope: String,
    pub paths: Vec<String>,
    pub sudo: bool,
    pub first_at: String,
    pub last_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The latest scan of one path of a server, with the one before it to compare with.
#[derive(Clone, Debug)]
pub struct ScanView {
    pub path: String,
    pub at: String,
    pub report: SpaceReport,
    pub tree: SpaceNode,
    /// When the scan before this one was made, and what each directory measured then, in KB.
    pub previous_at: Option<String>,
    pub before: HashMap<String, f64>,
}

impl ScanView {
    /// How much a directory grew (or shrank) since the scan before, when both measured it and the change is worth saying.
    pub fn delta(&self, node: &SpaceNode) -> Option<f64> {
        let old = *self.before.get(&node.path)?;
        let delta = node.kb - old;
        (delta.abs() >= (old * 0.01).max(1024.)).then_some(delta)
    }

    /// The directories that grew most since the scan before, the deepest that explains each growth.
    pub fn grown(&self, limit: usize) -> Vec<(String, f64)> {
        let floor = (self.tree.kb * 0.005).max(100. * 1024.);
        let mut grown: Vec<(&str, f64)> = self.report.dirs.iter().filter(|(path, _)| *path != self.path).filter_map(|(path, kb)| self.before.get(path).map(|old| (path.as_str(), kb - old))).filter(|(_, delta)| *delta >= floor).collect();
        grown.sort_by(|a, b| b.1.total_cmp(&a.1));
        grown.iter().enumerate().filter(|(i, (path, delta))| !grown.iter().enumerate().any(|(j, (other, more))| j != *i && other.strip_prefix(path).is_some_and(|rest| rest.starts_with('/')) && *more >= delta * 0.8)).take(limit).map(|(_, (path, delta))| (path.to_string(), *delta)).collect()
    }
}

/// Filesystems that are not a disk of the server: memory, images, layers, and other machines' storage.
const SKIPPED_TYPES: [&str; 22] = ["tmpfs", "devtmpfs", "squashfs", "overlay", "efivarfs", "iso9660", "vfat", "proc", "sysfs", "autofs", "ramfs", "nfs", "nfs4", "cifs", "smb3", "lustre", "gpfs", "beegfs", "ceph", "9p", "afs", "nsfs"];
const SKIPPED_MOUNTS: [&str; 6] = ["/boot", "/snap", "/run", "/dev", "/sys", "/proc"];
/// The most filesystems one full scan walks.
const MAX_MOUNTS: usize = 8;

/// The mount points a full scan walks: one per local device, the largest first.
pub fn local_mounts(filesystems: &[FsUsage]) -> Vec<String> {
    let mut kept: Vec<&FsUsage> = vec![];
    for fs in filesystems {
        let kind = fs.fs_type.as_deref().unwrap_or("");
        if !fs.mount.starts_with('/') || fs.size_kb < 1024. * 1024. || SKIPPED_TYPES.contains(&kind) || kind.starts_with("fuse.") || kind.starts_with("cgroup") { continue }
        if SKIPPED_MOUNTS.iter().any(|skip| fs.mount == *skip || fs.mount.strip_prefix(skip).is_some_and(|rest| rest.starts_with('/'))) { continue }
        // A device mounted twice (a bind mount, a btrfs subvolume) is walked once, from its shortest mount point.
        match kept.iter_mut().find(|known| known.filesystem == fs.filesystem) {
            Some(known) if fs.mount.len() < known.mount.len() => *known = fs,
            Some(_) => {}
            None => kept.push(fs),
        }
    }
    kept.sort_by(|a, b| b.used_kb.total_cmp(&a.used_kb));
    kept.into_iter().take(MAX_MOUNTS).map(|fs| fs.mount.clone()).collect()
}

static PLANS: Mutex<()> = Mutex::new(());

impl Fleet {
    /// Whether the window may read this server as root, and whether that takes sudo: `Ok(false)` logs in as root already.
    pub fn root_way(&self, host: &Host) -> Result<bool, String> {
        let probe = self.store.probes::<wisp_ops_collect::probe::HostProbe>().ok().and_then(|mut probes| probes.remove(&host.name));
        let privilege = probe.as_ref().map(|probe| probe.privilege);
        if privilege == Some(wisp_ops_collect::probe::Privilege::Root) || self.runner.login_user(host).ok().as_deref() == Some("root") { return Ok(false) }
        if host.policy.sudo == Permission::Deny { return Err(tf!("{} 的权限策略拒绝 sudo，不能以 root 读取。", "The policy of {} denies sudo, so it cannot be read as root.", host.name)) }
        if host.sudo_secret.is_some() || privilege == Some(wisp_ops_collect::probe::Privilege::SudoNopasswd) { return Ok(true) }
        Err(tf!("需要 root：请在「服务器」里给 {} 关联 sudo 凭据（或用 root 登录、配置免密 sudo 后重新探测）。", "Root is needed: link a sudo credential to {} on the Servers page (or log in as root, or set up passwordless sudo and probe again).", host.name))
    }

    fn one_host(&self, name: &str) -> Result<Host, String> {
        self.inventory().host(name).cloned().ok_or_else(|| tf!("清单里没有 {name}。", "{name} is not in the inventory."))
    }

    // ---- disk scans

    fn plans_file(&self) -> std::path::PathBuf {
        self.data_dir().join("disk-scans.json")
    }

    pub fn disk_plans(&self) -> BTreeMap<String, DiskPlan> {
        std::fs::read_to_string(self.plans_file()).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    fn edit_plans(&self, update: impl FnOnce(&mut BTreeMap<String, DiskPlan>)) {
        let _held = PLANS.lock().unwrap();
        let mut plans = self.disk_plans();
        update(&mut plans);
        let _ = std::fs::write(self.plans_file(), serde_json::to_string_pretty(&plans).unwrap_or_default());
    }

    /// One quick read-only command of the window on one host: its first line of output.
    fn ask_host(&self, host: &Host, tool: &str, command: &str) -> Result<String, String> {
        let mut exec = Exec::read(tool, Authorization::ReadOnly);
        exec.timeout_ms = self.config.ssh.connect_timeout_sec * 1000 + 20_000;
        let result = self.execute_one(std::slice::from_ref(host), command, &exec).remove(0);
        if result.status != RunStatus::Ok { return Err(format!("{}：{}", crate::i18n::t(crate::tools::status_label(result.status.as_str())), result.stderr.trim().chars().take(240).collect::<String>())) }
        Ok(result.stdout)
    }

    /// Scan a server's disks and keep the sizes: the first scan settles what is covered, a later
    /// one (`Scope::Again`, from the button or the timer) measures the same again so the page can
    /// say what grew. Says what was measured.
    pub fn scan_disk(&self, name: &str, scope: Scope, timed: bool) -> Result<String, String> {
        let result = self.scan_disk_now(name, scope, timed);
        // A scan that could not run is not tried again every minute.
        if let Err(error) = &result { self.edit_plans(|plans| if let Some(plan) = plans.get_mut(name) { (plan.last_at, plan.last_error) = (time::to_iso(time::now_ms()), Some(error.clone())) }) }
        result
    }

    fn scan_disk_now(&self, name: &str, scope: Scope, timed: bool) -> Result<String, String> {
        let host = self.one_host(name)?;
        let tool = if timed { "window:disk-auto" } else { "window:disk" };
        let known = self.disk_plans().remove(name);
        let (scope_word, paths, sudo) = match scope {
            Scope::Home => {
                let home = self.ask_host(&host, tool, "printf '%s\\n' \"$HOME\"")?.lines().next().unwrap_or("").trim().to_string();
                if !home.starts_with('/') || home.contains(['\0', '\r']) { return Err(tf!("没有读到 {name} 上的用户目录。", "Could not read the home directory on {name}.")) }
                ("home", vec![home], false)
            }
            Scope::Full => {
                let sudo = self.root_way(&host)?;
                let listing = self.ask_host(&host, tool, "export LC_ALL=C; df -PkT 2>/dev/null || df -Pk")?;
                let lines: Vec<String> = listing.lines().map(String::from).collect();
                let mounts = local_mounts(&sections::parse_df(&lines));
                if mounts.is_empty() { return Err(tf!("没有在 {name} 上找到本地文件系统。", "Found no local filesystem on {name}.")) }
                ("full", mounts, sudo)
            }
            Scope::Again => {
                let plan = known.clone().ok_or_else(|| tf!("{name} 还没有做过第一次扫描。", "{name} has had no first scan yet."))?;
                // The policy may have changed since the first scan: root is asked for again.
                let sudo = if plan.scope == "full" { self.root_way(&host)? } else { false };
                (if plan.scope == "full" { "full" } else { "home" }, plan.paths, sudo)
            }
        };
        // A scan the person started as root is theirs to approve; the timer repeats what they set up.
        let authorization = if !sudo { Authorization::ReadOnly } else if timed { Authorization::Task } else { Authorization::Approval };
        let collect = Collect { sudo, tool: tool.into(), session: None, authorization, cancel: None };
        let mut done = vec![];
        let mut failed = vec![];
        for path in &paths {
            let options = SpaceOptions { path: path.clone(), depth: 5, max_dirs: 2000, min_kb: 1024, walk_timeout_sec: 900 };
            match self.space(&host, &options, &collect) {
                (Some((report, _)), _) => done.push(format!("{path} {}", sections::format_kb(space::build_space_tree(&report.path, &report.dirs).kb))),
                (None, result) => failed.push(format!("{path}（{}{}）", crate::i18n::t(crate::tools::status_label(result.status.as_str())), result.stderr.trim().lines().next().map(|line| format!("：{}", line.chars().take(160).collect::<String>())).unwrap_or_default())),
            }
        }
        if done.is_empty() { return Err(tf!("扫描 {name} 失败：{}", "Scanning {name} failed: {}", failed.join("；"))) }
        let now = time::to_iso(time::now_ms());
        self.edit_plans(|plans| {
            let first_at = known.as_ref().filter(|plan| scope == Scope::Again || plan.scope == scope_word).map(|plan| plan.first_at.clone()).filter(|at| !at.is_empty()).unwrap_or_else(|| now.clone());
            plans.insert(name.to_string(), DiskPlan { scope: scope_word.into(), paths: paths.clone(), sudo, first_at, last_at: now.clone(), last_error: (!failed.is_empty()).then(|| failed.join("；")) });
        });
        let said = tf!("已扫描 {name}：{}", "Scanned {name}: {}", done.join("、"));
        if failed.is_empty() { Ok(said) } else { Err(tf!("{said}；未完成：{}", "{said}; not finished: {}", failed.join("；"))) }
    }

    /// The servers whose follow-up scan is due: a first scan was made, and the last one is older than the interval.
    pub fn disk_due(&self, minutes: u32) -> Vec<String> {
        if minutes == 0 { return vec![] }
        let cutoff = time::now_ms() - i64::from(minutes) * 60_000;
        let inventory = self.inventory();
        self.disk_plans().into_iter().filter(|(name, plan)| inventory.has_host(name) && (util::date_parse(&plan.last_at) as i64) < cutoff).map(|(name, _)| name).collect()
    }

    /// The stored scans of a server: the latest of each path with the one before it, the plan's paths first.
    pub fn disk_scans(&self, name: &str) -> Vec<ScanView> {
        let rows: Vec<SpaceSnapshot> = self.store.read_bounded("space", name).unwrap_or_default();
        let planned = self.disk_plans().remove(name).map(|plan| plan.paths).unwrap_or_default();
        let mut scans: Vec<ScanView> = vec![];
        for (at, row) in rows.iter().enumerate().rev() {
            if scans.iter().any(|scan| scan.path == row.report.path) { continue }
            let previous = rows[..at].iter().rev().find(|older| older.report.path == row.report.path);
            scans.push(ScanView { path: row.report.path.clone(), at: row.at.clone(), tree: space::build_space_tree(&row.report.path, &row.report.dirs), report: row.report.clone(), previous_at: previous.map(|older| older.at.clone()), before: previous.map(|older| older.report.dirs.iter().cloned().collect()).unwrap_or_default() });
        }
        let rank = |path: &str| planned.iter().position(|known| known == path).unwrap_or(planned.len());
        scans.sort_by(|a, b| rank(&a.path).cmp(&rank(&b.path)).then_with(|| a.path.cmp(&b.path)));
        scans
    }

    // ---- long-running tasks

    /// Look for user tasks that have run longer than `hours` on the selected servers, and keep what was found.
    pub fn long_jobs(&self, selector: &str, hours: u32, origin: &str) -> Result<String, String> {
        let hosts = self.select(selector)?;
        let collect = Collect { sudo: false, tool: format!("window:{origin}"), session: None, authorization: Authorization::ReadOnly, cancel: None };
        let found = self.long_jobs_on(&hosts, hours, &collect);
        let failed: Vec<&str> = found.iter().filter(|(_, report, _)| report.is_none()).map(|(host, ..)| host.as_str()).collect();
        let (with, total) = found.iter().filter_map(|(_, report, _)| report.as_ref()).fold((0, 0), |(with, total), report| (with + usize::from(!report.jobs.is_empty()), total + report.jobs.len()));
        let said = tf!("检查完成：{with} 台服务器上有运行超过 {hours} 小时的任务，共 {total} 个", "Checked: {with} servers have tasks running longer than {hours} h, {total} in all");
        if failed.is_empty() { Ok(said) } else { Err(tf!("{said}；没有检查到：{}", "{said}; not checked: {}", failed.join(", "))) }
    }

    /// The same, for whoever asks: each host's report, or the run that gave none.
    pub fn long_jobs_on(&self, hosts: &[Host], hours: u32, collect: &Collect) -> Vec<(String, Option<longrun::LongRunReport>, wisp_ops_engine::ssh::RunResult)> {
        let options = LongRunOptions::hours(hours.max(1));
        let mut exec = Exec::read(&collect.tool, collect.authorization);
        exec.timeout_ms = self.clamp_timeout(Some(self.config.ssh.connect_timeout_sec * 1000 + 40_000));
        exec.session = collect.session.clone();
        exec.cancel = collect.cancel.clone();
        exec.max_output_bytes = Some(2 << 20);
        exec.audit_command = Some(format!("(built-in read-only check for tasks running longer than {hours} h)"));
        let at = time::to_iso(time::now_ms());
        self.execute_one(hosts, &longrun::longrun_script(&options), &exec).into_iter().map(|result| {
            let report = result.stdout.contains("@@end").then(|| longrun::parse_longrun(&result.stdout, &options));
            if let Some(report) = &report { let _ = self.store.append_bounded("longrun", &result.host, &LongRunSnapshot { report: report.clone(), at: at.clone() }, 5); }
            (result.host.clone(), report, result)
        }).collect()
    }

    /// The latest check of every server that has one.
    pub fn long_runs(&self) -> BTreeMap<String, LongRunSnapshot> {
        self.inventory().hosts().iter().filter_map(|host| self.store.read_bounded::<LongRunSnapshot>("longrun", &host.name).ok().and_then(|mut rows| rows.pop()).map(|row| (host.name.clone(), row))).collect()
    }

    // ---- login attacks

    /// Triage the selected servers for the security page: as root wherever the window may (the
    /// auth log is root's to read), without it elsewhere.
    pub fn attack_scan(&self, selector: &str, hours: u32) -> Result<String, String> {
        let hosts = self.select(selector)?;
        let (rooted, plain): (Vec<Host>, Vec<Host>) = hosts.into_iter().partition(|host| self.root_way(host) == Ok(true));
        let mut found = vec![];
        for (group, sudo) in [(rooted, true), (plain, false)] {
            if group.is_empty() { continue }
            let collect = Collect { sudo, tool: "window:security".into(), session: None, authorization: if sudo { Authorization::Approval } else { Authorization::ReadOnly }, cancel: None };
            found.extend(self.security(&group, hours, &collect));
        }
        let failed: Vec<&str> = found.iter().filter(|(_, report, _)| report.is_none()).map(|(host, ..)| host.as_str()).collect();
        let blind = found.iter().filter(|(_, report, _)| report.as_ref().is_some_and(|report| !report.auth_log_readable)).count();
        let attempts: f64 = self.attacks().iter().filter(|(name, _)| found.iter().any(|(host, report, _)| host == *name && report.is_some())).map(|(_, row)| row.attacks.failed).sum();
        let mut said = tf!("排查完成：{} 台服务器，失败登录 {} 次", "Triage done: {} servers, {} failed logins", found.len() - failed.len(), util::n(attempts));
        if blind > 0 { said.push_str(&tf!("；{blind} 台读不到认证日志（需要 root）", "; {blind} could not read the auth log (root needed)")) }
        if failed.is_empty() { Ok(said) } else { Err(tf!("{said}；没有排查到：{}", "{said}; not reached: {}", failed.join(", "))) }
    }

    /// The latest triage of every server that has one.
    pub fn attacks(&self) -> BTreeMap<String, SecuritySnapshot> {
        self.inventory().hosts().iter().filter_map(|host| self.store.read_bounded::<SecuritySnapshot>("security", &host.name).ok().and_then(|mut rows| rows.pop()).map(|row| (host.name.clone(), row))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{FsUsage, local_mounts};

    fn fs(device: &str, kind: &str, size_gb: f64, used_gb: f64, mount: &str) -> FsUsage {
        const G: f64 = 1024. * 1024.;
        FsUsage { filesystem: device.into(), fs_type: Some(kind.into()), size_kb: size_gb * G, used_kb: used_gb * G, avail_kb: (size_gb - used_gb) * G, use_pct: 0., mount: mount.into() }
    }

    #[test]
    fn a_full_scan_walks_each_local_disk_once_and_nothing_else() {
        let mounts = local_mounts(&[
            fs("/dev/sda2", "ext4", 500., 100., "/"),
            fs("/dev/sda1", "vfat", 1., 0.1, "/boot/efi"),
            fs("tmpfs", "tmpfs", 64., 1., "/dev/shm"),
            fs("/dev/sdb1", "xfs", 4000., 3000., "/data"),
            fs("/dev/sdb1", "xfs", 4000., 3000., "/data/shared/bind"),
            fs("nas:/vol", "nfs4", 90000., 80000., "/mnt/nas"),
            fs("overlay", "overlay", 500., 100., "/var/lib/docker/overlay2/x/merged"),
            fs("/dev/loop3", "squashfs", 2., 2., "/snap/core/1"),
            fs("/dev/sdc1", "ext4", 0.5, 0.1, "/tiny"),
        ]);
        assert_eq!(mounts, ["/data", "/"]);
    }
}
