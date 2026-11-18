//! Disk quotas of the accounts on a host, read with the accounts (`scripts/quotas.sh` is part of
//! `ACCOUNTS_SCRIPT`): which filesystems have user quotas (asked for in the mount options, and
//! switched on or not by `quotaon -pa`), and what `repquota -aupv` says each user uses and may
//! use there. Reading the quotas takes root; finding the filesystems does not.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::sections::Sections;

/// Whether user quotas are enforced on a filesystem.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaState {
    On,
    /// Asked for in the mount options, but `quotaon` says they are off.
    Off,
    /// Asked for in the mount options; whether they are on is not known (no quota tools).
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QuotaFs {
    pub mount: String,
    pub device: String,
    pub fstype: String,
    pub state: QuotaState,
}

/// What one user uses on one filesystem and may use; sizes in KiB, a limit of 0 is none.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QuotaUse {
    pub user: String,
    pub mount: String,
    pub used_kb: u64,
    pub soft_kb: u64,
    pub hard_kb: u64,
    /// The epoch second the grace over the soft limit runs out.
    pub grace: Option<i64>,
    pub files: u64,
    pub files_soft: u64,
    pub files_hard: u64,
    pub files_grace: Option<i64>,
}

impl QuotaUse {
    /// The limit that counts: the hard one, else the soft one.
    pub fn limit_kb(&self) -> Option<u64> {
        [self.hard_kb, self.soft_kb].into_iter().find(|limit| *limit > 0)
    }

    /// How full it is, 0 to 1 and beyond, against `limit_kb`.
    pub fn ratio(&self) -> Option<f64> {
        self.limit_kb().map(|limit| self.used_kb as f64 / limit as f64)
    }

    /// Over the soft limit (of space or of files).
    pub fn over_soft(&self) -> bool {
        (self.soft_kb > 0 && self.used_kb > self.soft_kb) || (self.files_soft > 0 && self.files > self.files_soft)
    }

    /// At the hard limit: nothing more can be written.
    pub fn at_hard(&self) -> bool {
        (self.hard_kb > 0 && self.used_kb >= self.hard_kb) || (self.files_hard > 0 && self.files >= self.files_hard)
    }

    /// Anything to tell: some use or some limit.
    pub fn matters(&self) -> bool {
        self.used_kb > 0 || self.limit_kb().is_some() || self.files_soft > 0 || self.files_hard > 0
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QuotaReport {
    /// The quota tools (`repquota`) are installed.
    pub tools: bool,
    /// `repquota` reported at least one filesystem.
    pub read: bool,
    /// The filesystems with user quotas, asked for or on.
    pub filesystems: Vec<QuotaFs>,
    pub usage: Vec<QuotaUse>,
}

impl QuotaReport {
    pub fn of(&self, user: &str) -> Vec<&QuotaUse> {
        self.usage.iter().filter(|row| row.user == user && row.matters()).collect()
    }

    /// The filesystem of one user that is fullest against its limit, else the one most used.
    pub fn fullest(&self, user: &str) -> Option<&QuotaUse> {
        self.of(user).into_iter().max_by(|a, b| a.ratio().unwrap_or(-1.).total_cmp(&b.ratio().unwrap_or(-1.)).then(a.used_kb.cmp(&b.used_kb)))
    }

    pub fn any_on(&self) -> bool {
        self.filesystems.iter().any(|fs| fs.state == QuotaState::On)
    }
}

/// Mount options that ask for user quotas (ext*, xfs, and the old `quota`).
fn asks_for_user_quota(options: &str) -> bool {
    options.split(',').any(|option| matches!(option.split('=').next().unwrap_or(""), "usrquota" | "usrjquota" | "quota" | "uquota" | "uqnoenforce" | "qnoenforce"))
}

/// `/proc/mounts` escapes a space in a path as `\040`.
fn unescape(path: &str) -> String {
    path.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
}

/// A number of `repquota`, or a grace in seconds since the epoch (`-p`), 0 being none.
fn grace(word: &str) -> Option<i64> {
    word.parse::<i64>().ok().filter(|secs| *secs > 0)
}

/// One user's line of `repquota -p`: name, `--` flags, block used/soft/hard[/grace], file used/soft/hard[/grace].
fn usage_line(line: &str, mount: &str) -> Option<QuotaUse> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let (user, flags) = (*words.first()?, *words.get(1)?);
    if flags.len() != 2 || !flags.chars().all(|c| c == '-' || c == '+') { return None }
    let rest = &words[2..];
    // With `-p` both graces are printed; without it each only when over its soft limit.
    let (block_grace, file_grace) = if rest.len() == 8 { (true, true) } else { (flags.starts_with('+'), flags.ends_with('+')) };
    let mut at = 0;
    let mut next = || { let word = rest.get(at).copied(); at += 1; word };
    let number = |word: Option<&str>| word.and_then(|word| word.parse::<u64>().ok());
    let (used_kb, soft_kb, hard_kb) = (number(next())?, number(next())?, number(next())?);
    let grace_at = if block_grace { next().and_then(grace) } else { None };
    let (files, files_soft, files_hard) = (number(next())?, number(next())?, number(next())?);
    let files_grace = if file_grace { next().and_then(grace) } else { None };
    Some(QuotaUse { user: user.into(), mount: mount.into(), used_kb, soft_kb, hard_kb, grace: grace_at, files, files_soft, files_hard, files_grace })
}

/// Read the sections `scripts/quotas.sh` printed.
pub fn parse_quotas(s: &Sections) -> QuotaReport {
    let mut report = QuotaReport { tools: s.has("qtools"), ..Default::default() };
    // Every filesystem on a device, by device: (mount point, type, user quotas asked for).
    let mut by_device: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut found: Vec<QuotaFs> = vec![];
    for line in s.get("qmounts") {
        let cells: Vec<&str> = line.split('\t').collect();
        let [mount, device, fstype, options] = cells[..] else { continue };
        let mount = unescape(mount);
        by_device.entry(device.to_string()).or_insert_with(|| (mount.clone(), fstype.to_string()));
        if asks_for_user_quota(options) && !found.iter().any(|fs| fs.mount == mount) {
            found.push(QuotaFs { mount, device: device.into(), fstype: fstype.into(), state: if report.tools { QuotaState::Off } else { QuotaState::Unknown } });
        }
    }
    let mut set = |device: &str, mount: Option<String>, on: bool| {
        let mount = mount.or_else(|| by_device.get(device).map(|(mount, _)| mount.clone())).unwrap_or_else(|| device.to_string());
        let state = if on { QuotaState::On } else { QuotaState::Off };
        match found.iter_mut().find(|fs| fs.mount == mount) {
            Some(fs) => if on || fs.state != QuotaState::On { fs.state = state },
            None => found.push(QuotaFs { fstype: by_device.get(device).map(|(_, fstype)| fstype.clone()).unwrap_or_default(), mount, device: device.into(), state }),
        }
    };
    // `user quota on /home/data (/dev/sdb1) is on` (XFS adds `(enforced)` or `(accounted)`).
    for line in s.get("quotaon") {
        let Some(rest) = line.strip_prefix("user quota on ") else { continue };
        let Some((mount, tail)) = rest.rsplit_once(" (") else { continue };
        let Some((device, state)) = tail.split_once(") is ") else { continue };
        set(device, Some(mount.to_string()), state.starts_with("on"));
    }
    let mut mount: Option<String> = None;
    for line in s.get("repquota") {
        if let Some(device) = line.strip_prefix("*** Report for user quotas on device ") {
            let device = device.trim();
            let at = by_device.get(device).map(|(mount, _)| mount.clone()).unwrap_or_else(|| device.to_string());
            set(device, Some(at.clone()), true);
            report.read = true;
            mount = Some(at);
        } else if let Some(at) = &mount
            && let Some(row) = usage_line(line, at)
        {
            report.usage.push(row);
        }
    }
    report.filesystems = found;
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sections::parse_sections;

    const OUTPUT: &str = "@@qmounts
/\t/dev/sda1\text4\trw,relatime
/home/data\t/dev/sdb1\text4\trw,relatime,usrquota,grpquota
/scratch\t/dev/sdc1\txfs\trw,relatime,usrquota
/srv/my\\040files\t/dev/sdd1\text4\trw,relatime,usrjquota=aquota.user,jqfmt=vfsv0
@@qtools
repquota
@@quotaon
user quota on /home/data (/dev/sdb1) is on
user quota on /scratch (/dev/sdc1) is on (enforced)
user quota on /srv/my files (/dev/sdd1) is off
@@repquota
*** Report for user quotas on device /dev/sdb1
Block grace time: 7days; Inode grace time: 7days
                        Block limits                File limits
User            used    soft    hard  grace    used  soft  hard  grace
----------------------------------------------------------------------
root      --      20       0       0      0       2     0     0      0
alice     +-  10485760 10000000 12000000 1795600000    1234     0     0      0
bob       --       0       0       0      0       0     0     0      0
#1500     --    4096       0       0      0       3     0     0      0

Statistics:
Total blocks: 7
*** Report for user quotas on device /dev/sdc1
Block grace time: 7days; Inode grace time: 7days
alice     --  204800  1048576  2097152      0     10   100   200      0
carol     -+     512       0       0      0     250   100   200  6days
@@end
";

    #[test]
    fn filesystems_and_usage_are_read() {
        let report = parse_quotas(&parse_sections(OUTPUT));
        assert!(report.tools && report.read && report.any_on());
        let states: Vec<(&str, QuotaState)> = report.filesystems.iter().map(|fs| (fs.mount.as_str(), fs.state)).collect();
        assert_eq!(states, [("/home/data", QuotaState::On), ("/scratch", QuotaState::On), ("/srv/my files", QuotaState::Off)]);
        let alice = report.of("alice");
        assert_eq!(alice.len(), 2);
        assert_eq!((alice[0].used_kb, alice[0].soft_kb, alice[0].hard_kb, alice[0].grace), (10485760, 10000000, 12000000, Some(1795600000)));
        assert!(alice[0].over_soft() && !alice[0].at_hard());
        assert_eq!(report.fullest("alice").unwrap().mount, "/home/data");
        // Nothing used and no limit: nothing to say.
        assert!(report.of("bob").is_empty());
        let carol = &report.of("carol")[0];
        assert_eq!((carol.files, carol.files_hard, carol.files_grace, carol.grace), (250, 200, None, None));
        assert!(carol.at_hard() && carol.limit_kb().is_none());
        assert_eq!(report.of("#1500")[0].used_kb, 4096);
    }

    #[test]
    fn without_tools_or_root_the_filesystems_still_show() {
        let bare = "@@qmounts\n/home\t/dev/sdb1\text4\trw,usrquota\n/\t/dev/sda1\text4\trw\n@@end\n";
        let report = parse_quotas(&parse_sections(bare));
        assert!(!report.tools && !report.read);
        assert_eq!(report.filesystems, vec![QuotaFs { mount: "/home".into(), device: "/dev/sdb1".into(), fstype: "ext4".into(), state: QuotaState::Unknown }]);
        // Not root: repquota says nothing, quotaon still tells what is on.
        let plain = "@@qmounts\n/home\t/dev/sdb1\text4\trw,usrquota\n@@qtools\nrepquota\n@@quotaon\nuser quota on /home (/dev/sdb1) is on\n@@repquota\n@@end\n";
        let report = parse_quotas(&parse_sections(plain));
        assert!(report.tools && !report.read && report.any_on());
    }
}
