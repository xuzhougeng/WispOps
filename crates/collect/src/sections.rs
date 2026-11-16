//! Collector scripts print `@@<name>` marker lines between sections so that one round trip
//! returns many independent probes. A probe that is missing on the host (no GPU, no Slurm, no
//! systemd) prints nothing and its section is simply empty.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use crate::util::{num, num_opt};
use crate::util::{fields, to_fixed};

/// Collector output split into named sections.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sections(HashMap<String, Vec<String>>);

impl Sections {
    /// The non-empty lines of a section; empty when the section is absent.
    pub fn get(&self, name: &str) -> &[String] {
        self.0.get(name).map_or(&[], Vec::as_slice)
    }

    /// Whether the marker was printed at all.
    pub fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// The first line of a section.
    pub fn first(&self, name: &str) -> Option<&str> {
        self.get(name).first().map(String::as_str)
    }
}

fn marker(line: &str) -> Option<&str> {
    let name = line.strip_prefix("@@")?;
    (!name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')).then_some(name)
}

/// Split collector output into named sections.
pub fn parse_sections(output: &str) -> Sections {
    let mut sections: HashMap<String, Vec<String>> = HashMap::new();
    let mut current: Option<String> = None;
    for line in output.split('\n') {
        if let Some(name) = marker(line) {
            sections.insert(name.to_string(), Vec::new());
            current = Some(name.to_string());
            continue;
        }
        if let Some(name) = &current
            && !line.is_empty()
            && let Some(lines) = sections.get_mut(name)
        {
            lines.push(line.to_string());
        }
    }
    Sections(sections)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FsUsage {
    pub filesystem: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,
    pub size_kb: f64,
    pub used_kb: f64,
    pub avail_kb: f64,
    pub use_pct: f64,
    pub mount: String,
}

fn is_df_header(line: &str) -> bool {
    line.strip_prefix("Filesystem").is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

/// Parse `df -PkT` (with type) or `df -Pk` output.
pub fn parse_df(lines: &[String]) -> Vec<FsUsage> {
    let mut result = Vec::new();
    for line in lines {
        if is_df_header(line) {
            continue;
        }
        let f = fields(line);
        let with_type = f.len() >= 7;
        // Without a type column every later field sits one position to the left.
        let at = |index: usize| f.get(if with_type { index } else { index - 1 }).copied();
        let fs_type = if with_type { f.get(1).copied() } else { None };
        let (Some(use_pct), Some(size_kb)) = (num_opt(at(5).map(|p| p.replacen('%', "", 1)).as_deref()), num_opt(at(2))) else { continue };
        let mount_from = if with_type { 6 } else { 5 };
        result.push(FsUsage {
            filesystem: f[0].to_string(),
            fs_type: fs_type.map(str::to_string),
            size_kb,
            used_kb: num_opt(at(3)).unwrap_or(0.0),
            avail_kb: num_opt(at(4)).unwrap_or(0.0),
            use_pct,
            mount: f.get(mount_from..).unwrap_or(&[]).join(" "),
        });
    }
    result
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InodeUsage {
    pub mount: String,
    pub use_pct: f64,
}

/// Parse `df -Pi`; filesystems without inode accounting report `-`.
pub fn parse_df_inodes(lines: &[String]) -> Vec<InodeUsage> {
    let mut result = Vec::new();
    for line in lines {
        if is_df_header(line) {
            continue;
        }
        let f = fields(line);
        let Some(use_pct) = num_opt(f.get(4).map(|p| p.replacen('%', "", 1)).as_deref()) else { continue };
        result.push(InodeUsage { mount: f.get(5..).unwrap_or(&[]).join(" "), use_pct });
    }
    result
}

/// Human-readable size from kilobytes.
pub fn format_kb(kb: f64) -> String {
    const UNITS: [&str; 5] = ["K", "M", "G", "T", "P"];
    let mut value = kb;
    let mut unit = 0;
    while value.abs() >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{}{}", to_fixed(value, if value >= 100.0 || unit == 0 { 0 } else { 1 }), UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_sections_and_skips_banners() {
        let s = parse_sections("motd\n@@a\none\n\ntwo\n@@b\n@@Not\nthree\n@@a\nagain\n");
        assert_eq!(s.get("a"), ["again"]);
        assert_eq!(s.get("b"), ["@@Not", "three"]);
        assert!(s.has("b") && !s.has("c"));
        assert!(s.get("c").is_empty());
    }

    #[test]
    fn parses_df_with_and_without_type() {
        let typed = parse_df(&["Filesystem Type 1024-blocks Used Available Capacity Mounted on".into(), "/dev/sda1 ext4 1000 850 150 85% /my data".into()]);
        assert_eq!(typed[0].fs_type.as_deref(), Some("ext4"));
        assert_eq!(typed[0].mount, "/my data");
        let plain = parse_df(&["/dev/sda1 1000 850 150 85% /".into()]);
        assert_eq!((plain[0].fs_type.clone(), plain[0].size_kb, plain[0].use_pct, plain[0].mount.as_str()), (None, 1000.0, 85.0, "/"));
        assert!(parse_df(&["garbage".into()]).is_empty());
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(format_kb(512.0), "512K");
        assert_eq!(format_kb(1536.0), "1.5M");
        assert_eq!(format_kb(48_000_000.0), "45.8G");
        assert_eq!(format_kb(960_000_000.0), "916G");
        assert_eq!(format_kb(-2048.0), "-2.0M");
    }
}
