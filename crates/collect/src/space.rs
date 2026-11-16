//! Directory space map of one path: `du` sizes of every directory down to a fixed depth on the
//! same filesystem, keeping the largest ones so the panel can draw a map the owner opens level by
//! level, and the tree both the report and the map are built from. Read-only; the scan is stored
//! per host so the next one can report growth.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::sections::{FsUsage, format_kb, num, num_opt, parse_df, parse_sections};
use crate::util::{desc, fill, n, pad_start, shell_quote, to_fixed};

/// One directory of a size tree.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceNode {
    /// Last path segment; the scanned root keeps its full path.
    pub name: String,
    pub path: String,
    /// Size including every subdirectory, in KB.
    pub kb: f64,
    /// Files directly in this directory plus subdirectories too small to list, in KB.
    pub rest_kb: f64,
    /// Listed subdirectories, largest first.
    pub children: Vec<SpaceNode>,
}

/// `/data/` → `/data`; the filesystem root stays `/`.
pub fn normalize_root(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(cut) if cut > 0 => &path[..cut],
        _ => "/",
    }
}

fn under(path: &str, root: &str) -> bool {
    if root == "/" { path.starts_with('/') && path != "/" } else { path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/')) }
}

fn build_node(path: &str, top: &str, reported: &HashMap<&str, f64>, children: &HashMap<&str, Vec<&str>>) -> SpaceNode {
    let mut kids: Vec<SpaceNode> = children.get(path).into_iter().flatten().map(|child| build_node(child, top, reported, children)).collect();
    // Ties fall back to the name; the original compares with the locale's collation.
    kids.sort_by(|a, b| desc(a.kb, b.kb).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())).then_with(|| a.name.cmp(&b.name)));
    let sum: f64 = kids.iter().map(|k| k.kb).sum();
    let kb = reported.get(path).copied().unwrap_or(0.0).max(sum);
    let name = if path == top { top } else { path.rsplit('/').next().unwrap_or(path) };
    SpaceNode { name: name.to_string(), path: path.to_string(), kb, rest_kb: kb - sum, children: kids }
}

/// Nest `(path, kb)` rows under `root`. A directory missing from the rows (cut by the size floor or
/// an interrupted walk) is rebuilt from its listed subdirectories, so a partial scan still nests
/// correctly with sizes as lower bounds.
pub fn build_space_tree(root: &str, dirs: &[(String, f64)]) -> SpaceNode {
    let top = normalize_root(root);
    let mut reported: HashMap<&str, f64> = HashMap::new();
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for (raw, kb) in dirs {
        let path = normalize_root(raw);
        if path != top && !under(path, top) {
            continue;
        }
        let known = reported.get(path).copied().unwrap_or(0.0);
        reported.insert(path, kb.max(known));
        let mut child = path;
        while child != top {
            let parent = parent_of(child);
            let set = children.entry(parent).or_default();
            if set.contains(&child) {
                break;
            }
            set.push(child);
            child = parent;
        }
    }
    build_node(top, top, &reported, &children)
}

/// The node at `path`, or `None` when the tree does not list it.
pub fn find_space_node<'a>(tree: &'a SpaceNode, path: &str) -> Option<&'a SpaceNode> {
    if tree.path == path {
        return Some(tree);
    }
    let next = tree.children.iter().find(|child| path == child.path || path.strip_prefix(child.path.as_str()).is_some_and(|rest| rest.starts_with('/')))?;
    find_space_node(next, path)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceOptions {
    /// Absolute path whose directories are measured.
    pub path: String,
    /// `du` depth below the path.
    pub depth: u32,
    /// Largest directories kept, across all depths.
    pub max_dirs: u64,
    /// Directories smaller than this are dropped before sorting.
    pub min_kb: u64,
    /// Deadline for the `du` walk.
    pub walk_timeout_sec: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceReport {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FsUsage>,
    pub depth: u32,
    /// Whether the walk ran as root; otherwise unreadable directories are missing from the sizes.
    pub full_visibility: bool,
    pub walk_incomplete: bool,
    pub permission_denied: bool,
    /// `[path, kb]` of the largest directories, largest first.
    pub dirs: Vec<(String, f64)>,
    /// Directories at or above `min_kb`; more than `dirs.len()` means the list was cut.
    pub dir_count: f64,
    pub min_kb: f64,
    pub notes: Vec<String>,
}

/// One stored scan; the panel draws the latest per path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceSnapshot {
    #[serde(flatten)]
    pub report: SpaceReport,
    pub at: String,
}

/// Build the scan script; every user value is single-quoted.
pub fn space_script(o: &SpaceOptions) -> String {
    fill(
        include_str!("scripts/space.sh.tpl"),
        &[
            ("shellQuote(normalizeRoot(o.path))", &shell_quote(normalize_root(&o.path))),
            ("o.depth", &o.depth.to_string()),
            ("o.maxDirs", &o.max_dirs.to_string()),
            ("o.minKb", &o.min_kb.to_string()),
            ("o.walkTimeoutSec", &o.walk_timeout_sec.to_string()),
        ],
    )
}

/// Parse the scan script's output.
pub fn parse_space(output: &str, options: &SpaceOptions) -> SpaceReport {
    let s = parse_sections(output);
    let path = normalize_root(&options.path).to_string();
    let filesystem = parse_df(s.get("df")).into_iter().next();
    let full_visibility = s.first("whoami") == Some("0");
    let rc = num_opt(s.first("du_rc"));
    let dirs: Vec<(String, f64)> = s.get("du").iter().filter_map(|line| line.split_once('\t').and_then(|(kb, dir)| Some((normalize_root(dir).to_string(), num(kb)?)))).collect();
    let dir_count = num_opt(s.first("du_count")).unwrap_or(0.0).max(dirs.len() as f64);
    let walk_incomplete = rc == Some(124.0);
    let permission_denied = rc.is_some_and(|rc| rc != 0.0 && rc != 124.0);
    let min_kb = options.min_kb as f64;
    let mut notes: Vec<String> = Vec::new();
    if walk_incomplete {
        notes.push(format!("the du walk hit the {}s deadline; directories it had not finished (often the largest, including the root) are rebuilt from their listed subdirectories, so sizes are lower bounds", options.walk_timeout_sec));
    }
    if permission_denied {
        notes.push(format!("du could not read some directories{}; sizes are lower bounds — enable sudo on the task for full totals", if full_visibility { "" } else { " (not running as root)" }));
    }
    if dir_count > dirs.len() as f64 {
        notes.push(format!("{} directories are at least {}; only the {} largest are kept", n(dir_count), format_kb(min_kb), dirs.len()));
    }
    if filesystem.is_none() {
        notes.push(format!("df returned nothing for {path}; the path may not exist"));
    }
    SpaceReport { path, filesystem, depth: options.depth, full_visibility, walk_incomplete, permission_denied, dirs, dir_count, min_kb, notes }
}

/// Model-facing rendering: the largest directories nested a few levels, with growth since the previous scan.
pub fn render_space(host: &str, r: &SpaceReport, previous: Option<&SpaceSnapshot>) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(match &r.filesystem {
        None => format!("## {host}:{} — directory space", r.path),
        Some(fs) => format!("## {host}:{} — directory space on {} ({}) {}% used, {} free of {}", r.path, fs.mount, fs.filesystem, n(fs.use_pct), format_kb(fs.avail_kb), format_kb(fs.size_kb)),
    });
    let tree = build_space_tree(&r.path, &r.dirs);
    lines.push(format!("Directories under {} total {} (same filesystem, {} levels deep).", r.path, format_kb(tree.kb), r.depth));
    lines.extend(r.notes.iter().map(|note| format!("Note: {note}")));
    if tree.kb == 0.0 {
        return lines.join("\n");
    }
    let before: Option<(HashMap<&str, f64>, &str)> = previous.map(|p| (p.report.dirs.iter().map(|(path, kb)| (path.as_str(), *kb)).collect(), p.at.as_str()));
    let delta = |node: &SpaceNode| -> String {
        let Some((sizes, at)) = &before else { return String::new() };
        let Some(old) = sizes.get(node.path.as_str()) else { return String::new() };
        let d = node.kb - old;
        if d.abs() < (old * 0.01).max(1024.0) { String::new() } else { format!("  ({}{} since {at})", if d > 0.0 { "+" } else { "-" }, format_kb(d.abs())) }
    };
    // Enough levels to name the real space users without flooding the report.
    let floor = (tree.kb * 0.01).max(1024.0);
    let mut budget: i32 = 60;
    lines.extend([String::new(), "Largest directories (nested, share of the scanned total):".to_string()]);
    walk(&tree, 1, tree.kb, floor, &mut budget, &delta, &mut lines);
    if tree.rest_kb >= floor {
        lines.push(format!("  {}        files directly in {} and smaller directories", pad_start(&format_kb(tree.rest_kb), 7), r.path));
    }
    if let Some((sizes, at)) = &before {
        let mut grown: Vec<(&str, f64)> = r.dirs.iter().filter(|(path, _)| *path != r.path).filter_map(|(path, kb)| sizes.get(path.as_str()).map(|old| (path.as_str(), kb - old))).filter(|(_, d)| *d >= floor.max(1024.0 * 1024.0)).collect();
        grown.sort_by(|a, b| desc(a.1, b.1));
        // A parent grows with its child; name the deepest directory that explains the growth.
        let named: Vec<String> = grown
            .iter()
            .enumerate()
            .filter(|(i, (path, d))| !grown.iter().enumerate().any(|(j, (other, od))| j != *i && other.strip_prefix(path).is_some_and(|rest| rest.starts_with('/')) && *od >= d * 0.8))
            .take(5)
            .map(|(_, (path, d))| format!("{path} +{}", format_kb(*d)))
            .collect();
        if !named.is_empty() {
            lines.extend([String::new(), format!("Grew most since the previous scan ({at}): {}", named.join(", "))]);
        }
    }
    lines.join("\n")
}

fn walk(node: &SpaceNode, level: usize, total: f64, floor: f64, budget: &mut i32, delta: &dyn Fn(&SpaceNode) -> String, lines: &mut Vec<String>) {
    for child in node.children.iter().take(8) {
        if child.kb < floor {
            return;
        }
        let spent = *budget <= 0;
        *budget -= 1;
        if spent {
            return;
        }
        let share = child.kb / total;
        let pct = to_fixed(share * 100.0, if share >= 0.1 { 0 } else { 1 });
        let files = if !child.children.is_empty() && child.rest_kb >= floor.max(child.kb * 0.1) { format!("  [files directly here {}]", format_kb(child.rest_kb)) } else { String::new() };
        lines.push(format!("{}{}  {}%  {}{files}{}", "  ".repeat(level), pad_start(&format_kb(child.kb), 7), pad_start(&pct, 3), child.path, delta(child)));
        if level < 3 {
            walk(child, level + 1, total, floor, budget, delta, lines);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testing::assert_golden;

    const G: f64 = 1024.0 * 1024.0;
    const OUTPUT: &str = include_str!("testdata/space.txt");

    fn options() -> SpaceOptions {
        SpaceOptions { path: "/".into(), depth: 5, max_dirs: 4, min_kb: 1024, walk_timeout_sec: 300 }
    }

    fn rows(dirs: &[(&str, f64)]) -> Vec<(String, f64)> {
        dirs.iter().map(|(path, kb)| (path.to_string(), *kb)).collect()
    }

    #[test]
    fn nests_du_rows_keeps_direct_files_as_rest_and_rebuilds_missing_directories() {
        let tree = build_space_tree("/data/", &rows(&[("/data", 100.0), ("/data/a", 60.0), ("/data/a/x", 50.0), ("/data/b/deep/er", 20.0), ("/elsewhere", 999.0), ("/database", 7.0)]));
        assert_eq!((tree.name.as_str(), tree.path.as_str(), tree.kb, tree.rest_kb), ("/data", "/data", 100.0, 20.0));
        assert_eq!(tree.children.iter().map(|c| (c.name.as_str(), c.kb, c.rest_kb)).collect::<Vec<_>>(), [("a", 60.0, 10.0), ("b", 20.0, 0.0)]);
        assert_golden(&tree, include_str!("testdata/space.tree.json"));
        // `/data/b` and `/data/b/deep` were cut; their size is what their listed subdirectories add up to.
        let deep = find_space_node(&tree, "/data/b/deep").unwrap();
        assert_eq!((deep.name.as_str(), deep.kb), ("deep", 20.0));
        assert!(find_space_node(&tree, "/data/c").is_none());
        // An interrupted walk can lose the root; it becomes the sum of what was listed.
        let root = build_space_tree("/", &rows(&[("/var", 5.0), ("/home/a", 7.0)]));
        assert_eq!((root.name.as_str(), root.kb, root.rest_kb), ("/", 12.0, 0.0));
        assert_eq!(normalize_root("///"), "/");
    }

    #[test]
    fn builds_the_script_the_plugin_built() {
        assert_eq!(space_script(&SpaceOptions { path: "/da'ta//".into(), ..options() }), include_str!("testdata/space.golden.sh"));
    }

    #[test]
    fn parses_sizes_the_filesystem_and_why_totals_may_be_low() {
        let report = parse_space(OUTPUT, &options());
        let fs = report.filesystem.as_ref().unwrap();
        assert_eq!((fs.mount.as_str(), fs.use_pct, fs.avail_kb), ("/", 85.0, 150_000_000.0));
        assert_eq!(report.dirs, rows(&[("/", 300.0 * G), ("/home", 200.0 * G), ("/home/alice", 150.0 * G), ("/var", 60.0 * G)]));
        assert_eq!((report.dir_count, report.permission_denied, report.walk_incomplete, report.full_visibility), (37.0, true, false, false));
        let notes = report.notes.join(" ");
        assert!(notes.contains("enable sudo") && notes.contains("37 directories"));
        assert_golden(&report, include_str!("testdata/space.report.json"));
        assert_eq!(serde_json::from_str::<SpaceReport>(include_str!("testdata/space.report.json")).unwrap(), report);
        let partial = parse_space(&OUTPUT.replace("@@du_rc\n1", "@@du_rc\n124"), &options());
        assert_eq!((partial.walk_incomplete, partial.permission_denied), (true, false));
    }

    #[test]
    fn renders_nested_directories_with_growth_since_the_previous_scan() {
        let report = parse_space(OUTPUT, &options());
        let previous = SpaceSnapshot { report: SpaceReport { dirs: rows(&[("/", 250.0 * G), ("/home", 160.0 * G), ("/home/alice", 110.0 * G), ("/var", 60.0 * G)]), ..report.clone() }, at: "2026-10-20T00:00:00.000Z".into() };
        let text = render_space("gpu-01", &report, Some(&previous));
        assert_eq!(text, include_str!("testdata/space.render.txt"));
        assert!(text.contains("gpu-01:/ — directory space on / (/dev/sda2) 85% used"));
        // Growth names the deepest directory that explains it, not every ancestor.
        assert!(text.contains("Grew most since the previous scan (2026-10-20T00:00:00.000Z): /home/alice +40.0G"));
        assert_eq!(render_space("gpu-01", &report, None), include_str!("testdata/space.render-first.txt"));
        // A stored scan is the report with its time beside it.
        let stored = serde_json::to_value(&previous).unwrap();
        assert_eq!((stored["at"].as_str(), stored["path"].as_str(), stored["dirs"][1][0].as_str()), (Some("2026-10-20T00:00:00.000Z"), Some("/"), Some("/home")));
        assert_eq!(serde_json::from_value::<SpaceSnapshot>(stored).unwrap(), previous);
    }

    /// The script quotes the path and measures a real directory tree with the shell tools.
    #[cfg(unix)]
    #[test]
    fn measures_a_real_directory_tree() {
        use std::io::Write;
        let root = std::env::temp_dir().join(format!("wisp space ' {}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["a/a1", "b", "tiny"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("a/a1/f"), vec![b'x'; 3 * 1024 * 1024]).unwrap();
        std::fs::write(root.join("a/f"), vec![b'x'; 1024 * 1024]).unwrap();
        std::fs::write(root.join("b/f"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
        std::fs::write(root.join("tiny/f"), "x").unwrap();
        let root_text = root.to_str().unwrap().to_string();
        let o = SpaceOptions { path: format!("{root_text}/"), max_dirs: 100, walk_timeout_sec: 30, ..options() };
        let mut child = std::process::Command::new("sh").arg("-s").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(space_script(&o).as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        let parsed = parse_space(&String::from_utf8_lossy(&output.stdout), &o);
        assert_eq!(parsed.path, root_text);
        assert!(parsed.filesystem.is_some());
        let tree = build_space_tree(&parsed.path, &parsed.dirs);
        assert_eq!(tree.children.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        assert!(find_space_node(&tree, &format!("{root_text}/a/a1")).unwrap().kb >= 3.0 * 1024.0);
        assert!(tree.children[0].rest_kb >= 1024.0);
        assert_eq!(parsed.dir_count, 4.0);
    }
}
