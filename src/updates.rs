//! Update checks: GitHub's latest release of WispOps against the running
//! version, kept in `<data>/updates.json` with the time of the check, and
//! the package for this platform fetched on request into the Downloads
//! folder and verified against the release's `SHA256SUMS`. The builds are
//! not signed, so nothing here replaces the application or runs what it
//! downloaded: the person installs it. No GPUI in this file; the window's
//! side is `updates_view.rs`.

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wisp_ops_net::fetch;

pub const LATEST_URL: &str = "https://api.github.com/repos/xuzhougeng/WispOps/releases/latest";
/// Where a release's files must come from; anything else in the answer is ignored.
const DOWNLOAD_PREFIX: &str = "https://github.com/xuzhougeng/WispOps/releases/download/";
const RELEASE_PAGE: &str = "https://github.com/xuzhougeng/WispOps/releases/tag/";
pub const RUNNING: &str = env!("CARGO_PKG_VERSION");
/// Automatic checks are at most this far apart, whatever the last one found.
const CHECK_EVERY: chrono::TimeDelta = chrono::TimeDelta::hours(24);
const ANSWER_LIMIT: u64 = 1024 * 1024;
const SUMS_LIMIT: u64 = 64 * 1024;
const PACKAGE_LIMIT: u64 = 1024 * 1024 * 1024;

/// `x.y.z`, the only form of version this compares.
fn stable(version: &str) -> Option<[u64; 3]> {
    let mut parts = version.split('.');
    let mut out = [0u64; 3];
    for slot in &mut out {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) { return None }
        *slot = part.parse().ok()?;
    }
    if parts.next().is_some() { return None }
    Some(out)
}

/// `next` is a stable version newer than `current` (both `x.y.z`; anything else is never newer).
pub fn newer_stable(next: &str, current: &str) -> bool {
    match (stable(next), stable(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    #[default]
    Unchecked,
    /// The repository has no published release yet.
    NoRelease,
    Current,
    Available,
    Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

/// What the last check found. `latest` and the release's files are kept
/// through a failed check, so an update already known stays on show.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Status {
    #[serde(with = "rfc3339")]
    pub checked_at: Option<DateTime<Utc>>,
    /// The version that was running when this was written.
    pub current: String,
    pub latest: String,
    pub release_url: String,
    /// The package for this platform, if the release has one.
    pub asset: Option<Asset>,
    pub sums_url: String,
    pub state: State,
    /// Why the last check failed.
    pub detail: String,
    /// The verified package of `latest` in the Downloads folder.
    pub downloaded: String,
}

/// The time of a check as RFC 3339 text (this build's chrono has no serde).
mod rfc3339 {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(at: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error> {
        match at {
            Some(at) => serializer.serialize_some(&at.to_rfc3339_opts(SecondsFormat::Secs, true)),
            None => serializer.serialize_none(),
        }
    }

    /// Text that is not a time reads as no check at all, so the next one is due.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error> {
        let text: Option<String> = Option::deserialize(deserializer)?;
        Ok(text.and_then(|text| DateTime::parse_from_rfc3339(&text).ok()).map(|at| at.with_timezone(&Utc)))
    }
}

impl Status {
    pub fn unchecked() -> Status {
        Status { current: RUNNING.into(), ..Default::default() }
    }

    /// A release newer than the running version is known.
    pub fn update_known(&self) -> bool {
        newer_stable(&self.latest, &self.current)
    }
}

/// `updates.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Saved {
    pub status: Option<Status>,
    /// The version whose notice beside the pages was put away.
    pub dismissed: String,
}

pub fn file(data_dir: &Path) -> PathBuf {
    data_dir.join("updates.json")
}

/// A missing or unreadable file is a fresh start: it only caches what a check finds.
pub fn load(data_dir: &Path) -> Saved {
    std::fs::read(file(data_dir)).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
}

pub fn save(data_dir: &Path, saved: &Saved) -> Result<(), String> {
    let path = file(data_dir);
    let temporary = path.with_extension("json.tmp");
    let text = serde_json::to_vec_pretty(saved).map_err(|err| err.to_string())?;
    std::fs::create_dir_all(data_dir).and_then(|_| std::fs::write(&temporary, text)).and_then(|_| std::fs::rename(&temporary, &path)).map_err(|err| format!("无法写入 {}：{err}", path.display()))
}

/// A release as far as the check needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub release_url: String,
    pub assets: Vec<Asset>,
    pub sums_url: String,
}

/// Read GitHub's answer for the latest release. Drafts, pre-releases and tags
/// that are not `v?x.y.z` are not a release this offers; files whose name is
/// not a plain file name or that are not served from the repository's
/// release downloads are left out.
pub fn parse_release(body: &[u8]) -> Result<Release, String> {
    let json: serde_json::Value = serde_json::from_slice(body).map_err(|_| "GitHub 的回应不是有效的 JSON".to_string())?;
    if json["draft"].as_bool() != Some(false) || json["prerelease"].as_bool() != Some(false) { return Err("最新发布不是正式版本".into()) }
    let tag = json["tag_name"].as_str().unwrap_or_default();
    let version = tag.strip_prefix('v').unwrap_or(tag);
    if stable(version).is_none() { return Err("最新发布不是正式版本".into()) }
    let mut assets = vec![];
    let mut sums_url = String::new();
    for asset in json["assets"].as_array().into_iter().flatten() {
        let (Some(name), Some(url)) = (asset["name"].as_str(), asset["browser_download_url"].as_str()) else { continue };
        let plain = !name.is_empty() && !name.starts_with('.') && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !plain || url != format!("{DOWNLOAD_PREFIX}{tag}/{name}") { continue }
        if name == "SHA256SUMS" {
            sums_url = url.to_string();
        } else {
            assets.push(Asset { name: name.into(), url: url.into(), size: asset["size"].as_u64().unwrap_or(0) });
        }
    }
    Ok(Release { version: version.into(), release_url: format!("{RELEASE_PAGE}{tag}"), assets, sums_url })
}

/// The package name the release workflow gives this platform, if it builds one.
pub fn asset_name(version: &str, os: &str, arch: &str) -> Option<String> {
    let label = match (os, arch) {
        ("macos", "aarch64") => "macos-arm64.dmg",
        ("macos", "x86_64") => "macos-x64.dmg",
        ("windows", "x86_64") => "windows-x64.zip",
        ("linux", "x86_64") => "linux-x64.tar.gz",
        _ => return None,
    };
    Some(format!("WispOps-v{version}-{label}"))
}

pub fn pick_asset(release: &Release, os: &str, arch: &str) -> Option<Asset> {
    let name = asset_name(&release.version, os, arch)?;
    release.assets.iter().find(|asset| asset.name == name).cloned()
}

/// `sha256sum` output: `<hex>  <name>`, or `<hex> *<name>` in binary mode. Names to lowercase digests.
pub fn parse_sums(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (digest, name) = line.trim_end().split_once(' ')?;
            let name = name.trim_start_matches(' ').trim_start_matches('*');
            (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) && !name.is_empty()).then(|| (name.to_string(), digest.to_ascii_lowercase()))
        })
        .collect()
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut std::fs::File::open(path)?, &mut hasher)?;
    Ok(hex(&hasher.finalize()))
}

/// The version that runs now may not be the one that wrote the status (the
/// app was updated or rolled back): whether an update is known follows the
/// running version, and what was downloaded for an older one is forgotten.
pub fn reconcile(status: Status, running: &str) -> Status {
    if status.current == running { return status }
    let mut status = Status { current: running.into(), ..status };
    if status.state == State::Available || status.state == State::Current { status.state = if status.update_known() { State::Available } else { State::Current } }
    if !status.update_known() { status.downloaded.clear() }
    status
}

/// The status after a check: `fetched` is the answer for the latest release (`None` for none at all).
pub fn outcome(fetched: Result<Option<Vec<u8>>, String>, previous: &Status, running: &str, os: &str, arch: &str, now: DateTime<Utc>) -> Status {
    let base = Status { checked_at: Some(now), current: running.into(), ..Default::default() };
    let release = match fetched {
        Ok(None) => return Status { state: State::NoRelease, ..base },
        Ok(Some(body)) => parse_release(&body),
        Err(err) => Err(err),
    };
    match release {
        Ok(release) => {
            let state = if newer_stable(&release.version, running) { State::Available } else { State::Current };
            // A package already verified for this very version stays known.
            let downloaded = if previous.latest == release.version && state == State::Available { previous.downloaded.clone() } else { String::new() };
            Status { latest: release.version.clone(), release_url: release.release_url.clone(), asset: pick_asset(&release, os, arch), sums_url: release.sums_url.clone(), state, downloaded, ..base }
        }
        Err(detail) => Status { latest: previous.latest.clone(), release_url: previous.release_url.clone(), asset: previous.asset.clone(), sums_url: previous.sums_url.clone(), downloaded: previous.downloaded.clone(), state: State::Failed, detail, ..base },
    }
}

/// An automatic check is due: switched on, and none (successful or not) in the last day.
pub fn due(status: &Status, automatic: bool, now: DateTime<Utc>) -> bool {
    automatic && status.checked_at.is_none_or(|at| now - at >= CHECK_EVERY || at > now)
}

/// Ask GitHub and keep the outcome. Blocking: run it off the main thread.
pub fn check(data_dir: &Path, url: &str, proxy: &str) -> Status {
    let mut saved = load(data_dir);
    let previous = reconcile(saved.status.clone().unwrap_or_else(Status::unchecked), RUNNING);
    let fetched = fetch::get(url, "application/vnd.github+json", proxy, ANSWER_LIMIT, Duration::from_secs(20));
    let status = outcome(fetched, &previous, RUNNING, std::env::consts::OS, std::env::consts::ARCH, Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now));
    saved.status = Some(status.clone());
    // Not being able to keep the result does not make the result wrong: it is shown all the same.
    let _ = save(data_dir, &saved);
    status
}

/// Writes to the file and hashes what it writes.
struct Hashing<'a> {
    file: &'a mut std::fs::File,
    hasher: Sha256,
}

impl Write for Hashing<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.file.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Fetch the release's package for this platform into `folder` and verify
/// it against `SHA256SUMS`: the path of the verified package. Without a
/// checksum to compare with nothing is downloaded; a package whose checksum
/// does not match is deleted. A package of the same name already there that
/// matches is kept as it is. Blocking.
pub fn download(status: &Status, folder: &Path, proxy: &str) -> Result<PathBuf, String> {
    let Some(asset) = &status.asset else { return Err("这个平台没有现成的安装包，请到发布页面查看。".into()) };
    if status.sums_url.is_empty() { return Err("这个发布没有 SHA256SUMS，无法校验，没有下载。".into()) }
    let sums = fetch::get(&status.sums_url, "application/octet-stream", proxy, SUMS_LIMIT, Duration::from_secs(60))?.ok_or_else(|| "这个发布没有 SHA256SUMS，无法校验，没有下载。".to_string())?;
    let Some(expected) = parse_sums(&String::from_utf8_lossy(&sums)).remove(&asset.name) else { return Err(tf!("SHA256SUMS 里没有 {}，没有下载。", "SHA256SUMS does not list {}; nothing was downloaded.", asset.name)) };
    std::fs::create_dir_all(folder).map_err(|err| format!("{}: {err}", folder.display()))?;
    let target = folder.join(&asset.name);
    if sha256_file(&target).is_ok_and(|digest| digest == expected) { return Ok(target) }
    let part = folder.join(format!("{}.part", asset.name));
    let mut file = std::fs::File::create(&part).map_err(|err| format!("{}: {err}", part.display()))?;
    let mut sink = Hashing { file: &mut file, hasher: Sha256::new() };
    let fetched = fetch::download(&asset.url, proxy, PACKAGE_LIMIT, Duration::from_secs(30 * 60), &mut sink);
    let digest = hex(&sink.hasher.finalize());
    let flushed = file.sync_all();
    drop(file);
    let failed = |message: String| {
        let _ = std::fs::remove_file(&part);
        Err(message)
    };
    if let Err(err) = fetched { return failed(err) }
    if let Err(err) = flushed { return failed(format!("{}: {err}", part.display())) }
    if digest != expected { return failed(tf!("{} 的校验和与 SHA256SUMS 不符，已删除。", "The checksum of {} does not match SHA256SUMS; the file was deleted.", asset.name)) }
    if let Err(err) = std::fs::rename(&part, &target) { return failed(format!("{}: {err}", target.display())) }
    Ok(target)
}

/// Where a downloaded package goes.
pub fn downloads_folder() -> PathBuf {
    dirs::download_dir().unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Downloads"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    const FIXTURE: &[u8] = include_bytes!("testdata/github-release.json");

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn compares_stable_versions_as_the_plugin_did() {
        assert!(newer_stable("0.10.0", "0.9.0"));
        assert!(newer_stable("1.0.0", "0.99.99"));
        assert!(newer_stable("0.2.1", "0.2.0"));
        assert!(!newer_stable("0.5.1", "0.5.1"));
        assert!(!newer_stable("0.5.0", "0.5.1"));
        assert!(!newer_stable("0.6.0-beta.1", "0.5.1"));
        assert!(!newer_stable("v0.6.0", "0.5.1"));
        assert!(!newer_stable("0.6", "0.5.1"));
        assert!(!newer_stable("0.6.0.1", "0.5.1"));
        assert!(!newer_stable("0.6.0", "0.5.1-dev"));
        assert!(!newer_stable("", "0.5.1"));
        assert!(!newer_stable("0.+6.0", "0.5.1"));
    }

    #[test]
    fn reads_a_github_release() {
        let release = parse_release(FIXTURE).unwrap();
        assert_eq!(release.version, "0.3.0");
        assert_eq!(release.release_url, "https://github.com/xuzhougeng/WispOps/releases/tag/v0.3.0");
        assert_eq!(release.sums_url, "https://github.com/xuzhougeng/WispOps/releases/download/v0.3.0/SHA256SUMS");
        assert_eq!(release.assets.len(), 4);
        assert_eq!(release.assets[0], Asset { name: "WispOps-v0.3.0-macos-arm64.dmg".into(), url: "https://github.com/xuzhougeng/WispOps/releases/download/v0.3.0/WispOps-v0.3.0-macos-arm64.dmg".into(), size: 19812345 });
    }

    #[test]
    fn refuses_drafts_prereleases_odd_tags_and_foreign_files() {
        let mut json: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        let with = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut json = json.clone();
            change(&mut json);
            parse_release(json.to_string().as_bytes())
        };
        assert!(with(&|j| j["prerelease"] = true.into()).is_err());
        assert!(with(&|j| j["draft"] = true.into()).is_err());
        assert!(with(&|j| j["tag_name"] = "v0.3.0-rc.1".into()).is_err());
        assert!(with(&|j| j["tag_name"] = "nightly".into()).is_err());
        // A bare tag is a version, but the files served under `v0.3.0` are then not this release's.
        let bare = with(&|j| j["tag_name"] = "0.3.0".into()).unwrap();
        assert_eq!(bare.version, "0.3.0");
        assert!(bare.assets.is_empty() && bare.sums_url.is_empty());
        assert!(parse_release(b"not json").is_err());
        json["assets"][0]["browser_download_url"] = "https://example.com/WispOps-v0.3.0-macos-arm64.dmg".into();
        json["assets"][1]["name"] = "../WispOps-v0.3.0-macos-x64.dmg".into();
        let release = parse_release(json.to_string().as_bytes()).unwrap();
        assert_eq!(release.assets.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["WispOps-v0.3.0-windows-x64.zip", "WispOps-v0.3.0-linux-x64.tar.gz"]);
    }

    #[test]
    fn picks_the_package_for_each_platform() {
        let release = parse_release(FIXTURE).unwrap();
        let pick = |os, arch| pick_asset(&release, os, arch).map(|asset| asset.name);
        assert_eq!(pick("macos", "aarch64").as_deref(), Some("WispOps-v0.3.0-macos-arm64.dmg"));
        assert_eq!(pick("macos", "x86_64").as_deref(), Some("WispOps-v0.3.0-macos-x64.dmg"));
        assert_eq!(pick("windows", "x86_64").as_deref(), Some("WispOps-v0.3.0-windows-x64.zip"));
        assert_eq!(pick("linux", "x86_64").as_deref(), Some("WispOps-v0.3.0-linux-x64.tar.gz"));
        assert_eq!(pick("linux", "aarch64"), None);
        assert_eq!(pick("windows", "aarch64"), None);
        assert_eq!(pick("freebsd", "x86_64"), None);
    }

    #[test]
    fn reads_sha256sums_in_both_modes() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let sums = parse_sums(&format!("{a}  WispOps-v0.3.0-linux-x64.tar.gz\n{b} *WispOps-v0.3.0-windows-x64.zip\r\nnot a line\n{}  short\n", "c".repeat(10)));
        assert_eq!(sums.len(), 2);
        assert_eq!(sums["WispOps-v0.3.0-linux-x64.tar.gz"], a);
        assert_eq!(sums["WispOps-v0.3.0-windows-x64.zip"], "b".repeat(64));
    }

    #[test]
    fn moves_between_states() {
        let now = at("2026-11-16T10:00:00Z");
        let fresh = Status::unchecked();
        assert_eq!(fresh.state, State::Unchecked);
        assert!(due(&fresh, true, now));
        assert!(!due(&fresh, false, now));

        let available = outcome(Ok(Some(FIXTURE.to_vec())), &fresh, "0.2.0", "linux", "x86_64", now);
        assert_eq!((available.state, available.latest.as_str(), available.update_known()), (State::Available, "0.3.0", true));
        assert_eq!(available.asset.as_ref().map(|a| a.name.as_str()), Some("WispOps-v0.3.0-linux-x64.tar.gz"));
        assert!(!due(&available, true, at("2026-11-17T09:59:59Z")));
        assert!(due(&available, true, at("2026-11-17T10:00:00Z")));
        // A clock set back does not keep the check away for good.
        assert!(due(&available, true, at("2026-11-15T10:00:00Z")));

        let current = outcome(Ok(Some(FIXTURE.to_vec())), &fresh, "0.3.0", "linux", "x86_64", now);
        assert_eq!((current.state, current.update_known()), (State::Current, false));
        let ahead = outcome(Ok(Some(FIXTURE.to_vec())), &fresh, "0.4.0", "linux", "x86_64", now);
        assert_eq!(ahead.state, State::Current);

        let none = outcome(Ok(None), &available, "0.2.0", "linux", "x86_64", now);
        assert_eq!((none.state, none.latest.as_str()), (State::NoRelease, ""));

        // A failed check is recorded with its reason and keeps what was known.
        let downloaded = Status { downloaded: "/d/WispOps-v0.3.0-linux-x64.tar.gz".into(), ..available.clone() };
        let failed = outcome(Err("网络请求失败：timeout".into()), &downloaded, "0.2.0", "linux", "x86_64", at("2026-11-17T11:00:00Z"));
        assert_eq!((failed.state, failed.detail.as_str(), failed.update_known()), (State::Failed, "网络请求失败：timeout", true));
        assert_eq!(failed.downloaded, downloaded.downloaded);
        assert_eq!(failed.checked_at, Some(at("2026-11-17T11:00:00Z")));
        let unusable = outcome(Ok(Some(b"{}".to_vec())), &fresh, "0.2.0", "linux", "x86_64", now);
        assert_eq!(unusable.state, State::Failed);

        // Checking again for the same version keeps the package that was verified; a newer one forgets it.
        assert_eq!(outcome(Ok(Some(FIXTURE.to_vec())), &downloaded, "0.2.0", "linux", "x86_64", now).downloaded, downloaded.downloaded);
        let newer = String::from_utf8_lossy(FIXTURE).replace("0.3.0", "0.4.0");
        assert_eq!(outcome(Ok(Some(newer.into_bytes())), &downloaded, "0.2.0", "linux", "x86_64", now).downloaded, "");

        // After the person installed the update, the next start reads it as current.
        let restarted = reconcile(downloaded.clone(), "0.3.0");
        assert_eq!((restarted.state, restarted.current.as_str(), restarted.downloaded.as_str()), (State::Current, "0.3.0", ""));
        assert_eq!(reconcile(downloaded.clone(), "0.2.0"), downloaded);
        assert_eq!(reconcile(failed.clone(), "0.3.0").state, State::Failed);
    }

    #[test]
    fn keeps_the_status_in_the_data_folder() {
        let dir = std::env::temp_dir().join(format!("wisp-updates-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(load(&dir), Saved::default());
        let saved = Saved { status: Some(outcome(Ok(Some(FIXTURE.to_vec())), &Status::unchecked(), "0.2.0", "macos", "aarch64", at("2026-11-16T10:00:00Z"))), dismissed: "0.3.0".into() };
        save(&dir, &saved).unwrap();
        assert_eq!(load(&dir), saved);
        let text = std::fs::read_to_string(file(&dir)).unwrap();
        assert!(text.contains("\"state\": \"available\"") && text.contains("\"checkedAt\": \"2026-11-16T10:00:00Z\""), "{text}");
        std::fs::write(file(&dir), "{broken").unwrap();
        assert_eq!(load(&dir), Saved::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stand-in for GitHub on 127.0.0.1: each connection gets the answer for its path.
    fn serve(routes: Vec<(&'static str, u16, Vec<u8>)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                let _ = reader.read_line(&mut first);
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let path = first.split(' ').nth(1).unwrap_or("").to_string();
                let (status, body) = routes.iter().find(|(p, ..)| *p == path).map(|(_, s, b)| (*s, b.clone())).unwrap_or((404, vec![]));
                let mut stream = stream;
                let _ = write!(stream, "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(&body);
            }
        });
        format!("http://{address}")
    }

    #[test]
    fn checks_against_a_stand_in_and_keeps_the_result() {
        let base = serve(vec![("/latest", 200, FIXTURE.to_vec()), ("/none", 404, include_bytes!("testdata/github-no-release.json").to_vec()), ("/broken", 502, vec![])]);
        let dir = std::env::temp_dir().join(format!("wisp-updates-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let status = check(&dir, &format!("{base}/latest"), "direct");
        assert_eq!(status.latest, "0.3.0");
        assert_eq!(status.state, if newer_stable("0.3.0", RUNNING) { State::Available } else { State::Current });
        assert_eq!(load(&dir).status, Some(status.clone()));
        let failed = check(&dir, &format!("{base}/broken"), "direct");
        assert_eq!((failed.state, failed.detail.as_str(), failed.latest.as_str()), (State::Failed, "HTTP 502", "0.3.0"));
        assert_eq!(check(&dir, &format!("{base}/none"), "direct").state, State::NoRelease);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn downloads_verifies_and_deletes_what_does_not_match() {
        let package = b"pretend this is a disk image".to_vec();
        let digest = hex(&Sha256::digest(&package));
        let name = "WispOps-v0.3.0-linux-x64.tar.gz";
        let sums = format!("{digest}  {name}\n{}  WispOps-v0.3.0-windows-x64.zip\n", "0".repeat(64));
        let wrong = format!("{}  {name}\n", "f".repeat(64));
        let base = serve(vec![("/sums", 200, sums.into_bytes()), ("/wrong-sums", 200, wrong.into_bytes()), ("/pkg", 200, package.clone()), ("/unlisted", 200, b"x".to_vec())]);
        let dir = std::env::temp_dir().join(format!("wisp-updates-dl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let status = |sums: &str, url: &str, name: &str| Status { asset: Some(Asset { name: name.into(), url: format!("{base}{url}"), size: 0 }), sums_url: if sums.is_empty() { String::new() } else { format!("{base}{sums}") }, ..Status::unchecked() };

        let path = download(&status("/sums", "/pkg", name), &dir, "direct").unwrap();
        assert_eq!(path, dir.join(name));
        assert_eq!(std::fs::read(&path).unwrap(), package);
        assert!(!dir.join(format!("{name}.part")).exists());
        // A verified package already there is kept, not fetched again.
        assert_eq!(download(&status("/sums", "/gone", name), &dir, "direct").unwrap(), path);

        std::fs::remove_file(&path).unwrap();
        let err = download(&status("/wrong-sums", "/pkg", name), &dir, "direct").unwrap_err();
        assert!(err.contains("校验和") && err.contains(name), "{err}");
        assert!(!dir.join(name).exists() && !dir.join(format!("{name}.part")).exists());

        assert!(download(&status("", "/pkg", name), &dir, "direct").unwrap_err().contains("SHA256SUMS"));
        assert!(download(&status("/missing", "/pkg", name), &dir, "direct").unwrap_err().contains("SHA256SUMS"));
        assert!(download(&status("/sums", "/unlisted", "WispOps-v0.3.0-macos-x64.dmg"), &dir, "direct").unwrap_err().contains("SHA256SUMS"));
        assert!(download(&status("/sums", "/missing", name), &dir, "direct").is_err());
        assert!(!dir.join(format!("{name}.part")).exists());
        assert!(download(&Status::unchecked(), &dir, "direct").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
