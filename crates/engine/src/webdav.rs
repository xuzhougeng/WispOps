//! The few WebDAV verbs device sync needs (PROPFIND, MKCOL, PUT, GET) on one collection, as the
//! plugin uses them. Only snapshot files (`wispops-<time>-<uuid>.json`) are ever named, so no
//! request can reach another path of the account. HTTP itself is a [`Transport`]: the app passes
//! one over its HTTP client, tests a closure.

use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use regex::Regex;

use crate::sync_crypto::MAX_SYNC_BYTES;

/// A snapshot file's name: `wispops-20261116T083000123Z-<uuid>.json`.
pub static SNAPSHOT_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^wispops-\d{8}T\d{9}Z-[a-f0-9-]{36}\.json$").expect("snapshot name pattern"));

static HREF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<(?:[\w-]+:)?href\b[^>]*>([^<]+)</(?:[\w-]+:)?href>").expect("href pattern"));

/// One request. The transport sends it as is, follows no redirect, gives up after 30 seconds and
/// reads at most [`MAX_SYNC_BYTES`] of the answer (more is an error).
pub struct DavRequest {
    pub method: &'static str,
    pub url: String,
    /// Lower-case names; `authorization` among them, so a request is never printed.
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<Vec<u8>>,
}

impl std::fmt::Debug for DavRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DavRequest").field("method", &self.method).field("url", &self.url).finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DavResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Sends a request; `Err` when there was no answer at all (the text is for logs only, never shown with credentials).
pub trait Transport: Send + Sync {
    fn send(&self, request: &DavRequest) -> Result<DavResponse, String>;
}

impl<F: Fn(&DavRequest) -> Result<DavResponse, String> + Send + Sync> Transport for F {
    fn send(&self, request: &DavRequest) -> Result<DavResponse, String> {
        self(request)
    }
}

/// Where the snapshots live and who may read them. `password` is the account's application password.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct WebDavSettings {
    pub url: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for WebDavSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavSettings").field("url", &self.url).field("username", &self.username).field("password", &"[REDACTED]").finish()
    }
}

/// A collection URL, split: `scheme://authority` and a path that ends in `/` (percent-encoded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    origin: String,
    path: String,
}

fn loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

/// Percent-encode what may not stand in a URL path as is; `%` is kept, as already encoded.
fn encode_path(path: &str) -> String {
    let mut out = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/%".contains(&byte) { out.push(byte as char) } else { out.push_str(&format!("%{byte:02X}")) }
    }
    out
}

fn decode_percent(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl Collection {
    /// Parse a collection address: HTTPS (plain HTTP only to this computer), no credentials, query or fragment.
    pub fn parse(url: &str) -> Result<Collection, String> {
        let bad = || "WebDAV 地址需要是 HTTPS 的文件夹地址，不能含账号密码或查询参数。".to_string();
        let url = url.trim();
        let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
        let scheme = scheme.to_ascii_lowercase();
        if url.contains(['?', '#']) || url.chars().any(char::is_whitespace) { return Err(bad()) }
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') { return Err(bad()) }
        let authority = authority.to_ascii_lowercase();
        let host = if authority.starts_with('[') { authority.split_inclusive(']').next().unwrap_or("") } else { authority.split(':').next().unwrap_or("") };
        if host.is_empty() { return Err(bad()) }
        let authority = match (scheme.as_str(), authority.strip_suffix(":443"), authority.strip_suffix(":80")) {
            ("https", Some(bare), _) => bare.to_string(),
            ("http", _, Some(bare)) => bare.to_string(),
            _ => authority.clone(),
        };
        if scheme != "https" && !(scheme == "http" && loopback(host)) { return Err(bad()) }
        let mut path = encode_path(path);
        if !path.ends_with('/') { path.push('/') }
        Ok(Collection { origin: format!("{scheme}://{authority}"), path })
    }

    /// The collection's address, always ending in `/`.
    pub fn href(&self) -> String {
        format!("{}{}", self.origin, self.path)
    }

    fn file(&self, name: &str) -> String {
        format!("{}{}{name}", self.origin, self.path)
    }

    /// The snapshot an `href` of a listing names, if it is a snapshot directly in this collection.
    fn snapshot_in(&self, href: &str) -> Option<String> {
        let href = href.replace("&amp;", "&");
        let href = href.trim();
        let path = if let Some(at) = href.find("://") {
            let rest = &href[at + 3..];
            let slash = rest.find('/')?;
            let origin = Collection::parse(&format!("{}/", &href[..at + 3 + slash])).ok()?;
            if origin.origin != self.origin { return None }
            rest[slash..].to_string()
        } else if href.starts_with('/') {
            href.to_string()
        } else {
            format!("{}{href}", self.path)
        };
        let path = path.split(['?', '#']).next().unwrap_or("");
        let cut = path.rfind('/')? + 1;
        if decode_percent(&path[..cut])? != decode_percent(&self.path)? { return None }
        let name = decode_percent(&path[cut..])?;
        SNAPSHOT_NAME.is_match(&name).then_some(name)
    }
}

/// A WebDAV collection with Basic authentication.
pub struct WebDav<'a> {
    pub collection: Collection,
    authorization: String,
    transport: &'a dyn Transport,
}

const CONNECTION_FAILED: &str = "无法连接 WebDAV：请检查地址、应用密码和网络。";

impl<'a> WebDav<'a> {
    pub fn new(settings: &WebDavSettings, transport: &'a dyn Transport) -> Result<WebDav<'a>, String> {
        let collection = Collection::parse(&settings.url)?;
        if settings.username.is_empty() || settings.password.is_empty() || settings.username.contains([':', '\r', '\n']) || settings.password.contains(['\r', '\n']) {
            return Err("需要填写 WebDAV 用户名和应用密码。".to_string());
        }
        let authorization = format!("Basic {}", STANDARD.encode(format!("{}:{}", settings.username, settings.password)));
        Ok(WebDav { collection, authorization, transport })
    }

    fn request(&self, method: &'static str, name: &str, body: Option<Vec<u8>>, headers: &[(&'static str, &str)]) -> Result<DavResponse, String> {
        if !name.is_empty() && !SNAPSHOT_NAME.is_match(name) { return Err("快照名称无效。".to_string()) }
        let url = if name.is_empty() { self.collection.href() } else { self.collection.file(name) };
        let mut all = vec![("authorization", self.authorization.clone())];
        all.extend(headers.iter().map(|(key, value)| (*key, value.to_string())));
        let response = self.transport.send(&DavRequest { method, url, headers: all, body }).map_err(|_| CONNECTION_FAILED.to_string())?;
        if response.body.len() > MAX_SYNC_BYTES { return Err("WebDAV 返回的内容过大。".to_string()) }
        Ok(response)
    }

    /// The snapshots in the collection, newest first; a missing collection has none.
    pub fn list(&self) -> Result<Vec<String>, String> {
        let body = br#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>"#.to_vec();
        let response = self.request("PROPFIND", "", Some(body), &[("depth", "1"), ("content-type", "application/xml")])?;
        if response.status == 404 { return Ok(vec![]) }
        if response.status != 207 { return Err(format!("WebDAV 列出文件失败：HTTP {}", response.status)) }
        let xml = String::from_utf8_lossy(&response.body);
        let mut names: Vec<String> = HREF.captures_iter(&xml).filter_map(|captures| self.collection.snapshot_in(&captures[1])).collect();
        names.sort();
        names.dedup();
        names.reverse();
        Ok(names)
    }

    /// Store a new snapshot. The collection is created if missing; an existing file is never replaced.
    pub fn upload(&self, name: &str, body: &str) -> Result<(), String> {
        if body.len() > MAX_SYNC_BYTES { return Err("同步快照过大。".to_string()) }
        let collection = self.request("MKCOL", "", None, &[])?;
        if ![201, 405].contains(&collection.status) { return Err(format!("无法创建 WebDAV 文件夹，请先建好它的上级文件夹：HTTP {}", collection.status)) }
        let response = self.request("PUT", name, Some(body.as_bytes().to_vec()), &[("content-type", "application/json"), ("if-none-match", "*")])?;
        if ![200, 201, 204].contains(&response.status) { return Err(format!("WebDAV 上传失败：HTTP {}", response.status)) }
        Ok(())
    }

    pub fn download(&self, name: &str) -> Result<String, String> {
        let response = self.request("GET", name, None, &[])?;
        if !(200..300).contains(&response.status) { return Err(format!("WebDAV 下载失败：HTTP {}", response.status)) }
        String::from_utf8(response.body).map_err(|_| "WebDAV 返回的快照不是文本。".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const NAME: &str = "wispops-20261116T083000123Z-0f8fad5b-d9cb-469f-a165-70867728950e.json";

    fn settings(url: &str) -> WebDavSettings {
        WebDavSettings { url: url.into(), username: "test@example.org".into(), password: "test-app-password".into() }
    }

    #[test]
    fn rejects_insecure_endpoints_credentials_in_urls_and_traversal() {
        assert!(Collection::parse("http://example.org/dav/").unwrap_err().contains("HTTPS"));
        assert!(Collection::parse("https://user:pw@example.org/dav/").is_err());
        assert!(Collection::parse("https://example.org/dav/?x=1").is_err());
        assert!(Collection::parse("ftp://example.org/").is_err());
        assert_eq!(Collection::parse("https://DAV.example.org:443/dav/WispOps").unwrap().href(), "https://dav.example.org/dav/WispOps/");
        assert_eq!(Collection::parse("http://127.0.0.1:8080/s").unwrap().href(), "http://127.0.0.1:8080/s/");
        assert_eq!(Collection::parse("https://example.org/同步").unwrap().href(), "https://example.org/%E5%90%8C%E6%AD%A5/");
        let send = |_: &DavRequest| -> Result<DavResponse, String> { panic!("no request may be sent") };
        let dav = WebDav::new(&settings("https://example.org/dav/WispOps/"), &send).unwrap();
        assert!(dav.download("../vault.key").unwrap_err().contains("快照名称无效"));
        assert!(WebDav::new(&WebDavSettings { password: String::new(), ..settings("https://example.org/") }, &send).is_err());
        assert!(WebDav::new(&WebDavSettings { username: "a:b".into(), ..settings("https://example.org/") }, &send).is_err());
    }

    #[test]
    fn lists_only_snapshots_directly_in_the_collection() {
        let other = NAME.replace("0f8f", "1f8f");
        let xml = format!(
            "<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/dav/WispOps/</d:href></d:response><d:response><d:href>/dav/WispOps/{NAME}</d:href></d:response><D:response><D:href>https://dav.example.org/dav/WispOps/{other}</D:href></D:response><d:response><d:href>/dav/WispOps/sub/{NAME}</d:href></d:response><d:response><d:href>https://evil.example/dav/WispOps/{NAME}</d:href></d:response><d:response><d:href>/dav/WispOps/notes.txt</d:href></d:response><d:response><d:href>/dav/WispOps/{NAME}</d:href></d:response></d:multistatus>"
        );
        let seen = Mutex::new(Vec::new());
        let send = |request: &DavRequest| -> Result<DavResponse, String> {
            seen.lock().unwrap().push((request.method, request.url.clone(), request.headers.clone()));
            Ok(DavResponse { status: 207, body: xml.clone().into_bytes() })
        };
        let dav = WebDav::new(&settings("https://dav.example.org/dav/WispOps"), &send).unwrap();
        assert_eq!(dav.list().unwrap(), vec![other.clone(), NAME.to_string()]);
        let seen = seen.lock().unwrap();
        let (method, url, headers) = &seen[0];
        assert_eq!((*method, url.as_str()), ("PROPFIND", "https://dav.example.org/dav/WispOps/"));
        assert!(headers.contains(&("depth", "1".into())));
        assert!(headers.contains(&("authorization", format!("Basic {}", STANDARD.encode("test@example.org:test-app-password")))));
    }

    #[test]
    fn uploads_without_overwriting_and_reads_status_codes() {
        let seen = Mutex::new(Vec::new());
        let send = |request: &DavRequest| -> Result<DavResponse, String> {
            seen.lock().unwrap().push((request.method, request.headers.iter().filter(|(key, _)| *key != "authorization").cloned().collect::<Vec<_>>()));
            Ok(DavResponse { status: match request.method { "MKCOL" => 405, "PUT" => 201, "PROPFIND" => 404, _ => 500 }, body: vec![] })
        };
        let dav = WebDav::new(&settings("https://dav.example.org/dav/WispOps/"), &send).unwrap();
        dav.upload(NAME, "{}").unwrap();
        assert_eq!(dav.list().unwrap(), Vec::<String>::new());
        assert!(dav.download(NAME).unwrap_err().contains("HTTP 500"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen[1].0, "PUT");
        assert!(seen[1].1.contains(&("if-none-match", "*".into())));
        let refused = |_: &DavRequest| -> Result<DavResponse, String> { Ok(DavResponse { status: 409, body: vec![] }) };
        assert!(WebDav::new(&settings("https://dav.example.org/x/"), &refused).unwrap().upload(NAME, "{}").unwrap_err().contains("HTTP 409"));
        let down = |_: &DavRequest| -> Result<DavResponse, String> { Err("connection refused".into()) };
        assert_eq!(WebDav::new(&settings("https://dav.example.org/x/"), &down).unwrap().list().unwrap_err(), CONNECTION_FAILED);
    }
}
