//! Private-file helpers: owner-only directories and files, random names, home expansion.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Create a directory and its parents, owner-only on Unix.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Options for an owner-only file (`0600` on Unix).
pub fn private_options() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Set a file's permission bits; a no-op where there are none.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Write a new owner-only file; fails when it already exists.
pub fn write_new_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file: File = private_options().write(true).create_new(true).open(path)?;
    file.write_all(data)
}

/// Create or truncate an owner-only file with this content.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file: File = private_options().write(true).create(true).truncate(true).open(path)?;
    file.write_all(data)
}

/// Append to an owner-only file, creating it when missing.
pub fn append_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file: File = private_options().append(true).create(true).open(path)?;
    file.write_all(data)
}

/// Random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| "system random source is unavailable".to_string())?;
    Ok(bytes)
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A random lowercase-hex token of `2 * N` characters.
pub fn random_hex<const N: usize>() -> Result<String, String> {
    Ok(hex(&random_bytes::<N>()?))
}

/// The user's home directory; the current directory when it cannot be determined.
pub fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// Expand a leading `~/` (or a bare `~`) against the home directory.
pub fn expand_home(path: &str) -> String {
    if path == "~" {
        home_dir().to_string_lossy().into_owned()
    } else if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{}", home_dir().to_string_lossy(), rest)
    } else {
        path.to_string()
    }
}

/// `path` with `suffix` appended to its file name (`vault.json` → `vault.json.lock`).
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}
