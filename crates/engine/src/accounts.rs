//! Changes to the accounts of a host that the window makes as root: new accounts (one or many,
//! on one or many hosts) and a new password for one. Only the scripts and what is checked before
//! them live here; `Fleet` runs them.
//!
//! A password travels inside the script, which goes to `sh -s` on stdin, and reaches `chpasswd`
//! on its stdin through the `printf` builtin: it is never an argument of a process, never in the
//! audit (`describe_*` say what was done without it), and the caller blanks it out of whatever
//! comes back.

use crate::fsutil::random_bytes;
use crate::ssh::shell_quote;

/// The most accounts one request creates on each host.
pub const MAX_NEW: usize = 200;

/// What is wrong with an account or group name, if anything: lower-case letters, digits, `_`
/// and `-`, starting with a letter or `_`, at most 32 long (what `useradd` takes everywhere).
pub fn name_problem(name: &str) -> Option<String> {
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    if name.is_empty() { return Some("名称不能为空。".into()) }
    if name.len() > 32 { return Some(format!("「{name}」太长：最多 32 个字符。")) }
    if !first_ok || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') { return Some(format!("「{name}」不能用作名称：只用小写字母、数字、_ 和 -，并以字母或 _ 开头。")) }
    None
}

/// Names written one per line, or apart by spaces or commas: each checked, repeats dropped.
pub fn parse_names(text: &str) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = vec![];
    for name in text.split(|c: char| c.is_whitespace() || c == ',' || c == '，' || c == '、').filter(|name| !name.is_empty()) {
        if let Some(problem) = name_problem(name) { return Err(problem) }
        if !names.iter().any(|known| known == name) { names.push(name.to_string()) }
    }
    if names.len() > MAX_NEW { return Err(format!("一次最多创建 {MAX_NEW} 个账号。")) }
    Ok(names)
}

/// What is wrong with a login shell: an absolute path of plain characters.
pub fn shell_problem(shell: &str) -> Option<String> {
    let plain = shell.starts_with('/') && shell.len() <= 128 && shell.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'));
    (!plain).then(|| format!("「{shell}」不是可用的 shell 路径，例如 /bin/bash。"))
}

/// What is wrong with a password someone typed: something, at most 128 characters, on one line.
pub fn password_problem(password: &str) -> Option<String> {
    if password.is_empty() { return Some("密码不能为空。".into()) }
    if password.chars().count() > 128 { return Some("密码最多 128 个字符。".into()) }
    if password.chars().any(char::is_control) { return Some("密码里不能有换行或控制字符。".into()) }
    None
}

/// Letters and digits that are not mistaken for one another when read off a screen.
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
/// The length of a password made here: 16 of 57 signs, about 93 bits.
pub const GENERATED_LEN: usize = 16;

/// A new random password from the system's random source, every sign equally likely.
pub fn generate_password() -> Result<String, String> {
    let mut out = String::with_capacity(GENERATED_LEN);
    // The highest multiple of the alphabet below 256: bytes above it are passed over, so no sign is likelier.
    let limit = 256 - 256 % ALPHABET.len();
    while out.len() < GENERATED_LEN {
        for byte in random_bytes::<32>()? {
            if usize::from(byte) < limit && out.len() < GENERATED_LEN { out.push(char::from(ALPHABET[usize::from(byte) % ALPHABET.len()])) }
        }
    }
    Ok(out)
}

/// New accounts, the same on every host.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NewAccounts {
    pub names: Vec<String>,
    /// Groups besides each one's own; they must exist on the host.
    pub groups: Vec<String>,
    pub shell: String,
    /// The password must be changed at the first login.
    pub expire: bool,
}

/// How the new accounts get a password.
#[derive(Clone, Debug, PartialEq)]
pub enum NewPassword {
    /// A different random one for each account on each host.
    Random,
    /// The one written, for all of them.
    Same(String),
    /// None: the account is locked until a password is set (a key can still be put in place).
    Locked,
}

impl NewPassword {
    fn words(&self) -> &'static str {
        match self {
            NewPassword::Random => "a random password each",
            NewPassword::Same(_) => "one password written in the window",
            NewPassword::Locked => "no password (locked)",
        }
    }
}

const PRELUDE: &str = "export LC_ALL=C\noneline() { tr '\\t\\n\\r' '   ' | cut -c1-300; }\n";

fn expire_line(name: &str) -> String {
    format!("chage -d 0 {name} >/dev/null 2>&1 || passwd -e {name} >/dev/null 2>&1\n", name = shell_quote(name))
}

/// The script that creates `spec.names`, the password of each beside it (`None`: locked). It
/// prints a line for each account: `created`, `exists`, `failed\t<why>` or `nopass\t<why>` (made,
/// but the password did not take), the name after the word.
pub fn create_script(spec: &NewAccounts, passwords: &[Option<String>]) -> String {
    let mut script = String::from(PRELUDE);
    script.push_str("command -v useradd >/dev/null 2>&1 || { echo 'failed\t*\tuseradd not found on this host'; exit 0; }\n");
    script.push_str(&format!("SH={}\nGR={}\nEXPIRE={}\n", shell_quote(&spec.shell), shell_quote(&spec.groups.join(",")), u8::from(spec.expire)));
    script.push_str(
        "add() {\n\
  if id -u \"$1\" >/dev/null 2>&1; then printf 'exists\\t%s\\n' \"$1\"; return 0; fi\n\
  if [ -n \"$GR\" ]; then err=$(useradd -m -s \"$SH\" -G \"$GR\" \"$1\" 2>&1); else err=$(useradd -m -s \"$SH\" \"$1\" 2>&1); fi\n\
  if [ $? -ne 0 ]; then printf 'failed\\t%s\\t%s\\n' \"$1\" \"$(printf '%s' \"$err\" | oneline)\"; return 0; fi\n\
  if [ -n \"$2\" ]; then\n\
    if ! err=$(printf '%s:%s\\n' \"$1\" \"$2\" | chpasswd 2>&1); then printf 'nopass\\t%s\\t%s\\n' \"$1\" \"$(printf '%s' \"$err\" | oneline)\"; return 0; fi\n\
    if [ \"$EXPIRE\" = 1 ]; then chage -d 0 \"$1\" >/dev/null 2>&1 || passwd -e \"$1\" >/dev/null 2>&1; fi\n\
  fi\n\
  printf 'created\\t%s\\n' \"$1\"\n\
}\n",
    );
    for (n, name) in spec.names.iter().enumerate() {
        let password = passwords.get(n).cloned().flatten().unwrap_or_default();
        script.push_str(&format!("add {} {}\n", shell_quote(name), shell_quote(&password)));
    }
    script
}

/// The script that gives `name` a new password (which also lifts a lock): it prints `reset`,
/// `missing` or `failed\t<why>`, the name after the word.
pub fn reset_script(name: &str, password: &str, expire: bool) -> String {
    let quoted = shell_quote(name);
    let mut script = String::from(PRELUDE);
    script.push_str(&format!("id -u {quoted} >/dev/null 2>&1 || {{ printf 'missing\\t%s\\n' {quoted}; exit 0; }}\n"));
    script.push_str(&format!("if ! err=$(printf '%s:%s\\n' {quoted} {} | chpasswd 2>&1); then printf 'failed\\t%s\\t%s\\n' {quoted} \"$(printf '%s' \"$err\" | oneline)\"; exit 0; fi\n", shell_quote(password)));
    if expire { script.push_str(&expire_line(name)) }
    script.push_str(&format!("printf 'reset\\t%s\\n' {quoted}\n"));
    script
}

/// What the audit keeps of a creation: what was asked, without any password.
pub fn describe_create(spec: &NewAccounts, password: &NewPassword) -> String {
    let groups = if spec.groups.is_empty() { String::new() } else { format!(", groups {}", spec.groups.join(",")) };
    let expire = if spec.expire && *password != NewPassword::Locked { ", password to be changed at first login" } else { "" };
    format!("(built-in account creation as root: {}; shell {}{groups}; {}{expire})", spec.names.join(", "), spec.shell, password.words())
}

/// What the audit keeps of a new password: whose, and how it was made, not the password.
pub fn describe_reset(name: &str, generated: bool, expire: bool) -> String {
    format!("(built-in password reset as root: {name}; {}{})", if generated { "a random password" } else { "a password written in the window" }, if expire { ", to be changed at next login" } else { "" })
}

/// What became of one account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Created,
    Exists,
    /// Created, but its password did not take: the account is locked.
    NoPassword(String),
    Reset,
    Missing,
    Failed(String),
}

/// The lines a create or reset script printed, by account (`*` for the whole host).
pub fn parse_outcomes(stdout: &str) -> Vec<(String, Outcome)> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let (word, name, why) = (parts.next()?, parts.next()?.to_string(), parts.next().unwrap_or("").trim().to_string());
            let outcome = match word {
                "created" => Outcome::Created,
                "exists" => Outcome::Exists,
                "nopass" => Outcome::NoPassword(why),
                "reset" => Outcome::Reset,
                "missing" => Outcome::Missing,
                "failed" => Outcome::Failed(why),
                _ => return None,
            };
            Some((name, outcome))
        })
        .collect()
}

/// `text` with every one of `secrets` blanked out.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    secrets.iter().filter(|secret| !secret.is_empty()).fold(text.to_string(), |text, secret| text.replace(secret, "******"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked_and_split_every_way() {
        assert_eq!(parse_names("alice bob\ncarol,dave，erin、alice").unwrap(), ["alice", "bob", "carol", "dave", "erin"]);
        assert!(parse_names("Alice").is_err());
        assert!(parse_names("1st").is_err());
        assert!(parse_names("a;rm").is_err());
        assert!(parse_names(&"a".repeat(33)).is_err());
        assert!(parse_names(&(0..=MAX_NEW).map(|n| format!("u{n}")).collect::<Vec<_>>().join(" ")).is_err());
        assert!(shell_problem("/bin/bash").is_none() && shell_problem("bash").is_some() && shell_problem("/bin/sh -c x").is_some());
        assert!(password_problem("a b'c\"$x").is_none() && password_problem("two\nlines").is_some() && password_problem("").is_some());
    }

    #[test]
    fn generated_passwords_are_long_and_differ() {
        let (a, b) = (generate_password().unwrap(), generate_password().unwrap());
        assert_eq!(a.len(), GENERATED_LEN);
        assert!(a.bytes().all(|byte| ALPHABET.contains(&byte)));
        assert_ne!(a, b);
    }

    #[test]
    fn descriptions_never_carry_the_password() {
        let spec = NewAccounts { names: vec!["alice".into()], groups: vec!["docker".into()], shell: "/bin/bash".into(), expire: true };
        let said = describe_create(&spec, &NewPassword::Same("Hunter2!".into()));
        assert!(!said.contains("Hunter2") && said.contains("alice") && said.contains("docker"));
        assert!(!describe_reset("alice", false, true).contains("Hunter2"));
        assert_eq!(redact("chpasswd: Hunter2! bad", &["Hunter2!", ""]), "chpasswd: ****** bad");
    }

    #[test]
    fn outcomes_are_read_line_by_line() {
        let got = parse_outcomes("created\talice\nexists\tbob\nfailed\tcarol\tuseradd: group 'gpu' does not exist\nnoise\nnopass\tdave\tbad\n");
        assert_eq!(got, [("alice".into(), Outcome::Created), ("bob".into(), Outcome::Exists), ("carol".into(), Outcome::Failed("useradd: group 'gpu' does not exist".into())), ("dave".into(), Outcome::NoPassword("bad".into()))]);
    }

    /// The scripts run under `sh` against stand-ins for the account tools, which note what they
    /// were given: the password reaches `chpasswd` on stdin and no command line.
    #[cfg(unix)]
    #[test]
    fn the_scripts_run_and_hand_the_password_to_chpasswd_on_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("log");
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let tool = |name: &str, body: &str| {
            let path = bin.join(name);
            std::fs::write(&path, format!("#!/bin/sh\necho \"{name} $*\" >> '{}'\n{body}\n", log.display())).unwrap();
            crate::fsutil::set_mode(&path, 0o755).unwrap();
        };
        tool("useradd", "case \"$*\" in *nogroup*) echo \"useradd: group 'nogroup' does not exist\" >&2; exit 6;; esac");
        tool("chpasswd", &format!("cat >> '{}'", dir.path().join("stdin").display()));
        tool("chage", "");
        // `id` knows only root.
        tool("id", "[ \"$2\" = root ]");
        let run = |script: &str| {
            let out = std::process::Command::new("sh").arg("-s").env("PATH", format!("{}:/usr/bin:/bin", bin.display())).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(script.as_bytes())?;
                child.wait_with_output()
            });
            String::from_utf8(out.unwrap().stdout).unwrap()
        };
        let spec = NewAccounts { names: vec!["alice".into(), "root".into(), "o'brien".into()], groups: vec![], shell: "/bin/bash".into(), expire: true };
        let secret = "p@ss w'rd $(x)";
        let out = run(&create_script(&spec, &[Some(secret.into()), Some("x".into()), None]));
        assert_eq!(parse_outcomes(&out), [("alice".into(), Outcome::Created), ("root".into(), Outcome::Exists), ("o'brien".into(), Outcome::Created)]);
        let fed = std::fs::read_to_string(dir.path().join("stdin")).unwrap();
        assert_eq!(fed, format!("alice:{secret}\n"));
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(!calls.contains("w'rd"), "{calls}");
        assert!(calls.contains("useradd -m -s /bin/bash alice") && calls.contains("chage -d 0 alice"), "{calls}");

        let failed = run(&create_script(&NewAccounts { names: vec!["eve".into()], groups: vec!["nogroup".into()], shell: "/bin/sh".into(), expire: false }, &[None]));
        assert_eq!(parse_outcomes(&failed), [("eve".into(), Outcome::Failed("useradd: group 'nogroup' does not exist".into()))]);

        assert_eq!(parse_outcomes(&run(&reset_script("root", "n3w", false))), [("root".into(), Outcome::Reset)]);
        assert_eq!(parse_outcomes(&run(&reset_script("ghost", "n3w", false))), [("ghost".into(), Outcome::Missing)]);
        assert!(std::fs::read_to_string(dir.path().join("stdin")).unwrap().ends_with("root:n3w\n"));
    }
}
