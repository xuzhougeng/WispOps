//! The runner against a stand-in `ssh` (`fixtures/fake-ssh.sh`), and its helpers (`ssh.spec.ts`).
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use wisp_ops_engine::config::{AuthMethod, HostSpec, Policy, SshSpec};
use wisp_ops_engine::inventory::{Host, Inventory};
use wisp_ops_engine::ssh::{AuthGuard, RunRequest, RunStatus, SshRunner, classify_exit, decode_stderr, legacy_decoder, password_sudo_command, prelude, shell_quote};

const PASSWORD: &str = "pa$$ w0rd";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn spec() -> SshSpec {
    SshSpec {
        binary: fixtures().join("fake-ssh.sh").to_string_lossy().into_owned(),
        connect_timeout_sec: 5,
        control_persist_sec: 0,
        extra_args: Vec::new(),
        concurrency: 2,
        load_profile: false,
        extra_path: Vec::new(),
        auth_failure_block_minutes: 1,
    }
}

fn host(name: &str) -> Host {
    Inventory::from_specs(vec![HostSpec::named(name)], Default::default(), Policy::default()).unwrap().host(name).unwrap().clone()
}

/// A runner whose fake sudo keeps its state in `dir`; every test gets its own directory.
fn runner_with(dir: &Path, extra: &[(&str, &str)]) -> SshRunner {
    let mut env: Vec<(String, String)> = vec![
        ("FAKE_BIN".to_string(), fixtures().join("bin").to_string_lossy().into_owned()),
        ("FAKE_SUDO_STATE".to_string(), dir.join("state").to_string_lossy().into_owned()),
        ("FAKE_SUDO_PASSWORD".to_string(), PASSWORD.to_string()),
    ];
    env.extend(extra.iter().map(|(key, value)| (key.to_string(), value.to_string())));
    SshRunner::new(spec(), 1024 * 1024, dir).with_env(env)
}

fn request(script: &str) -> RunRequest {
    RunRequest::new(host("box"), script).timeout_ms(5000)
}

#[test]
fn pipes_the_script_on_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let r = runner_with(dir.path(), &[]).run(request("echo \"a b\"; echo err >&2; exit 3"));
    assert_eq!((r.status, r.exit_code, r.stdout.as_str(), r.stderr.as_str()), (RunStatus::Failed, Some(3), "a b\n", "err\n"));
    assert_eq!(r.host, "box");
    assert!(!r.truncated);
}

#[test]
fn sends_windows_line_ends_as_unix_ones() {
    let dir = tempfile::tempdir().unwrap();
    let r = runner_with(dir.path(), &[]).run(request("export LC_ALL=C\r\nif true; then\r\n  echo \"[$LC_ALL]\"\r\nfi\r\n"));
    assert_eq!((r.status, r.stdout.as_str(), r.stderr.as_str()), (RunStatus::Ok, "[C]\n", ""), "{r:?}");
}

#[test]
fn runs_sudo_with_a_stored_password_that_never_reaches_the_script_or_output() {
    let dir = tempfile::tempdir().unwrap();
    let r = runner_with(dir.path(), &[]).run(request("echo root=$FAKE_ROOT; cat; echo 'pa$$ w0rd'").sudo(true).sudo_password(Some(PASSWORD.to_string())));
    assert_eq!(r.status, RunStatus::Ok, "{r:?}");
    assert!(r.stdout.contains("root=1"));
    assert!(!r.stdout.contains("w0rd"));
    assert!(r.stdout.contains("[REDACTED]"));
}

#[test]
fn reports_a_rejected_sudo_password() {
    let dir = tempfile::tempdir().unwrap();
    let r = runner_with(dir.path(), &[]).run(request("echo should-not-run").sudo(true).sudo_password(Some("wrong".to_string())));
    assert_eq!(r.status, RunStatus::SudoRequired);
    assert_eq!(r.exit_code, Some(97));
    assert!(!r.stdout.contains("should-not-run"));
}

#[test]
fn keeps_sudo_validation_and_execution_in_the_same_parent_scoped_timestamp_session() {
    let dir = tempfile::tempdir().unwrap();
    let r = runner_with(dir.path(), &[("FAKE_SUDO_BIND_PARENT", "1")]).run(request("echo root=$FAKE_ROOT").sudo(true).sudo_password(Some(PASSWORD.to_string())));
    assert_eq!((r.status, r.stdout.as_str()), (RunStatus::Ok, "root=1\n"), "{r:?}");
}

#[test]
fn never_treats_a_supplied_password_as_script_input_when_sudo_does_not_consume_it() {
    let dir = tempfile::tempdir().unwrap();
    let r = runner_with(dir.path(), &[("FAKE_SUDO_NOPASSWD", "1")]).run(request("echo safe; cat").sudo(true).sudo_password(Some("echo credential-must-not-run".to_string())));
    assert_eq!((r.status, r.stdout.as_str()), (RunStatus::Ok, "safe\n"), "{r:?}");
}

#[test]
fn reports_sudo_that_needs_a_password_when_none_is_stored() {
    let dir = tempfile::tempdir().unwrap();
    let r = runner_with(dir.path(), &[]).run(request("id").sudo(true));
    assert_eq!(r.status, RunStatus::SudoRequired);
}

#[test]
fn times_the_login_to_the_first_output_before_the_profile_prelude() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner_with(dir.path(), &[]);
    let timed = runner.run(request("sleep 0.4; echo done").time_login(true));
    assert_eq!((timed.status, timed.stdout.as_str()), (RunStatus::Ok, "@@login\ndone\n"));
    assert!(timed.first_output_ms.unwrap() + 250 < timed.duration_ms, "{timed:?}");
    assert_eq!(runner.run(request("echo done")).stdout, "done\n");
    assert_eq!(runner.run(request("true")).first_output_ms, None);
}

#[test]
fn times_out_and_can_be_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner_with(dir.path(), &[]);
    let started = Instant::now();
    let r = runner.run(request("sleep 5").timeout_ms(300));
    assert_eq!(r.status, RunStatus::Timeout);
    assert_eq!(r.exit_code, None);
    assert!(started.elapsed() < Duration::from_secs(4), "the local ssh was not stopped");

    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let trigger = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        flag.store(true, Ordering::SeqCst);
    });
    let started = Instant::now();
    let r = runner.run(request("echo begun; sleep 5").cancel(cancel.clone()));
    trigger.join().unwrap();
    assert_eq!(r.status, RunStatus::Cancelled);
    assert_eq!(r.stdout, "begun\n");
    assert!(started.elapsed() < Duration::from_secs(4));
    // Already cancelled: nothing is started.
    let r = runner.run(request("echo never").cancel(cancel));
    assert_eq!((r.status, r.duration_ms, r.stdout.as_str()), (RunStatus::Cancelled, 0, ""));
}

#[test]
fn caps_output() {
    let dir = tempfile::tempdir().unwrap();
    let small = SshRunner::new(spec(), 1024, dir.path());
    let r = small.run(request("yes | head -c 5000"));
    assert!(r.truncated);
    assert_eq!(r.stdout.len(), 1024);
    assert_eq!(r.status, RunStatus::Ok);
    // A per-request limit overrides the runner's.
    let r = small.run(request("yes | head -c 5000").max_output_bytes(8192));
    assert!(!r.truncated);
    assert_eq!(r.stdout.len(), 5000);
}

#[test]
fn keeps_the_destination_after_the_double_dash() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner_with(dir.path(), &[]);
    let mut target = host("box");
    target.ssh = Some("alice@10.0.0.1".to_string());
    target.port = Some(2222);
    target.proxy_jump = Some("bastion".to_string());
    target.identity_file = Some("/k/id".to_string());
    let argv = runner.argv(&target, false, false);
    assert_eq!(argv[argv.len() - 3..], ["--", "alice@10.0.0.1", "sh -s"]);
    assert!(argv.contains(&"BatchMode=yes".to_string()));
    for expected in ["-J", "bastion", "-i", "/k/id", "IdentitiesOnly=yes", "-p", "2222", "-T", "ConnectTimeout=5"] {
        assert!(argv.contains(&expected.to_string()), "{expected} missing from {argv:?}");
    }
    assert!(!argv.iter().any(|arg| arg.starts_with("ControlMaster")));
    let mut password = host("box");
    password.auth = Some(AuthMethod::Password);
    let argv = runner.argv(&password, false, false);
    for expected in ["BatchMode=no", "StrictHostKeyChecking=accept-new", "NumberOfPasswordPrompts=1", "PubkeyAuthentication=no"] {
        assert!(argv.contains(&expected.to_string()), "{expected} missing from {argv:?}");
    }
    // sudo: non-interactive without a password, the stdin wrapper with one; the sudo user is quoted.
    let mut sudo = host("box");
    sudo.user = Some("ops".to_string());
    sudo.sudo_user = Some("postgres".to_string());
    assert_eq!(runner.argv(&sudo, true, false).last().unwrap(), "sudo -n -u 'postgres' -- sh -s");
    assert_eq!(runner.argv(&sudo, true, true).last().unwrap(), &password_sudo_command(Some("postgres")));
    let argv = runner.argv(&sudo, false, false);
    assert_eq!(argv[argv.len() - 5..], ["-l", "ops", "--", "box", "sh -s"]);
    // Multiplexing puts the control socket under the data directory; extra arguments precede `--`.
    let multiplexed = SshRunner::new(SshSpec { control_persist_sec: 60, extra_args: vec!["-4".to_string()], ..spec() }, 1024, dir.path());
    let argv = multiplexed.argv(&host("box"), false, false);
    assert!(argv.contains(&"ControlMaster=auto".to_string()) && argv.contains(&"ControlPersist=60s".to_string()));
    assert!(argv.contains(&format!("ControlPath={}", dir.path().join("cm").join("%C").display())));
    assert_eq!(argv[argv.len() - 4..], ["-4", "--", "box", "sh -s"]);
    assert!(dir.path().join("cm").is_dir());
}

#[test]
fn resolves_an_alias_user_locally_and_respects_explicit_user_precedence() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner_with(dir.path(), &[]);
    let with = |ssh: &str, user: Option<&str>| {
        let mut target = host("box");
        target.ssh = Some(ssh.to_string());
        target.user = user.map(str::to_string);
        target
    };
    assert_eq!(runner.login_user(&with("alias", None)).unwrap(), "fixture-user");
    assert_eq!(runner.login_user(&with("alice@192.0.2.10", None)).unwrap(), "alice");
    assert_eq!(runner.login_user(&with("alice@192.0.2.10", Some("admin"))).unwrap(), "admin");
    let unavailable = SshRunner::new(SshSpec { binary: dir.path().join("missing-ssh").to_string_lossy().into_owned(), ..spec() }, 1024, dir.path());
    assert!(unavailable.login_user(&with("alias", None)).unwrap_err().contains("显式填写用户名"));
    // Without usable `ssh -G` output the inventory fields are the target.
    let target = unavailable.resolve_target(&with("alice@192.0.2.10", None));
    assert_eq!((target.hostname.as_str(), target.port), ("192.0.2.10", 22));
    let r = unavailable.run(request("true"));
    assert_eq!(r.status, RunStatus::Unreachable);
    assert!(r.stderr.starts_with("failed to start "), "{}", r.stderr);
}

#[test]
fn pauses_logins_after_an_authentication_failure() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log");
    let runner = runner_with(dir.path(), &[("FAKE_SSH_LOG", log.to_str().unwrap())]);
    let down = runner.run(RunRequest::new(host("down-1"), "true").timeout_ms(5000));
    assert_eq!((down.status, down.exit_code), (RunStatus::Unreachable, Some(255)));
    let locked = runner.run(RunRequest::new(host("locked-1"), "true").timeout_ms(5000));
    assert_eq!(locked.status, RunStatus::AuthFailed);
    let again = runner.run(RunRequest::new(host("locked-1"), "true").timeout_ms(5000));
    assert_eq!(again.status, RunStatus::Blocked);
    assert!(again.stderr.contains("Permission denied") && again.stderr.contains("/ops-unblock locked-1"), "{}", again.stderr);
    // The second attempt never reached ssh.
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "down-1\nlocked-1\n");
    assert_eq!(runner.guard().list().len(), 1);
    assert_eq!(runner.guard().clear("locked-1"), ["locked-1"]);
    assert_eq!(runner.run(RunRequest::new(host("locked-1"), "true").timeout_ms(5000)).status, RunStatus::AuthFailed);
}

#[test]
fn answers_a_password_login_through_a_one_shot_askpass() {
    let dir = tempfile::tempdir().unwrap();
    let login = "s3cret pass'word";
    let runner = runner_with(dir.path(), &[("FAKE_SSH_LOGIN_PASSWORD", login)]);
    let mut target = host("nas");
    target.auth = Some(AuthMethod::Password);
    // The helper's location and anything it leaves behind are observable from the "remote" side.
    let script = "echo \"askpass=$SSH_ASKPASS require=$SSH_ASKPASS_REQUIRE\"; ls -l \"$(dirname \"$SSH_ASKPASS\")\"; echo --script; cat \"$SSH_ASKPASS\"; echo --again; \"$SSH_ASKPASS\"";
    let ok = runner.run(RunRequest::new(target.clone(), script).timeout_ms(5000).login_password(Some(login.to_string())));
    assert_eq!(ok.status, RunStatus::Ok, "{ok:?}");
    assert!(ok.stdout.contains("require=force"));
    assert!(!ok.stdout.contains(login));
    // It is a FIFO fed from memory (`p` in `ls -l`), not a regular file holding the password.
    assert!(ok.stdout.lines().any(|line| line.starts_with("prw-------") && line.ends_with("pass")), "{}", ok.stdout);
    let askpass = ok.stdout.lines().find_map(|line| line.strip_prefix("askpass=")).and_then(|rest| rest.split(' ').next()).unwrap().to_string();
    // The helper script only names the FIFO; nothing in it had to be redacted.
    let (_, rest) = ok.stdout.split_once("--script\n").unwrap();
    let (script_text, again) = rest.split_once("--again\n").unwrap();
    assert_eq!(script_text, format!("#!/bin/sh\ncat {}\n", shell_quote(&Path::new(&askpass).with_file_name("pass").to_string_lossy())));
    // A second prompt gets the same answer, and the password is redacted when the remote side echoes it.
    assert_eq!(again, "[REDACTED]\n");
    // Removed once ssh exits.
    assert!(!Path::new(&askpass).exists());
    assert!(!Path::new(&askpass).parent().unwrap().exists());

    // When ssh never asks (a reused master connection, an unreachable host), the helper is torn down promptly.
    let unasked = runner_with(dir.path(), &[]);
    let started = Instant::now();
    let quiet = unasked.run(RunRequest::new(target.clone(), "echo \"$SSH_ASKPASS\"").timeout_ms(5000).login_password(Some(login.to_string())));
    assert_eq!(quiet.status, RunStatus::Ok);
    assert!(started.elapsed() < Duration::from_millis(900), "{:?}", started.elapsed());
    assert!(!Path::new(quiet.stdout.trim()).parent().unwrap().exists());

    let wrong = runner.run(RunRequest::new(target.clone(), "echo in").timeout_ms(5000).login_password(Some("nope".to_string())));
    assert_eq!(wrong.status, RunStatus::AuthFailed);
    runner.guard().clear("all");
    let missing = runner.run(RunRequest::new(target, "echo in").timeout_ms(5000));
    assert_eq!(missing.status, RunStatus::AuthFailed);
    assert!(missing.stderr.contains("no password is available"));
    assert_eq!(missing.duration_ms, 0);
}

#[test]
fn runs_a_fleet_with_bounded_parallelism_in_input_order() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner_with(dir.path(), &[]);
    let names = ["h1", "down-2", "h3", "locked-4", "h5"];
    let started = Instant::now();
    let results = runner.run_many(names.iter().map(|name| RunRequest::new(host(name), "sleep 0.3; echo $FAKE_HOST").timeout_ms(5000)).collect());
    assert_eq!(results.iter().map(|r| r.host.as_str()).collect::<Vec<_>>(), names);
    assert_eq!(results.iter().map(|r| r.status).collect::<Vec<_>>(), [RunStatus::Ok, RunStatus::Unreachable, RunStatus::Ok, RunStatus::AuthFailed, RunStatus::Ok]);
    assert_eq!(results[2].stdout, "h3\n");
    // Three sleeping hosts on two workers take at least two rounds.
    assert!(started.elapsed() >= Duration::from_millis(550), "{:?}", started.elapsed());
    assert!(runner.run_many(Vec::new()).is_empty());

    let hosts: Vec<Host> = ["a", "b", "c"].iter().map(|name| host(name)).collect();
    let built = runner.run_many_with(&hosts, |host| if host.name == "b" { Err("vault entry missing".to_string()) } else { Ok(RunRequest::new(host.clone(), "echo $FAKE_HOST").timeout_ms(5000)) });
    assert_eq!(built.iter().map(|r| (r.host.as_str(), r.status)).collect::<Vec<_>>(), [("a", RunStatus::Ok), ("b", RunStatus::Failed), ("c", RunStatus::Ok)]);
    assert_eq!(built[1].stderr, "vault entry missing");
}

#[test]
fn applies_the_path_prelude_before_the_script() {
    let dir = tempfile::tempdir().unwrap();
    let runner = SshRunner::new(SshSpec { load_profile: true, extra_path: vec!["/opt/wisp-test/bin".to_string()], ..spec() }, 4096, dir.path());
    let r = runner.run(request("case \":$PATH:\" in *:/opt/wisp-test/bin:*) echo extended;; *) echo missing;; esac"));
    assert_eq!((r.status, r.stdout.as_str()), (RunStatus::Ok, "extended\n"), "{r:?}");
}

#[test]
fn does_not_print_secrets_when_debug_formatted() {
    let text = format!("{:?}", request("id").sudo_password(Some("hunter2".to_string())).login_password(Some("hunter3".to_string())));
    assert!(!text.contains("hunter"), "{text}");
}

#[test]
fn classifies_exits() {
    assert_eq!(classify_exit(Some(255), "alice@h: Permission denied (publickey).", false, false), RunStatus::AuthFailed);
    assert_eq!(classify_exit(Some(255), "ssh: connect to host h port 22: Connection refused", false, false), RunStatus::Unreachable);
    assert_eq!(classify_exit(Some(1), "sudo: a password is required", true, false), RunStatus::SudoRequired);
    assert_eq!(classify_exit(Some(97), "", true, true), RunStatus::SudoRequired);
    assert_eq!(classify_exit(Some(97), "", true, false), RunStatus::Failed);
    assert_eq!(classify_exit(Some(1), "boom", false, false), RunStatus::Failed);
    assert_eq!(classify_exit(Some(1), "alice is not in the sudoers file", true, false), RunStatus::Failed);
    assert_eq!(classify_exit(Some(1), "sudo: alice is not in the sudoers file", true, false), RunStatus::SudoRequired);
    assert_eq!(classify_exit(Some(255), "Host key verification failed.", false, false), RunStatus::AuthFailed);
    assert_eq!(classify_exit(None, "", false, false), RunStatus::Failed);
    assert_eq!(classify_exit(Some(0), "Permission denied (", false, false), RunStatus::Ok);
}

#[test]
fn decodes_windows_ssh_errors_without_mangling_remote_utf8() {
    let gbk = legacy_decoder("win32", "zh-CN");
    // Windows OpenSSH: "No such host is known." in GBK, written as octal escapes.
    let escaped = b"ssh: Could not resolve hostname xzg: \\262\\273\\326\\252\\265\\300\\325\\342\\321\\371\\265\\304\\326\\367\\273\\372\\241\\243\r\n";
    assert_eq!(decode_stderr(escaped, gbk), "ssh: Could not resolve hostname xzg: 不知道这样的主机。\r\n");
    let mut mixed = "远端错误\n".as_bytes().to_vec();
    mixed.extend_from_slice(&[0xb2, 0xbb, 0xd6, 0xaa, 0xb5, 0xc0]);
    assert_eq!(decode_stderr(&mixed, gbk), "远端错误\n不知道");
    assert_eq!(decode_stderr("名称解析暂时失败 \\345\\220\\215 \\377".as_bytes(), None), "名称解析暂时失败 名 \\377");
    assert!(legacy_decoder("linux", "zh-CN").is_none());
    let names: Vec<String> = ["zh-TW", "ja", "ru", "de"].iter().map(|locale| legacy_decoder("win32", locale).unwrap().name().to_lowercase()).collect();
    assert_eq!(names, ["big5", "shift_jis", "windows-1251", "windows-1252"]);
    assert_eq!(legacy_decoder("win32", "zh-Hant-HK").unwrap().name(), "Big5");
    assert_eq!(legacy_decoder("win32", "tr-TR").unwrap().name(), "windows-1254");
}

#[test]
fn builds_the_sudo_wrapper_and_prelude_exactly_as_the_plugin_did() {
    let golden: Vec<&str> = include_str!("fixtures/ssh-strings.golden.txt").split("\n---\n").collect();
    assert_eq!(password_sudo_command(None), golden[0]);
    assert_eq!(password_sudo_command(Some("postgres")), golden[1]);
    assert_eq!(prelude(true, &["/usr/local/sbin".to_string(), "/opt/slurm/bin".to_string()]), golden[2]);
    assert_eq!(prelude(false, &["/opt/slurm/bin".to_string()]), "PATH=\"$PATH:/opt/slurm/bin\"\nexport PATH\n");
    assert!(prelude(true, &[]).contains("/etc/profile"));
    assert_eq!(prelude(false, &[]), "");
    assert_eq!(shell_quote("it's"), "'it'\\''s'");
}

#[test]
fn pauses_and_resumes_logins() {
    let guard = AuthGuard::new(60_000);
    guard.record_at("h", "x\nalice@h: Permission denied (publickey).", 0);
    let message = guard.check_at("h", 0).unwrap();
    assert!(message.contains("Permission denied") && message.contains("1970-01-01T00:01:00.000Z"), "{message}");
    assert_eq!(guard.list_at(0)[0].until, "1970-01-01T00:01:00.000Z");
    assert!(guard.check_at("h", 61_000).is_none());
    assert!(guard.list_at(61_000).is_empty());
    guard.record_at("h", "", 61_000);
    assert!(guard.check_at("h", 61_000).unwrap().contains("(authentication failed)"));
    assert_eq!(guard.clear("all"), ["h"]);
    assert!(guard.clear("h").is_empty());
    // A zero block time disables the pause.
    let off = AuthGuard::new(0);
    off.record_at("h", "Permission denied (publickey).", 0);
    assert!(off.check_at("h", 0).is_none());
}
