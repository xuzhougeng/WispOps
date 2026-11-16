//! Importable aliases from OpenSSH client configuration (`ssh-config.spec.ts`).

use wisp_ops_engine::config::{HostSpec, validate_host};
use wisp_ops_engine::ssh_config::{SshConfigHost, describe_ssh_config_host, inventory_name_for, load_ssh_config_hosts, parse_ssh_config, ssh_config_host_spec};

const SAMPLE: &str = r#"# lab machines
Host gpu-01 gpu-02
    HostName 10.0.0.11
    User alice
    Port 2222
    IdentityFile ~/.ssh/id_lab

Host bastion
  HostName bastion.example.com
  User ops

Host web-*
    ProxyJump bastion

Host "quoted name"
    HostName 10.0.0.9

Host gpu-01
    User bob

Match host gpu-02
    User eve

Host nas=
    HostName 192.168.1.20
Host all
    HostName 10.9.9.9
Host *
    ServerAliveInterval 30
"#;

fn alias(alias: &str) -> SshConfigHost {
    SshConfigHost { alias: alias.to_string(), source: "c".to_string(), ..SshConfigHost::default() }
}

#[test]
fn collects_literal_host_aliases_first_block_wins_wildcards_and_match_blocks_are_skipped() {
    let hosts = parse_ssh_config(SAMPLE, "/x/config").hosts;
    assert_eq!(hosts.iter().map(|h| h.alias.as_str()).collect::<Vec<_>>(), ["gpu-01", "gpu-02", "bastion", "nas=", "all"]);
    assert_eq!(
        hosts[0],
        SshConfigHost {
            alias: "gpu-01".to_string(),
            host_name: Some("10.0.0.11".to_string()),
            user: Some("alice".to_string()),
            port: Some(2222),
            identity_file: Some("~/.ssh/id_lab".to_string()),
            proxy_jump: None,
            source: "/x/config".to_string(),
        }
    );
    assert_eq!(hosts[1].user.as_deref(), Some("alice"));
    let bastion = hosts.iter().find(|h| h.alias == "bastion").unwrap();
    assert_eq!((bastion.host_name.as_deref(), bastion.user.as_deref(), bastion.port), (Some("bastion.example.com"), Some("ops"), None));
    assert_eq!(parse_ssh_config("Include ~/.ssh/conf.d/*\nInclude extra.conf", "c").includes, ["~/.ssh/conf.d/*", "extra.conf"]);
    assert_eq!(parse_ssh_config("Host  a\n  Port 99999\n  Port=2200", "c").hosts[0].port, Some(2200));
    assert_eq!(parse_ssh_config("Host a\r\n  HostName = 10.0.0.1\r\n  ProxyJump \"jump box\"\r\n", "c").hosts[0].host_name.as_deref(), Some("10.0.0.1"));
    assert!(parse_ssh_config("Host -oProxyCommand=x !neg\n  HostName h\n", "c").hosts.is_empty());
}

#[test]
fn derives_inventory_names_and_connects_through_the_alias() {
    assert_eq!(inventory_name_for("gpu-01"), "gpu-01");
    assert_eq!(inventory_name_for("lab:gpu"), "lab-gpu");
    assert_eq!(inventory_name_for("all"), "host-all");
    assert_eq!(inventory_name_for("_x"), "x");
    assert_eq!(inventory_name_for("::"), "host-x");
    let full = SshConfigHost { host_name: Some("10.0.0.11".to_string()), user: Some("alice".to_string()), port: Some(2222), ..alias("gpu-01") };
    assert_eq!(
        ssh_config_host_spec(&full),
        HostSpec { groups: vec!["ssh-config".to_string()], description: Some("ssh_config gpu-01 → alice@10.0.0.11:2222".to_string()), ..HostSpec::named("gpu-01") }
    );
    assert_eq!(
        ssh_config_host_spec(&alias("lab:gpu")),
        HostSpec { ssh: Some("lab:gpu".to_string()), groups: vec!["ssh-config".to_string()], description: Some("ssh_config lab:gpu".to_string()), ..HostSpec::named("lab-gpu") }
    );
    assert_eq!(describe_ssh_config_host(&SshConfigHost { host_name: Some("h".to_string()), ..alias("b") }), "h");
    // Every spec the importer produces must satisfy the inventory schema.
    for host in parse_ssh_config(SAMPLE, "c").hosts {
        validate_host(&ssh_config_host_spec(&host)).unwrap();
    }
}

#[test]
fn follows_include_globs_relative_to_the_main_file_bounded_and_tolerates_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
    std::fs::create_dir(dir.join("conf.d")).unwrap();
    std::fs::write(dir.join("config"), format!("Include conf.d/*.conf\nInclude {}\nInclude missing.conf\nInclude conf.d\nHost main\n  HostName 10.0.0.1\n", path("absolute.conf"))).unwrap();
    std::fs::write(dir.join("conf.d/a.conf"), "Host a-host\n  HostName 10.0.0.2\nHost main\n  HostName ignored\n").unwrap();
    std::fs::write(dir.join("conf.d/b.conf"), format!("Include {}\nHost b-host\n  HostName 10.0.0.3\n", path("config"))).unwrap();
    std::fs::write(dir.join("conf.d/notes.txt"), "Host not-included\n").unwrap();
    std::fs::write(dir.join("absolute.conf"), "Host abs\n  User root\n").unwrap();
    let loaded = load_ssh_config_hosts(&path("config")).unwrap();
    assert_eq!(loaded.path, path("config"));
    assert_eq!(loaded.hosts.iter().map(|h| h.alias.as_str()).collect::<Vec<_>>(), ["main", "a-host", "b-host", "abs"]);
    assert_eq!(loaded.hosts[0].host_name.as_deref(), Some("10.0.0.1"));
    // Compared as paths: Windows writes the separator the other way.
    assert_eq!(std::path::Path::new(&loaded.hosts[1].source), std::path::Path::new(&path("conf.d/a.conf")));
    assert!(load_ssh_config_hosts(&path("nope")).unwrap().hosts.is_empty());
}
