//! Connection diagnosis against local listeners (`diagnose.spec.ts`).

use std::io::Write;
use std::net::TcpListener;

use wisp_ops_engine::diagnose::{DiagnosisStepName, SshTarget, Verdict, Via, diagnose_target, parse_ssh_g};

/// A local listener that writes `greeting` to each connection, on a free port.
fn listen(greeting: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut socket in listener.incoming().flatten() {
            let _ = socket.write_all(greeting.as_bytes());
            // Keep the connection open briefly so the client decides when to stop reading.
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                drop(socket);
            });
        }
    });
    port
}

fn target(hostname: &str, port: u16) -> SshTarget {
    SshTarget::direct(hostname, port)
}

#[test]
fn reads_the_destination_ssh_would_use_including_the_first_proxy_jump_hop() {
    assert_eq!(parse_ssh_g("user alice\nhostname 10.0.0.5\nport 2222\nproxyjump none\n", "box", None), target("10.0.0.5", 2222));
    assert_eq!(
        parse_ssh_g("hostname inner\nport 22\nproxyjump ops@bastion.example:2200,second\n", "x", None),
        SshTarget { proxy_jump: Some("bastion.example:2200".to_string()), ..target("inner", 22) }
    );
    assert_eq!(parse_ssh_g("hostname h\nproxycommand nc %h %p\n", "x", Some(2022)), SshTarget { proxy_command: true, ..target("h", 2022) });
    assert_eq!(parse_ssh_g("", "fallback", None), target("fallback", 22));
    assert_eq!(parse_ssh_g("HostName first\nhostname second\nport 99999\nproxyjump ssh://u@jump\n", "x", None), SshTarget { proxy_jump: Some("jump".to_string()), ..target("first", 22) });
}

#[test]
fn passes_every_step_when_an_ssh_server_answers_skipping_dns_for_an_address() {
    let port = listen("Welcome\r\nSSH-2.0-OpenSSH_9.6\r\n");
    let result = diagnose_target("box", &target("127.0.0.1", port), 2000);
    assert_eq!((result.host.as_str(), result.target.as_str(), result.port, result.verdict, result.via), ("box", "127.0.0.1", port, Verdict::Ok, None));
    assert_eq!(result.steps.iter().map(|s| (s.step, s.ok)).collect::<Vec<_>>(), [(DiagnosisStepName::Tcp, true), (DiagnosisStepName::Banner, true)]);
    assert_eq!(result.steps[0].detail, format!("127.0.0.1:{port}"));
    assert_eq!(result.steps[1].detail, "SSH-2.0-OpenSSH_9.6");
}

#[test]
fn names_the_step_that_fails() {
    let http = listen("HTTP/1.1 400 Bad Request\r\n\r\n");
    let web = diagnose_target("web", &target("127.0.0.1", http), 1000);
    assert_eq!(web.verdict, Verdict::Banner);
    assert!(!web.steps[1].ok);
    // A port nothing listens on: bind one, then close it.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let refused = diagnose_target("down", &target("127.0.0.1", closed), 1000);
    assert_eq!(refused.verdict, Verdict::Tcp);
    assert_eq!((refused.steps.len(), refused.steps[0].step, refused.steps[0].ok, refused.steps[0].detail.as_str()), (1, DiagnosisStepName::Tcp, false, "ECONNREFUSED"));
    let dns = diagnose_target("typo", &target("no-such-host.invalid", 22), 1000);
    assert_eq!(dns.verdict, Verdict::Dns);
    assert_eq!((dns.steps.len(), dns.steps[0].step, dns.steps[0].ok), (1, DiagnosisStepName::Dns, false));
    let proxied = diagnose_target("pc", &SshTarget { proxy_command: true, ..target("h", 22) }, 1000);
    assert_eq!((proxied.verdict, proxied.via, proxied.steps.len()), (Verdict::ProxyCommand, Some(Via::ProxyCommand), 0));
}

#[test]
fn reports_a_server_that_closes_or_stays_silent() {
    let silent = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(1).collect();
            std::thread::sleep(std::time::Duration::from_secs(3));
            drop(held);
        });
        port
    };
    let result = diagnose_target("quiet", &target("127.0.0.1", silent), 300);
    assert_eq!(result.verdict, Verdict::Banner);
    assert_eq!(result.steps[1].detail, "no identification within the time limit");
    let closing = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for socket in listener.incoming().flatten() {
                drop(socket);
            }
        });
        port
    };
    let result = diagnose_target("closing", &target("127.0.0.1", closing), 1000);
    assert_eq!(result.verdict, Verdict::Banner);
    assert!(["closed without an identification line", "ECONNRESET"].contains(&result.steps[1].detail.as_str()), "{}", result.steps[1].detail);
}

#[test]
fn tests_the_jump_host_when_the_connection_goes_through_one() {
    let port = listen("SSH-2.0-bastion\r\n");
    let through = SshTarget { proxy_jump: Some(format!("127.0.0.1:{port}")), ..target("inner.internal", 22) };
    let result = diagnose_target("inner", &through, 2000);
    assert_eq!((result.target.as_str(), result.port, result.via, result.verdict), ("127.0.0.1", port, Some(Via::ProxyJump), Verdict::Ok));
    // A jump host with a proxy command of its own is still tested through the jump host.
    let both = SshTarget { proxy_command: true, ..through };
    assert_eq!(diagnose_target("inner", &both, 2000).verdict, Verdict::Ok);
}
