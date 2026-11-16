//! One webhook post: JSON out, a short reply back. Blocking, so the app runs
//! it off the main thread. Redirects are not followed (a token in the URL
//! must not be carried somewhere else) and the reply is read up to a limit.

use std::time::Duration;

/// The longest reply read.
pub const MAX_REPLY_BYTES: u64 = 16_384;

/// Post `body` to `url` with `headers` and give the status and the reply's
/// text; the whole exchange is bounded by `timeout`. The error says what kind
/// of failure it was, without the URL.
pub fn post_json(url: &str, headers: &[(String, String)], body: &str, timeout: Duration) -> Result<(u16, String), String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_connect(Some(timeout.min(Duration::from_secs(10))))
        .timeout_global(Some(timeout))
        .user_agent(super::USER_AGENT)
        // A receiver on this machine is reached directly, whatever proxy the rest goes through.
        .proxy(if loopback(url) { None } else { super::proxy_for("")? })
        .build()
        .into();
    let mut call = agent.post(url);
    for (name, value) in headers {
        call = call.header(name, value);
    }
    let mut response = call.send(body).map_err(|err| match err {
        ureq::Error::Timeout(_) => "timed out".to_string(),
        ureq::Error::Io(err) => format!("connection failed ({:?})", err.kind()),
        ureq::Error::HostNotFound => "host not found".to_string(),
        ureq::Error::ConnectionFailed => "connection failed".to_string(),
        ureq::Error::Tls(_) => "TLS failed".to_string(),
        ureq::Error::ConnectProxyFailed(_) => "the proxy could not connect".to_string(),
        _ => "request failed".to_string(),
    })?;
    let status = response.status().as_u16();
    // A reply over the limit is cut, which a JSON check then rejects.
    let mut text = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::Read::take(response.body_mut().as_reader(), MAX_REPLY_BYTES + 1), &mut text);
    Ok((status, text))
}

/// Whether `url` points at this machine.
fn loopback(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = if authority.starts_with('[') { authority.split(']').next().unwrap_or("").trim_start_matches('[') } else { authority.split(':').next().unwrap_or("") };
    matches!(host.to_ascii_lowercase().as_str(), "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// A one-request HTTP server on 127.0.0.1: gives back what it received and answers `reply`.
    fn serve(reply: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook?token=t", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") { length = value.trim().parse().unwrap() }
                head.push_str(&line);
                if line == "\r\n" { break }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = stream;
            stream.write_all(reply.as_bytes()).unwrap();
            format!("{head}{}", String::from_utf8_lossy(&body))
        });
        (url, handle)
    }

    #[test]
    fn posts_json_and_reads_the_reply() {
        let (url, server) = serve("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"errcode\":0}");
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let (status, reply) = post_json(&url, &headers, r#"{"a":1}"#, Duration::from_secs(5)).unwrap();
        assert_eq!((status, reply.as_str()), (200, r#"{"errcode":0}"#));
        let seen = server.join().unwrap();
        assert!(seen.starts_with("POST /hook?token=t HTTP/1.1"), "{seen}");
        assert!(seen.ends_with(r#"{"a":1}"#));
    }

    #[test]
    fn loopback_is_told_apart() {
        assert!(loopback("http://127.0.0.1:9/x") && loopback("http://localhost/x") && loopback("http://[::1]:8/x"));
        assert!(!loopback("https://example.org/x") && !loopback("https://127.0.0.1.example.org/x"));
    }

    #[test]
    fn a_redirect_is_not_followed() {
        let (url, server) = serve("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let (status, _) = post_json(&url, &[], "{}", Duration::from_secs(5)).unwrap();
        assert_eq!(status, 302);
        server.join().unwrap();
    }

    #[test]
    fn a_closed_port_fails_without_naming_the_url() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let err = post_json(&format!("http://127.0.0.1:{port}/hook?token=secret"), &[], "{}", Duration::from_secs(5)).unwrap_err();
        assert!(!err.contains("secret") && err.starts_with("connection failed"), "{err}");
    }
}
