//! One WebDAV request for device sync: any method, the headers as given, no redirect followed,
//! thirty seconds in all, the answer read up to a limit. It goes through the global proxy.

use std::time::Duration;

/// Whether a URL points at this computer: such a request never goes through a proxy.
fn loopback(url: &str) -> bool {
    let authority = url.split_once("://").map_or("", |(_, rest)| rest.split('/').next().unwrap_or(""));
    let host = if authority.starts_with('[') { authority.split_inclusive(']').next().unwrap_or("") } else { authority.split(':').next().unwrap_or("") };
    matches!(host.to_ascii_lowercase().as_str(), "127.0.0.1" | "localhost" | "[::1]")
}

/// Send a request and read the whole answer: its status and body. `Err` when there is no answer,
/// or one longer than `limit` bytes. The headers (the authorization among them) are never in the text of an error.
pub fn send(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&[u8]>, limit: u64) -> Result<(u16, Vec<u8>), String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .allow_non_standard_methods(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(super::USER_AGENT)
        .proxy(if loopback(url) { None } else { super::proxy_for("")? })
        .build()
        .into();
    let mut builder = ureq::http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let failed = |err: ureq::Error| format!("WebDAV request failed: {}", match err { ureq::Error::Timeout(_) => "timeout".to_string(), ureq::Error::Io(io) => io.kind().to_string(), other => other.to_string() });
    let mut response = match body {
        Some(body) => agent.run(builder.body(body.to_vec()).map_err(|_| "invalid WebDAV request".to_string())?),
        None => agent.run(builder.body(()).map_err(|_| "invalid WebDAV request".to_string())?),
    }
    .map_err(failed)?;
    let status = response.status().as_u16();
    let body = response.body_mut().with_config().limit(limit).read_to_vec().map_err(failed)?;
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// Serve one connection with `reply` and give back the request line, its headers and body.
    fn serve(reply: &'static str) -> (String, std::thread::JoinHandle<(String, Vec<String>, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut headers = Vec::new();
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let header = header.trim_end().to_string();
                if header.is_empty() { break }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") { length = value.trim().parse().unwrap() }
                headers.push(header.to_ascii_lowercase());
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = stream;
            stream.write_all(reply.as_bytes()).unwrap();
            (line.trim_end().to_string(), headers, String::from_utf8(body).unwrap())
        });
        (address, handle)
    }

    #[test]
    fn sends_webdav_methods_with_their_headers_and_body() {
        let (address, server) = serve("HTTP/1.1 207 Multi-Status\r\nContent-Length: 5\r\nConnection: close\r\n\r\n<x/>\n");
        let (status, body) = send("PROPFIND", &format!("{address}/dav/"), &[("authorization", "Basic dTpw"), ("depth", "1")], Some(b"<propfind/>"), 1024).unwrap();
        assert_eq!((status, body.as_slice()), (207, b"<x/>\n".as_slice()));
        let (line, headers, body) = server.join().unwrap();
        assert_eq!(line, "PROPFIND /dav/ HTTP/1.1");
        assert!(headers.contains(&"authorization: basic dtpw".to_string()) && headers.contains(&"depth: 1".to_string()));
        assert_eq!(body, "<propfind/>");
    }

    #[test]
    fn never_proxies_this_computer() {
        assert!(loopback("http://127.0.0.1:8080/dav/") && loopback("http://localhost/x") && loopback("http://[::1]:80/"));
        assert!(!loopback("https://dav.jianguoyun.com/dav/") && !loopback("https://127.0.0.1.example.org/"));
    }

    #[test]
    fn follows_no_redirect_and_refuses_long_answers() {
        let (address, server) = serve("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        assert_eq!(send("GET", &format!("{address}/f"), &[], None, 1024).unwrap().0, 302);
        server.join().unwrap();
        let (address, server) = serve("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789");
        let error = send("GET", &format!("{address}/f"), &[("authorization", "Basic c2VjcmV0")], None, 4).unwrap_err();
        assert!(!error.contains("c2VjcmV0"));
        server.join().unwrap();
    }
}
