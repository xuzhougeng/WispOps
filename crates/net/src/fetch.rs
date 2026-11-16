//! Plain GET requests for the update check: a small document read whole, and
//! a file streamed into whatever the caller writes it to. Both go through the
//! same proxy as the model requests and send only the generic `WispOps/<version>`
//! User-Agent.

use std::io::{Read, Write};
use std::time::Duration;

/// GET `url` and read the body whole, up to `limit` bytes. A 404 is `None`
/// (GitHub's answer for a repository without releases); any other status
/// that is not a success is an error.
pub fn get(url: &str, accept: &str, proxy: &str, limit: u64, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
    let agent = super::patient_agent(Some(timeout), proxy, Duration::from_secs(30))?;
    let mut response = agent.get(url).header("accept", accept).call().map_err(super::network_error)?;
    let status = response.status().as_u16();
    if status == 404 { return Ok(None) }
    if !(200..300).contains(&status) { return Err(format!("HTTP {status}")) }
    response.body_mut().with_config().limit(limit).read_to_vec().map(Some).map_err(|err| match err {
        ureq::Error::BodyExceedsLimit(_) => format!("回应超过 {limit} 字节"),
        err => super::network_error(err),
    })
}

/// GET `url` and copy the body into `sink`, at most `limit` bytes; the bytes copied.
pub fn download(url: &str, proxy: &str, limit: u64, timeout: Duration, sink: &mut dyn Write) -> Result<u64, String> {
    let agent = super::patient_agent(Some(timeout), proxy, Duration::from_secs(30))?;
    let mut response = agent.get(url).header("accept", "application/octet-stream").call().map_err(super::network_error)?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) { return Err(format!("HTTP {status}")) }
    let mut reader = response.body_mut().with_config().limit(limit).reader();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(format!("下载中断：{err}")),
        };
        sink.write_all(&buffer[..read]).map_err(|err| format!("无法写入文件：{err}"))?;
        total += read as u64;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::{download, get};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    /// A stand-in server on 127.0.0.1 that answers each connection with the next of `answers`.
    fn serve(answers: Vec<(u16, Vec<u8>)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for (status, body) in answers {
                let Ok((stream, _)) = listener.accept() else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let mut stream = stream;
                let _ = write!(stream, "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(&body);
            }
        });
        format!("http://{address}")
    }

    #[test]
    fn reads_bodies_maps_404_and_refuses_what_is_too_large() {
        let base = serve(vec![(200, b"{\"a\":1}".to_vec()), (404, vec![]), (500, vec![]), (200, vec![b'x'; 100])]);
        let ask = |limit| get(&format!("{base}/x"), "application/json", "direct", limit, Duration::from_secs(5));
        assert_eq!(ask(1024).unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(ask(1024).unwrap(), None);
        assert_eq!(ask(1024).unwrap_err(), "HTTP 500");
        assert!(ask(10).is_err());
    }

    #[test]
    fn streams_a_download_into_the_sink() {
        let base = serve(vec![(200, vec![7u8; 200_000]), (403, vec![])]);
        let mut sink = vec![];
        assert_eq!(download(&format!("{base}/f"), "direct", 1 << 20, Duration::from_secs(5), &mut sink).unwrap(), 200_000);
        assert!(sink.iter().all(|b| *b == 7) && sink.len() == 200_000);
        assert_eq!(download(&format!("{base}/f"), "direct", 1 << 20, Duration::from_secs(5), &mut vec![]).unwrap_err(), "HTTP 403");
    }
}
