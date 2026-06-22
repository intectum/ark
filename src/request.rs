use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

use crate::util::{B64, io_err, load_identity_from_tree, parse_host_port, resolve_target};

pub fn signing_message(method: &str, path: &str, ts: u64, body: &[u8]) -> Vec<u8> {
    let ts_str = ts.to_string();
    let mut msg = Vec::with_capacity(method.len() + path.len() + ts_str.len() + body.len() + 3);
    msg.extend_from_slice(method.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(path.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(ts_str.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(body);
    msg
}

pub fn request(
    method: &str,
    connect_host: &str,
    port: u16,
    host_header: &str,
    path: &str,
    body: &[u8],
    sk: &SigningKey,
    extra_headers: &[(&str, &str)],
) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let msg = signing_message(method, path, ts, body);
    let sig_b64 = B64.encode(sk.sign(&msg).to_bytes());

    let mut stream = TcpStream::connect((connect_host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut req_head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nAuthorization: ArkAccount {}\r\nX-Ark-Timestamp: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        method, path, host_header, sig_b64, ts, body.len()
    );
    for (k, v) in extra_headers {
        req_head.push_str(&format!("{}: {}\r\n", k, v));
    }
    req_head.push_str("\r\n");
    stream.write_all(req_head.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io_err("malformed response (no header end)"))?;
    let header_str = std::str::from_utf8(&buf[..split]).map_err(|_| io_err("non-utf8 headers"))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().ok_or_else(|| io_err("empty response"))?;
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io_err("no status code"))?
        .parse()
        .map_err(|_| io_err("bad status code"))?;
    let mut resp_headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            resp_headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let resp_body = buf[split + 4..].to_vec();
    Ok((code, resp_headers, resp_body))
}

pub fn request_ark(
    method: &str,
    arg: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let cwd = std::env::current_dir()?;
    let ctx = load_identity_from_tree(&cwd)?;
    let target = resolve_target(&cwd, &ctx, arg);
    let (host, port) = parse_host_port(&target.host);
    request(method, &host, port, &target.host, &target.url_path, body, &ctx.sk, extra_headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testutil::bind_local;
    use ed25519_dalek::{Signature, Verifier};
    use std::thread;

    fn read_full_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let mut header_end: Option<usize> = None;
        let mut content_length: usize = 0;
        loop {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if header_end.is_none() {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(p + 4);
                    let h = std::str::from_utf8(&buf[..p]).unwrap();
                    for line in h.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                content_length = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                }
            }
            if let Some(he) = header_end {
                if buf.len() >= he + content_length {
                    break;
                }
            }
        }
        buf
    }

    fn parse_header<'a>(req: &'a [u8], key: &str) -> Option<&'a str> {
        let split = req.windows(4).position(|w| w == b"\r\n\r\n")?;
        let h = std::str::from_utf8(&req[..split]).ok()?;
        for line in h.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case(key) {
                    return Some(v.trim());
                }
            }
        }
        None
    }

    #[test]
    fn request_returns_status_and_body() {
        let (listener, port) = bind_local();
        let handle = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_full_request(&mut s);
            s.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").unwrap();
        });

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let (code, headers, body) = request("PUT", "127.0.0.1", port, "127.0.0.1", "/x", b"data", &sk, &[]).unwrap();
        assert_eq!(code, 201);
        assert_eq!(body, b"hello");
        assert!(headers.iter().any(|(k, v)| k == "content-length" && v == "5"));
        handle.join().unwrap();
    }

    #[test]
    fn request_sends_method_path_and_body() {
        let (listener, port) = bind_local();
        let captured = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let req = read_full_request(&mut s);
            s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            req
        });

        let sk = SigningKey::from_bytes(&[2u8; 32]);
        let (code, _, _) = request("PUT", "127.0.0.1", port, "example.com", "/ark/alice/x", b"payload", &sk, &[]).unwrap();
        assert_eq!(code, 204);

        let req = captured.join().unwrap();
        let req_str = String::from_utf8_lossy(&req);
        assert!(req_str.starts_with("PUT /ark/alice/x HTTP/1.1\r\n"), "request was: {}", req_str);
        assert_eq!(parse_header(&req, "Host"), Some("example.com"));
        assert_eq!(parse_header(&req, "Content-Length"), Some("7"));
        assert!(req.ends_with(b"payload"));
    }

    #[test]
    fn request_signs_method_path_timestamp_body() {
        let (listener, port) = bind_local();
        let captured = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let req = read_full_request(&mut s);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            req
        });

        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let _ = request("GET", "127.0.0.1", port, "127.0.0.1", "/ark/x", &[], &sk, &[]).unwrap();

        let req = captured.join().unwrap();
        let auth = parse_header(&req, "Authorization").unwrap();
        let ts = parse_header(&req, "X-Ark-Timestamp").unwrap();
        let sig_b64 = auth.strip_prefix("ArkAccount ").unwrap();
        let sig_bytes: [u8; 64] = B64.decode(sig_b64).unwrap().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);

        let ts_n: u64 = ts.parse().unwrap();
        let msg = signing_message("GET", "/ark/x", ts_n, &[]);
        assert!(sk.verifying_key().verify(&msg, &sig).is_ok());
    }

    #[test]
    fn request_propagates_non_2xx_status() {
        let (listener, port) = bind_local();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_full_request(&mut s);
            s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndenied!").unwrap();
        });

        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let (code, _, body) = request("GET", "127.0.0.1", port, "127.0.0.1", "/ark/x", &[], &sk, &[]).unwrap();
        assert_eq!(code, 403);
        assert_eq!(body, b"denied!");
    }

    #[test]
    fn request_sends_extra_headers() {
        let (listener, port) = bind_local();
        let captured = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let req = read_full_request(&mut s);
            s.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            req
        });

        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let _ = request(
            "PUT",
            "127.0.0.1",
            port,
            "127.0.0.1",
            "/x",
            b"d",
            &sk,
            &[("X-Ark-Meta-Encryption", "aes-256-gcm"), ("X-Custom", "hi")],
        ).unwrap();

        let req = captured.join().unwrap();
        assert_eq!(parse_header(&req, "X-Ark-Meta-Encryption"), Some("aes-256-gcm"));
        assert_eq!(parse_header(&req, "X-Custom"), Some("hi"));
    }
}
