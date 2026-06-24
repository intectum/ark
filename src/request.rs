use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration};

use url::Url;

use crate::crypto::{sign_bytes};
use crate::identity::{read_identity_key, read_nearest_identity};
use crate::util::{encode_base64url, io_err, now_seconds, request_to_bytes, resolve_url};

pub fn ark_request(
    method: &str,
    arg: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let (identity, account_dir) = read_nearest_identity()?;
    let key = read_identity_key(&account_dir.join(".ark").join("identity.key"))?;
    let url = resolve_url(arg, &identity.address, &account_dir)?;
    request(method, &url, body, extra_headers, &key)
}

pub fn request(
    method: &str,
    url: &Url,
    body: &[u8],
    extra_headers: &[(&str, &str)],
    key: &[u8],
) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let host = url.host_str().ok_or_else(|| io_err("URL missing host"))?;
    let host_header = match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    };

    let timestamp = now_seconds();

    let bytes = request_to_bytes(method, url.path(), timestamp, body);
    let signature_b64 = encode_base64url(sign_bytes(key, &bytes));

    let mut stream = TcpStream::connect((host, url.port().unwrap()))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    let mut request_header = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nAuthorization: ArkAccount {}\r\nX-Ark-Timestamp: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        method, url.path(), host_header, signature_b64, timestamp, body.len()
    );
    for (k, v) in extra_headers {
        request_header.push_str(&format!("{}: {}\r\n", k, v));
    }
    request_header.push_str("\r\n");
    stream.write_all(request_header.as_bytes())?;

    if !body.is_empty() {
        stream.write_all(body)?;
    }

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io_err("malformed response (no header end)"))?;

    let response_header = std::str::from_utf8(&buf[..split]).map_err(|_| io_err("non-utf8 headers"))?;
    let mut response_header_lines = response_header.split("\r\n");

    let response_status_line = response_header_lines.next().ok_or_else(|| io_err("empty response header"))?;
    let response_code: u16 = response_status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io_err("no status code"))?
        .parse()
        .map_err(|_| io_err("bad status code"))?;

    let mut response_headers = Vec::new();
    for response_header_line in response_header_lines {
        if let Some((name, value)) = response_header_line.split_once(':') {
            response_headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let response_body = buf[split + 4..].to_vec();

    Ok((response_code, response_headers, response_body))
}

#[cfg(test)]
mod tests {
    use std::thread;

    use ed25519_dalek::{SigningKey};

    use super::*;
    use crate::crypto::verify_bytes;
    use crate::util::decode_base64url;
    use crate::util::test::bind_local;

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

        let url = Url::parse(&format!("http://127.0.0.1:{}/x", port)).unwrap();
        let (code, headers, body) = request("PUT", &url, b"data", &[], &[1u8; 32]).unwrap();
        assert_eq!(code, 201);
        assert_eq!(body, b"hello");
        assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-length") && v == "5"));
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

        let url = Url::parse(&format!("http://127.0.0.1:{}/ark/alice/x", port)).unwrap();
        let (code, _, _) = request("PUT", &url, b"payload", &[], &[2u8; 32]).unwrap();
        assert_eq!(code, 204);

        let req = captured.join().unwrap();
        let req_str = String::from_utf8_lossy(&req);
        assert!(req_str.starts_with("PUT /ark/alice/x HTTP/1.1\r\n"), "request was: {}", req_str);
        assert_eq!(parse_header(&req, "Host"), Some(format!("127.0.0.1:{}", port).as_str()));
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

        let url = Url::parse(&format!("http://127.0.0.1:{}/x", port)).unwrap();
        let key = [3u8; 32];
        let _ = request("GET", &url, &[], &[], &key).unwrap();

        let req = captured.join().unwrap();
        let auth = parse_header(&req, "Authorization").unwrap();
        let ts = parse_header(&req, "X-Ark-Timestamp").unwrap();
        let sig_b64 = auth.strip_prefix("ArkAccount ").unwrap();
        let sig_bytes: [u8; 64] = decode_base64url(sig_b64).unwrap().try_into().unwrap();

        let ts_n: u64 = ts.parse().unwrap();
        let msg = request_to_bytes("GET", "/x", ts_n, &[]);
        let public_key = SigningKey::from_bytes(&key).verifying_key().to_bytes();
        assert!(verify_bytes(&public_key, &sig_bytes, msg).is_ok());
    }

    #[test]
    fn request_propagates_non_2xx_status() {
        let (listener, port) = bind_local();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_full_request(&mut s);
            s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndenied!").unwrap();
        });

        let url = Url::parse(&format!("http://127.0.0.1:{}/ark/x", port)).unwrap();
        let (code, _, body) = request("GET", &url, &[], &[], &[4u8; 32]).unwrap();
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

        let url = Url::parse(&format!("http://127.0.0.1:{}/x", port)).unwrap();
        let _ = request(
            "PUT",
            &url,
            b"d",
            &[("X-Ark-Meta-Encryption", "aes-256-gcm"), ("X-Custom", "hi")],
            &[5u8; 32],
        ).unwrap();

        let req = captured.join().unwrap();
        assert_eq!(parse_header(&req, "X-Ark-Meta-Encryption"), Some("aes-256-gcm"));
        assert_eq!(parse_header(&req, "X-Custom"), Some("hi"));
    }
}
