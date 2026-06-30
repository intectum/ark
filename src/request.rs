use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use url::Url;

use crate::crypto::{sign_bytes};
use crate::http::{read_response, write_request};
use crate::identity::read_identity_key;
use crate::util::{encode_base64url, io_err, now_seconds, request_to_bytes};

pub fn ark_request(
    root: &Path,
    url: &Url,
    method: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let key = read_identity_key(&root.join(".ark").join("identity.key"))?;
    request(method, &url, headers, body, &key)
}

pub fn request(
    method: &str,
    url: &Url,
    headers: &[(&str, &str)],
    body: &[u8],
    key: &[u8],
) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut final_headers = headers.to_vec();

    let timestamp = now_seconds();
    let timestamp_string = timestamp.to_string();
    let bytes = request_to_bytes(method, url.path(), timestamp, body);
    let signature = sign_bytes(key, &bytes);
    let authorization = format!("ArkAccount {}", encode_base64url(signature));
    final_headers.push(("Authorization", &authorization));
    final_headers.push(("X-Ark-Timestamp", &timestamp_string));

    final_headers.push(("Connection", "close"));

    let host = url.host_str().ok_or_else(|| io_err("URL missing host"))?;
    let mut stream = TcpStream::connect((host, url.port().unwrap_or(80)))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    write_request(&mut stream, url, method, &final_headers, body)?;
    read_response(&mut stream, method)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
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
        let (code, headers, body) = request("PUT", &url, &[], b"data", &[1u8; 32]).unwrap();
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
        let (code, _, _) = request("PUT", &url, &[], b"payload", &[2u8; 32]).unwrap();
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
            &[("X-Ark-Meta-Encryption", "aes-256-gcm"), ("X-Custom", "hi")],
            b"d",
            &[5u8; 32],
        ).unwrap();

        let req = captured.join().unwrap();
        assert_eq!(parse_header(&req, "X-Ark-Meta-Encryption"), Some("aes-256-gcm"));
        assert_eq!(parse_header(&req, "X-Custom"), Some("hi"));
    }
}
