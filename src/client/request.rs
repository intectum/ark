use std::net::TcpStream;
use std::time::Duration;

use url::Url;

use crate::crypto::sign_bytes;
use crate::types::IdentityContext;
use crate::http::{read_response, write_request};
use crate::util::{encode_base64url, io_err, now_seconds, request_to_bytes};

pub fn ark_request(ctx: Option<&IdentityContext>, method: &str, url: &Url, headers: &[(&str, &str)], body: &[u8]) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut final_headers = headers.to_vec();

    let host = url.host_str().ok_or_else(|| io_err("URL missing host"))?;
    let host_header = match url.port() {
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    };

    let authorization = match ctx {
        Some(c) => {
            let timestamp = now_seconds();
            let request_bytes = request_to_bytes(method, &host_header, url.path(), timestamp, body);
            let signature = sign_bytes(c.identity_key.as_ref().expect("client context missing identity_key"), &request_bytes)?;
            Some(format!(
                "ArkAccount address=\"{}\", timestamp=\"{}\", signature=\"{}\"",
                c.identity.address,
                timestamp,
                encode_base64url(signature.value),
            ))
        }
        None => None,
    };

    if let Some(ref a) = authorization {
        final_headers.push(("Authorization", a));
    }

    final_headers.push(("Connection", "close"));

    let mut stream = TcpStream::connect((host, url.port().unwrap_or(80)))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    write_request(&mut stream, url, method, &final_headers, body)?;
    read_response(&mut stream, method)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use crate::client::init;
    use crate::crypto::verify_bytes;
    use crate::context::create_client_context;
    use crate::types::Signature;
    use crate::util::decode_base64url;
    use crate::util::test::in_test_dir;

    pub fn bind_local() -> (TcpListener, u16) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

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

    fn parse_auth_params(value: &str) -> Option<std::collections::HashMap<String, String>> {
        let rest = value.strip_prefix("ArkAccount ")?.trim();
        let mut out = std::collections::HashMap::new();
        for part in rest.split(',') {
            let (k, v) = part.trim().split_once('=')?;
            out.insert(k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string());
        }
        Some(out)
    }

    #[test]
    fn ark_request_returns_status_and_body() {
        in_test_dir("ark_request_test", |temp_dir| {
            init(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let (listener, port) = bind_local();
            let handle = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_full_request(&mut s);
                s.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").unwrap();
            });

            let url = Url::parse(&format!("http://127.0.0.1:{}/x", port)).unwrap();
            let (code, headers, body) = ark_request(Some(&ctx), "PUT", &url, &[], b"data").unwrap();
            assert_eq!(code, 201);
            assert_eq!(body, b"hello");
            assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-length") && v == "5"));
            handle.join().unwrap();
        });
    }

    #[test]
    fn ark_request_sends_method_path_and_body() {
        in_test_dir("ark_request_test", |temp_dir| {
            init(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let (listener, port) = bind_local();
            let captured = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let req = read_full_request(&mut s);
                s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                req
            });

            let url = Url::parse(&format!("http://127.0.0.1:{}/ark/alice/x", port)).unwrap();
            let (code, _, _) = ark_request(Some(&ctx), "PUT", &url, &[], b"payload").unwrap();
            assert_eq!(code, 204);

            let req = captured.join().unwrap();
            let req_str = String::from_utf8_lossy(&req);
            assert!(req_str.starts_with("PUT /ark/alice/x HTTP/1.1\r\n"), "request was: {}", req_str);
            assert_eq!(parse_header(&req, "Host"), Some(format!("127.0.0.1:{}", port).as_str()));
            assert_eq!(parse_header(&req, "Content-Length"), Some("7"));
            assert!(req.ends_with(b"payload"));
        });
    }

    #[test]
    fn ark_request_signs_method_path_timestamp_body() {
        in_test_dir("ark_request_test", |temp_dir| {
            let (identity, _) = init(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let (listener, port) = bind_local();
            let captured = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let req = read_full_request(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                req
            });

            let url = Url::parse(&format!("http://127.0.0.1:{}/x", port)).unwrap();
            let _ = ark_request(Some(&ctx), "GET", &url, &[], &[]).unwrap();

            let req = captured.join().unwrap();
            let auth = parse_header(&req, "Authorization").unwrap();
            let params = parse_auth_params(auth).unwrap();
            assert_eq!(params.get("address").map(String::as_str), Some(identity.address.as_str()));
            let ts_n: u64 = params.get("timestamp").unwrap().parse().unwrap();
            let sig_value = decode_base64url(params.get("signature").unwrap()).unwrap();

            let msg = request_to_bytes("GET", &format!("127.0.0.1:{}", port), "/x", ts_n, &[]);
            let signature = Signature { algorithm: identity.public_key.algorithm.clone(), value: sig_value };
            assert!(verify_bytes(&identity.public_key, &signature, &msg).is_ok());
        });
    }

    #[test]
    fn ark_request_propagates_non_2xx_status() {
        in_test_dir("ark_request_test", |temp_dir| {
            init(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let (listener, port) = bind_local();
            thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_full_request(&mut s);
                s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndenied!").unwrap();
            });

            let url = Url::parse(&format!("http://127.0.0.1:{}/ark/x", port)).unwrap();
            let (code, _, body) = ark_request(Some(&ctx), "GET", &url, &[], &[]).unwrap();
            assert_eq!(code, 403);
            assert_eq!(body, b"denied!");
        });
    }

    #[test]
    fn ark_request_sends_extra_headers() {
        in_test_dir("ark_request_test", |temp_dir| {
            init(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let (listener, port) = bind_local();
            let captured = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let req = read_full_request(&mut s);
                s.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                req
            });

            let url = Url::parse(&format!("http://127.0.0.1:{}/x", port)).unwrap();
            let _ = ark_request(
                Some(&ctx),
                "PUT",
                &url,
                &[("X-Ark-Meta-Encryption-Algorithm", "aes-256-gcm"), ("X-Custom", "hi")],
                b"d",
            ).unwrap();

            let req = captured.join().unwrap();
            assert_eq!(parse_header(&req, "X-Ark-Meta-Encryption-Algorithm"), Some("aes-256-gcm"));
            assert_eq!(parse_header(&req, "X-Custom"), Some("hi"));
        });
    }
}
