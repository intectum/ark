use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier};

use crate::identity::{read_identity, verifying_key_from_key};
use crate::request::signing_message;
use crate::util::B64;

const MAX_CLOCK_SKEW_SECS: u64 = 300;

pub fn cmd_server(port: u16) {
    let root = env::current_dir().expect("cwd");
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    eprintln!("serving {} on http://0.0.0.0:{}", root.display(), port);
    serve(listener, root, true);
}

pub fn serve(listener: TcpListener, root: PathBuf, verbose: bool) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let root = root.clone();
                thread::spawn(move || {
                    if let Err(e) = handle(s, &root, verbose) {
                        if verbose {
                            eprintln!("error: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                if verbose {
                    eprintln!("accept: {}", e);
                }
            }
        }
    }
}

fn handle(mut stream: TcpStream, root: &Path, verbose: bool) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.trim_end().split_whitespace().collect();
    if parts.len() != 3 {
        return write_status(&mut stream, 400, "Bad Request", b"bad request line");
    }
    let method = parts[0].to_string();
    let target = parts[1].to_string();

    let mut content_length: usize = 0;
    let mut auth_header: Option<String> = None;
    let mut timestamp_header: Option<u64> = None;
    let mut meta_headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            } else if key.eq_ignore_ascii_case("authorization") {
                auth_header = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("x-ark-timestamp") {
                timestamp_header = val.parse().ok();
            } else if let Some(meta_name) = strip_meta_prefix(key) {
                meta_headers.push((meta_name.to_ascii_lowercase(), val.to_string()));
            }
        }
    }

    if verbose {
        eprintln!("{:?} {} {}", peer, method, target);
    }

    if !is_allowed(&target) {
        return write_status(&mut stream, 403, "Forbidden", b"forbidden");
    }

    let body = read_body(&mut reader, content_length)?;

    match verify_auth(root, &target, &method, auth_header.as_deref(), timestamp_header, &body) {
        AuthResult::Ok => {}
        AuthResult::Unauthorized(msg) => {
            return write_status(&mut stream, 401, "Unauthorized", msg.as_bytes());
        }
        AuthResult::Forbidden(msg) => {
            return write_status(&mut stream, 403, "Forbidden", msg.as_bytes());
        }
    }

    if is_ark_root(&target) && method != "GET" && method != "HEAD" {
        return write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed");
    }

    let path = match resolve(root, &target) {
        Some(p) => p,
        None => return write_status(&mut stream, 400, "Bad Request", b"bad path"),
    };

    match method.as_str() {
        "GET" => serve_get(&mut stream, &path, true),
        "HEAD" => serve_get(&mut stream, &path, false),
        "PUT" => serve_put(&mut stream, &path, &body, &meta_headers),
        "DELETE" => serve_delete(&mut stream, &path),
        _ => write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed"),
    }
}

fn read_body(reader: &mut BufReader<TcpStream>, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut buf)?;
    }
    Ok(buf)
}

fn is_allowed(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or("");
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    parts.len() >= 2 && parts[0] == "ark"
}

fn is_ark_root(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or("");
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    parts.len() == 2 && parts[0] == "ark"
}

fn account_from_target(target: &str) -> Option<&str> {
    let path = target.split('?').next()?;
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < 2 || parts[0] != "ark" {
        return None;
    }
    Some(parts[1])
}

enum AuthResult {
    Ok,
    Unauthorized(&'static str),
    Forbidden(&'static str),
}

fn verify_auth(
    root: &Path,
    target: &str,
    method: &str,
    auth_header: Option<&str>,
    timestamp: Option<u64>,
    body: &[u8],
) -> AuthResult {
    let header = match auth_header {
        Some(h) => h,
        None => return AuthResult::Unauthorized("missing Authorization header"),
    };
    let sig_b64 = match header.strip_prefix("ArkAccount ") {
        Some(s) => s.trim(),
        None => return AuthResult::Unauthorized("unsupported Authorization scheme"),
    };
    let ts = match timestamp {
        Some(t) => t,
        None => return AuthResult::Unauthorized("missing X-Ark-Timestamp header"),
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if now.abs_diff(ts) > MAX_CLOCK_SKEW_SECS {
        return AuthResult::Unauthorized("timestamp outside allowed window");
    }

    let account = match account_from_target(target) {
        Some(a) if a != ".." && !a.is_empty() => a,
        _ => return AuthResult::Forbidden("invalid account"),
    };

    let id_path = root.join("ark").join(account).join(".ark").join("identity.json");
    let identity = match read_identity(&id_path) {
        Ok(i) => i,
        Err(_) => return AuthResult::Forbidden("identity not valid"),
    };
    let vk = match verifying_key_from_key(&identity.key) {
        Ok(v) => v,
        Err(_) => return AuthResult::Forbidden("identity key not valid"),
    };

    let sig_bytes = match B64.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return AuthResult::Forbidden("signature not base64"),
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return AuthResult::Forbidden("signature wrong length"),
    };
    let sig = Signature::from_bytes(&sig_arr);

    let msg = signing_message(method, target, ts, body);

    if vk.verify(&msg, &sig).is_ok() {
        AuthResult::Ok
    } else {
        AuthResult::Forbidden("signature verification failed")
    }
}

fn resolve(root: &Path, target: &str) -> Option<PathBuf> {
    let raw = target.split('?').next().unwrap_or("");
    let decoded = percent_decode(raw)?;
    let rel = decoded.trim_start_matches('/');
    let candidate = root.join(rel);
    for comp in candidate.components() {
        if matches!(comp, Component::ParentDir) {
            return None;
        }
    }
    Some(candidate)
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                out.push(((hi << 4) | lo) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn serve_get(stream: &mut TcpStream, path: &Path, send_body: bool) -> std::io::Result<()> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return write_status(stream, 404, "Not Found", b"not found"),
    };
    if meta.is_dir() {
        let body = list_dir(path)?;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes())?;
        if send_body {
            stream.write_all(body.as_bytes())?;
        }
        return Ok(());
    }
    let len = meta.len();
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content_type(path),
        len
    );
    stream.write_all(headers.as_bytes())?;
    if send_body {
        let mut f = fs::File::open(path)?;
        std::io::copy(&mut f, stream)?;
    }
    Ok(())
}

fn serve_put(stream: &mut TcpStream, path: &Path, body: &[u8], meta: &[(String, String)]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let existed = path.exists();
    let mut f = fs::File::create(path)?;
    f.write_all(body)?;
    drop(f);
    for (name, val) in meta {
        let attr = format!("user.ark.{}", name);
        xattr::set(path, &attr, val.as_bytes())?;
    }
    let (code, msg) = if existed { (204, "No Content") } else { (201, "Created") };
    let response = format!("HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, msg);
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn strip_meta_prefix(key: &str) -> Option<&str> {
    let prefix = "x-ark-meta-";
    if key.len() > prefix.len() && key[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&key[prefix.len()..])
    } else {
        None
    }
}

fn serve_delete(stream: &mut TcpStream, path: &Path) -> std::io::Result<()> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return write_status(stream, 404, "Not Found", b"not found"),
    };
    let res = if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match res {
        Ok(_) => stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").map(|_| ()),
        Err(_) => write_status(stream, 500, "Internal Server Error", b"delete failed"),
    }
}

fn list_dir(path: &Path) -> std::io::Result<String> {
    let mut entries: Vec<_> = fs::read_dir(path)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    let mut body = String::from("[");
    let mut first = true;
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let meta = e.metadata()?;
        let kind = if meta.is_dir() { "dir" } else if meta.is_symlink() { "symlink" } else { "file" };
        let size = meta.len();
        if !first {
            body.push(',');
        }
        first = false;
        body.push_str(&format!(
            "{{\"name\":\"{}\",\"type\":\"{}\",\"size\":{}}}",
            json_escape(&name),
            kind,
            size
        ));
    }
    body.push(']');
    Ok(body)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" | "md" => "text/plain; charset=utf-8",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn write_status(stream: &mut TcpStream, code: u16, msg: &str, body: &[u8]) -> std::io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        code,
        msg,
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_seed;
    use crate::util::testutil::TempDir;
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::Duration;

    fn start_server(root: PathBuf) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || serve(listener, root, false));
        port
    }

    fn setup_account(td: &Path, account: &str, seed: [u8; 32]) -> (PathBuf, SigningKey) {
        let address = format!("{}@example.com", account);
        let (sk, _) = create_account_with_seed(td, &address, seed).unwrap();
        let acc_dir = td.join("ark").join(account);
        (acc_dir, sk)
    }

    fn sign(sk: &SigningKey, method: &str, path: &str, ts: u64, body: &[u8]) -> String {
        let msg = signing_message(method, path, ts, body);
        B64.encode(sk.sign(&msg).to_bytes())
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn request(port: u16, method: &str, path: &str, body: &[u8], extra: &[(&str, &str)]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut head = format!("{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n", method, path, body.len());
        for (k, v) in extra {
            head.push_str(&format!("{}: {}\r\n", k, v));
        }
        head.push_str("\r\n");
        s.write_all(head.as_bytes()).unwrap();
        if !body.is_empty() {
            s.write_all(body).unwrap();
        }
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end");
        let header_str = std::str::from_utf8(&buf[..split]).unwrap();
        let body_bytes = buf[split + 4..].to_vec();
        let mut lines = header_str.split("\r\n");
        let status_line = lines.next().unwrap();
        let code: u16 = status_line.split_whitespace().nth(1).unwrap().parse().unwrap();
        let headers = lines
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
            })
            .collect();
        (code, body_bytes, headers)
    }

    fn signed_request(port: u16, sk: &SigningKey, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        signed_request_with_headers(port, sk, method, path, body, &[])
    }

    fn signed_request_with_headers(port: u16, sk: &SigningKey, method: &str, path: &str, body: &[u8], extra: &[(&str, &str)]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        let ts = now_secs();
        let sig_b64 = sign(sk, method, path, ts, body);
        let auth = format!("ArkAccount {}", sig_b64);
        let ts_str = ts.to_string();
        let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth), ("X-Ark-Timestamp", &ts_str)];
        headers.extend_from_slice(extra);
        request(port, method, path, body, &headers)
    }

    fn header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn get_file_returns_content() {
        let td = TempDir::new("ark_server_test");
        let (acc, sk) = setup_account(&td.0, "test", [1u8; 32]);
        fs::write(acc.join("hello.txt"), b"hi there").unwrap();
        let port = start_server(td.0.clone());
        let (code, body, headers) = signed_request(port, &sk, "GET", "/ark/test/hello.txt", &[]);
        assert_eq!(code, 200);
        assert_eq!(body, b"hi there");
        assert_eq!(header(&headers, "content-length"), Some("8"));
    }

    #[test]
    fn get_missing_file_404() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [2u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "GET", "/ark/test/nope.txt", &[]);
        assert_eq!(code, 404);
    }

    #[test]
    fn get_dir_returns_json_listing() {
        let td = TempDir::new("ark_server_test");
        let (acc, sk) = setup_account(&td.0, "test", [3u8; 32]);
        fs::write(acc.join("a.txt"), b"a").unwrap();
        fs::create_dir(acc.join("sub")).unwrap();
        let port = start_server(td.0.clone());
        let (code, body, headers) = signed_request(port, &sk, "GET", "/ark/test/", &[]);
        assert_eq!(code, 200);
        assert_eq!(header(&headers, "content-type"), Some("application/json"));
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("\"name\":\"a.txt\""), "body was {}", s);
        assert!(s.contains("\"type\":\"file\""), "body was {}", s);
        assert!(s.contains("\"name\":\"sub\""), "body was {}", s);
        assert!(s.contains("\"type\":\"dir\""), "body was {}", s);
    }

    #[test]
    fn head_file_no_body_with_length() {
        let td = TempDir::new("ark_server_test");
        let (acc, sk) = setup_account(&td.0, "test", [4u8; 32]);
        fs::write(acc.join("x"), b"abcde").unwrap();
        let port = start_server(td.0.clone());
        let (code, body, headers) = signed_request(port, &sk, "HEAD", "/ark/test/x", &[]);
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert_eq!(header(&headers, "content-length"), Some("5"));
    }

    #[test]
    fn head_dir_no_body_with_json_type() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [5u8; 32]);
        let port = start_server(td.0.clone());
        let (code, body, headers) = signed_request(port, &sk, "HEAD", "/ark/test/", &[]);
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert_eq!(header(&headers, "content-type"), Some("application/json"));
    }

    #[test]
    fn put_new_file_returns_201() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [6u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "PUT", "/ark/test/new.txt", b"payload");
        assert_eq!(code, 201);
        assert_eq!(fs::read(td.0.join("ark/test/new.txt")).unwrap(), b"payload");
    }

    #[test]
    fn put_overwrite_returns_204() {
        let td = TempDir::new("ark_server_test");
        let (acc, sk) = setup_account(&td.0, "test", [7u8; 32]);
        fs::write(acc.join("x"), b"old").unwrap();
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "PUT", "/ark/test/x", b"new content");
        assert_eq!(code, 204);
        assert_eq!(fs::read(td.0.join("ark/test/x")).unwrap(), b"new content");
    }

    #[test]
    fn put_nested_path_creates_dirs() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [8u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "PUT", "/ark/test/a/b/c.txt", b"deep");
        assert_eq!(code, 201);
        assert_eq!(fs::read(td.0.join("ark/test/a/b/c.txt")).unwrap(), b"deep");
    }

    #[test]
    fn delete_file_removes_and_returns_204() {
        let td = TempDir::new("ark_server_test");
        let (acc, sk) = setup_account(&td.0, "test", [9u8; 32]);
        let p = acc.join("d.txt");
        fs::write(&p, b"bye").unwrap();
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "DELETE", "/ark/test/d.txt", &[]);
        assert_eq!(code, 204);
        assert!(!p.exists());
    }

    #[test]
    fn delete_dir_recursively_removes_and_returns_204() {
        let td = TempDir::new("ark_server_test");
        let (acc, sk) = setup_account(&td.0, "test", [10u8; 32]);
        let d = acc.join("sub");
        fs::create_dir(&d).unwrap();
        fs::write(d.join("inner"), b"x").unwrap();
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "DELETE", "/ark/test/sub", &[]);
        assert_eq!(code, 204);
        assert!(!d.exists());
    }

    #[test]
    fn delete_missing_404() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [11u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "DELETE", "/ark/test/nope", &[]);
        assert_eq!(code, 404);
    }

    #[test]
    fn unsupported_method_returns_405() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [12u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "POST", "/ark/test/x", b"hello");
        assert_eq!(code, 405);
    }

    #[test]
    fn path_traversal_blocked() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [13u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "GET", "/ark/test/../../../etc/passwd", &[]);
        assert_eq!(code, 400);
    }

    #[test]
    fn root_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/", &[], &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn non_ark_path_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/something/else", &[], &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn ark_without_subdir_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let port = start_server(td.0.clone());
        let (c1, _, _) = request(port, "GET", "/ark", &[], &[]);
        let (c2, _, _) = request(port, "GET", "/ark/", &[], &[]);
        assert_eq!(c1, 403);
        assert_eq!(c2, 403);
    }

    #[test]
    fn put_at_ark_root_405() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [14u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "PUT", "/ark/test", b"x");
        assert_eq!(code, 405);
    }

    #[test]
    fn delete_at_ark_root_405() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [15u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "DELETE", "/ark/test", &[]);
        assert_eq!(code, 405);
        assert!(td.0.join("ark/test").exists());
    }

    #[test]
    fn put_outside_ark_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "PUT", "/oops.txt", b"x", &[]);
        assert_eq!(code, 403);
        assert!(!td.0.join("oops.txt").exists());
    }

    #[test]
    fn missing_auth_header_401() {
        let td = TempDir::new("ark_server_test");
        let (_acc, _sk) = setup_account(&td.0, "test", [16u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/ark/test/anything", &[], &[]);
        assert_eq!(code, 401);
    }

    #[test]
    fn missing_timestamp_header_401() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [17u8; 32]);
        let port = start_server(td.0.clone());
        let sig = sign(&sk, "GET", "/ark/test/x", now_secs(), &[]);
        let auth = format!("ArkAccount {}", sig);
        let (code, _, _) = request(port, "GET", "/ark/test/x", &[], &[("Authorization", &auth)]);
        assert_eq!(code, 401);
    }

    #[test]
    fn stale_timestamp_401() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [18u8; 32]);
        let port = start_server(td.0.clone());
        let old = now_secs() - (MAX_CLOCK_SKEW_SECS + 60);
        let sig = sign(&sk, "GET", "/ark/test/x", old, &[]);
        let auth = format!("ArkAccount {}", sig);
        let ts = old.to_string();
        let (code, _, _) = request(port, "GET", "/ark/test/x", &[], &[("Authorization", &auth), ("X-Ark-Timestamp", &ts)]);
        assert_eq!(code, 401);
    }

    #[test]
    fn wrong_signature_403() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [19u8; 32]);
        let port = start_server(td.0.clone());
        let ts = now_secs();
        let sig = sign(&sk, "GET", "/ark/test/somethingelse", ts, &[]);
        let auth = format!("ArkAccount {}", sig);
        let ts_s = ts.to_string();
        let (code, _, _) = request(port, "GET", "/ark/test/realtarget", &[], &[("Authorization", &auth), ("X-Ark-Timestamp", &ts_s)]);
        assert_eq!(code, 403);
    }

    #[test]
    fn wrong_key_403() {
        let td = TempDir::new("ark_server_test");
        let (_acc, _sk) = setup_account(&td.0, "test", [20u8; 32]);
        let attacker = SigningKey::from_bytes(&[99u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &attacker, "GET", "/ark/test/x", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn no_identity_file_403() {
        let td = TempDir::new("ark_server_test");
        let attacker = SigningKey::from_bytes(&[21u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &attacker, "GET", "/ark/ghost/x", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn created_identity_authenticates_with_server() {
        let td = TempDir::new("ark_server_test");
        let (sk, _) = create_account_with_seed(&td.0, "gyan@example.com", [77u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/hello.txt"), b"hi gyan").unwrap();
        let port = start_server(td.0.clone());
        let (code, body, _) = signed_request(port, &sk, "GET", "/ark/gyan/hello.txt", &[]);
        assert_eq!(code, 200);
        assert_eq!(body, b"hi gyan");
    }

    #[test]
    fn put_signature_covers_body() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [22u8; 32]);
        let port = start_server(td.0.clone());
        let ts = now_secs();
        let signed_body = b"original";
        let sig = sign(&sk, "PUT", "/ark/test/file", ts, signed_body);
        let auth = format!("ArkAccount {}", sig);
        let ts_s = ts.to_string();
        let (code, _, _) = request(port, "PUT", "/ark/test/file", b"tampered", &[("Authorization", &auth), ("X-Ark-Timestamp", &ts_s)]);
        assert_eq!(code, 403);
        assert!(!td.0.join("ark/test/file").exists());
    }

    #[test]
    fn put_stores_x_ark_meta_headers_as_xattr() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [23u8; 32]);
        let port = start_server(td.0.clone());
        let extra = [
            ("X-Ark-Meta-Encryption", "aes-256-gcm"),
            ("X-Ark-Meta-Foo", "bar"),
        ];
        let (code, _, _) = signed_request_with_headers(port, &sk, "PUT", "/ark/test/secret", b"ciphertext", &extra);
        assert_eq!(code, 201);
        let p = td.0.join("ark/test/secret");
        assert_eq!(
            xattr::get(&p, "user.ark.encryption").unwrap().as_deref(),
            Some(b"aes-256-gcm".as_slice())
        );
        assert_eq!(
            xattr::get(&p, "user.ark.foo").unwrap().as_deref(),
            Some(b"bar".as_slice())
        );
    }

    #[test]
    fn put_without_meta_headers_writes_no_xattr() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [24u8; 32]);
        let port = start_server(td.0.clone());
        let (code, _, _) = signed_request(port, &sk, "PUT", "/ark/test/plain", b"data");
        assert_eq!(code, 201);
        let p = td.0.join("ark/test/plain");
        assert_eq!(xattr::get(&p, "user.ark.encryption").unwrap(), None);
    }

    #[test]
    fn put_ignores_non_meta_custom_headers() {
        let td = TempDir::new("ark_server_test");
        let (_acc, sk) = setup_account(&td.0, "test", [25u8; 32]);
        let port = start_server(td.0.clone());
        let extra = [("X-Custom-Foo", "bar")];
        let (code, _, _) = signed_request_with_headers(port, &sk, "PUT", "/ark/test/file", b"x", &extra);
        assert_eq!(code, 201);
        let p = td.0.join("ark/test/file");
        assert_eq!(xattr::get(&p, "user.ark.foo").unwrap(), None);
    }

    #[test]
    fn strip_meta_prefix_recognises_case_insensitive() {
        assert_eq!(strip_meta_prefix("X-Ark-Meta-Encryption"), Some("Encryption"));
        assert_eq!(strip_meta_prefix("x-ark-meta-foo"), Some("foo"));
        assert_eq!(strip_meta_prefix("X-Custom-Foo"), None);
        assert_eq!(strip_meta_prefix("X-Ark-Meta-"), None);
        assert_eq!(strip_meta_prefix(""), None);
    }
}
