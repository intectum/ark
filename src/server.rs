use std::env;
use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

use url::Url;

use crate::crypto::verify_bytes;
use crate::http::{read_request, write_response};
use crate::identity::{read_identity, resolve_identity_server};
use crate::metadata::{read_metadata_attributes, read_metadata_headers, verify_metadata, write_metadata_attributes, write_metadata_headers};
use crate::types::{DirectoryEntry, DirectoryEntryKind, Identity};
use crate::util::{decode_base64url, io_err, now_seconds, request_to_bytes, resolve_url};

const MAX_CLOCK_SKEW_SECS: u64 = 300;

pub fn cmd_server(port: u16) {
    let root = env::current_dir().expect("cwd");
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    eprintln!("Ark serving {} on http://0.0.0.0:{}", root.display(), port);
    serve(listener, root, true);
}

#[cfg(test)]
pub fn start_test_server(root: PathBuf) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve(listener, root, false));
    port
}

pub fn serve(listener: TcpListener, root: PathBuf, verbose: bool) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let root = root.clone();
                thread::spawn(move || {
                    if let Err(e) = handle(s, &root, verbose) {
                        if verbose {
                            eprintln!("ERROR: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                if verbose {
                    eprintln!("ERROR: {}", e);
                }
            }
        }
    }
}

fn handle(mut stream: TcpStream, root: &Path, verbose: bool) -> std::io::Result<()> {
    let (method, target, headers, body) = read_request(&mut stream)?;

    if verbose {
        println!("{} {}", method, target)
    }

    let url = match resolve_url(&target, "", root, true) {
        Ok(u) => u,
        Err(_) => return write_status(&mut stream, 400, "Bad Request", b"bad path"),
    };

    let segments: Vec<&str> = url.path_segments()
        .map(|s| s.filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    if segments.first() != Some(&"ark") || segments.len() < 2 {
        return write_status(&mut stream, 403, "Forbidden", b"forbidden");
    }
    if segments.len() == 2 && method != "GET" && method != "HEAD" {
        return write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed");
    }

    let account_name = segments[1];
    let identity = match read_identity(&root.join("ark").join(account_name).join(".ark").join("identity.json")) {
        Ok(i) => i,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
            return write_status(&mut stream, 403, "Forbidden", b"forbidden"),
        Err(e) => return Err(e),
    };

    let fs_path = root.join(url.path().trim_start_matches('/'));

    if fs::symlink_metadata(&fs_path).map(|m| m.is_symlink()).unwrap_or(false) {
        return write_status(&mut stream, 403, "Forbidden", b"symlinks not allowed");
    }

    match verify_auth(&identity, &url, &method, &headers, &body) {
        AuthResult::Ok => {}
        AuthResult::Unauthorized(msg) => {
            return write_status(&mut stream, 401, "Unauthorized", msg.as_bytes());
        }
        AuthResult::Forbidden(msg) => {
            return write_status(&mut stream, 403, "Forbidden", msg.as_bytes());
        }
    }

    match method.as_str() {
        "GET" => serve_get(&fs_path, &mut stream, true),
        "HEAD" => serve_get(&fs_path, &mut stream, false),
        "PUT" => serve_put(root, &identity, &fs_path, &mut stream, &body, &headers),
        "DELETE" => serve_delete(&fs_path, &mut stream),
        _ => write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed"),
    }
}

enum AuthResult {
    Ok,
    Unauthorized(&'static str),
    Forbidden(&'static str),
}

fn verify_auth(
    identity: &Identity,
    url: &Url,
    method: &str,
    headers: &Vec<(String, String)>,
    body: &[u8],
) -> AuthResult {
    let authorization = headers.iter().find_map(|(name, value)| if name.eq_ignore_ascii_case("authorization") { Some(value) } else { None });
    let authorization_value = match authorization {
        Some(h) => h,
        None => return AuthResult::Unauthorized("missing Authorization header"),
    };

    let signature_b64 = match authorization_value.strip_prefix("ArkAccount ") {
        Some(s) => s.trim(),
        None => return AuthResult::Unauthorized("unsupported Authorization scheme"),
    };

    let timestamp = headers.iter().find_map(|(name, value)| if name.eq_ignore_ascii_case("x-ark-timestamp") { Some(value) } else { None });
    let timestamp_value: u64 = match timestamp {
        Some(t) => t.parse().unwrap_or(0),
        None => return AuthResult::Unauthorized("missing X-Ark-Timestamp header"),
    };

    if now_seconds().abs_diff(timestamp_value) > MAX_CLOCK_SKEW_SECS {
        return AuthResult::Unauthorized("timestamp outside allowed window");
    }

    let signature = match decode_base64url(signature_b64) {
        Ok(b) => b,
        Err(_) => return AuthResult::Forbidden("auth signature not base64url encoded"),
    };

    if signature.len() != 64 {
        return AuthResult::Forbidden("auth signature wrong length");
    }

    let bytes = request_to_bytes(method, url.path(), timestamp_value, body);
    if verify_bytes(&identity.public_key.value, &signature, bytes).is_ok() {
        AuthResult::Ok
    } else {
        AuthResult::Forbidden("signature verification failed")
    }
}

fn serve_get(fs_path: &Path, stream: &mut TcpStream, send_body: bool) -> std::io::Result<()> {
    let fs_metadata = match fs::metadata(fs_path) {
        Ok(m) => m,
        Err(_) => return write_status(stream, 404, "Not Found", b"not found"),
    };

    if fs_metadata.is_dir() {
        let body = list_dir(fs_path)?;
        let content_length = body.len().to_string();
        let headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", content_length.as_str()),
            ("Connection", "close"),
        ];
        return write_response(stream, 200, "OK", &headers, if send_body { body.as_bytes() } else { &[] });
    }

    let metadata = match read_metadata_attributes(fs_path) {
        Ok(m) => m,
        Err(e) => return write_status(stream, 500, "Internal Server Error", e.to_string().as_bytes()),
    };

    let metadata_headers = write_metadata_headers(&metadata);
    let content_length = fs_metadata.len().to_string();
    let mut headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    headers.push(("Content-Type", content_type(fs_path)));
    headers.push(("Content-Length", &content_length));
    headers.push(("Connection", "close"));

    write_response(stream, 200, "OK", &headers, &[])?;
    if send_body {
        let mut file = fs::File::open(fs_path)?;
        std::io::copy(&mut file, stream)?;
    }

    Ok(())
}

fn serve_put(root: &Path, self_identity: &Identity, fs_path: &Path, stream: &mut TcpStream, body: &[u8], headers: &[(String, String)]) -> std::io::Result<()> {
    let metadata = match read_metadata_headers(headers) {
        Ok(m) => m,
        Err(e) => return write_status(stream, 400, "Bad Request", e.to_string().as_bytes()),
    };

    let modifier_identity = match resolve_identity_server(root, self_identity, &metadata.modified_by) {
        Ok(i) => i,
        Err(e) => return write_status(stream, 403, "Forbidden", e.to_string().as_bytes()),
    };

    if let Err(e) = verify_metadata(&modifier_identity.public_key.value, &metadata, body) {
        return write_status(stream, 403, "Forbidden", e.to_string().as_bytes());
    }

    if let Some(parent) = fs_path.parent() { fs::create_dir_all(parent)?; }

    let (status_code, status_msg) = if fs_path.exists() { (204, "No Content") } else { (201, "Created") };

    let mut file = fs::File::create(fs_path)?;
    write_metadata_attributes(fs_path, &metadata)?;
    file.write_all(body)?;
    drop(file);

    write_status(stream, status_code, status_msg, &[])
}

fn serve_delete(fs_path: &Path, stream: &mut TcpStream) -> std::io::Result<()> {
    let fs_metadata = match fs::metadata(fs_path) {
        Ok(m) => m,
        Err(_) => return write_status(stream, 404, "Not Found", b"not found"),
    };

    let result = if fs_metadata.is_dir() {
        fs::remove_dir_all(fs_path)
    } else {
        fs::remove_file(fs_path)
    };

    match result {
        Ok(_) => write_status(stream, 204, "No Content", &[]),
        Err(_) => write_status(stream, 500, "Internal Server Error", b"delete failed"),
    }
}

fn list_dir(path: &Path) -> std::io::Result<String> {
    let mut entries: Vec<_> = fs::read_dir(path)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    let items: Vec<DirectoryEntry> = entries
        .into_iter()
        .map(|e| {
            let meta = e.metadata()?;
            let kind = if meta.is_dir() { DirectoryEntryKind::Dir }
                else if meta.is_symlink() { DirectoryEntryKind::Symlink }
                else { DirectoryEntryKind::File };
            Ok(DirectoryEntry {
                kind,
                name: e.file_name().to_string_lossy().into_owned(),
                size: meta.len(),
            })
        })
        .collect::<std::io::Result<_>>()?;
    serde_json::to_string(&items).map_err(|e| io_err(&e.to_string()))
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

fn write_status(stream: &mut TcpStream, status_code: u16, status_msg: &str, body: &[u8]) -> std::io::Result<()> {
    write_response(stream, status_code, status_msg, &[("Content-Type", "text/plain"), ("Connection", "close")], body)
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::time::Duration;

    use super::*;
    use crate::create_account::create_account_with_key;
    use crate::crypto::sign_bytes;
    use crate::identity::{create_identity, write_identity};
    use crate::metadata::sign_metadata;
    use crate::util::encode_base64url;
    use crate::util::test::{TEST_ADDRESS, TempDir, get_default_test_metadata, write_file_with_default_test_metadata};

    fn setup_account(td: &Path, account: &str, key: &[u8]) -> PathBuf {
        let address = format!("{}@example.com", account);
        create_account_with_key(td, &address, key).unwrap();
        td.join("ark").join(account)
    }

    fn sign(key: &[u8], method: &str, path: &str, ts: u64, body: &[u8]) -> String {
        let bytes = request_to_bytes(method, path, ts, body);
        encode_base64url(sign_bytes(key, &bytes))
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

    fn signed_request(port: u16, key: &[u8], method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        signed_request_with_headers(port, key, method, path, body, &[])
    }

    fn signed_request_with_headers(port: u16, key: &[u8], method: &str, path: &str, body: &[u8], extra: &[(&str, &str)]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        let timestamp = now_seconds();
        let sig_b64 = sign(key, method, path, timestamp, body);
        let auth = format!("ArkAccount {}", sig_b64);
        let ts_str = timestamp.to_string();
        let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth), ("X-Ark-Timestamp", &ts_str)];
        headers.extend_from_slice(extra);
        request(port, method, path, body, &headers)
    }

    fn signed_put_with_default_metadata(port: u16, key: &[u8], path: &str, body: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        let meta = write_metadata_headers(&get_default_test_metadata(key, TEST_ADDRESS, body));
        let extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        signed_request_with_headers(port, key, "PUT", path, body, &extra)
    }

    fn header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn get_file_returns_content() {
        let td = TempDir::new("ark_server_test");
        let key = [1u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        write_file_with_default_test_metadata(&acc.join("hello.txt"), &key, TEST_ADDRESS, b"hi there");
        let port = start_test_server(td.0.clone());
        let (code, body, headers) = signed_request(port, &key, "GET", "/ark/test/hello.txt", &[]);
        assert_eq!(code, 200);
        assert_eq!(body, b"hi there");
        assert_eq!(header(&headers, "content-length"), Some("8"));
    }

    #[test]
    fn get_missing_file_404() {
        let td = TempDir::new("ark_server_test");
        let key = [2u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "GET", "/ark/test/nope.txt", &[]);
        assert_eq!(code, 404);
    }

    #[test]
    fn get_dir_returns_json_listing() {
        let td = TempDir::new("ark_server_test");
        let key = [3u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        fs::write(acc.join("a.txt"), b"hello").unwrap();
        fs::create_dir(acc.join("sub")).unwrap();
        let port = start_test_server(td.0.clone());
        let (code, body, headers) = signed_request(port, &key, "GET", "/ark/test/", &[]);
        assert_eq!(code, 200);
        assert_eq!(header(&headers, "content-type"), Some("application/json"));

        let entries: Vec<DirectoryEntry> = serde_json::from_slice(&body).unwrap();
        let file = entries.iter().find(|e| e.name == "a.txt").unwrap();
        assert!(matches!(file.kind, DirectoryEntryKind::File));
        assert_eq!(file.size, 5);
        let dir = entries.iter().find(|e| e.name == "sub").unwrap();
        assert!(matches!(dir.kind, DirectoryEntryKind::Dir));
    }

    #[test]
    fn get_dir_empty_returns_empty_array() {
        let td = TempDir::new("ark_server_test");
        let key = [40u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        fs::create_dir(acc.join("empty")).unwrap();
        let port = start_test_server(td.0.clone());
        let (code, body, _) = signed_request(port, &key, "GET", "/ark/test/empty/", &[]);
        assert_eq!(code, 200);
        let entries: Vec<DirectoryEntry> = serde_json::from_slice(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn get_dir_lists_symlink_as_symlink_kind() {
        let td = TempDir::new("ark_server_test");
        let key = [41u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let target = acc.join("real.txt");
        fs::write(&target, b"hi").unwrap();
        std::os::unix::fs::symlink(&target, acc.join("link")).unwrap();
        let port = start_test_server(td.0.clone());
        let (code, body, _) = signed_request(port, &key, "GET", "/ark/test/", &[]);
        assert_eq!(code, 200);
        let entries: Vec<DirectoryEntry> = serde_json::from_slice(&body).unwrap();
        let link = entries.iter().find(|e| e.name == "link").unwrap();
        assert!(matches!(link.kind, DirectoryEntryKind::Symlink));
    }

    #[test]
    fn head_file_no_body_with_length() {
        let td = TempDir::new("ark_server_test");
        let key = [4u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        write_file_with_default_test_metadata(&acc.join("x"), &key, TEST_ADDRESS, b"abcde");
        let port = start_test_server(td.0.clone());
        let (code, body, headers) = signed_request(port, &key, "HEAD", "/ark/test/x", &[]);
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert_eq!(header(&headers, "content-length"), Some("5"));
    }

    #[test]
    fn head_dir_no_body_with_json_type() {
        let td = TempDir::new("ark_server_test");
        let key = [5u8; 32];
         setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, body, headers) = signed_request(port, &key, "HEAD", "/ark/test/", &[]);
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert_eq!(header(&headers, "content-type"), Some("application/json"));
    }

    #[test]
    fn put_new_file_returns_201() {
        let td = TempDir::new("ark_server_test");
        let key = [6u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_put_with_default_metadata(port, &key, "/ark/test/new.txt", b"payload");
        assert_eq!(code, 201);
        assert_eq!(fs::read(td.0.join("ark/test/new.txt")).unwrap(), b"payload");
    }

    #[test]
    fn put_overwrite_returns_204() {
        let td = TempDir::new("ark_server_test");
        let key = [7u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        write_file_with_default_test_metadata(&acc.join("x"), &key, TEST_ADDRESS, b"old");
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_put_with_default_metadata(port, &key, "/ark/test/x", b"new content");
        assert_eq!(code, 204);
        assert_eq!(fs::read(td.0.join("ark/test/x")).unwrap(), b"new content");
    }

    #[test]
    fn put_nested_path_creates_dirs() {
        let td = TempDir::new("ark_server_test");
        let key = [8u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_put_with_default_metadata(port, &key, "/ark/test/a/b/c.txt", b"deep");
        assert_eq!(code, 201);
        assert_eq!(fs::read(td.0.join("ark/test/a/b/c.txt")).unwrap(), b"deep");
    }

    #[test]
    fn delete_file_removes_and_returns_204() {
        let td = TempDir::new("ark_server_test");
        let key = [9u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let p = acc.join("d.txt");
        fs::write(&p, b"bye").unwrap();
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "DELETE", "/ark/test/d.txt", &[]);
        assert_eq!(code, 204);
        assert!(!p.exists());
    }

    #[test]
    fn delete_dir_recursively_removes_and_returns_204() {
        let td = TempDir::new("ark_server_test");
        let key = [10u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let d = acc.join("sub");
        fs::create_dir(&d).unwrap();
        fs::write(d.join("inner"), b"x").unwrap();
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "DELETE", "/ark/test/sub", &[]);
        assert_eq!(code, 204);
        assert!(!d.exists());
    }

    #[test]
    fn delete_missing_404() {
        let td = TempDir::new("ark_server_test");
        let key = [11u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "DELETE", "/ark/test/nope", &[]);
        assert_eq!(code, 404);
    }

    #[test]
    fn unsupported_method_returns_405() {
        let td = TempDir::new("ark_server_test");
        let key = [12u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, body, _) = signed_request(port, &key, "POST", "/ark/test/x", b"hello");
        println!("code: {}, body: {}", code, std::str::from_utf8(&body).unwrap());
        assert_eq!(code, 405);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_get_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let key = [50u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let target = acc.join("real.txt");
        write_file_with_default_test_metadata(&target, &key, TEST_ADDRESS, b"secret");
        std::os::unix::fs::symlink(&target, acc.join("link")).unwrap();
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "GET", "/ark/test/link", &[]);
        assert_eq!(code, 403);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_head_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let key = [51u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let target = acc.join("real.txt");
        write_file_with_default_test_metadata(&target, &key, TEST_ADDRESS, b"secret");
        std::os::unix::fs::symlink(&target, acc.join("link")).unwrap();
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "HEAD", "/ark/test/link", &[]);
        assert_eq!(code, 403);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_put_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let key = [52u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let target = acc.join("real.txt");
        write_file_with_default_test_metadata(&target, &key, TEST_ADDRESS, b"original");
        std::os::unix::fs::symlink(&target, acc.join("link")).unwrap();
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_put_with_default_metadata(port, &key, "/ark/test/link", b"clobber");
        assert_eq!(code, 403);
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_delete_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let key = [53u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let target = acc.join("real.txt");
        write_file_with_default_test_metadata(&target, &key, TEST_ADDRESS, b"keep");
        let link = acc.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "DELETE", "/ark/test/link", &[]);
        assert_eq!(code, 403);
        assert!(link.exists());
        assert!(target.exists());
    }

    #[test]
    fn path_traversal_blocked() {
        let td = TempDir::new("ark_server_test");
        let key = [13u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "GET", "/ark/test/../../../etc/passwd", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn root_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let port = start_test_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/", &[], &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn non_ark_path_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let port = start_test_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/something/else", &[], &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn ark_without_subdir_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let port = start_test_server(td.0.clone());
        let (c1, _, _) = request(port, "GET", "/ark", &[], &[]);
        let (c2, _, _) = request(port, "GET", "/ark/", &[], &[]);
        assert_eq!(c1, 403);
        assert_eq!(c2, 403);
    }

    #[test]
    fn put_at_ark_root_405() {
        let td = TempDir::new("ark_server_test");
        let key = [14u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "PUT", "/ark/test", b"x");
        assert_eq!(code, 405);
    }

    #[test]
    fn delete_at_ark_root_405() {
        let td = TempDir::new("ark_server_test");
        let key = [15u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "DELETE", "/ark/test", &[]);
        assert_eq!(code, 405);
        assert!(td.0.join("ark/test").exists());
    }

    #[test]
    fn put_outside_ark_blocked_403() {
        let td = TempDir::new("ark_server_test");
        let port = start_test_server(td.0.clone());
        let (code, _, _) = request(port, "PUT", "/oops.txt", b"x", &[]);
        assert_eq!(code, 403);
        assert!(!td.0.join("oops.txt").exists());
    }

    #[test]
    fn missing_auth_header_401() {
        let td = TempDir::new("ark_server_test");
        setup_account(&td.0, "test", &[16u8; 32]);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/ark/test/anything", &[], &[]);
        assert_eq!(code, 401);
    }

    #[test]
    fn missing_timestamp_header_401() {
        let td = TempDir::new("ark_server_test");
        let key = [17u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let sig = sign(&key, "GET", "/ark/test/x", now_seconds(), &[]);
        let auth = format!("ArkAccount {}", sig);
        let (code, _, _) = request(port, "GET", "/ark/test/x", &[], &[("Authorization", &auth)]);
        assert_eq!(code, 401);
    }

    #[test]
    fn stale_timestamp_401() {
        let td = TempDir::new("ark_server_test");
        let key = [18u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let old = now_seconds() - (MAX_CLOCK_SKEW_SECS + 60);
        let sig = sign(&key, "GET", "/ark/test/x", old, &[]);
        let auth = format!("ArkAccount {}", sig);
        let ts = old.to_string();
        let (code, _, _) = request(port, "GET", "/ark/test/x", &[], &[("Authorization", &auth), ("X-Ark-Timestamp", &ts)]);
        assert_eq!(code, 401);
    }

    #[test]
    fn wrong_signature_403() {
        let td = TempDir::new("ark_server_test");
        let key = [19u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let ts = now_seconds();
        let sig = sign(&key, "GET", "/ark/test/somethingelse", ts, &[]);
        let auth = format!("ArkAccount {}", sig);
        let ts_s = ts.to_string();
        let (code, _, _) = request(port, "GET", "/ark/test/realtarget", &[], &[("Authorization", &auth), ("X-Ark-Timestamp", &ts_s)]);
        assert_eq!(code, 403);
    }

    #[test]
    fn wrong_key_403() {
        let td = TempDir::new("ark_server_test");
        setup_account(&td.0, "test", &[20u8; 32]);
        let attacker = [99u8; 32];
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &attacker, "GET", "/ark/test/x", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn no_identity_file_403() {
        let td = TempDir::new("ark_server_test");
        let attacker = [21u8; 32];
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &attacker, "GET", "/ark/ghost/x", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn created_identity_authenticates_with_server() {
        let td = TempDir::new("ark_server_test");
        create_account_with_key(&td.0, "gyan@example.com", &[77u8; 32]).unwrap();
        write_file_with_default_test_metadata(&td.0.join("ark/gyan/hello.txt"), &[77u8; 32], "gyan@example.com", b"hi gyan");
        let port = start_test_server(td.0.clone());
        let (code, body, _) = signed_request(port, &[77u8; 32], "GET", "/ark/gyan/hello.txt", &[]);
        assert_eq!(code, 200);
        assert_eq!(body, b"hi gyan");
    }

    #[test]
    fn put_signature_covers_body() {
        let td = TempDir::new("ark_server_test");
        let key = [22u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let ts = now_seconds();
        let signed_body = b"original";
        let sig = sign(&key, "PUT", "/ark/test/file", ts, signed_body);
        let auth = format!("ArkAccount {}", sig);
        let ts_s = ts.to_string();
        let (code, _, _) = request(port, "PUT", "/ark/test/file", b"tampered", &[("Authorization", &auth), ("X-Ark-Timestamp", &ts_s)]);
        assert_eq!(code, 403);
        assert!(!td.0.join("ark/test/file").exists());
    }

    #[test]
    fn put_stores_metadata_headers_as_xattr() {
        let td = TempDir::new("ark_server_test");
        let key = [23u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let alice_key = [99u8; 32];
        let alice_identity = create_identity(&alice_key, "alice@x");
        let cache_dir = td.0.join("ark/ark/.ark/identities");
        fs::create_dir_all(&cache_dir).unwrap();
        write_identity(&cache_dir.join("alice@x.json"), &alice_identity).unwrap();
        let mut m = get_default_test_metadata(&alice_key, "alice@x", b"ciphertext");
        m.members[0].wrapped_key = [7u8; 32].to_vec();
        sign_metadata(&alice_key, &mut m, b"ciphertext");
        let headers = write_metadata_headers(&m);
        let extra: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let (code, _, _) = signed_request_with_headers(port, &key, "PUT", "/ark/test/secret", b"ciphertext", &extra);
        assert_eq!(code, 201);
        let p = td.0.join("ark/test/secret");
        assert_eq!(
            xattr::get(&p, "user.ark.encryption").unwrap().as_deref(),
            Some(b"aes-256-gcm".as_slice())
        );
        let loaded = read_metadata_attributes(&p).unwrap();
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0].address, "alice@x");
        assert_eq!(loaded.members[0].wrapped_key, [7u8; 32]);
    }

    #[test]
    fn put_ignores_unknown_meta_headers() {
        let td = TempDir::new("ark_server_test");
        let key = [26u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let meta = write_metadata_headers(&get_default_test_metadata(&key, TEST_ADDRESS, b"x"));
        let mut extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        extra.push(("X-Ark-Meta-Foo", "bar"));
        let (code, _, _) = signed_request_with_headers(port, &key, "PUT", "/ark/test/file", b"x", &extra);
        assert_eq!(code, 201);
        let p = td.0.join("ark/test/file");
        assert_eq!(xattr::get(&p, "user.ark.foo").unwrap(), None);
    }

    #[test]
    fn get_returns_metadata_headers_from_xattr() {
        let td = TempDir::new("ark_server_test");
        let key = [30u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let file = acc.join("secret");
        write_file_with_default_test_metadata(&file, &key, TEST_ADDRESS, b"ciphertext");
        let port = start_test_server(td.0.clone());

        let (code, body, headers) = signed_request(port, &key, "GET", "/ark/test/secret", &[]);
        assert_eq!(code, 200);
        assert_eq!(body, b"ciphertext");
        assert_eq!(header(&headers, "x-ark-meta-encryption"), Some("aes-256-gcm"));
        assert_eq!(header(&headers, "x-ark-meta-member-0-address"), Some(TEST_ADDRESS));
    }

    #[test]
    fn get_ignores_unknown_user_ark_xattrs() {
        let td = TempDir::new("ark_server_test");
        let key = [32u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        let file = acc.join("file");
        write_file_with_default_test_metadata(&file, &key, TEST_ADDRESS, b"data");
        xattr::set(&file, "user.ark.foo", b"bar").unwrap();
        let port = start_test_server(td.0.clone());

        let (code, _, headers) = signed_request(port, &key, "GET", "/ark/test/file", &[]);
        assert_eq!(code, 200);
        assert_eq!(header(&headers, "x-ark-meta-foo"), None);
    }

    #[test]
    fn get_file_without_xattr_returns_500() {
        let td = TempDir::new("ark_server_test");
        let key = [31u8; 32];
        let acc = setup_account(&td.0, "test", &key);
        fs::write(acc.join("plain"), b"raw").unwrap();
        let port = start_test_server(td.0.clone());

        let (code, _, _) = signed_request(port, &key, "GET", "/ark/test/plain", &[]);
        assert_eq!(code, 500);
    }

    #[test]
    fn put_without_meta_headers_returns_400() {
        let td = TempDir::new("ark_server_test");
        let key = [24u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, &key, "PUT", "/ark/test/plain", b"data");
        assert_eq!(code, 400);
        assert!(!td.0.join("ark/test/plain").exists());
    }

    #[test]
    fn put_ignores_non_meta_custom_headers() {
        let td = TempDir::new("ark_server_test");
        let key = [25u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let meta = write_metadata_headers(&get_default_test_metadata(&key, TEST_ADDRESS, b"x"));
        let mut extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        extra.push(("X-Custom-Foo", "bar"));
        let (code, _, _) = signed_request_with_headers(port, &key, "PUT", "/ark/test/file", b"x", &extra);
        assert_eq!(code, 201);
        let p = td.0.join("ark/test/file");
        assert_eq!(xattr::get(&p, "user.ark.foo").unwrap(), None);
    }
}
