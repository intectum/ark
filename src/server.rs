use std::env;
use std::fs;
use std::io::{Result, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

use url::Url;

use crate::crypto::verify_bytes;
use crate::http::{read_request, write_response};
use crate::identity::{read_identity, resolve_identity_server};
use crate::metadata::{get_member, read_metadata_attributes, read_metadata_headers, verify_metadata, write_metadata_attributes, write_metadata_headers};
use crate::types::{DirectoryEntry, DirectoryEntryKind, Identity, Member, Permission};
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
    let target_identity = match read_identity(&root.join("ark").join(account_name).join(".ark").join("identity.json")) {
        Ok(i) => i,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
            return write_status(&mut stream, 403, "Forbidden", b"forbidden"),
        Err(e) => return Err(e),
    };

    let fs_path = root.join(url.path().trim_start_matches('/'));

    if fs::symlink_metadata(&fs_path).map(|m| m.is_symlink()).unwrap_or(false) {
        return write_status(&mut stream, 403, "Forbidden", b"symlinks not allowed");
    }

    let existing_members = read_metadata_attributes(&fs_path).ok().map(|metadata| metadata.members);
    let existing_public_member = existing_members
        .as_deref()
        .and_then(|members| members.iter().find(|member| member.address == "*"));

    if existing_public_member.is_some() && (method == "GET" || method == "HEAD") {
        return serve_get(&fs_path, &mut stream, method == "GET");
    }

    let requestor_identity = match authenticate(root, &target_identity, &url, &method, &headers, &body) {
        Ok(i) => i,
        Err(e) => return write_status(&mut stream, 401, "Unauthorized", e.to_string().as_bytes())
    };

    let permission = match authorize(&target_identity, &&requestor_identity, existing_members.as_deref()) {
        Ok(p) => p,
        Err(e) => return write_status(&mut stream, 403, "Forbidden", e.to_string().as_bytes())
    };

    if permission == Permission::Read {
        match method.as_str() {
            "PUT" | "DELETE" => return write_status(&mut stream, 403, "Forbidden", b"write permission required"),
            _ => {}
        }
    }

    match method.as_str() {
        "GET" => serve_get(&fs_path, &mut stream, true),
        "HEAD" => serve_get(&fs_path, &mut stream, false),
        "PUT" => serve_put(root, &target_identity, &fs_path, &mut stream, &body, &headers, existing_members, permission),
        "DELETE" => serve_delete(&fs_path, &mut stream),
        _ => write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed"),
    }
}

fn authenticate(
    root: &Path,
    target_identity: &Identity,
    url: &Url,
    method: &str,
    headers: &Vec<(String, String)>,
    body: &[u8],
) -> Result<Identity> {
    let authorization_opt = headers.iter().find_map(|(name, value)| if name.eq_ignore_ascii_case("authorization") { Some(value) } else { None });
    let authorization= match authorization_opt {
        Some(h) => h,
        None => return Err(io_err("missing Authorization header")),
    };

    let params = match parse_auth_params(authorization) {
        Some(p) => p,
        None => return Err(io_err("unsupported Authorization scheme")),
    };

    let address = params.get("address").ok_or_else(|| io_err("missing address in Authorization"))?;
    let signature_b64 = params.get("signature").ok_or_else(|| io_err("missing signature in Authorization"))?;
    let timestamp_str = params.get("timestamp").ok_or_else(|| io_err("missing timestamp in Authorization"))?;

    let requestor_identity = resolve_identity_server(root, target_identity, address)?;

    let signature = decode_base64url(signature_b64).map_err(|_| io_err("auth signature not base64url encoded"))?;

    let timestamp: u64 = timestamp_str.parse().map_err(|_| io_err("invalid timestamp in Authorization"))?;
    if now_seconds().abs_diff(timestamp) > MAX_CLOCK_SKEW_SECS {
        return Err(io_err("timestamp outside allowed window"));
    }

    let bytes = request_to_bytes(method, url.path(), timestamp, body);
    verify_bytes(&requestor_identity.public_key.value, &signature, bytes).map_err(|_| io_err("signature verification failed"))?;

    Ok(requestor_identity)
}

fn authorize(
    target_identity: &Identity,
    requestor_identity: &Identity,
    existing_members: Option<&[Member]>,
) -> Result<Permission> {
    if requestor_identity.address == target_identity.address {
        return Ok(Permission::Owner);
    }

    let identity_member = existing_members
        .and_then(|members| get_member(members, &requestor_identity.address));

    let public_member = existing_members
        .and_then(|members| members.iter().find(|member| member.address == "*"));

    [identity_member, public_member]
        .into_iter()
        .flatten()
        .map(|member| member.permission)
        .max_by_key(|permission| permission_rank(*permission))
        .ok_or_else(|| io_err("requestor not a member"))
}

fn permission_rank(permission: Permission) -> u8 {
    match permission {
        Permission::Read => 0,
        Permission::Write => 1,
        Permission::Owner => 2,
    }
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

fn serve_put(root: &Path, target_identity: &Identity, fs_path: &Path, stream: &mut TcpStream, body: &[u8], headers: &[(String, String)], existing_members: Option<Vec<Member>>, permission: Permission) -> std::io::Result<()> {
    let metadata = match read_metadata_headers(headers) {
        Ok(m) => m,
        Err(e) => return write_status(stream, 400, "Bad Request", e.to_string().as_bytes()),
    };

    let modifier_identity = match resolve_identity_server(root, target_identity, &metadata.modified_by) {
        Ok(i) => i,
        Err(e) => return write_status(stream, 403, "Forbidden", e.to_string().as_bytes()),
    };

    if let Err(e) = verify_metadata(&modifier_identity.public_key.value, &metadata, body) {
        return write_status(stream, 403, "Forbidden", e.to_string().as_bytes());
    }

    if let Some(old) = existing_members.as_deref() {
        if members_differ(old, &metadata.members) && permission != Permission::Owner {
            return write_status(stream, 403, "Forbidden", b"owner permission required to change members");
        }
    }

    if let Some(parent) = fs_path.parent() { fs::create_dir_all(parent)?; }

    let (status_code, status_msg) = if fs_path.exists() { (204, "No Content") } else { (201, "Created") };

    let mut file = fs::File::create(fs_path)?;
    write_metadata_attributes(fs_path, &metadata)?;
    file.write_all(body)?;
    drop(file);

    write_status(stream, status_code, status_msg, &[])
}

fn members_differ(old: &[Member], new: &[Member]) -> bool {
    if old.len() != new.len() { return true; }
    let mut old_set: Vec<(&str, Permission)> = old.iter().map(|m| (m.address.as_str(), m.permission)).collect();
    let mut new_set: Vec<(&str, Permission)> = new.iter().map(|m| (m.address.as_str(), m.permission)).collect();
    old_set.sort_by(|a, b| a.0.cmp(b.0));
    new_set.sort_by(|a, b| a.0.cmp(b.0));
    old_set != new_set
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
    use crate::types::Metadata;
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

    fn build_auth(address: &str, timestamp: u64, sig_b64: &str) -> String {
        format!(
            "ArkAccount address=\"{}\", timestamp=\"{}\", signature=\"{}\"",
            address, timestamp, sig_b64,
        )
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

    fn signed_request(port: u16, sender: &str, key: &[u8], method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        signed_request_with_headers(port, sender, key, method, path, body, &[])
    }

    fn signed_request_with_headers(port: u16, sender: &str, key: &[u8], method: &str, path: &str, body: &[u8], extra: &[(&str, &str)]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        let timestamp = now_seconds();
        let sig_b64 = sign(key, method, path, timestamp, body);
        let auth = build_auth(sender, timestamp, &sig_b64);
        let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth)];
        headers.extend_from_slice(extra);
        request(port, method, path, body, &headers)
    }

    fn signed_put_with_default_metadata(port: u16, sender: &str, key: &[u8], path: &str, body: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        let meta = write_metadata_headers(&get_default_test_metadata(key, TEST_ADDRESS, body));
        let extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        signed_request_with_headers(port, sender, key, "PUT", path, body, &extra)
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
        let (code, body, headers) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/hello.txt", &[]);
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
        let (code, _, _) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/nope.txt", &[]);
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
        let (code, body, headers) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/", &[]);
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
        let (code, body, _) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/empty/", &[]);
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
        let (code, body, _) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/", &[]);
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
        let (code, body, headers) = signed_request(port, "test@example.com", &key, "HEAD", "/ark/test/x", &[]);
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
        let (code, body, headers) = signed_request(port, "test@example.com", &key, "HEAD", "/ark/test/", &[]);
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
        let (code, _, _) = signed_put_with_default_metadata(port, "test@example.com", &key, "/ark/test/new.txt", b"payload");
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
        let (code, _, _) = signed_put_with_default_metadata(port, "test@example.com", &key, "/ark/test/x", b"new content");
        assert_eq!(code, 204);
        assert_eq!(fs::read(td.0.join("ark/test/x")).unwrap(), b"new content");
    }

    #[test]
    fn put_nested_path_creates_dirs() {
        let td = TempDir::new("ark_server_test");
        let key = [8u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_put_with_default_metadata(port, "test@example.com", &key, "/ark/test/a/b/c.txt", b"deep");
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
        let (code, _, _) = signed_request(port, "test@example.com", &key, "DELETE", "/ark/test/d.txt", &[]);
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
        let (code, _, _) = signed_request(port, "test@example.com", &key, "DELETE", "/ark/test/sub", &[]);
        assert_eq!(code, 204);
        assert!(!d.exists());
    }

    #[test]
    fn delete_missing_404() {
        let td = TempDir::new("ark_server_test");
        let key = [11u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, "test@example.com", &key, "DELETE", "/ark/test/nope", &[]);
        assert_eq!(code, 404);
    }

    #[test]
    fn unsupported_method_returns_405() {
        let td = TempDir::new("ark_server_test");
        let key = [12u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, body, _) = signed_request(port, "test@example.com", &key, "POST", "/ark/test/x", b"hello");
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
        let (code, _, _) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/link", &[]);
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
        let (code, _, _) = signed_request(port, "test@example.com", &key, "HEAD", "/ark/test/link", &[]);
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
        let (code, _, _) = signed_put_with_default_metadata(port, "test@example.com", &key, "/ark/test/link", b"clobber");
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
        let (code, _, _) = signed_request(port, "test@example.com", &key, "DELETE", "/ark/test/link", &[]);
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
        let (code, _, _) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/../../../etc/passwd", &[]);
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
        let (code, _, _) = signed_request(port, "test@example.com", &key, "PUT", "/ark/test", b"x");
        assert_eq!(code, 405);
    }

    #[test]
    fn delete_at_ark_root_405() {
        let td = TempDir::new("ark_server_test");
        let key = [15u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, "test@example.com", &key, "DELETE", "/ark/test", &[]);
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
    fn missing_timestamp_param_401() {
        let td = TempDir::new("ark_server_test");
        let key = [17u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let sig = sign(&key, "GET", "/ark/test/x", now_seconds(), &[]);
        let auth = format!("ArkAccount address=\"test@example.com\", signature=\"{}\"", sig);
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
        let auth = build_auth("test@example.com", old, &sig);
        let (code, _, _) = request(port, "GET", "/ark/test/x", &[], &[("Authorization", &auth)]);
        assert_eq!(code, 401);
    }

    #[test]
    fn wrong_signature_401() {
        let td = TempDir::new("ark_server_test");
        let key = [19u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let ts = now_seconds();
        let sig = sign(&key, "GET", "/ark/test/somethingelse", ts, &[]);
        let auth = build_auth("test@example.com", ts, &sig);
        let (code, _, _) = request(port, "GET", "/ark/test/realtarget", &[], &[("Authorization", &auth)]);
        assert_eq!(code, 401);
    }

    #[test]
    fn wrong_key_401() {
        let td = TempDir::new("ark_server_test");
        setup_account(&td.0, "test", &[20u8; 32]);
        let attacker = [99u8; 32];
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, "test@example.com", &attacker, "GET", "/ark/test/x", &[]);
        assert_eq!(code, 401);
    }

    #[test]
    fn no_identity_file_403() {
        let td = TempDir::new("ark_server_test");
        let attacker = [21u8; 32];
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, "ghost@example.com", &attacker, "GET", "/ark/ghost/x", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn created_identity_authenticates_with_server() {
        let td = TempDir::new("ark_server_test");
        create_account_with_key(&td.0, "gyan@example.com", &[77u8; 32]).unwrap();
        write_file_with_default_test_metadata(&td.0.join("ark/gyan/hello.txt"), &[77u8; 32], "gyan@example.com", b"hi gyan");
        let port = start_test_server(td.0.clone());
        let (code, body, _) = signed_request(port, "gyan@example.com", &[77u8; 32], "GET", "/ark/gyan/hello.txt", &[]);
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
        let auth = build_auth("test@example.com", ts, &sig);
        let (code, _, _) = request(port, "PUT", "/ark/test/file", b"tampered", &[("Authorization", &auth)]);
        assert_eq!(code, 401);
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
        m.members[0].wrapped_key = Some([7u8; 32].to_vec());
        sign_metadata(&alice_key, &mut m, b"ciphertext");
        let headers = write_metadata_headers(&m);
        let extra: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let (code, _, _) = signed_request_with_headers(port, "test@example.com", &key, "PUT", "/ark/test/secret", b"ciphertext", &extra);
        assert_eq!(code, 201);
        let p = td.0.join("ark/test/secret");
        assert_eq!(
            xattr::get(&p, "user.ark.encryption").unwrap().as_deref(),
            Some(b"aes-256-gcm".as_slice())
        );
        let loaded = read_metadata_attributes(&p).unwrap();
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0].address, "alice@x");
        assert_eq!(loaded.members[0].wrapped_key.as_deref(), Some(&[7u8; 32][..]));
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
        let (code, _, _) = signed_request_with_headers(port, "test@example.com", &key, "PUT", "/ark/test/file", b"x", &extra);
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

        let (code, body, headers) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/secret", &[]);
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

        let (code, _, headers) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/file", &[]);
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

        let (code, _, _) = signed_request(port, "test@example.com", &key, "GET", "/ark/test/plain", &[]);
        assert_eq!(code, 500);
    }

    #[test]
    fn put_without_meta_headers_returns_400() {
        let td = TempDir::new("ark_server_test");
        let key = [24u8; 32];
        setup_account(&td.0, "test", &key);
        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, "test@example.com", &key, "PUT", "/ark/test/plain", b"data");
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
        let (code, _, _) = signed_request_with_headers(port, "test@example.com", &key, "PUT", "/ark/test/file", b"x", &extra);
        assert_eq!(code, 201);
        let p = td.0.join("ark/test/file");
        assert_eq!(xattr::get(&p, "user.ark.foo").unwrap(), None);
    }

    fn seed_shared_file(
        td: &Path,
        owner_key: &[u8],
        owner_addr: &str,
        rel_path: &str,
        body: &[u8],
        extra_members: Vec<Member>,
    ) -> PathBuf {
        let file = td.join(rel_path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let mut m = get_default_test_metadata(owner_key, owner_addr, body);
        m.encryption = "none".to_string();
        m.members[0].wrapped_key = None;
        for member in extra_members {
            m.members.push(member);
        }
        sign_metadata(owner_key, &mut m, body);
        fs::write(&file, body).unwrap();
        write_metadata_attributes(&file, &m).unwrap();
        file
    }

    fn signed_put_metadata(
        port: u16,
        signer_address: &str,
        signer_key: &[u8],
        path: &str,
        body: &[u8],
        metadata: &Metadata,
    ) -> u16 {
        let headers = write_metadata_headers(metadata);
        let extra: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        signed_request_with_headers(port, signer_address, signer_key, "PUT", path, body, &extra).0
    }

    #[test]
    fn put_by_write_member_updates_body() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [100u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let writer_key = [101u8; 32];
        setup_account(&td.0, "writer", &writer_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"v1", vec![
            Member { address: "writer@example.com".to_string(), permission: Permission::Write, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());

        let mut new_meta = get_default_test_metadata(&writer_key, "writer@example.com", b"v2");
        new_meta.encryption = "none".to_string();
        new_meta.members = vec![
            Member { address: "owner@example.com".to_string(), permission: Permission::Owner, wrapped_key: None },
            Member { address: "writer@example.com".to_string(), permission: Permission::Write, wrapped_key: None },
        ];
        sign_metadata(&writer_key, &mut new_meta, b"v2");

        let code = signed_put_metadata(port, "writer@example.com", &writer_key, "/ark/owner/file.txt", b"v2", &new_meta);
        assert_eq!(code, 204);
        assert_eq!(fs::read(td.0.join("ark/owner/file.txt")).unwrap(), b"v2");
    }

    #[test]
    fn put_by_read_only_member_forbidden() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [102u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let reader_key = [103u8; 32];
        setup_account(&td.0, "reader", &reader_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"v1", vec![
            Member { address: "reader@example.com".to_string(), permission: Permission::Read, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());

        let mut new_meta = get_default_test_metadata(&reader_key, "reader@example.com", b"v2");
        new_meta.encryption = "none".to_string();
        new_meta.members = vec![
            Member { address: "owner@example.com".to_string(), permission: Permission::Owner, wrapped_key: None },
            Member { address: "reader@example.com".to_string(), permission: Permission::Read, wrapped_key: None },
        ];
        sign_metadata(&reader_key, &mut new_meta, b"v2");

        let code = signed_put_metadata(port, "reader@example.com", &reader_key, "/ark/owner/file.txt", b"v2", &new_meta);
        assert_eq!(code, 403);
        assert_eq!(fs::read(td.0.join("ark/owner/file.txt")).unwrap(), b"v1");
    }

    #[test]
    fn put_by_non_member_forbidden() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [104u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let stranger_key = [105u8; 32];
        setup_account(&td.0, "stranger", &stranger_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"v1", vec![]);

        let port = start_test_server(td.0.clone());

        let mut new_meta = get_default_test_metadata(&stranger_key, "stranger@example.com", b"v2");
        new_meta.encryption = "none".to_string();
        new_meta.members = vec![
            Member { address: "owner@example.com".to_string(), permission: Permission::Owner, wrapped_key: None },
        ];
        sign_metadata(&stranger_key, &mut new_meta, b"v2");

        let code = signed_put_metadata(port, "stranger@example.com", &stranger_key, "/ark/owner/file.txt", b"v2", &new_meta);
        assert_eq!(code, 403);
        assert_eq!(fs::read(td.0.join("ark/owner/file.txt")).unwrap(), b"v1");
    }

    #[test]
    fn put_member_change_by_write_member_forbidden() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [106u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let writer_key = [107u8; 32];
        setup_account(&td.0, "writer", &writer_key);
        let outsider_key = [108u8; 32];
        setup_account(&td.0, "outsider", &outsider_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"v1", vec![
            Member { address: "writer@example.com".to_string(), permission: Permission::Write, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());

        let mut new_meta = get_default_test_metadata(&writer_key, "writer@example.com", b"v2");
        new_meta.encryption = "none".to_string();
        new_meta.members = vec![
            Member { address: "owner@example.com".to_string(), permission: Permission::Owner, wrapped_key: None },
            Member { address: "writer@example.com".to_string(), permission: Permission::Write, wrapped_key: None },
            Member { address: "outsider@example.com".to_string(), permission: Permission::Read, wrapped_key: None },
        ];
        sign_metadata(&writer_key, &mut new_meta, b"v2");

        let code = signed_put_metadata(port, "writer@example.com", &writer_key, "/ark/owner/file.txt", b"v2", &new_meta);
        assert_eq!(code, 403);
        assert_eq!(fs::read(td.0.join("ark/owner/file.txt")).unwrap(), b"v1");
    }

    #[test]
    fn put_member_change_by_owner_member_succeeds() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [109u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let co_owner_key = [110u8; 32];
        setup_account(&td.0, "coowner", &co_owner_key);
        let newbie_key = [111u8; 32];
        setup_account(&td.0, "newbie", &newbie_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"v1", vec![
            Member { address: "coowner@example.com".to_string(), permission: Permission::Owner, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());

        let mut new_meta = get_default_test_metadata(&co_owner_key, "coowner@example.com", b"v2");
        new_meta.encryption = "none".to_string();
        new_meta.members = vec![
            Member { address: "owner@example.com".to_string(), permission: Permission::Owner, wrapped_key: None },
            Member { address: "coowner@example.com".to_string(), permission: Permission::Owner, wrapped_key: None },
            Member { address: "newbie@example.com".to_string(), permission: Permission::Read, wrapped_key: None },
        ];
        sign_metadata(&co_owner_key, &mut new_meta, b"v2");

        let code = signed_put_metadata(port, "coowner@example.com", &co_owner_key, "/ark/owner/file.txt", b"v2", &new_meta);
        assert_eq!(code, 204);
        assert_eq!(fs::read(td.0.join("ark/owner/file.txt")).unwrap(), b"v2");
    }

    #[test]
    fn delete_by_write_member_succeeds() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [112u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let writer_key = [113u8; 32];
        setup_account(&td.0, "writer", &writer_key);

        let file = seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"v1", vec![
            Member { address: "writer@example.com".to_string(), permission: Permission::Write, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, "writer@example.com", &writer_key, "DELETE", "/ark/owner/file.txt", &[]);
        assert_eq!(code, 204);
        assert!(!file.exists());
    }

    #[test]
    fn delete_by_read_only_member_forbidden() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [114u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let reader_key = [115u8; 32];
        setup_account(&td.0, "reader", &reader_key);

        let file = seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"v1", vec![
            Member { address: "reader@example.com".to_string(), permission: Permission::Read, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, "reader@example.com", &reader_key, "DELETE", "/ark/owner/file.txt", &[]);
        assert_eq!(code, 403);
        assert!(file.exists());
    }

    #[test]
    fn get_by_read_only_member_succeeds() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [116u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let reader_key = [117u8; 32];
        setup_account(&td.0, "reader", &reader_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"secret", vec![
            Member { address: "reader@example.com".to_string(), permission: Permission::Read, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());
        let (code, body, _) = signed_request(port, "reader@example.com", &reader_key, "GET", "/ark/owner/file.txt", &[]);
        assert_eq!(code, 200);
        assert_eq!(body, b"secret");
    }

    #[test]
    fn get_by_non_member_forbidden() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [118u8; 32];
        setup_account(&td.0, "owner", &owner_key);
        let stranger_key = [119u8; 32];
        setup_account(&td.0, "stranger", &stranger_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/file.txt", b"secret", vec![]);

        let port = start_test_server(td.0.clone());
        let (code, _, _) = signed_request(port, "stranger@example.com", &stranger_key, "GET", "/ark/owner/file.txt", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn get_public_file_no_auth_succeeds() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [120u8; 32];
        setup_account(&td.0, "owner", &owner_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/public.txt", b"open", vec![
            Member { address: "*".to_string(), permission: Permission::Read, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());
        let (code, body, _) = request(port, "GET", "/ark/owner/public.txt", &[], &[]);
        assert_eq!(code, 200);
        assert_eq!(body, b"open");
    }

    #[test]
    fn head_public_file_no_auth_succeeds() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [121u8; 32];
        setup_account(&td.0, "owner", &owner_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/public.txt", b"open", vec![
            Member { address: "*".to_string(), permission: Permission::Read, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());
        let (code, body, headers) = request(port, "HEAD", "/ark/owner/public.txt", &[], &[]);
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert_eq!(header(&headers, "content-length"), Some("4"));
    }

    #[test]
    fn get_public_file_ignores_bad_auth() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [122u8; 32];
        setup_account(&td.0, "owner", &owner_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/public.txt", b"open", vec![
            Member { address: "*".to_string(), permission: Permission::Read, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());
        let (code, body, _) = request(port, "GET", "/ark/owner/public.txt", &[], &[
            ("Authorization", "ArkAccount address=\"nobody@x\", timestamp=\"0\", signature=\"AAAA\""),
        ]);
        assert_eq!(code, 200);
        assert_eq!(body, b"open");
    }

    #[test]
    fn put_public_file_no_auth_still_unauthorized() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [123u8; 32];
        setup_account(&td.0, "owner", &owner_key);

        seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/public.txt", b"open", vec![
            Member { address: "*".to_string(), permission: Permission::Read, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());
        let (code, _, _) = request(port, "PUT", "/ark/owner/public.txt", b"clobber", &[]);
        assert_eq!(code, 401);
        assert_eq!(fs::read(td.0.join("ark/owner/public.txt")).unwrap(), b"open");
    }

    #[test]
    fn delete_public_file_no_auth_still_unauthorized() {
        let td = TempDir::new("ark_server_test");
        let owner_key = [124u8; 32];
        setup_account(&td.0, "owner", &owner_key);

        let file = seed_shared_file(&td.0, &owner_key, "owner@example.com", "ark/owner/public.txt", b"open", vec![
            Member { address: "*".to_string(), permission: Permission::Read, wrapped_key: None },
        ]);

        let port = start_test_server(td.0.clone());
        let (code, _, _) = request(port, "DELETE", "/ark/owner/public.txt", &[], &[]);
        assert_eq!(code, 401);
        assert!(file.exists());
    }
}
