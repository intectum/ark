use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::crypto::{DEFAULT_SIGNING_ALGORITHM, sign_bytes};
use crate::metadata::{sign_metadata, write_metadata_attributes, write_metadata_headers};
use crate::types::{Identity, Key, Member, Metadata};
use crate::util::{encode_base64url, now_seconds, request_to_bytes};
use crate::util::test::create_plain_test_metadata;

pub fn test_host(port: u16) -> String {
    format!("127.0.0.1:{}", port)
}

pub fn sign(key: &[u8], port: u16, method: &str, path: &str, ts: u64, body: &[u8]) -> String {
    let bytes = request_to_bytes(method, &test_host(port), path, ts, body);
    encode_base64url(sign_bytes(&Key { algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(), value: key.to_vec() }, &bytes).unwrap().value)
}

pub fn build_auth(address: &str, timestamp: u64, sig_b64: &str) -> String {
    format!(
        "ArkAccount address=\"{}\", timestamp=\"{}\", signature=\"{}\"",
        address, timestamp, sig_b64,
    )
}

pub fn request(port: u16, method: &str, path: &str, body: &[u8], extra: &[(&str, &str)]) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = format!("{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n", method, path, test_host(port), body.len());
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

pub fn signed_request(port: u16, requestor: &Identity, secret_key: &Key, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
    signed_request_with_headers(port, requestor, secret_key, method, path, body, &[])
}

pub fn signed_request_with_headers(port: u16, requestor: &Identity, secret_key: &Key, method: &str, path: &str, body: &[u8], extra: &[(&str, &str)]) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let timestamp = now_seconds();
    let sig_b64 = sign(&secret_key.value, port, method, path, timestamp, body);
    let auth = build_auth(&requestor.address, timestamp, &sig_b64);
    let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth)];
    headers.extend_from_slice(extra);
    request(port, method, path, body, &headers)
}

pub fn signed_put_with_default_metadata(port: u16, requestor: &Identity, secret_key: &Key, path: &str, body: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let meta = write_metadata_headers(&create_plain_test_metadata(requestor, secret_key, body));
    let extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    signed_request_with_headers(port, requestor, secret_key, "PUT", path, body, &extra)
}

pub fn header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

pub fn seed_shared_file(
    td: &Path,
    owner: &Identity,
    owner_secret_key: &Key,
    rel_path: &str,
    body: &[u8],
    extra_members: Vec<Member>,
) -> PathBuf {
    let file = td.join(rel_path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    let mut m = create_plain_test_metadata(owner, owner_secret_key, body);
    m.encryption_algorithm = None;
    m.members[0].key = None;
    for member in extra_members {
        m.members.push(member);
    }
    sign_metadata(owner_secret_key, &mut m, Some(body)).unwrap();
    fs::write(&file, body).unwrap();
    write_metadata_attributes(&file, &m).unwrap();
    file
}

pub fn seed_shared_dir(
    td: &Path,
    owner: &Identity,
    owner_secret_key: &Key,
    rel_path: &str,
    extra_members: Vec<Member>,
) -> PathBuf {
    let dir = td.join(rel_path);
    fs::create_dir_all(&dir).unwrap();
    let mut m = create_plain_test_metadata(owner, owner_secret_key, b"");
    m.encryption_algorithm = None;
    m.members[0].key = None;
    for member in extra_members {
        m.members.push(member);
    }
    sign_metadata(owner_secret_key, &mut m, None).unwrap();
    write_metadata_attributes(&dir, &m).unwrap();
    dir
}

pub fn signed_put_dir_metadata(
    port: u16,
    signer: &Identity,
    signer_key: &Key,
    path: &str,
    metadata: &Metadata,
) -> u16 {
    signed_put_dir_metadata_with_headers(port, signer, signer_key, path, metadata, &[])
}

pub fn signed_put_dir_metadata_with_headers(
    port: u16,
    signer: &Identity,
    signer_key: &Key,
    path: &str,
    metadata: &Metadata,
    extra: &[(&str, &str)],
) -> u16 {
    let headers = write_metadata_headers(metadata);
    let mut all: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    all.extend_from_slice(extra);
    signed_request_with_headers(port, signer, signer_key, "PUT", path, b"", &all).0
}

pub fn signed_put_metadata(
    port: u16,
    signer: &Identity,
    signer_key: &Key,
    path: &str,
    body: &[u8],
    metadata: &Metadata,
) -> u16 {
    signed_put_metadata_with_headers(port, signer, signer_key, path, body, metadata, &[])
}

pub fn signed_put_metadata_with_headers(
    port: u16,
    signer: &Identity,
    signer_key: &Key,
    path: &str,
    body: &[u8],
    metadata: &Metadata,
    extra: &[(&str, &str)],
) -> u16 {
    let headers = write_metadata_headers(metadata);
    let mut all: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    all.extend_from_slice(extra);
    signed_request_with_headers(port, signer, signer_key, "PUT", path, body, &all).0
}
