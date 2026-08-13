use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use std::time::Duration;

use crate::crypto::{DEFAULT_SIGNING_ALGORITHM, sign_bytes};
use crate::http::read_response;
use crate::metadata::{sign_metadata, write_metadata_attributes, write_metadata_headers};
pub use crate::server::start_test_server;
use crate::testing::fs::create_plain_test_metadata;
use crate::timestamp;
use crate::types::{Identity, Key, Member, Metadata};
use crate::util::{encode_base64url, request_to_bytes};
pub use crate::util::format_authorization_header;

pub fn test_host(port: u16) -> String {
    format!("127.0.0.1:{}", port)
}

/// Sign a request with a raw key (for negative auth tests that skip a full context).
pub fn sign_request(key: &[u8], port: u16, method: &str, path: &str, ts: u64, body: &[u8]) -> String {
    let bytes = request_to_bytes(method, &test_host(port), path, ts, body);
    encode_base64url(
        sign_bytes(
            &Key {
                algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(),
                value: key.to_vec(),
            },
            &bytes,
        )
        .unwrap()
        .value,
    )
}

pub fn request(port: u16, method: &str, path: &str, body: &[u8], extra: &[(&str, &str)]) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        method,
        path,
        test_host(port),
        body.len()
    );
    for (key, value) in extra {
        head.push_str(&format!("{}: {}\r\n", key, value));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    if !body.is_empty() {
        stream.write_all(body).unwrap();
    }
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end");
    let header_str = from_utf8(&buf[..split]).unwrap();
    let body_bytes = buf[split + 4..].to_vec();
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap();
    let code: u16 = status_line.split_whitespace().nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    (code, body_bytes, headers)
}

pub fn signed_request(
    port: u16,
    requestor: &Identity,
    secret_key: &Key,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    signed_request_with_headers(port, requestor, secret_key, method, path, body, &[])
}

pub fn signed_request_with_headers(
    port: u16,
    requestor: &Identity,
    secret_key: &Key,
    method: &str,
    target: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let sign_path = target.split_once('?').map(|(path, _)| path).unwrap_or(target);
    let ts = timestamp::now_ms();
    let sig_b64 = sign_request(&secret_key.value, port, method, sign_path, ts, body);
    let auth = format_authorization_header(&requestor.address, ts, &sig_b64);
    let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth)];
    headers.extend_from_slice(extra);
    request(port, method, target, body, &headers)
}

/// Open an SSE subscription to `path` and return its status and headers. The
/// connection is closed before returning, so no events are read.
pub fn signed_stream_request(
    port: u16,
    requestor: &Identity,
    secret_key: &Key,
    path: &str,
) -> (u16, Vec<(String, String)>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let ts = timestamp::now_ms();
    let sig_b64 = sign_request(&secret_key.value, port, "GET", path, ts, &[]);
    let auth = format_authorization_header(&requestor.address, ts, &sig_b64);
    let head = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nAuthorization: {}\r\nAccept: text/event-stream\r\n\r\n",
        path,
        test_host(port),
        auth
    );
    stream.write_all(head.as_bytes()).unwrap();

    // Skip the body: an accepted subscription never sends one that ends.
    let (code, headers, _) = read_response(&mut stream, true).unwrap();
    let headers = headers.into_iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .collect();

    (code, headers)
}

pub fn signed_put_with_default_metadata(
    port: u16,
    requestor: &Identity,
    secret_key: &Key,
    path: &str,
    body: &[u8],
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let meta = write_metadata_headers(&create_plain_test_metadata(requestor, secret_key, body));
    let extra: Vec<(&str, &str)> = meta.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
    signed_request_with_headers(port, requestor, secret_key, "PUT", path, body, &extra)
}

pub fn header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str())
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
    let mut metadata = create_plain_test_metadata(owner, owner_secret_key, body);
    metadata.encryption_algorithm = None;
    metadata.members[0].key = None;
    for member in extra_members {
        metadata.members.push(member);
    }
    sign_metadata(owner_secret_key, &mut metadata, Some(body)).unwrap();
    fs::write(&file, body).unwrap();
    write_metadata_attributes(&file, &metadata).unwrap();
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
    let mut metadata = create_plain_test_metadata(owner, owner_secret_key, b"");
    metadata.encryption_algorithm = None;
    metadata.members[0].key = None;
    for member in extra_members {
        metadata.members.push(member);
    }
    sign_metadata(owner_secret_key, &mut metadata, None).unwrap();
    write_metadata_attributes(&dir, &metadata).unwrap();
    dir
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
    let mut all: Vec<(&str, &str)> = headers.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
    all.extend_from_slice(extra);
    signed_request_with_headers(port, signer, signer_key, "PUT", path, body, &all).0
}
