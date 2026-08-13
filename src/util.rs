use std::env::current_dir;
use std::io;
use std::path::{Component, Path, PathBuf};

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

use crate::crypto::sign_bytes;
use crate::http::{read_request, read_response};
use crate::identity::parse_address;
use crate::types::{IdentityContext, RequestEntry};

/// Expand a CLI/library path argument into a fully-qualified address string
/// (`name@host[:port][/path]`).
///
/// Accepts the three forms used by put/get/list/identity:
/// - relative: `team.json` (cwd relative to account root)
/// - account-absolute: `/groups/team.json`
/// - address form: `bob@host/team.json` (optional scheme)
///
/// Relative and account-absolute forms take name/host from `ctx.identity.address`.
/// An omitted path stays omitted.
pub fn resolve_address(ctx: &IdentityContext, path: &str) -> io::Result<String> {
    let url = resolve_client_url(ctx, path)?;

    let name = url.username();
    let host = match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap_or(""), port),
        None => url.host_str().unwrap_or("").to_string(),
    };
    let account_path = url.path()
        .strip_prefix(&format!("/ark/{}", name)).unwrap_or("")
        .trim_end_matches('/');

    Ok(format!("{}@{}{}", name, host, account_path))
}

pub fn resolve_client_url(ctx: &IdentityContext, path: &str) -> io::Result<Url> {
    resolve_client_url_raw(&ctx.root, path, &ctx.identity.address)
}

pub fn resolve_client_url_raw(root: &Path, path: &str, address: &str) -> io::Result<Url> {
    let mut s = path.to_string();
    if !s.contains('@') {
        if !s.starts_with('/') {
            let cwd = current_dir()?;
            let rel = cwd.strip_prefix(root).unwrap_or(Path::new("")).to_string_lossy();
            s = match rel.as_ref() {
                "" => format!("/{}", s),
                _ => format!("/{}/{}", rel, s),
            };
        }
        s = format!("{}{}", address, s);
    }
    let had_scheme = s.contains("://");
    if !had_scheme {
        s = format!("https://{}", s);
    }

    let mut url = Url::parse(&s)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid URL {}: {}", path, e)))?;

    if !had_scheme && url.host_str().map(is_loopback_host).unwrap_or(false) {
        url.set_scheme("http").expect("http is a valid scheme");
    }

    url.set_path(&format!("/ark/{}{}", url.username(), url.path()));

    reject_path_traversal(&url)?;

    Ok(url)
}

pub fn resolve_local_path(ctx: &IdentityContext, path: &str) -> io::Result<PathBuf> {
    let rel = if path.contains('@') {
        let (_, _, path_part) = parse_address(path)?;
        path_part.trim_start_matches('/').to_string()
    } else if path.starts_with('/') {
        path.trim_start_matches('/').to_string()
    } else {
        return Ok(PathBuf::from(path));
    };

    Ok(ctx.root.join(rel))
}

pub fn resolve_server_url(path: &str) -> io::Result<Url> {
    let url = Url::parse(&format!("http://localhost{}", path))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid URL {}: {}", path, e)))?;

    reject_path_traversal(&url)?;

    Ok(url)
}

pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn reject_path_traversal(url: &Url) -> io::Result<()> {
    for component in Path::new(url.path()).components() {
        if matches!(component, Component::ParentDir) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path traversal not allowed"));
        }
    }

    Ok(())
}

pub fn request_to_bytes(method: &str, host: &str, path: &str, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let host_lower = host.to_ascii_lowercase();
    let timestamp_string = timestamp.to_string();
    let mut bytes = Vec::with_capacity(method.len() + host_lower.len() + path.len() + timestamp_string.len() + body.len() + 4);
    bytes.extend_from_slice(method.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(host_lower.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(timestamp_string.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(body);
    bytes
}

pub fn parse_request_entry(entry_bytes: &[u8]) -> io::Result<RequestEntry> {
    let boundary = entry_bytes.windows(4).position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no header separator"))?;

    let request_bytes = &entry_bytes[..boundary];
    let response_bytes = &entry_bytes[boundary + 4..];

    let (method, target, request_headers, _) = read_request(&mut &request_bytes[..], true)?;
    let (status, _, _) = read_response(&mut &response_bytes[..], true)?;

    Ok(RequestEntry { method, target, request_headers, status })
}

pub fn create_authorization_header(ctx: &IdentityContext, method: &str, host: &str, path: &str, timestamp: u64, body: &[u8]) -> io::Result<String> {
    let identity_key = ctx.identity_key.as_ref().ok_or_else(|| io::Error::other("context missing identity_key"))?;
    let request_bytes = request_to_bytes(method, host, path, timestamp, body);
    let signature = sign_bytes(identity_key, &request_bytes)?;
    Ok(format_authorization_header(
        &ctx.identity.address,
        timestamp,
        &encode_base64url(signature.value),
    ))
}

pub fn format_authorization_header(address: &str, timestamp: u64, signature_b64: &str) -> String {
    format!(
        "ArkIdentity address=\"{}\", timestamp=\"{}\", signature=\"{}\"",
        address, timestamp, signature_b64,
    )
}

pub fn parse_authorization_header(value: &str) -> Option<(String, String, String)> {
    let mut address = None;
    let mut timestamp = None;
    let mut signature = None;

    let rest = value.strip_prefix("ArkIdentity ")?.trim();
    for part in rest.split(',') {
        let (key, value) = part.trim().split_once('=')?;
        let value = value.trim().trim_matches('"').to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "address" => address = Some(value),
            "timestamp" => timestamp = Some(value),
            "signature" => signature = Some(value),
            _ => {},
        }
    }

    Some((address?, timestamp?, signature?))
}

pub fn encode_base64url<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub fn decode_base64url<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    use crate::client::init_local;
    use crate::context::create_client_context;
    use crate::testing::fs::in_test_dir;

    #[test]
    fn resolve_local_path_address_without_path_is_account_root() {
        in_test_dir("ark_util_test", |temp_dir| {
            init_local(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let path = resolve_local_path(&ctx, "bob@example.com").unwrap();
            assert_eq!(path, ctx.root);
        });
    }

    #[test]
    fn resolve_local_path_address_with_path_is_under_account_root() {
        in_test_dir("ark_util_test", |temp_dir| {
            init_local(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let path = resolve_local_path(&ctx, "bob@example.com/notes/todo.txt").unwrap();
            assert_eq!(path, ctx.root.join("notes/todo.txt"));
        });
    }

    #[test]
    fn resolve_url_absolute() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_client_url_raw(Path::new(account_dir), "/path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/ark/gyan/path/to/file.txt");
    }

    #[test]
    fn resolve_url_relative_at_account_root() {
        let account_dir = env::current_dir().unwrap();
        let url = resolve_client_url_raw(&account_dir, "path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/ark/gyan/path/to/file.txt");
    }

    #[test]
    fn resolve_url_relative_in_subdir() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let dir = cwd.file_name().unwrap();
        let url = resolve_client_url_raw(account_dir, "path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), format!("/ark/gyan/{}{}", dir.to_string_lossy(), "/path/to/file.txt"));
    }

    #[test]
    fn resolve_url_address_with_path() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_client_url_raw(account_dir, "alice@example.com/path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/ark/alice/path/to/file.txt");
    }

    #[test]
    fn resolve_url_address_with_scheme_and_port_and_path() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_client_url_raw(account_dir, "http://alice@example.com:9000/path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), Some(9000));
        assert_eq!(url.path(), "/ark/alice/path/to/file.txt");
    }

    #[test]
    fn resolve_url_address_only() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_client_url_raw(account_dir, "alice@example.com", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/ark/alice/");
    }

    #[test]
    fn resolve_url_loopback_address_defaults_to_http() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_client_url_raw(account_dir, "alice@localhost:9000/x", "gyan@example.com").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.port(), Some(9000));
    }

    #[test]
    fn resolve_url_explicit_https_on_loopback_preserved() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_client_url_raw(account_dir, "https://alice@127.0.0.1:9000/x", "gyan@example.com").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
    }

    #[test]
    fn resolve_url_server_localhost() {
        let url = resolve_server_url("/ark/gyan/notes.txt").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.path(), "/ark/gyan/notes.txt");
    }

    #[test]
    fn resolve_url_server_strips_query() {
        let url = resolve_server_url("/ark/gyan/notes.txt?x=1").unwrap();
        assert_eq!(url.path(), "/ark/gyan/notes.txt");
    }
}
