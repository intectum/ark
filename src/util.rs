use std::io;
use std::path::{Component, Path};

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::crypto::sign_bytes;
use crate::http::{read_request, read_response};
use crate::metadata::{verify_metadata, verify_metadata_signature};
use crate::storage::to_account_path_raw;
use crate::types::{Context, Key, Metadata, RequestEntry};

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
pub fn resolve_address(ctx: &Context, path: &str) -> io::Result<String> {
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

pub fn resolve_client_url(ctx: &Context, path: &str) -> io::Result<Url> {
    resolve_client_url_raw(&ctx.root, path, &ctx.identity.address)
}

pub fn resolve_client_url_raw(root: &Path, path: &str, address: &str) -> io::Result<Url> {
    let mut s = path.to_string();
    if !s.contains('@') {
        s = format!("{}{}", address, to_account_path_raw(root, &s)?);
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

pub fn create_authorization_header(ctx: &Context, method: &str, host: &str, path: &str, timestamp: u64, body: &[u8]) -> io::Result<String> {
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

/// Validate a change received from another node, against the copy of the file
/// it replaces.
///
/// Checks that the metadata is signed by the account that made the change and
/// matches the body that arrived with it, and that `existing_metadata` — the
/// copy being replaced, where there is one — is being continued rather than
/// overwritten by an unrelated or older file.
///
/// Whether the change is a directory is taken from the metadata, which carries
/// a `body_hash` only for a file. A change may not turn one into the other.
///
/// `body` is what arrived with the metadata. `None` on a directory, which has
/// no body; `None` on a file means the change keeps the body the existing copy
/// already has, so only the signature is checked and `existing_metadata` is
/// required.
///
/// `Err` carries the kind the rejection corresponds to, as
/// [`crate::http::error_response_code`] maps it: `InvalidData` where the
/// metadata does not verify or is malformed, `NotFound` where the copy it
/// continues is missing, `AlreadyExists` where it loses to the copy already
/// held.
///
/// Whether the modifier was allowed to change the members is not covered: that
/// needs the authoritative member list, which only the account's own server
/// holds.
pub fn validate_update(
    modifier_public_key: &Key,
    metadata: &Metadata,
    existing_metadata: Option<&Metadata>,
    body: Option<&[u8]>,
) -> io::Result<()> {
    let is_dir = metadata.body_hash.is_none();

    if body.is_none() && !is_dir {
        let existing_metadata = match existing_metadata {
            Some(m) => m,
            None => return Err(io::Error::new(io::ErrorKind::NotFound, "metadata-only update requires existing file")),
        };

        let new_hash = metadata.body_hash.as_ref().map(|h| &h.value);
        let old_hash = existing_metadata.body_hash.as_ref().map(|h| &h.value);
        if new_hash != old_hash {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "metadata-only update must not change body_hash"));
        }

        verify_metadata_signature(modifier_public_key, metadata)?;
    } else {
        verify_metadata(modifier_public_key, metadata, body)?;
    }

    if let Some(existing_metadata) = existing_metadata {
        if existing_metadata.id != metadata.id {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "id is wrong"));
        }
        if existing_metadata.body_hash.is_none() != is_dir {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, if is_dir { "existing is a file" } else { "existing is a dir" }));
        }
        if metadata.modified < existing_metadata.modified {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "modified is older than existing"));
        }
    }

    Ok(())
}

/// The UUID `value` spells.
///
/// Only the plain hyphenated lowercase form is accepted — the braced, URN and
/// unhyphenated forms parse as UUIDs but carry characters, or a case, that a
/// value read from outside is not expected to use, and such a value may become
/// a path segment.
pub fn parse_uuid(value: &str) -> io::Result<Uuid> {
    let uuid = Uuid::try_parse(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("not a uuid: {}", value)))?;

    if uuid.hyphenated().to_string() != value {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("uuid is not hyphenated lowercase: {}", value)));
    }

    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    #[test]
    fn parse_uuid_accepts_only_the_plain_hyphenated_lowercase_form() {
        let id = "0f3e1c62-9a4b-4d7e-8c11-2b5a6d9e4f30";
        assert_eq!(parse_uuid(id).unwrap().hyphenated().to_string(), id);
        assert!(parse_uuid(&format!("{{{}}}", id)).is_err());
        assert!(parse_uuid(&format!("urn:uuid:{}", id)).is_err());
        assert!(parse_uuid(&id.replace('-', "")).is_err());
        assert!(parse_uuid(&id.to_uppercase()).is_err());
        assert!(parse_uuid("../../etc").is_err());
        assert!(parse_uuid("").is_err());
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
