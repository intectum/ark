use std::env::current_dir;
use std::fs;
use std::io;
use std::io::{Error, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

use crate::crypto::sign_bytes;
use crate::http::{read_request, read_response};
use crate::types::{IdentityContext, RequestEntry};

pub fn find_account_root() -> io::Result<PathBuf> {
    let current = current_dir()?;

    let mut root = current.as_path();
    while !fs::exists(root.join(".ark"))? {
        root = root
            .parent()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "no .ark dir found"))?;
    }

    Ok(root.to_path_buf())
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
        .map_err(|e| io_invalid_input(&format!("invalid URL {}: {}", path, e)))?;

    if !had_scheme && url.host_str().map(is_loopback_host).unwrap_or(false) {
        url.set_scheme("http").expect("http is a valid scheme");
    }

    url.set_path(&format!("/ark/{}{}", url.username(), url.path()));

    reject_path_traversal(&url)?;

    Ok(url)
}

pub fn resolve_server_url(path: &str) -> io::Result<Url> {
    let url = Url::parse(&format!("http://localhost{}", path))
        .map_err(|e| io_invalid_input(&format!("invalid URL {}: {}", path, e)))?;

    reject_path_traversal(&url)?;

    Ok(url)
}

pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn reject_path_traversal(url: &Url) -> io::Result<()> {
    for component in Path::new(url.path()).components() {
        if matches!(component, Component::ParentDir) {
            return Err(io_invalid_input("path traversal not allowed"));
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
        .ok_or_else(|| io_err("no header separator"))?;

    let request_bytes = &entry_bytes[..boundary];
    let response_bytes = &entry_bytes[boundary + 4..];

    let (method, target, request_headers, _) = read_request(&mut &request_bytes[..], true)?;
    let (status, _, _) = read_response(&mut &response_bytes[..], true)?;

    Ok(RequestEntry { method, target, request_headers, status })
}

pub fn create_authorization_header(ctx: &IdentityContext, method: &str, host: &str, path: &str, timestamp: u64, body: &[u8]) -> io::Result<String> {
    let identity_key = ctx.identity_key.as_ref().ok_or_else(|| io_err("context missing identity_key"))?;
    let request_bytes = request_to_bytes(method, host, path, timestamp, body);
    let signature = sign_bytes(identity_key, &request_bytes)?;
    Ok(format!(
        "ArkIdentity address=\"{}\", timestamp=\"{}\", signature=\"{}\"",
        ctx.identity.address,
        timestamp,
        encode_base64url(signature.value),
    ))
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

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

pub fn now_iso() -> String {
    let millis = now();
    let secs = (millis / 1000) as i64;
    let sub_millis = (millis % 1000) as u16;
    let dt = time::OffsetDateTime::from_unix_timestamp(secs).expect("valid unix timestamp");
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        dt.year(), dt.month() as u8, dt.day(), dt.hour(), dt.minute(), dt.second(), sub_millis
    )
}

pub fn now_iso_fs() -> String {
    now_iso().replace(':', "-")
}

pub fn io_err(s: &str) -> Error {
    Error::other(s.to_string())
}

pub fn io_invalid_input(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidInput, msg.to_string())
}

#[cfg(test)]
pub mod test {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::client::init_local;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_secret_key, encrypt_bytes};
    use crate::context::create_client_context;
    use crate::identity::{parse_address, write_identity};
    use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
    use crate::types::{IdentityContext, Identity, Key, Metadata};

    static CWD_LOCK: Mutex<()> = Mutex::new(());
    pub const TEST_ADDRESS: &str = "test@example.com";

    pub fn in_test_dir<R>(prefix: &str, f: impl FnOnce(&Path) -> R) -> R {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = env::current_dir().unwrap_or_else(|_| env::temp_dir());

        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = env::temp_dir().join(format!("{}_{}_{}", prefix, process::id(), nanos));
        fs::create_dir_all(&dir).unwrap();

        struct Cleanup(PathBuf, PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = env::set_current_dir(&self.0);
                let _ = fs::remove_dir_all(&self.1);
            }
        }
        let _cleanup = Cleanup(prev, dir.clone());

        env::set_current_dir(&dir).unwrap();
        f(&dir)
    }

    pub fn create_test_account(temp_dir: &Path, address: &str) -> (Identity, Key, PathBuf) {
        let (name, _, _) = parse_address(address).unwrap();
        let account_dir = temp_dir.join("ark").join(&name);
        fs::create_dir_all(&account_dir).unwrap();
        let (identity, secret_key) = init_local(&account_dir, address).unwrap();
        (identity, secret_key, account_dir)
    }

    pub fn init_with_server(temp_dir: &Path, address: &str) -> IdentityContext {
        let (identity, _) = init_local(temp_dir, address).unwrap();
        let (name, _, _) = parse_address(address).unwrap();
        let server_dot_ark = temp_dir.join("ark").join(&name).join(".ark");
        fs::create_dir_all(&server_dot_ark).unwrap();
        write_identity(&server_dot_ark.join("identity.json"), &identity).unwrap();
        create_client_context().unwrap()
    }

    pub fn create_plain_test_metadata(owner: &Identity, owner_key: &Key, body: &[u8]) -> Metadata {
        let mut metadata = create_metadata(&owner.address, None);
        sign_metadata(owner_key, &mut metadata, Some(body)).unwrap();

        metadata
    }

    pub fn write_plain_test_file(path: &Path, owner: &Identity, owner_key: &Key, body: &[u8]) {
        let metadata = create_plain_test_metadata(owner, owner_key, body);
        fs::write(path, body).unwrap();
        write_metadata_attributes(path, &metadata).unwrap();
    }

    pub fn create_encrypted_test_metadata(owner: &Identity, owner_key: &Key, plaintext: &[u8]) -> (Metadata, Vec<u8>) {
        let mut metadata = create_metadata(&owner.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
        let file_key = create_secret_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
        let (_, ciphertext) = encrypt_bytes(&file_key, plaintext).unwrap();
        let (wrap_alg, wrapped) = encrypt_bytes(&owner.public_key, &file_key.value).unwrap();
        metadata.members[0].key = Some(Key { algorithm: wrap_alg, value: wrapped });
        sign_metadata(owner_key, &mut metadata, Some(&ciphertext)).unwrap();
        (metadata, ciphertext)
    }

    pub fn write_encrypted_test_file(path: &Path, owner: &Identity, owner_key: &Key, plaintext: &[u8]) {
        let (metadata, ciphertext) = create_encrypted_test_metadata(owner, owner_key, plaintext);
        fs::write(path, ciphertext).unwrap();
        write_metadata_attributes(path, &metadata).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

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
