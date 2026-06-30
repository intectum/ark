use std::env;
use std::io::{Error, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

pub fn find_root(cwd: &Path) -> std::io::Result<PathBuf> {
    let mut root = cwd;
    while !std::fs::exists(root.join(".ark"))? {
        root = root
            .parent()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "no .ark dir found"))?;
    }
    Ok(root.to_path_buf())
}

pub fn resolve_url(
    input: &str,
    address: &str,
    account_dir: &Path,
    is_server: bool,
) -> std::io::Result<Url> {
    let raw = if is_server {
        format!("http://localhost{}", input)
    } else {
        let mut s = input.to_string();
        if !s.contains('@') {
            if !s.starts_with('/') {
                let cwd = env::current_dir()?;
                let rel = cwd.strip_prefix(account_dir).unwrap_or(Path::new("")).to_string_lossy();
                s = match rel.as_ref() {
                    "" => format!("/{}", s),
                    _ => format!("/{}/{}", rel, s),
                };
            }
            s = format!("{}{}", address, s);
        }
        if !s.contains("://") {
            s = format!("https://{}", s);
        }
        s
    };

    let mut url = Url::parse(&raw)
        .map_err(|e| io_invalid_input(&format!("invalid URL {}: {}", input, e)))?;

    if !is_server {
        url.set_path(&format!("/ark/{}{}", url.username(), url.path()));
    }

    for component in Path::new(url.path()).components() {
        if matches!(component, Component::ParentDir) {
            return Err(io_invalid_input("path traversal not allowed"));
        }
    }

    Ok(url)
}

pub fn request_to_bytes(method: &str, path: &str, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let timestamp_string = timestamp.to_string();
    let mut bytes = Vec::with_capacity(method.len() + path.len() + timestamp_string.len() + body.len() + 3);
    bytes.extend_from_slice(method.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(timestamp_string.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(body);
    bytes
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

pub fn now_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn now_iso() -> String {
    let timestamp = time::OffsetDateTime::from_unix_timestamp(now_seconds() as i64).expect("valid unix timestamp");
    timestamp.format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 format")
}

pub fn io_err(s: &str) -> Error {
    Error::new(ErrorKind::Other, s.to_string())
}

pub fn io_invalid_input(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidInput, msg.to_string())
}

#[cfg(test)]
pub mod test {
    use std::env;
    use std::fs;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::metadata::{sign_metadata, write_metadata_attributes};
    use crate::types::{Hash, Member, Metadata, Signature};

    static CWD_LOCK: Mutex<()> = Mutex::new(());

    pub fn with_cwd<R>(dir: &Path, f: impl FnOnce() -> R) -> R {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = env::current_dir().unwrap_or_else(|_| env::temp_dir());

        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = env::set_current_dir(&self.0);
            }
        }
        let _restore = Restore(prev);

        env::set_current_dir(dir).unwrap();
        f()
    }

    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let p = env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub fn bind_local() -> (TcpListener, u16) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    pub const TEST_ADDRESS: &str = "test@example.com";

    pub fn get_default_test_metadata(key: &[u8], address: &str, body: &[u8]) -> crate::types::Metadata {
        let mut m = Metadata {
            id: "00000000-0000-0000-0000-000000000001".to_string(),
            modified_by: address.to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            modified: "2026-01-01T00:00:00Z".to_string(),
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![Member {
                address: address.to_string(),
                permission: "owner".to_string(),
                wrapped_key: [2u8; 32].to_vec(),
            }],
            body_hash: Hash { algorithm: String::new(), value: Vec::new() },
            signature: Signature { algorithm: String::new(), value: Vec::new() },
        };
        sign_metadata(key, &mut m, body);
        m
    }

    pub fn write_file_with_default_test_metadata(path: &Path, key: &[u8], address: &str, body: &[u8]) {
        fs::write(path, body).unwrap();
        write_metadata_attributes(path, &get_default_test_metadata(key, address, body)).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_url_absolute() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_url("/path/to/file.txt", "gyan@127.0.0.1:8080", Path::new(account_dir), false).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/ark/gyan/path/to/file.txt");
    }

    #[test]
    fn resolve_url_relative_at_account_root() {
        let account_dir = env::current_dir().unwrap();
        let url = resolve_url("path/to/file.txt", "gyan@127.0.0.1:8080", &account_dir, false).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/ark/gyan/path/to/file.txt");
    }

    #[test]
    fn resolve_url_relative_in_subdir() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let dir = cwd.file_name().unwrap();
        let url = resolve_url("path/to/file.txt", "gyan@127.0.0.1:8080", account_dir, false).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), format!("/ark/gyan/{}{}", dir.to_string_lossy(), "/path/to/file.txt"));
    }

    #[test]
    fn resolve_url_address_with_path() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_url("alice@example.com/path/to/file.txt", "gyan@127.0.0.1:8080", account_dir, false).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/ark/alice/path/to/file.txt");
    }

    #[test]
    fn resolve_url_address_with_scheme_and_port_and_path() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_url("http://alice@example.com:9000/path/to/file.txt", "gyan@127.0.0.1:8080", account_dir, false).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), Some(9000));
        assert_eq!(url.path(), "/ark/alice/path/to/file.txt");
    }

    #[test]
    fn resolve_url_address_only() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_url("alice@example.com", "gyan@127.0.0.1:8080", account_dir, false).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/ark/alice/");
    }

    #[test]
    fn resolve_url_server_localhost() {
        let url = resolve_url("/ark/gyan/notes.txt", "", Path::new(""), true).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.path(), "/ark/gyan/notes.txt");
    }

    #[test]
    fn resolve_url_server_strips_query() {
        let url = resolve_url("/ark/gyan/notes.txt?x=1", "", Path::new(""), true).unwrap();
        assert_eq!(url.path(), "/ark/gyan/notes.txt");
    }
}
