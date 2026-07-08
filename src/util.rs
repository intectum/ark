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
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::client::create_account;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_key, encrypt_bytes};
    use crate::metadata::{apply_key_to_metadata, create_metadata, sign_metadata, write_metadata_attributes};
    use crate::types::{Identity, Key, Metadata};

    static CWD_LOCK: Mutex<()> = Mutex::new(());
    pub const TEST_ADDRESS: &str = "test@example.com";

    pub fn in_test_dir<R>(prefix: &str, f: impl FnOnce(&Path) -> R) -> R {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = env::current_dir().unwrap_or_else(|_| env::temp_dir());

        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos));
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
        let (identity, secret_key) = create_account(temp_dir, address).unwrap();
        let name = address.split_once('@').unwrap().0;
        (identity, secret_key, temp_dir.join("ark").join(name))
    }

    pub fn create_plain_test_metadata(owner: &Identity, owner_key: &Key, body: &[u8]) -> Metadata {
        let mut metadata = create_metadata(&owner.address, None);
        sign_metadata(owner_key, &mut metadata, body).unwrap();

        metadata
    }

    pub fn write_plain_test_file(path: &Path, owner: &Identity, owner_key: &Key, body: &[u8]) {
        let metadata = create_plain_test_metadata(owner, owner_key, body);
        fs::write(path, body).unwrap();
        write_metadata_attributes(path, &metadata).unwrap();
    }

    pub fn create_encrypted_test_metadata(owner: &Identity, owner_key: &Key, plaintext: &[u8]) -> (Metadata, Vec<u8>) {
        let mut metadata = create_metadata(&owner.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
        let file_key = create_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
        let (_, ciphertext) = encrypt_bytes(&file_key, plaintext).unwrap();
        apply_key_to_metadata(&mut metadata, &file_key).unwrap();
        sign_metadata(owner_key, &mut metadata, &ciphertext).unwrap();
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
