use std::io::{Error, ErrorKind};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

pub fn resolve_url(
    input: &str,
    address: &str,
    account_dir: &Path,
) -> std::io::Result<url::Url> {
    let mut url_string = input.to_string();

    if !url_string.contains("@") {
        if !url_string.starts_with("/") {
            let cwd = std::env::current_dir()?;
            let rel = cwd.strip_prefix(account_dir).unwrap_or(Path::new("")).to_string_lossy();
            url_string = match rel.as_ref() {
                "" => format!("/{}", url_string),
                _ => format!("/{}/{}", rel, url_string)
            }
        }

        url_string = format!("{}{}", address, url_string);
    }

    if !url_string.contains("://") {
        url_string = format!("https://{}", url_string);
    }

    let mut url = Url::parse(&url_string).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid URL {}: {}", input, e)))?;

    url.set_path(&format!("/ark/{}{}", url.username(), url.path()));

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

#[allow(dead_code)]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
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

    pub fn get_default_test_metadata() -> crate::types::Metadata {
        crate::types::Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![crate::types::Member {
                address: "test@example.com".to_string(),
                identity_key: [1u8; 32].to_vec(),
                permission: "owner".to_string(),
                wrapped_file_key: [2u8; 32].to_vec(),
            }],
        }
    }

    pub fn write_file_with_default_test_metadata(path: &Path, body: &[u8]) {
        fs::write(path, body).unwrap();
        crate::metadata::write_metadata_attributes(path, &get_default_test_metadata()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_url_absolute() {
        let cwd = std::env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_url("/path/to/file.txt", "gyan@127.0.0.1:8080", Path::new(account_dir)).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/ark/gyan/path/to/file.txt");
    }

    #[test]
    fn resolve_url_relative_at_account_root() {
        let account_dir = std::env::current_dir().unwrap();
        let url = resolve_url("path/to/file.txt", "gyan@127.0.0.1:8080", &account_dir).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/ark/gyan/path/to/file.txt");
    }

    #[test]
    fn resolve_url_relative_in_subdir() {
        let cwd = std::env::current_dir().unwrap();
        println!("cwd:i {}", cwd.to_string_lossy());
        let account_dir = cwd.parent().unwrap();
        let dir = cwd.file_name().unwrap();
        let url = resolve_url("path/to/file.txt", "gyan@127.0.0.1:8080", account_dir).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), format!("/ark/gyan/{}{}", dir.to_string_lossy(), "/path/to/file.txt"));
    }

    #[test]
    fn resolve_url_address_with_path() {
        let cwd = std::env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_url("alice@example.com/path/to/file.txt", "gyan@127.0.0.1:8080", account_dir).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/ark/alice/path/to/file.txt");
    }

    #[test]
    fn resolve_url_address_with_scheme_and_port_and_path() {
        let cwd = std::env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_url("http://alice@example.com:9000/path/to/file.txt", "gyan@127.0.0.1:8080", account_dir).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), Some(9000));
        assert_eq!(url.path(), "/ark/alice/path/to/file.txt");
    }

    #[test]
    fn resolve_url_address_only() {
        let cwd = std::env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = resolve_url("alice@example.com", "gyan@127.0.0.1:8080", account_dir).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/ark/alice/");
    }

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
