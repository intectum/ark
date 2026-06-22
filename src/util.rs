use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::identity::{parse_address, read_identity, read_signing_key};

pub const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn canonicalize_for_sig(doc: &serde_json::Value) -> Vec<u8> {
    let mut clone = doc.clone();
    if let Some(obj) = clone.as_object_mut() {
        obj.remove("signature");
    }
    serde_jcs::to_vec(&clone).expect("jcs serialize")
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

pub fn unix_to_iso8601(secs: u64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(secs as i64).expect("valid unix ts");
    dt.format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 format")
}

pub fn is_valid_host_port(s: &str) -> bool {
    let (host, port_str) = match s.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (s, None),
    };
    if !is_valid_host(host) {
        return false;
    }
    if let Some(p) = port_str {
        match p.parse::<u16>() {
            Ok(n) if n > 0 => {}
            _ => return false,
        }
    }
    true
}

fn is_valid_host(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return is_valid_ipv4(s);
    }
    is_valid_hostname(s)
}

fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u8>().is_ok())
}

fn is_valid_hostname(s: &str) -> bool {
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

pub fn is_valid_account_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let allowed = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_');
    if !allowed {
        return false;
    }
    name.chars().any(|c| c != '.')
}

pub struct Target {
    pub host: String,
    pub url_path: String,
}

pub struct IdentityCtx {
    pub account_dir: PathBuf,
    pub account: String,
    pub host: String,
    pub sk: SigningKey,
}

pub fn load_identity_from_tree(start: &Path) -> std::io::Result<IdentityCtx> {
    let mut current: Option<&Path> = Some(start);
    while let Some(d) = current {
        let ark_meta = d.join(".ark");
        let id_path = ark_meta.join("identity.json");
        let key_path = ark_meta.join("identity.key");
        if id_path.is_file() && key_path.is_file() {
            let identity = read_identity(&id_path)?;
            let (_name, host) = parse_address(&identity.address)?;
            let account = d
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| io_err("account dir name not utf-8"))?
                .to_string();
            let sk = read_signing_key(&key_path)?;
            return Ok(IdentityCtx {
                account_dir: d.to_path_buf(),
                account,
                host,
                sk,
            });
        }
        current = d.parent();
    }
    Err(io_err("no .ark/identity.json + identity.key found in cwd or any parent"))
}

pub fn resolve_target(cwd: &Path, ctx: &IdentityCtx, arg: &str) -> Target {
    let at_pos = arg.find('@');
    let slash_pos = arg.find('/');
    let is_address_form = match (at_pos, slash_pos) {
        (Some(a), Some(s)) => a < s,
        (Some(_), None) => true,
        _ => false,
    };
    if is_address_form {
        let (acct_part, sub) = match arg.split_once('/') {
            Some((a, b)) => (a, b),
            None => (arg, ""),
        };
        let (account, host) = acct_part.split_once('@').unwrap();
        let url_path = if sub.is_empty() {
            format!("/ark/{}/", account)
        } else {
            format!("/ark/{}/{}", account, sub)
        };
        return Target {
            host: host.to_string(),
            url_path: collapse_slashes(&url_path),
        };
    }
    if arg.starts_with('/') {
        return Target {
            host: ctx.host.clone(),
            url_path: arg.to_string(),
        };
    }
    let rel = cwd.strip_prefix(&ctx.account_dir).unwrap_or(Path::new(""));
    let rel_str = rel.to_string_lossy();
    let combined = if rel_str.is_empty() {
        format!("/ark/{}/{}", ctx.account, arg)
    } else {
        format!("/ark/{}/{}/{}", ctx.account, rel_str, arg)
    };
    Target {
        host: ctx.host.clone(),
        url_path: collapse_slashes(&combined),
    }
}

pub fn collapse_slashes(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut prev_slash = false;
    for c in p.chars() {
        if c == '/' {
            if !prev_slash {
                out.push(c);
            }
            prev_slash = true;
        } else {
            out.push(c);
            prev_slash = false;
        }
    }
    out
}

pub fn parse_host_port(host: &str) -> (String, u16) {
    if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (host.to_string(), 80)
}

pub fn io_err(s: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.to_string())
}

#[cfg(test)]
pub mod testutil {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_omits_signature_and_sorts_keys() {
        let doc = serde_json::json!({
            "z": 1,
            "a": 2,
            "signature": { "algorithm": "ed25519", "signature": "abc" }
        });
        let bytes = canonicalize_for_sig(&doc);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(s, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn canonicalize_is_stable_regardless_of_key_order() {
        let a = serde_json::json!({"b":1,"a":2,"c":{"y":1,"x":2}});
        let b = serde_json::json!({"c":{"x":2,"y":1},"a":2,"b":1});
        assert_eq!(canonicalize_for_sig(&a), canonicalize_for_sig(&b));
    }

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn host_port_validation() {
        let valid = [
            "example.com",
            "localhost",
            "a.b.c.d",
            "sub.example.com",
            "example.com:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
            "10.0.0.1:443",
            "single",
            "x-y.z",
        ];
        for h in valid {
            assert!(is_valid_host_port(h), "{} should be valid", h);
        }
        let invalid = [
            "",
            ":",
            ":8080",
            "host:",
            "host:abc",
            "host:0",
            "host:99999",
            "host:-1",
            "-leading.com",
            "trailing-.com",
            "white space",
            "host..com",
            "127.0.0.256",
            "127.0.0",
            "127.0.0.1.2",
            "host:8080:9090",
        ];
        for h in invalid {
            assert!(!is_valid_host_port(h), "{} should be invalid", h);
        }
    }

    fn mk_ctx(account: &str, host: &str, dir: &Path) -> IdentityCtx {
        IdentityCtx {
            account_dir: dir.to_path_buf(),
            account: account.to_string(),
            host: host.to_string(),
            sk: SigningKey::from_bytes(&[7u8; 32]),
        }
    }

    #[test]
    fn collapse_slashes_removes_dupes() {
        assert_eq!(collapse_slashes("/ark//gyan///x"), "/ark/gyan/x");
        assert_eq!(collapse_slashes("/a/b/c"), "/a/b/c");
    }

    #[test]
    fn parse_host_port_with_explicit_port() {
        assert_eq!(parse_host_port("127.0.0.1:8080"), ("127.0.0.1".to_string(), 8080));
        assert_eq!(parse_host_port("example.com:443"), ("example.com".to_string(), 443));
    }

    #[test]
    fn parse_host_port_default() {
        assert_eq!(parse_host_port("example.com"), ("example.com".to_string(), 80));
    }

    #[test]
    fn resolve_target_absolute_uses_ctx_host() {
        let cwd = Path::new("/x/ark/gyan");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "/ark/alice/foo.txt");
        assert_eq!(t.url_path, "/ark/alice/foo.txt");
        assert_eq!(t.host, "127.0.0.1:8080");
    }

    #[test]
    fn resolve_target_relative_at_account_root() {
        let cwd = Path::new("/x/ark/gyan");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "notes/todo.txt");
        assert_eq!(t.url_path, "/ark/gyan/notes/todo.txt");
        assert_eq!(t.host, "127.0.0.1:8080");
    }

    #[test]
    fn resolve_target_relative_in_subdir() {
        let cwd = Path::new("/x/ark/gyan/notes");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "todo.txt");
        assert_eq!(t.url_path, "/ark/gyan/notes/todo.txt");
        assert_eq!(t.host, "127.0.0.1:8080");
    }

    #[test]
    fn resolve_target_address_form_with_path() {
        let cwd = Path::new("/anywhere");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "alice@example.com/path/to/file");
        assert_eq!(t.url_path, "/ark/alice/path/to/file");
        assert_eq!(t.host, "example.com");
    }

    #[test]
    fn resolve_target_address_form_with_port() {
        let cwd = Path::new("/anywhere");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "alice@example.com:9000/foo.txt");
        assert_eq!(t.url_path, "/ark/alice/foo.txt");
        assert_eq!(t.host, "example.com:9000");
    }

    #[test]
    fn resolve_target_address_form_no_path() {
        let cwd = Path::new("/anywhere");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "alice@example.com");
        assert_eq!(t.url_path, "/ark/alice/");
        assert_eq!(t.host, "example.com");
    }

    #[test]
    fn account_name_validation_matches_spec() {
        let valid = ["a", "gyan", "alice123", "user.name", "user-name", "user_name", "a.b-c_d.0", &"a".repeat(64)];
        for n in valid {
            assert!(is_valid_account_name(n), "{} should be valid", n);
        }
        let invalid: &[&str] = &[
            "",
            ".",
            "..",
            "...",
            "Alice",
            "ALICE",
            "user@host",
            "user name",
            "user/slash",
            "user\\back",
            "user+plus",
            "user#hash",
            "café",
            &"a".repeat(65),
        ];
        for n in invalid {
            assert!(!is_valid_account_name(n), "{} should be invalid", n);
        }
    }
}
