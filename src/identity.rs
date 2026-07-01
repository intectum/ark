use std::fs;
use std::io;
use std::path::Path;

use url::Url;

use crate::crypto::{DEFAULT_SIGNING_ALGORITHM, sign_json, to_public_key, verify_json};
use crate::get::cmd_get;
use crate::types::{Identity, Key, Signature};
use crate::util::{decode_base64url, encode_base64url, io_err, io_invalid_input, now_iso};

pub fn create_identity(key: &[u8], address: &str) -> Identity {
    let mut identity = Identity {
        public_key: Key {
            algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(),
            value: to_public_key(key)
        },
        address: address.to_string(),
        modified: now_iso(),
        signature: Signature {
            algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(),
            value: Vec::new()
        }
    };

    sign_identity(key, &mut identity);

    identity
}

pub fn read_identity(path: &Path) -> io::Result<Identity> {
    let content = fs::read_to_string(path)?;
    let identity: Identity = serde_json::from_str(&content)
        .map_err(|e| io_err(&format!("identity.json parse: {}", e)))?;
    validate_identity(&identity)?;

    Ok(identity)
}

pub fn resolve_identity_client(root: &Path, self_identity: &Identity, address: &str) -> io::Result<Identity> {
    if address == self_identity.address {
        return Ok(self_identity.clone());
    }

    resolve_remote_identity(&root.join(".ark/identities"), address)
}

pub fn resolve_identity_server(root: &Path, self_identity: &Identity, address: &str) -> io::Result<Identity> {
    if address == self_identity.address {
        return Ok(self_identity.clone());
    }

    let (address_name, _) = address.split_once("@").expect("address split");
    let local_identity_path = root.join("ark").join(address_name).join(".ark").join("identity.json");
    if fs::exists(&local_identity_path)? {
        return read_identity(&local_identity_path);
    }

    resolve_remote_identity(&root.join("ark/ark/.ark/identities"), address)
}

fn resolve_remote_identity(cache_dir: &Path, address: &str) -> io::Result<Identity> {
    let cache_path = cache_dir.join(format!("{}.json", address));
    if !fs::exists(&cache_path)? {
        cmd_get(&format!("{}/.ark/identity.json", address), cache_path.to_str(), false)?;
    }

    return read_identity(&cache_path);
}

pub fn write_identity(path: &Path, identity: &Identity) -> io::Result<()> {
    let pretty = serde_json::to_string_pretty(identity)
        .map_err(|e| io_err(&e.to_string()))?;
    fs::write(path, pretty)
}

pub fn validate_identity(identity: &Identity) -> io::Result<()> {
    if identity.public_key.algorithm == DEFAULT_SIGNING_ALGORITHM {
        if identity.public_key.value.len() != 32 {
            return Err(io_invalid_input("public key wrong length"));
        }
    } else {
        return Err(io_invalid_input("unsupported key algorithm"));
    }

    let address_url = Url::parse(&format!("https://{}", identity.address))
        .map_err(|_| io_invalid_input("invalid address"))?;
    if address_url.host_str().is_none() {
        return Err(io_invalid_input("address must be <name>@<host>"));
    }

    if !is_valid_account_name(address_url.username()) {
        return Err(io_invalid_input("invalid account name (must be lowercase alphanumeric, dots, hyphens, underscores; 1-64 chars; not pure dots)"));
    }

    time::OffsetDateTime::parse(&identity.modified, &time::format_description::well_known::Rfc3339)
        .map_err(|e| io_invalid_input(&format!("modified is not a valid RFC 3339 timestamp: {}", e)))?;

    if identity.signature.algorithm == DEFAULT_SIGNING_ALGORITHM {
        if identity.signature.value.len() != 64 {
            return Err(io_invalid_input("signature wrong length"));
        }
    } else {
        return Err(io_invalid_input("unsupported signature algorithm"));
    }

    verify_identity(&identity)
        .map_err(|_| io_invalid_input("signature verification failed"))?;

    Ok(())
}

pub fn sign_identity(key: &[u8], identity: &mut Identity) {
    identity.signature.algorithm = DEFAULT_SIGNING_ALGORITHM.to_string();
    let json = serde_json::to_value(identity_for_signing(identity)).expect("serialize identity");
    identity.signature.value = sign_json(key, &json);
}

pub fn verify_identity(identity: &Identity) -> io::Result<()> {
    let json = serde_json::to_value(identity_for_signing(identity)).expect("serialize identity");
    verify_json(&identity.public_key.value, &identity.signature.value, &json)
        .map_err(|_| io_err("identity signature verification failed"))
}

fn identity_for_signing(identity: &Identity) -> Identity {
    let mut clone = identity.clone();
    clone.signature.value = Vec::new();
    clone
}

// TODO: minimize time key is in memory, something like with_private_key (zeros memory after)
pub fn read_identity_key(path: &Path) -> io::Result<Vec<u8>> {
    let content = fs::read_to_string(path)?;
    let key = decode_base64url(content)
        .map_err(|_| io_invalid_input("public key is not base64url encoded"))?;

    Ok(key)
}

#[cfg(unix)]
pub fn write_identity_key(path: &Path, key: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(encode_base64url(key).as_bytes())?;

    Ok(())
}

#[cfg(not(unix))]
pub fn write_identity_key(path: &Path, key: &[u8]) -> io::Result<()> {
    fs::write(path, encode_base64url(key))
}

fn is_valid_account_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 { return false };

    let allowed = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_');
    if !allowed { return false };

    name.chars().any(|c| c != '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test::TempDir;

    #[test]
    fn create_identity_has_valid_signature() {
        let identity = create_identity(&[42u8; 32], "alice@example.com");
        assert_eq!(identity.address, "alice@example.com");
        assert_eq!(identity.public_key.algorithm, DEFAULT_SIGNING_ALGORITHM);
        assert_eq!(identity.signature.algorithm, DEFAULT_SIGNING_ALGORITHM);

        assert!(verify_identity(&identity).is_ok());
    }

    #[test]
    fn create_identity_signature_detects_tampering() {
        let identity = create_identity(&[43u8; 32], "alice@example.com");
        assert_eq!(identity.address, "alice@example.com");
        assert_eq!(identity.public_key.algorithm, DEFAULT_SIGNING_ALGORITHM);
        assert_eq!(identity.signature.algorithm, DEFAULT_SIGNING_ALGORITHM);

        let mut identity_tampered = identity.clone();
        identity_tampered.address = "mallory@example.com".to_string();

        assert!(verify_identity(&identity_tampered).is_err());
    }

    #[test]
    fn identity_json_round_trip() {
        let identity = create_identity(&[44u8; 32], "alice@example.com");
        let s = serde_json::to_string(&identity).unwrap();
        let parsed: Identity = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.address, identity.address);
        assert_eq!(parsed.modified, identity.modified);
        assert_eq!(parsed.public_key.algorithm, identity.public_key.algorithm);
        assert_eq!(parsed.public_key.value, identity.public_key.value);
        assert_eq!(parsed.signature.algorithm, identity.signature.algorithm);
        assert_eq!(parsed.signature.value, identity.signature.value);
    }

    #[test]
    fn read_write_identity_round_trip() {
        let td = TempDir::new("ark_identity_test");
        let identity = create_identity(&[45u8; 32], "alice@example.com");
        let path = td.0.join("identity.json");
        write_identity(&path, &identity).unwrap();
        let loaded = read_identity(&path).unwrap();
        assert_eq!(loaded.address, identity.address);
        assert_eq!(loaded.modified, identity.modified);
        assert_eq!(loaded.public_key.algorithm, identity.public_key.algorithm);
        assert_eq!(loaded.public_key.value, identity.public_key.value);
        assert_eq!(loaded.signature.algorithm, identity.signature.algorithm);
        assert_eq!(loaded.signature.value, identity.signature.value);
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

    #[test]
    fn validate_identity_accepts_well_formed() {
        let identity = create_identity(&[60u8; 32], "alice@example.com");
        validate_identity(&identity).unwrap();
    }

    #[test]
    fn validate_identity_rejects_unsupported_key_algorithm() {
        let mut identity = create_identity(&[61u8; 32], "alice@example.com");
        identity.public_key.algorithm = "rsa".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("unsupported key algorithm"));
    }

    #[test]
    fn validate_identity_rejects_wrong_public_key_length() {
        let mut identity = create_identity(&[62u8; 32], "alice@example.com");
        identity.public_key.value = vec![0u8; 16];
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("public key wrong length"));
    }

    #[test]
    fn validate_identity_rejects_invalid_account_name() {
        let mut identity = create_identity(&[63u8; 32], "alice@example.com");
        identity.address = "BAD@example.com".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("invalid account name"));
    }

    #[test]
    fn validate_identity_rejects_bad_timestamp() {
        let mut identity = create_identity(&[64u8; 32], "alice@example.com");
        identity.modified = "not-a-timestamp".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("not a valid RFC 3339 timestamp"));
    }

    #[test]
    fn validate_identity_rejects_unsupported_signature_algorithm() {
        let mut identity = create_identity(&[65u8; 32], "alice@example.com");
        identity.signature.algorithm = "rsa".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("unsupported signature algorithm"));
    }

    #[test]
    fn validate_identity_rejects_wrong_signature_length() {
        let mut identity = create_identity(&[66u8; 32], "alice@example.com");
        identity.signature.value = vec![0u8; 32];
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("signature wrong length"));
    }

    #[test]
    fn validate_identity_rejects_tampered_address() {
        let mut identity = create_identity(&[67u8; 32], "alice@example.com");
        identity.address = "bob@example.com".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn read_write_identity_key_round_trip() {
        let td = TempDir::new("ark_identity_test");
        let key = [77u8; 32];
        let path = td.0.join("identity.key");
        write_identity_key(&path, &key).unwrap();
        let loaded = read_identity_key(&path).unwrap();
        assert_eq!(loaded, key);
    }

    #[test]
    fn resolve_remote_identity_returns_cached_when_present() {
        let td = TempDir::new("ark_identity_test");
        let cache_dir = td.0.join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        let identity = create_identity(&[80u8; 32], "bob@example.com");
        write_identity(&cache_dir.join("bob@example.com.json"), &identity).unwrap();

        let loaded = resolve_remote_identity(&cache_dir, "bob@example.com").unwrap();
        assert_eq!(loaded.address, identity.address);
        assert_eq!(loaded.public_key.value, identity.public_key.value);
        assert_eq!(loaded.signature.value, identity.signature.value);
    }

    #[test]
    fn resolve_remote_identity_errors_on_invalid_cached_file() {
        let td = TempDir::new("ark_identity_test");
        let cache_dir = td.0.join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("bob@example.com.json"), b"not json").unwrap();

        let err = resolve_remote_identity(&cache_dir, "bob@example.com").err().expect("expected error");
        assert!(err.to_string().contains("identity.json parse"), "msg was {}", err);
    }

    #[test]
    #[ignore = "server auth currently requires sig matching path's account; cross-account fetch returns 403"]
    fn resolve_remote_identity_fetches_and_caches_on_miss() {
        use crate::create_account::create_account_with_key;
        use crate::server::start_test_server;
        use crate::util::test::with_cwd;

        let td = TempDir::new("ark_identity_test");
        let port = start_test_server(td.0.clone());

        let self_address = format!("alice@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &self_address, &[81u8; 32]).unwrap();

        let remote_address = format!("bob@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &remote_address, &[82u8; 32]).unwrap();
        let expected = read_identity(&td.0.join("ark/bob/.ark/identity.json")).unwrap();

        let account_dir = td.0.join("ark/alice");
        let cache_dir = account_dir.join(".ark/identities");

        let fetched = with_cwd(&account_dir, || {
            resolve_remote_identity(&cache_dir, &remote_address).unwrap()
        });

        assert_eq!(fetched.address, expected.address);
        assert_eq!(fetched.public_key.value, expected.public_key.value);
        assert_eq!(fetched.signature.value, expected.signature.value);

        let cache_path = cache_dir.join(format!("{}.json", remote_address));
        assert!(cache_path.exists(), "cache file not written: {:?}", cache_path);
        let cached = read_identity(&cache_path).unwrap();
        assert_eq!(cached.public_key.value, expected.public_key.value);
    }

    #[cfg(unix)]
    #[test]
    fn write_identity_key_sets_0600() {
        use std::os::unix::fs::PermissionsExt;

        let td = TempDir::new("ark_identity_test");
        let path = td.0.join("identity.key");
        write_identity_key(&path, &[78u8; 32]).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
