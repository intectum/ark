use std::env::current_dir;
use std::fs;
use std::io;
use std::path::Path;

use getrandom::getrandom;
use url::Url;

use crate::crypto::{DEFAULT_SIGNING_ALGORITHM, create_key, sign_json, to_public_key, verify_json};
use crate::client::cmd_get;
use crate::types::{Identity, Key, Signature};
use crate::util::{decode_base64url, encode_base64url, io_err, io_invalid_input, now_iso};

pub fn create_identity(address: &str) -> io::Result<(Identity, Key)> {
    let mut secret_key = create_key(DEFAULT_SIGNING_ALGORITHM)?;

    getrandom(&mut secret_key.value)
        .map_err(|e| io_err(&e.to_string()))?;

    let mut identity = Identity {
        public_key: to_public_key(&secret_key)?,
        address: address.to_string(),
        modified: now_iso(),
        signature: Signature {
            algorithm: String::new(),
            value: Vec::new()
        }
    };

    let json = serde_json::to_value(identity_for_signing(&identity)).expect("serialize identity");
    identity.signature = sign_json(&secret_key, &json)?;

    Ok((identity, secret_key))
}

pub fn read_identity(path: &Path) -> io::Result<Identity> {
    let content = fs::read_to_string(path)?;
    let identity: Identity = serde_json::from_str(&content)
        .map_err(|e| io_err(&format!("identity.json parse: {}", e)))?;
    validate_identity(&identity)?;

    Ok(identity)
}

pub fn resolve_identity(address: &str) -> io::Result<Identity> {
    let cwd = current_dir()?;
    let (address_name, _) = address.split_once("@").expect("address split");
    let cache_filename = format!("{}.json", address);

    let mut best_cache_dir: Option<std::path::PathBuf> = None;

    let mut current = cwd.as_path();
    loop {
        let direct_identity_path = current.join(".ark").join("identity.json");
        if fs::exists(&direct_identity_path)? {
            if let Ok(id) = read_identity(&direct_identity_path) {
                if id.address == address {
                    return Ok(id);
                }
            }
        }

        let direct_cache_path = current.join(".ark").join("identities").join(&cache_filename);
        if fs::exists(&direct_cache_path)? {
            return read_identity(&direct_cache_path);
        }

        let account_identity_path = current.join("ark").join(address_name).join(".ark").join("identity.json");
        if fs::exists(&account_identity_path)? {
            return read_identity(&account_identity_path);
        }

        let ark_account_cache_path = current.join("ark").join("ark").join(".ark").join("identities").join(&cache_filename);
        if fs::exists(&ark_account_cache_path)? {
            return read_identity(&ark_account_cache_path);
        }

        if best_cache_dir.is_none() {
            let ark_account_path = current.join("ark").join("ark");
            if fs::exists(&ark_account_path.join(".ark"))? {
                best_cache_dir = Some(ark_account_path.join(".ark").join("identities"));
            } else if fs::exists(current.join(".ark"))? {
                best_cache_dir = Some(current.join(".ark").join("identities"));
            }
        }

        match current.parent() {
            Some(p) => current = p,
            None => break,
        }
    }

    let cache_dir = best_cache_dir.ok_or_else(|| io_err("no identity cache dir found"))?;
    fs::create_dir_all(&cache_dir)?;
    let cache_path = cache_dir.join(&cache_filename);
    cmd_get(&format!("{}/.ark/identity.json", address), cache_path.to_str(), false)?;

    read_identity(&cache_path)
}

pub fn write_identity(path: &Path, identity: &Identity) -> io::Result<()> {
    let pretty = serde_json::to_string_pretty(identity)
        .map_err(|e| io_err(&e.to_string()))?;
    fs::write(path, pretty)
}

pub fn validate_identity(identity: &Identity) -> io::Result<()> {
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

    verify_identity(&identity)
        .map_err(|_| io_invalid_input("signature verification failed"))?;

    Ok(())
}

pub fn verify_identity(identity: &Identity) -> io::Result<()> {
    let json = serde_json::to_value(identity_for_signing(identity)).expect("serialize identity");

    verify_json(&identity.public_key, &identity.signature, &json)
        .map_err(|_| io_err("identity signature verification failed"))
}

fn identity_for_signing(identity: &Identity) -> Identity {
    let mut clone = identity.clone();
    clone.signature.algorithm = String::new();
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
    use crate::server::start_test_server;
    use crate::util::test::{create_test_account, in_test_dir};


    #[test]
    fn create_identity_has_valid_signature() {
        let (identity, _) = create_identity("alice@example.com").unwrap();
        assert_eq!(identity.address, "alice@example.com");
        assert_eq!(identity.public_key.algorithm, DEFAULT_SIGNING_ALGORITHM);
        assert_eq!(identity.signature.algorithm, DEFAULT_SIGNING_ALGORITHM);

        assert!(verify_identity(&identity).is_ok());
    }

    #[test]
    fn create_identity_signature_detects_tampering() {
        let (identity, _) = create_identity("alice@example.com").unwrap();
        assert_eq!(identity.address, "alice@example.com");
        assert_eq!(identity.public_key.algorithm, DEFAULT_SIGNING_ALGORITHM);
        assert_eq!(identity.signature.algorithm, DEFAULT_SIGNING_ALGORITHM);

        let mut identity_tampered = identity.clone();
        identity_tampered.address = "mallory@example.com".to_string();

        assert!(verify_identity(&identity_tampered).is_err());
    }

    #[test]
    fn identity_json_round_trip() {
        let (identity, _) = create_identity("alice@example.com").unwrap();
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
        in_test_dir("ark_identity_test", |temp_dir| {
            let (identity, _) = create_identity("alice@example.com").unwrap();
            let path = temp_dir.join("identity.json");
            write_identity(&path, &identity).unwrap();
            let loaded = read_identity(&path).unwrap();
            assert_eq!(loaded.address, identity.address);
            assert_eq!(loaded.modified, identity.modified);
            assert_eq!(loaded.public_key.algorithm, identity.public_key.algorithm);
            assert_eq!(loaded.public_key.value, identity.public_key.value);
            assert_eq!(loaded.signature.algorithm, identity.signature.algorithm);
            assert_eq!(loaded.signature.value, identity.signature.value);
        });
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
        let (identity, _) = create_identity("alice@example.com").unwrap();
        validate_identity(&identity).unwrap();
    }

    #[test]
    fn validate_identity_rejects_invalid_account_name() {
        let (mut identity, _) = create_identity("alice@example.com").unwrap();
        identity.address = "BAD@example.com".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("invalid account name"));
    }

    #[test]
    fn validate_identity_rejects_bad_timestamp() {
        let (mut identity, _) = create_identity("alice@example.com").unwrap();
        identity.modified = "not-a-timestamp".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("not a valid RFC 3339 timestamp"));
    }

    #[test]
    fn validate_identity_rejects_tampered_address() {
        let (mut identity, _) = create_identity("alice@example.com").unwrap();
        identity.address = "bob@example.com".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn read_write_identity_key_round_trip() {
        in_test_dir("ark_identity_test", |temp_dir| {
            let key = [77u8; 32];
            let path = temp_dir.join("identity.key");
            write_identity_key(&path, &key).unwrap();
            let loaded = read_identity_key(&path).unwrap();
            assert_eq!(loaded, key);
        });
    }

    #[test]
    fn resolve_identity_returns_cached_when_present() {
        in_test_dir("ark_identity_test", |temp_dir| {
            let cache_dir = temp_dir.join(".ark/identities");
            fs::create_dir_all(&cache_dir).unwrap();
            let (identity, _) = create_identity("bob@example.com").unwrap();
            write_identity(&cache_dir.join("bob@example.com.json"), &identity).unwrap();

            let loaded = resolve_identity("bob@example.com").unwrap();
            assert_eq!(loaded.address, identity.address);
            assert_eq!(loaded.public_key.value, identity.public_key.value);
            assert_eq!(loaded.signature.value, identity.signature.value);
        });
    }

    #[test]
    fn resolve_identity_errors_on_invalid_cached_file() {
        in_test_dir("ark_identity_test", |temp_dir| {
            let cache_dir = temp_dir.join(".ark/identities");
            fs::create_dir_all(&cache_dir).unwrap();
            fs::write(cache_dir.join("bob@example.com.json"), b"not json").unwrap();

            let err = resolve_identity("bob@example.com").err().expect("expected error");
            assert!(err.to_string().contains("identity.json parse"), "msg was {}", err);
        });
    }

    #[test]
    #[ignore = "server auth currently requires sig matching path's account; cross-account fetch returns 403"]
    fn resolve_identity_fetches_and_caches_on_miss() {
        in_test_dir("ark_identity_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());

            let self_address = format!("alice@127.0.0.1:{}", port);
            let (_, _, account_dir) = create_test_account(temp_dir, &self_address);

            let remote_address = format!("bob@127.0.0.1:{}", port);
            let (_, _, bob_dir) = create_test_account(temp_dir, &remote_address);
            let expected = read_identity(&bob_dir.join(".ark/identity.json")).unwrap();

            let cache_dir = account_dir.join(".ark/identities");

            std::env::set_current_dir(&account_dir).unwrap();
            let fetched = resolve_identity(&remote_address).unwrap();

            assert_eq!(fetched.address, expected.address);
            assert_eq!(fetched.public_key.value, expected.public_key.value);
            assert_eq!(fetched.signature.value, expected.signature.value);

            let cache_path = cache_dir.join(format!("{}.json", remote_address));
            assert!(cache_path.exists(), "cache file not written: {:?}", cache_path);
            let cached = read_identity(&cache_path).unwrap();
            assert_eq!(cached.public_key.value, expected.public_key.value);
        });
    }

    #[cfg(unix)]
    #[test]
    fn write_identity_key_sets_0600() {
        use std::os::unix::fs::PermissionsExt;

        in_test_dir("ark_identity_test", |temp_dir| {
            let path = temp_dir.join("identity.key");
            write_identity_key(&path, &[78u8; 32]).unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        });
    }
}
