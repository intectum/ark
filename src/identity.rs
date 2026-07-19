use std::fs;
use std::io;
use std::path::Path;

use getrandom::getrandom;
use url::Url;

use crate::crypto::{DEFAULT_SIGNING_ALGORITHM, create_secret_key, sign_json, to_public_key, verify_json};
use crate::client::request;
use crate::types::IdentityContext;
use crate::types::{Identity, Key, Signature};
use crate::util::{decode_base64url, encode_base64url, io_err, io_invalid_input, now_iso, resolve_client_url};

pub fn create_identity(address: &str) -> io::Result<(Identity, Key)> {
    let mut secret_key = create_secret_key(DEFAULT_SIGNING_ALGORITHM)?;

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

pub fn resolve_identity(ctx: &IdentityContext, address: &str) -> io::Result<Identity> {
    if address == ctx.identity.address {
        return Ok(ctx.identity.clone());
    }

    let (name, host, path) = parse_address(address)?;

    let peer_path = ctx.root.parent().unwrap()
        .join(&name).join(path.trim_start_matches('/'));

    if fs::exists(&peer_path)? {
        let peer_identity = read_identity(&peer_path)?;
        if peer_identity.address == address {
            return Ok(peer_identity);
        }
    }

    let cache_dir = ctx.root.join(".ark").join("identities");
    let cache_path = cache_dir.join(format!("{}.json", address.replace('/', "_")));

    if fs::exists(&cache_path)? {
        return read_identity(&cache_path);
    }

    let url = resolve_client_url(ctx, &format!("{}@{}{}", name, host, path))?;
    let (code, _, body) = request(Some(ctx), "GET", &url, &[], &[])?;
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    let identity: Identity = serde_json::from_slice(&body)
        .map_err(|e| io_err(&format!("identity.json parse: {}", e)))?;
    validate_identity(&identity)?;

    fs::create_dir_all(&cache_dir)?;
    fs::write(&cache_path, &body)?;

    Ok(identity)
}

pub fn write_identity(path: &Path, identity: &Identity) -> io::Result<()> {
    let pretty = serde_json::to_string_pretty(identity)
        .map_err(|e| io_err(&e.to_string()))?;
    fs::write(path, pretty)
}

pub fn sign_identity(secret_key: &Key, identity: &mut Identity) -> io::Result<()> {
    let json = serde_json::to_value(identity_for_signing(identity)).expect("serialize identity");
    identity.signature = sign_json(secret_key, &json)?;

    Ok(())
}

pub fn validate_identity(identity: &Identity) -> io::Result<()> {
    let (name, _, _) = parse_address(&identity.address)?;

    if !is_valid_account_name(&name) {
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

pub fn parse_address(address: &str) -> io::Result<(String, String, String)> {
    let url = Url::parse(&format!("https://{}", address))
        .map_err(|_| io_invalid_input("invalid address"))?;

    let name = url.username();
    let host_str = url.host_str();
    if name.is_empty() || host_str.is_none() {
        return Err(io_invalid_input("address must be <name>@<host>[/<path>]"));
    }
    let host = match url.port() {
        Some(port) => format!("{}:{}", host_str.unwrap(), port),
        None => host_str.unwrap().to_string(),
    };

    let path = if url.path().is_empty() || url.path() == "/" {
        "/.ark/identity.json".to_string()
    } else {
        url.path().to_string()
    };

    Ok((name.to_string(), host, path))
}

fn identity_for_signing(identity: &Identity) -> Identity {
    let mut clone = identity.clone();
    clone.signature.algorithm = String::new();
    clone.signature.value = Vec::new();
    clone
}

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
    use crate::client::init_local;
    use crate::context::create_client_context;
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
            init_local(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let cache_dir = temp_dir.join(".ark/identities");
            fs::create_dir_all(&cache_dir).unwrap();
            let (identity, _) = create_identity("bob@example.com").unwrap();
            write_identity(&cache_dir.join("bob@example.com.json"), &identity).unwrap();

            let loaded = resolve_identity(&ctx, "bob@example.com").unwrap();
            assert_eq!(loaded.address, identity.address);
            assert_eq!(loaded.public_key.value, identity.public_key.value);
            assert_eq!(loaded.signature.value, identity.signature.value);
        });
    }

    #[test]
    fn resolve_identity_returns_self_without_cache_lookup() {
        in_test_dir("ark_identity_test", |temp_dir| {
            let (identity, _) = init_local(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let loaded = resolve_identity(&ctx, &identity.address).unwrap();
            assert_eq!(loaded.public_key.value, identity.public_key.value);
        });
    }

    #[test]
    fn resolve_identity_errors_on_invalid_cached_file() {
        in_test_dir("ark_identity_test", |temp_dir| {
            init_local(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            let cache_dir = temp_dir.join(".ark/identities");
            fs::create_dir_all(&cache_dir).unwrap();
            fs::write(cache_dir.join("bob@example.com.json"), b"not json").unwrap();

            let err = resolve_identity(&ctx, "bob@example.com").err().expect("expected error");
            assert!(err.to_string().contains("identity.json parse"), "msg was {}", err);
        });
    }

    #[test]
    fn resolve_identity_reads_local_peer_account() {
        in_test_dir("ark_identity_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());

            let self_address = format!("alice@127.0.0.1:{}", port);
            let (_, _, account_dir) = create_test_account(temp_dir, &self_address);

            let peer_address = format!("bob@127.0.0.1:{}", port);
            let (_, _, bob_dir) = create_test_account(temp_dir, &peer_address);
            let expected = read_identity(&bob_dir.join(".ark/identity.json")).unwrap();

            std::env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let fetched = resolve_identity(&ctx, &peer_address).unwrap();

            assert_eq!(fetched.address, expected.address);
            assert_eq!(fetched.public_key.value, expected.public_key.value);
            assert_eq!(fetched.signature.value, expected.signature.value);

            let cache_path = account_dir.join(".ark/identities").join(format!("{}.json", peer_address));
            assert!(!cache_path.exists(), "peer path should not write cache");
        });
    }

    #[test]
    fn resolve_identity_fetches_and_caches_on_miss() {
        use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
        use crate::types::{Member, Permission};

        in_test_dir("ark_identity_test", |temp_dir| {
            let server_a_root = temp_dir.join("server_a");
            fs::create_dir_all(&server_a_root).unwrap();
            let server_b_root = temp_dir.join("server_b");
            fs::create_dir_all(&server_b_root).unwrap();
            let port_a = start_test_server(server_a_root.clone());
            let port_b = start_test_server(server_b_root.clone());

            let alice_address = format!("alice@127.0.0.1:{}", port_a);
            let (_, _, alice_dir) = create_test_account(&server_a_root, &alice_address);

            let bob_address = format!("bob@127.0.0.1:{}", port_b);
            let (_, bob_key, bob_dir) = create_test_account(&server_b_root, &bob_address);
            let bob_identity_path = bob_dir.join(".ark/identity.json");
            let body = fs::read(&bob_identity_path).unwrap();
            let mut meta = create_metadata(&bob_address, None);
            meta.members.push(Member { address: "*".to_string(), permission: Permission::Read, key: None });
            sign_metadata(&bob_key, &mut meta, Some(&body)).unwrap();
            write_metadata_attributes(&bob_identity_path, &meta).unwrap();
            let expected = read_identity(&bob_identity_path).unwrap();

            std::env::set_current_dir(&alice_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let fetched = resolve_identity(&ctx, &bob_address).unwrap();

            assert_eq!(fetched.address, expected.address);
            assert_eq!(fetched.public_key.value, expected.public_key.value);
            assert_eq!(fetched.signature.value, expected.signature.value);

            let cache_path = alice_dir.join(".ark/identities").join(format!("{}.json", bob_address));
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
