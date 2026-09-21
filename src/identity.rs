use std::io;
use std::path::Path;

use url::Url;

use crate::client::request;
use crate::crypto::{DEFAULT_SIGNING_ALGORITHM, create_secret_key, sign_json, to_public_key, verify_json};
use crate::http::check_response_code;
use crate::storage::{Body, create_dir_all, exists, exists_raw, read_to_string, read_to_string_raw, to_fs_path_raw, write_atomic_without_metadata, write_raw};
use crate::types::{Context, Identity, Key, Signature};
use crate::util::{decode_base64url, encode_base64url, resolve_client_url};

/// Create a fresh identity keypair for `address`.
///
/// When `members` is `Some`, the identity is a group and those addresses are
/// included in the signed document.
pub fn create_identity(address: &str, members: Option<Vec<String>>) -> io::Result<(Identity, Key)> {
    let secret_key = create_secret_key(DEFAULT_SIGNING_ALGORITHM)?;

    let mut identity = Identity {
        public_key: to_public_key(&secret_key)?,
        address: address.to_string(),
        members,
        signature: Signature {
            algorithm: String::new(),
            value: Vec::new()
        }
    };

    let json = serde_json::to_value(identity_for_signing(&identity)).expect("serialize identity");
    identity.signature = sign_json(&secret_key, &json)?;

    Ok((identity, secret_key))
}

pub fn read_identity(ctx: &Context, path: &str) -> io::Result<Identity> {
    read_identity_raw(&ctx.root, path)
}

/// As [`read_identity`], for a caller holding only the account root — one
/// running before its [`Context`] can be built, or reading another account
/// under the server root.
pub fn read_identity_raw(root: &Path, path: &str) -> io::Result<Identity> {
    let content = read_to_string_raw(root, path)?;
    let identity: Identity = serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("identity.json parse: {}", e)))?;
    validate_identity(&identity)?;

    Ok(identity)
}

pub fn resolve_identity(ctx: &Context, address: &str) -> io::Result<Identity> {
    if address == ctx.identity.address {
        return Ok(ctx.identity.clone());
    }

    let (name, host, mut path) = parse_address(address)?;
    if path.is_empty() {
        path = "/.ark/identity.json".to_string();
    }

    // A peer account is a sibling of this one under the same server root, so
    // its identity is reached against that root rather than this account's —
    // the account-path form refuses anything outside the root it is given.
    let accounts_root = ctx.root.parent().unwrap();
    let peer_path = format!("/{}{}", name, path);

    if exists_raw(accounts_root, &peer_path) {
        let peer_identity = read_identity_raw(accounts_root, &peer_path)?;
        if peer_identity.address == address {
            return Ok(peer_identity);
        }
    }

    let cache_path = format!("/.ark/identities/{}.json", address.replace('/', "_"));

    if exists(ctx, &cache_path) {
        return read_identity(ctx, &cache_path);
    }

    let url = resolve_client_url(ctx, &format!("{}@{}{}", name, host, path))?;
    let (code, _, body) = request(Some(ctx), "GET", &url, &[], &[])?;
    check_response_code(code, &body)?;

    let identity: Identity = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("identity.json parse: {}", e)))?;
    validate_identity(&identity)?;

    create_dir_all(ctx, "/.ark/identities")?;
    write_atomic_without_metadata(ctx, &cache_path, Body::Bytes(&body))?;

    Ok(identity)
}

pub fn write_identity(ctx: &Context, path: &str, identity: &Identity) -> io::Result<()> {
    write_identity_raw(&ctx.root, path, identity)
}

/// As [`write_identity`], for a caller holding only the account root — one
/// running before its [`Context`] can be built.
pub fn write_identity_raw(root: &Path, path: &str, identity: &Identity) -> io::Result<()> {
    let pretty = serde_json::to_vec_pretty(identity)
        .map_err(|e| io::Error::other(e.to_string()))?;
    write_raw(root, path, &pretty)
}

pub fn sign_identity(secret_key: &Key, identity: &mut Identity) -> io::Result<()> {
    let json = serde_json::to_value(identity_for_signing(identity)).expect("serialize identity");
    identity.signature = sign_json(secret_key, &json)?;

    Ok(())
}

pub fn validate_identity(identity: &Identity) -> io::Result<()> {
    let (name, _, _) = parse_address(&identity.address)?;

    if !is_valid_account_name(&name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid account name (must be lowercase alphanumeric, dots, hyphens, underscores; 1-64 chars; not pure dots)"));
    }

    verify_identity(identity)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "signature verification failed"))?;

    Ok(())
}

pub fn verify_identity(identity: &Identity) -> io::Result<()> {
    let json = serde_json::to_value(identity_for_signing(identity)).expect("serialize identity");

    verify_json(&identity.public_key, &identity.signature, &json)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "identity signature verification failed"))
}

/// Split `<name>@<host>[:<port>][/<path>]` into name, host (with port when
/// given) and path. The path is empty when the address omits one.
pub fn parse_address(address: &str) -> io::Result<(String, String, String)> {
    let url = Url::parse(&format!("https://{}", address))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid address"))?;

    let name = url.username();
    let host_str = url.host_str();
    if name.is_empty() || host_str.is_none() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "address must be <name>@<host>[/<path>]"));
    }
    let host = match url.port() {
        Some(port) => format!("{}:{}", host_str.unwrap(), port),
        None => host_str.unwrap().to_string(),
    };

    let path = if url.path() == "/" {
        String::new()
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

pub fn read_identity_key(ctx: &Context, path: &str) -> io::Result<Vec<u8>> {
    let content = read_to_string(ctx, path)?;
    let key = decode_base64url(content.trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key is not base64url encoded"))?;

    Ok(key)
}

pub fn write_identity_key(ctx: &Context, path: &str, key: &[u8]) -> io::Result<()> {
    write_identity_key_raw(&ctx.root, path, key)
}

/// As [`write_identity_key`], for a caller holding only the account root —
/// one running before its [`Context`] can be built.
///
/// The key is created private to the current user, and never over a key that
/// is already there.
#[cfg(unix)]
pub fn write_identity_key_raw(root: &Path, path: &str, key: &[u8]) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to_fs_path_raw(root, path)?)?;
    file.write_all(encode_base64url(key).as_bytes())?;

    Ok(())
}

#[cfg(not(unix))]
pub fn write_identity_key_raw(root: &Path, path: &str, key: &[u8]) -> io::Result<()> {
    write_raw(root, path, encode_base64url(key).as_bytes())
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
    use std::env::set_current_dir;
    use std::fs;

    use super::*;

    use crate::client::init_local;
    use crate::context::create_client_context;
    use crate::testing::fs::{account_context, create_test_account, in_test_dir};
    use crate::testing::http::start_test_server;


    #[test]
    fn create_identity_has_valid_signature() {
        let (identity, _) = create_identity("alice@example.com", None).unwrap();
        assert_eq!(identity.address, "alice@example.com");
        assert_eq!(identity.public_key.algorithm, DEFAULT_SIGNING_ALGORITHM);
        assert_eq!(identity.signature.algorithm, DEFAULT_SIGNING_ALGORITHM);
        assert!(identity.members.is_none());

        assert!(verify_identity(&identity).is_ok());
    }

    #[test]
    fn create_identity_with_members_is_group() {
        let members = vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
        ];
        let (identity, _) = create_identity(
            "alice@example.com/.ark/groups/team.json",
            Some(members.clone()),
        )
        .unwrap();

        assert_eq!(identity.members.as_ref().unwrap(), &members);
        assert!(verify_identity(&identity).is_ok());
        validate_identity(&identity).unwrap();
    }

    #[test]
    fn create_identity_signature_detects_tampering() {
        let (identity, _) = create_identity("alice@example.com", None).unwrap();
        assert_eq!(identity.address, "alice@example.com");
        assert_eq!(identity.public_key.algorithm, DEFAULT_SIGNING_ALGORITHM);
        assert_eq!(identity.signature.algorithm, DEFAULT_SIGNING_ALGORITHM);

        let mut identity_tampered = identity.clone();
        identity_tampered.address = "mallory@example.com".to_string();

        assert!(verify_identity(&identity_tampered).is_err());
    }

    #[test]
    fn identity_json_round_trip() {
        let (identity, _) = create_identity("alice@example.com", None).unwrap();
        let s = serde_json::to_string(&identity).unwrap();
        let parsed: Identity = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.address, identity.address);
        assert_eq!(parsed.public_key.algorithm, identity.public_key.algorithm);
        assert_eq!(parsed.public_key.value, identity.public_key.value);
        assert_eq!(parsed.signature.algorithm, identity.signature.algorithm);
        assert_eq!(parsed.signature.value, identity.signature.value);
    }

    #[test]
    fn read_write_identity_round_trip() {
        in_test_dir("ark_identity_test", |temp_dir| {
            let (identity, _) = create_identity("alice@example.com", None).unwrap();
            write_identity_raw(temp_dir, "/identity.json", &identity).unwrap();
            let loaded = read_identity_raw(temp_dir, "/identity.json").unwrap();
            assert_eq!(loaded.address, identity.address);
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
    fn parse_address_path_is_empty_when_omitted() {
        let (name, host, path) = parse_address("bob@example.com").unwrap();
        assert_eq!(name, "bob");
        assert_eq!(host, "example.com");
        assert_eq!(path, "");
    }

    #[test]
    fn parse_address_keeps_port_and_path() {
        let (name, host, path) = parse_address("bob@example.com:9000/groups/team.json").unwrap();
        assert_eq!(name, "bob");
        assert_eq!(host, "example.com:9000");
        assert_eq!(path, "/groups/team.json");
    }

    #[test]
    fn validate_identity_accepts_well_formed() {
        let (identity, _) = create_identity("alice@example.com", None).unwrap();
        validate_identity(&identity).unwrap();
    }

    #[test]
    fn validate_identity_rejects_invalid_account_name() {
        let (mut identity, _) = create_identity("alice@example.com", None).unwrap();
        identity.address = "BAD@example.com".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("invalid account name"));
    }

    #[test]
    fn validate_identity_rejects_tampered_address() {
        let (mut identity, _) = create_identity("alice@example.com", None).unwrap();
        identity.address = "bob@example.com".to_string();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn read_write_identity_key_round_trip() {
        use crate::testing::fs::account_context;

        in_test_dir("ark_identity_test", |temp_dir| {
            let (_, _, account_dir) = create_test_account(temp_dir, "alice@example.com");
            let key = [77u8; 32];
            write_identity_key_raw(&account_dir, "/group.key", &key).unwrap();

            let (ctx, account_path) = account_context(&account_dir.join("group.key"));
            let loaded = read_identity_key(&ctx, &account_path).unwrap();
            assert_eq!(loaded, key);
        });
    }

    #[test]
    fn resolve_identity_returns_cached_when_present() {
        in_test_dir("ark_identity_test", |temp_dir| {
            init_local(temp_dir, "alice@example.com").unwrap();
            let ctx = create_client_context().unwrap();

            create_dir_all(&ctx, "/.ark/identities").unwrap();
            let (identity, _) = create_identity("bob@example.com", None).unwrap();
            write_identity(&ctx, "/.ark/identities/bob@example.com.json", &identity).unwrap();

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
            let (bob_ctx, bob_account_path) = account_context(&bob_dir.join(".ark/identity.json"));
            let expected = read_identity(&bob_ctx, &bob_account_path).unwrap();

            set_current_dir(&account_dir).unwrap();
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
            meta.members.push(Member { address: "*".to_string(), permission: Permission::Reader, key: None });
            sign_metadata(&bob_key, &mut meta, Some(&body)).unwrap();
            let (bob_ctx, bob_account_path) = account_context(&bob_identity_path);
            write_metadata_attributes(&bob_ctx, &bob_account_path, &meta).unwrap();
            let expected = read_identity(&bob_ctx, &bob_account_path).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let fetched = resolve_identity(&ctx, &bob_address).unwrap();

            assert_eq!(fetched.address, expected.address);
            assert_eq!(fetched.public_key.value, expected.public_key.value);
            assert_eq!(fetched.signature.value, expected.signature.value);

            let cache_path = format!("/.ark/identities/{}.json", bob_address);
            assert!(exists(&ctx, &cache_path), "cache file not written: {}", cache_path);
            let cached = read_identity(&ctx, &cache_path).unwrap();
            assert_eq!(cached.public_key.value, expected.public_key.value);
        });
    }

    #[cfg(unix)]
    #[test]
    fn write_identity_key_sets_0600() {
        use std::os::unix::fs::PermissionsExt;

        in_test_dir("ark_identity_test", |temp_dir| {
            write_identity_key_raw(temp_dir, "/identity.key", &[78u8; 32]).unwrap();
            let mode = fs::metadata(temp_dir.join("identity.key")).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        });
    }
}
