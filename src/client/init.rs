use std::fs;
use std::io;
use std::path::Path;
use std::str::from_utf8;

use super::{decrypt_stream, put, request};

use crate::context::create_client_context;
use crate::crypto::{DEFAULT_PASSWORD_ALGORITHM, create_secret_key_from_password, restore_secret_key_from_password, to_public_key};
use crate::http::check_response_code;
use crate::identity::{create_identity, parse_address, sign_identity, validate_identity, write_identity, write_identity_key};
use crate::metadata::{read_metadata_headers, write_metadata_attributes};
use crate::permissions::{reader, writer};
use crate::types::{Identity, IdentityContext, Key, Signature};
use crate::util::{decode_base64url, resolve_client_url_raw};

/// Initialize the ark account at `address` under `root`.
///
/// If the server already hosts an identity for `address`, pins it locally
/// (identity file only, no private key). Otherwise generates a fresh keypair,
/// stores it under `root/.ark/`, and uploads the identity to the server.
///
/// When `password` is provided, the identity key is encrypted with a
/// password-derived identity and stored on the server. Another client can then
/// call `init` with the same address and password to recover the identity key
/// without out-of-band transfer.
///
/// With `local_only = true`, generates a fresh keypair locally and skips all
/// network calls. `password` must be `None` in this mode.
///
/// Errors if `root/.ark/identity.json` or `root/.ark/identity.key` already
/// exists, or if the server returns a non-200/403/404 response.
pub fn init(root: &Path, address: &str, password: Option<&str>, local_only: bool) -> io::Result<()> {
    let dot_ark_dir = root.join(".ark");

    let identity_path = dot_ark_dir.join("identity.json");
    if identity_path.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", identity_path.display())));
    }

    let identity_key_path = dot_ark_dir.join("identity.key");
    if identity_key_path.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", identity_key_path.display())));
    }

    if local_only {
        if password.is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "--password not supported with --local-only"));
        }
        init_local(root, address)?;
        return Ok(());
    }

    let url = resolve_client_url_raw(root, "/.ark/identity.json", address)?;
    let (code, _, body) = request(None, "GET", &url, &[], &[])?;
    match code {
        200..300 => {
            let identity: Identity = serde_json::from_slice(&body)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("identity json: {}", e)))?;
            validate_identity(&identity)?;
            if identity.address != address {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("server identity address {} does not match {}", identity.address, address)));
            }
            fs::create_dir_all(&dot_ark_dir)?;
            write_identity(&identity_path, &identity)?;

            if let Some(pw) = password {
                pull_secret_key_with_password(root, &identity, pw)?;
            }
        }
        403 | 404 => {
            let (_identity, _secret_key) = init_local(root, address)?;

            let ctx = create_client_context()?;
            put(&ctx, "/.ark/identity.json", identity_path.to_str(), &reader("public"), Some("none"), false)?;

            let (_, host, _) = parse_address(&ctx.identity.address)?;
            let ark_address = format!("ark@{}", host);

            let requests_dir = ctx.root.join(".ark").join("requests");
            fs::create_dir_all(&requests_dir)?;

            put(&ctx, "/.ark/requests/", requests_dir.to_str(), &writer(ark_address), None, false)?;

            if let Some(pw) = password {
                push_secret_key_with_password(&ctx, pw)?;
            }
        }
        _ => check_response_code(code, &body)?,
    }

    Ok(())
}

/// Create a fresh identity keypair under `root/.ark/` without touching the
/// network. Returns the new [`Identity`] and its secret [`Key`]. Test helper.
pub fn init_local(root: &Path, address: &str) -> io::Result<(Identity, Key)> {
    let dot_ark_dir = root.join(".ark");
    let (identity, secret_key) = create_identity(address, None)?;
    validate_identity(&identity)?;

    fs::create_dir_all(&dot_ark_dir)?;
    write_identity(&dot_ark_dir.join("identity.json"), &identity)?;
    write_identity_key(&dot_ark_dir.join("identity.key"), &secret_key.value)?;

    Ok((identity, secret_key))
}

fn pull_secret_key_with_password(
    root: &Path,
    identity: &Identity,
    password: &str,
) -> io::Result<()> {
    let password_address = format!("{}/.ark/passwords/primary.json", identity.address);
    let password_url = resolve_client_url_raw(root, &password_address, &identity.address)?;
    let (password_code, _, password_body) = request(None, "GET", &password_url, &[], &[])?;
    check_response_code(password_code, &password_body)?;

    let password_identity: Identity = serde_json::from_slice(&password_body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("password json: {}", e)))?;
    validate_identity(&password_identity)?;

    let password_ctx = IdentityContext {
        // TODO: should use identity key path to limit scope
        root: root.to_path_buf(),
        identity: password_identity.clone(),
        identity_key: Some(restore_secret_key_from_password(&password_identity, password)?),
    };

    let identity_key_url = resolve_client_url_raw(root, "/.ark/identity.key", &identity.address)?;
    let (identity_key_code, identity_key_headers, identity_key_body) = request(Some(&password_ctx), "GET", &identity_key_url, &[], &[])?;
    check_response_code(identity_key_code, &identity_key_body)?;

    let identity_key_metadata = read_metadata_headers(&identity_key_headers)?;

    let mut identity_key_bytes = Vec::new();
    decrypt_stream(&password_ctx, &identity_key_metadata, &mut identity_key_body.as_slice(), &mut identity_key_bytes)?;

    let identity_key_b64 = from_utf8(&identity_key_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "identity.key plaintext not utf8"))?;
    let secret_key = decode_base64url(identity_key_b64.trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "identity.key plaintext not base64url"))?;

    let identity_key_path = root.join(".ark").join("identity.key");
    write_identity_key(&identity_key_path, &secret_key)?;
    write_metadata_attributes(&identity_key_path, &identity_key_metadata)?;

    Ok(())
}

fn push_secret_key_with_password(
    ctx: &IdentityContext,
    password: &str,
) -> io::Result<()> {
    let password_secret_key = create_secret_key_from_password(DEFAULT_PASSWORD_ALGORITHM, password)?;
    let dot_ark_dir = ctx.root.join(".ark");

    let mut password_identity = Identity {
        public_key: to_public_key(&password_secret_key)?,
        address: format!("{}/.ark/passwords/primary.json", ctx.identity.address),
        members: None,
        signature: Signature {
            algorithm: String::new(),
            value: Vec::new()
        },
    };
    sign_identity(&password_secret_key, &mut password_identity)?;

    let passwords_dir = dot_ark_dir.join("passwords");
    fs::create_dir_all(&passwords_dir)?;
    let password_path = passwords_dir.join("primary.json");
    write_identity(&password_path, &password_identity)?;

    put(ctx, "/.ark/passwords/primary.json", password_path.to_str(), &reader("public"), Some("none"), false)?;

    let identity_key_path = dot_ark_dir.join("identity.key");
    put(ctx, "/.ark/identity.key", identity_key_path.to_str(), &reader(&password_identity.address), None, false)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env::{current_dir, set_current_dir};

    use ed25519_dalek::SigningKey;

    use super::*;

    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, DEFAULT_SIGNING_ALGORITHM, PASSWORD_SALT_LEN, PASSWORD_VERIFIER_LEN, decrypt_bytes};
    use crate::identity::read_identity;
    use crate::metadata::{create_metadata, read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::testing::fs::in_test_dir;
    use crate::testing::http::start_test_server;
    use crate::types::{Member, Permission};
    use crate::util::decode_base64url;

    #[test]
    fn init_writes_identity_file() {
        in_test_dir("ark_init_test", |temp_dir| {
            let (_, secret_key) = init_local(temp_dir, "gyan@example.com:8080").unwrap();
            let identity_path = temp_dir.join(".ark/identity.json");
            assert!(Path::new(&identity_path).exists());

            let content = fs::read_to_string(&identity_path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();

            assert_eq!(v["public_key"]["algorithm"].as_str(), Some(DEFAULT_SIGNING_ALGORITHM));
            let pk_b64 = v["public_key"]["value"].as_str().unwrap();
            let pk_bytes = decode_base64url(pk_b64).unwrap();
            let seed: [u8; 32] = secret_key.value.as_slice().try_into().unwrap();
            assert_eq!(pk_bytes, SigningKey::from_bytes(&seed).verifying_key().to_bytes());

            assert_eq!(v["address"].as_str(), Some("gyan@example.com:8080"));
            assert!(v.get("modified").is_none());
            assert_eq!(v["signature"]["algorithm"].as_str(), Some(DEFAULT_SIGNING_ALGORITHM));
        });
    }

    #[test]
    fn init_writes_identity_key_file() {
        in_test_dir("ark_init_test", |temp_dir| {
            let (_, secret_key) = init_local(temp_dir, "gyan@example.com").unwrap();
            let identity_key_path = temp_dir.join(".ark/identity.key");
            assert!(Path::new(&identity_key_path).exists());

            let content = fs::read_to_string(&identity_key_path).unwrap();
            let decoded = decode_base64url(content.trim()).unwrap();
            assert_eq!(decoded, secret_key.value);
        });
    }

    #[test]
    fn init_downloads_existing_server_identity() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            let server_account_dir = temp_dir.join("ark").join("gyan");
            fs::create_dir_all(&server_account_dir).unwrap();
            let (server_identity, server_secret_key) = init_local(&server_account_dir, &address).unwrap();

            let server_identity_path = server_account_dir.join(".ark").join("identity.json");
            let identity_bytes = fs::read(&server_identity_path).unwrap();
            let mut meta = create_metadata(&server_identity.address, None);
            meta.members[0].key = None;
            meta.members.push(Member {
                address: "*".to_string(),
                permission: Permission::Reader,
                key: None,
            });
            sign_metadata(&server_secret_key, &mut meta, Some(&identity_bytes)).unwrap();
            write_metadata_attributes(&server_identity_path, &meta).unwrap();

            let client_dir = temp_dir.join("client");
            fs::create_dir_all(&client_dir).unwrap();
            set_current_dir(&client_dir).unwrap();

            init(&current_dir().unwrap(), &address, None, false).unwrap();

            let identity_path = client_dir.join(".ark").join("identity.json");
            assert!(identity_path.exists());
            let downloaded = read_identity(&identity_path).unwrap();
            assert_eq!(downloaded.address, server_identity.address);
            assert_eq!(downloaded.public_key.value, server_identity.public_key.value);

            let identity_key_path = client_dir.join(".ark").join("identity.key");
            assert!(!identity_key_path.exists(), "no key should be written on download");
        });
    }

    #[test]
    fn init_creates_and_uploads_when_server_empty() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            init(&current_dir().unwrap(), &address, None, false).unwrap();

            let identity_path = temp_dir.join(".ark").join("identity.json");
            let identity_key_path = temp_dir.join(".ark").join("identity.key");
            assert!(identity_path.exists());
            assert!(identity_key_path.exists());

            let local = read_identity(&identity_path).unwrap();
            assert_eq!(local.address, address);

            let server_path = temp_dir.join("ark").join("gyan").join(".ark").join("identity.json");
            assert!(server_path.exists(), "server should have uploaded identity");
            let server = read_identity(&server_path).unwrap();
            assert_eq!(server.public_key.value, local.public_key.value);
        });
    }

    #[test]
    fn init_grants_ark_write_on_requests_dir() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            init(&current_dir().unwrap(), &address, None, false).unwrap();

            let requests_dir = temp_dir.join("ark/gyan/.ark/requests");
            assert!(requests_dir.is_dir(), "server should have requests dir");

            let metadata = read_metadata_attributes(&requests_dir).unwrap();
            let ark_address = format!("ark@127.0.0.1:{}", port);
            let ark_member = metadata.members.iter().find(|m| m.address == ark_address)
                .expect("ark must be a member of requests dir");
            assert_eq!(ark_member.permission, Permission::Writer);

            let owner = metadata.members.iter().find(|m| m.address == address)
                .expect("account must be owner of requests dir");
            assert_eq!(owner.permission, Permission::Owner);
        });
    }

    #[test]
    fn init_errors_when_server_unreachable() {
        in_test_dir("ark_init_test", |_temp_dir| {
            let err = init(&current_dir().unwrap(), "gyan@127.0.0.1:1", None, false).unwrap_err();
            assert!(
                matches!(err.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::PermissionDenied | io::ErrorKind::Other),
                "unexpected error kind: {:?} ({})", err.kind(), err
            );
        });
    }

    #[test]
    fn init_rejects_existing_local_identity() {
        in_test_dir("ark_init_test", |temp_dir| {
            fs::create_dir_all(temp_dir.join(".ark")).unwrap();
            fs::write(temp_dir.join(".ark/identity.json"), b"placeholder").unwrap();
            let err = init(&current_dir().unwrap(), "gyan@127.0.0.1:1", None, false).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        });
    }

    #[test]
    fn init_password_uploads_credential_and_identity_key() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let expected_credential_address = format!("{}/.ark/passwords/primary.json", address);

            init(&current_dir().unwrap(), &address, Some("hunter2"), false).unwrap();

            let local_key_path = temp_dir.join(".ark/identity.key");
            assert!(local_key_path.exists(), "local seed file must remain");
            let local_seed = decode_base64url(fs::read_to_string(&local_key_path).unwrap().trim()).unwrap();

            let credential_server = temp_dir.join("ark/gyan/.ark/passwords/primary.json");
            assert!(credential_server.exists(), "credential json uploaded");
            let credential_identity = read_identity(&credential_server).unwrap();
            assert_eq!(credential_identity.address, expected_credential_address);
            assert_eq!(credential_identity.public_key.algorithm, DEFAULT_PASSWORD_ALGORITHM);
            assert_eq!(credential_identity.public_key.value.len(), PASSWORD_VERIFIER_LEN + PASSWORD_SALT_LEN + 32);

            let salt = &credential_identity.public_key.value[PASSWORD_VERIFIER_LEN..PASSWORD_VERIFIER_LEN + PASSWORD_SALT_LEN];
            let mut seed_value = Vec::with_capacity(PASSWORD_SALT_LEN + "hunter2".len());
            seed_value.extend_from_slice(salt);
            seed_value.extend_from_slice(b"hunter2");
            let seed_key = Key { algorithm: DEFAULT_PASSWORD_ALGORITHM.to_string(), value: seed_value };
            let expected_public = to_public_key(&seed_key).unwrap();
            assert_eq!(credential_identity.public_key.value, expected_public.value);

            let server_key_path = temp_dir.join("ark/gyan/.ark/identity.key");
            assert!(server_key_path.exists(), "server-side identity.key uploaded");
            let ciphertext = fs::read(&server_key_path).unwrap();
            let metadata = read_metadata_attributes(&server_key_path).unwrap();
            assert_eq!(metadata.encryption_algorithm.as_deref(), Some(DEFAULT_ENCRYPTION_ALGORITHM));
            assert_eq!(metadata.members.len(), 2);
            assert_eq!(metadata.members[0].address, address);
            assert_eq!(metadata.members[1].address, expected_credential_address);

            let owner_wrap = metadata.members[0].key.as_ref().unwrap();
            let owner_decrypt_key = Key { algorithm: owner_wrap.algorithm.clone(), value: local_seed.clone() };
            let file_key_bytes = decrypt_bytes(&owner_decrypt_key, &owner_wrap.value).unwrap();
            let file_key = Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: file_key_bytes };
            let decrypted = decrypt_bytes(&file_key, &ciphertext).unwrap();
            let decoded = decode_base64url(from_utf8(&decrypted).unwrap().trim()).unwrap();
            assert_eq!(decoded, local_seed, "encrypted body decrypts to identity seed");
        });
    }

    #[test]
    fn init_password_recovers_identity_key_on_second_client() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            init(&current_dir().unwrap(), &address, Some("hunter2"), false).unwrap();
            let original_seed = decode_base64url(fs::read_to_string(temp_dir.join(".ark/identity.key")).unwrap().trim()).unwrap();

            let second_client = temp_dir.join("second");
            fs::create_dir_all(&second_client).unwrap();
            set_current_dir(&second_client).unwrap();

            init(&current_dir().unwrap(), &address, Some("hunter2"), false).unwrap();

            let recovered = decode_base64url(fs::read_to_string(second_client.join(".ark/identity.key")).unwrap().trim()).unwrap();
            assert_eq!(recovered, original_seed);
        });
    }

    #[test]
    fn init_password_wrong_password_errors() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            init(&current_dir().unwrap(), &address, Some("hunter2"), false).unwrap();

            let second_client = temp_dir.join("second");
            fs::create_dir_all(&second_client).unwrap();
            set_current_dir(&second_client).unwrap();

            let err = init(&current_dir().unwrap(), &address, Some("wrongpw"), false).unwrap_err();
            assert!(err.to_string().contains("verifier mismatch"), "err was {}", err);
        });
    }

    #[test]
    fn init_second_client_downloads_from_server() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            init(&current_dir().unwrap(), &address, None, false).unwrap();
            let first_identity = read_identity(&temp_dir.join(".ark/identity.json")).unwrap();

            let second_client = temp_dir.join("second");
            fs::create_dir_all(&second_client).unwrap();
            set_current_dir(&second_client).unwrap();

            init(&current_dir().unwrap(), &address, None, false).unwrap();

            let downloaded = read_identity(&second_client.join(".ark/identity.json")).unwrap();
            assert_eq!(downloaded.public_key.value, first_identity.public_key.value);
            assert!(!second_client.join(".ark/identity.key").exists());
        });
    }
}
