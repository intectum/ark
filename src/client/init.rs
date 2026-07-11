use std::env::current_dir;
use std::fs;
#[cfg(test)]
use std::path::Path;

use crate::client::put::cmd_put;
use crate::client::request::ark_request;
use crate::context::create_client_context;
use crate::identity::{create_identity, validate_identity, write_identity, write_identity_key};
use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
#[cfg(test)]
use crate::types::Key;
use crate::types::{Identity, Member, Permission};
use crate::util::{io_err, resolve_client_url_raw};

pub fn cmd_init(address: &str) -> std::io::Result<()> {
    let root = current_dir()?;
    let url = resolve_client_url_raw(&root, "/.ark/identity.json", address)?;
    let dot_ark_dir = root.join(".ark");

    let identity_path = dot_ark_dir.join("identity.json");
    if identity_path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} already exists", identity_path.display())));
    }

    let identity_key_path = dot_ark_dir.join("identity.key");
    if identity_key_path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} already exists", identity_key_path.display())));
    }

    let (code, _, body) = ark_request(None, "GET", &url, &[], &[])?;
    match code {
        200 => {
            let identity: Identity = serde_json::from_slice(&body)
                .map_err(|e| io_err(&format!("identity json: {}", e)))?;
            validate_identity(&identity)?;
            if identity.address != address {
                return Err(io_err(&format!("server identity address {} does not match {}", identity.address, address)));
            }
            fs::create_dir_all(&dot_ark_dir)?;
            write_identity(&identity_path, &identity)?;
        }
        403 | 404 => {
            let (identity, secret_key) = create_identity(address)?;
            validate_identity(&identity)?;

            fs::create_dir_all(&dot_ark_dir)?;
            write_identity(&identity_path, &identity)?;
            write_identity_key(&identity_key_path, &secret_key.value)?;

            let body = fs::read(&identity_path)?;
            let mut metadata = create_metadata(&identity.address, None);
            metadata.members.push(Member {
                address: "*".to_string(),
                permission: Permission::Read,
                key: None,
            });
            sign_metadata(&secret_key, &mut metadata, Some(&body))?;
            write_metadata_attributes(&identity_path, &metadata)?;

            let ctx = create_client_context()?;
            cmd_put(&ctx, "/.ark/identity.json", identity_path.to_str(), None)?;
        }
        _ => return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body)))),
    }

    Ok(())
}

#[cfg(test)]
pub fn init(root: &Path, address: &str) -> std::io::Result<(Identity, Key)> {
    let dot_ark_dir = root.join(".ark");
    let (identity, secret_key) = create_identity(address)?;

    fs::create_dir_all(&dot_ark_dir)?;
    write_identity(&dot_ark_dir.join("identity.json"), &identity)?;
    write_identity_key(&dot_ark_dir.join("identity.key"), &secret_key.value)?;

    Ok((identity, secret_key))
}

#[cfg(test)]
mod tests {
    use std::env::set_current_dir;

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::identity::read_identity;
    use crate::metadata::write_metadata_attributes;
    use crate::server::start_test_server;
    use crate::util::decode_base64url;
    use crate::util::test::in_test_dir;

    #[test]
    fn init_writes_identity_file() {
        in_test_dir("ark_init_test", |temp_dir| {
            let (_, secret_key) = init(temp_dir, "gyan@example.com:8080").unwrap();
            let identity_path = temp_dir.join(".ark/identity.json");
            assert!(Path::new(&identity_path).exists());

            let content = fs::read_to_string(&identity_path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();

            assert_eq!(v["public_key"]["algorithm"].as_str(), Some("ed25519"));
            let pk_b64 = v["public_key"]["value"].as_str().unwrap();
            let pk_bytes = decode_base64url(pk_b64).unwrap();
            let seed: [u8; 32] = secret_key.value.as_slice().try_into().unwrap();
            assert_eq!(pk_bytes, SigningKey::from_bytes(&seed).verifying_key().to_bytes());

            assert_eq!(v["address"].as_str(), Some("gyan@example.com:8080"));
            let modified = v["modified"].as_str().unwrap();
            time::OffsetDateTime::parse(modified, &time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|e| panic!("modified is not RFC 3339: {} ({})", modified, e));
            assert_eq!(v["signature"]["algorithm"].as_str(), Some("ed25519"));
        });
    }

    #[test]
    fn init_writes_identity_key_file() {
        in_test_dir("ark_init_test", |temp_dir| {
            let (_, secret_key) = init(temp_dir, "gyan@example.com").unwrap();
            let identity_key_path = temp_dir.join(".ark/identity.key");
            assert!(Path::new(&identity_key_path).exists());

            let content = fs::read_to_string(&identity_key_path).unwrap();
            let decoded = decode_base64url(content.trim()).unwrap();
            assert_eq!(decoded, secret_key.value);
        });
    }

    #[test]
    fn cmd_init_downloads_existing_server_identity() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            let server_account_dir = temp_dir.join("ark").join("gyan");
            fs::create_dir_all(&server_account_dir).unwrap();
            let (server_identity, server_secret_key) = init(&server_account_dir, &address).unwrap();

            let server_identity_path = server_account_dir.join(".ark").join("identity.json");
            let identity_bytes = fs::read(&server_identity_path).unwrap();
            let mut meta = create_metadata(&address, None);
            meta.members[0].key = None;
            meta.members.push(Member {
                address: "*".to_string(),
                permission: Permission::Read,
                key: None,
            });
            sign_metadata(&server_secret_key, &mut meta, Some(&identity_bytes)).unwrap();
            write_metadata_attributes(&server_identity_path, &meta).unwrap();

            let client_dir = temp_dir.join("client");
            fs::create_dir_all(&client_dir).unwrap();
            set_current_dir(&client_dir).unwrap();

            cmd_init(&address).unwrap();

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
    fn cmd_init_creates_and_uploads_when_server_empty() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            cmd_init(&address).unwrap();

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
    fn cmd_init_errors_when_server_unreachable() {
        in_test_dir("ark_init_test", |_temp_dir| {
            let err = cmd_init("gyan@127.0.0.1:1").unwrap_err();
            assert!(
                matches!(err.kind(), std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Other),
                "unexpected error kind: {:?} ({})", err.kind(), err
            );
        });
    }

    #[test]
    fn cmd_init_rejects_existing_local_identity() {
        in_test_dir("ark_init_test", |temp_dir| {
            fs::create_dir_all(temp_dir.join(".ark")).unwrap();
            fs::write(temp_dir.join(".ark/identity.json"), b"placeholder").unwrap();
            let err = cmd_init("gyan@127.0.0.1:1").unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        });
    }

    #[test]
    fn cmd_init_second_client_downloads_from_server() {
        in_test_dir("ark_init_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);

            cmd_init(&address).unwrap();
            let first_identity = read_identity(&temp_dir.join(".ark/identity.json")).unwrap();

            let second_client = temp_dir.join("second");
            fs::create_dir_all(&second_client).unwrap();
            set_current_dir(&second_client).unwrap();

            cmd_init(&address).unwrap();

            let downloaded = read_identity(&second_client.join(".ark/identity.json")).unwrap();
            assert_eq!(downloaded.public_key.value, first_identity.public_key.value);
            assert!(!second_client.join(".ark/identity.key").exists());
        });
    }
}
