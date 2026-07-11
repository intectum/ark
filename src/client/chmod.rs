use std::path::Path;

use crate::crypto::{decrypt_bytes, encrypt_bytes};
use crate::types::IdentityContext;
use crate::identity::resolve_identity;
use crate::metadata::{get_member, read_metadata_attributes, sign_metadata, verify_metadata_signature, write_metadata_attributes};
use crate::types::{Key, Member, Permission};
use crate::util::{io_err, io_invalid_input, now_iso};

const PUBLIC_CLI: &str = "public";
const PUBLIC_WIRE: &str = "*";

pub fn cmd_chmod(
    ctx: &IdentityContext,
    path: &str,
    owners: &[String],
    writers: &[String],
    readers: &[String],
    drops: &[String],
) -> std::io::Result<()> {
    let input_path = Path::new(path);
    if !std::fs::exists(input_path)? {
        return Err(io_invalid_input("input does not exist"));
    }

    let mut metadata = read_metadata_attributes(input_path)?;

    let modifier_identity = resolve_identity(ctx, &metadata.modified_by)?;
    verify_metadata_signature(&modifier_identity.public_key, &metadata)?;

    match get_member(&metadata.members, &ctx.identity.address) {
        Some(m) if m.permission == Permission::Owner => {}
        _ => return Err(io_err("only an owner can change permissions")),
    }

    let encrypted = metadata.encryption_algorithm.is_some();

    let file_key = if encrypted {
        let member = get_member(&metadata.members, &ctx.identity.address)
            .ok_or_else(|| io_err("no member entry for current account"))?;
        let encrypted_file_key = member.key.as_ref()
            .ok_or_else(|| io_err("no file key for current account"))?;
        Some(decrypt_bytes(
            &Key {
                algorithm: encrypted_file_key.algorithm.clone(),
                value: ctx.identity_key.as_ref().expect("client context missing identity_key").value.clone()
            },
            &encrypted_file_key.value,
        )?)
    } else {
        None
    };

    apply_changes(ctx, &mut metadata.members, owners, Permission::Owner, file_key.as_deref())?;
    apply_changes(ctx, &mut metadata.members, writers, Permission::Write, file_key.as_deref())?;
    apply_changes(ctx, &mut metadata.members, readers, Permission::Read, file_key.as_deref())?;

    for addr in drops {
        let wire = cli_address_to_wire(addr);
        metadata.members.retain(|m| m.address != wire);
    }

    if !metadata.members.iter().any(|m| m.permission == Permission::Owner) {
        return Err(io_invalid_input("at least one owner must remain"));
    }

    metadata.modified = now_iso();
    metadata.modified_by = ctx.identity.address.clone();

    let body = if input_path.is_dir() { Vec::new() } else { std::fs::read(input_path)? };
    let sign_body = if input_path.is_dir() { None } else { Some(body.as_slice()) };
    sign_metadata(ctx.identity_key.as_ref().expect("client context missing identity_key"), &mut metadata, sign_body)?;

    write_metadata_attributes(input_path, &metadata)?;

    Ok(())
}

fn apply_changes(
    ctx: &IdentityContext,
    members: &mut Vec<Member>,
    addresses: &[String],
    permission: Permission,
    file_key: Option<&[u8]>,
) -> std::io::Result<()> {
    let encrypted = file_key.is_some();
    for addr in addresses {
        let wire = cli_address_to_wire(addr);
        if wire == PUBLIC_WIRE && encrypted {
            return Err(io_invalid_input("cannot add public member to encrypted file"));
        }

        match members.iter_mut().find(|m| m.address == wire) {
            Some(existing) => existing.permission = permission,
            None => {
                let key = match (file_key, wire.as_str()) {
                    (Some(fk), w) if w != PUBLIC_WIRE => {
                        let new_identity = resolve_identity(ctx, &wire)?;
                        let (algorithm, value) = encrypt_bytes(&new_identity.public_key, fk)?;
                        Some(Key { algorithm, value })
                    }
                    _ => None,
                };
                members.push(Member {
                    address: wire,
                    permission,
                    key,
                });
            }
        }
    }
    Ok(())
}

fn cli_address_to_wire(addr: &str) -> String {
    if addr == PUBLIC_CLI { PUBLIC_WIRE.to_string() } else { addr.to_string() }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::context::create_client_context;
    use crate::identity::write_identity;
    use crate::metadata::{create_metadata, sign_metadata, verify_metadata, write_metadata_attributes};
    use crate::types::{Identity, Key};
    use crate::util::test::{create_test_account, in_test_dir, write_encrypted_test_file, write_plain_test_file, TEST_ADDRESS};

    fn setup(temp_dir: &Path) -> (Identity, Key, PathBuf) {
        let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
        let cache_dir = account_dir.join(".ark").join("identities");
        fs::create_dir_all(&cache_dir).unwrap();
        write_identity(&cache_dir.join(format!("{}.json", TEST_ADDRESS)), &identity).unwrap();
        (identity, secret_key, account_dir)
    }

    #[test]
    fn adds_reader_to_local_file() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("notes.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"hello");

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_chmod(&ctx, path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[]).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let john = m.members.iter().find(|m| m.address == "john@example.com").unwrap();
            assert_eq!(john.permission, Permission::Read);
            assert!(m.members.iter().any(|m| m.address == TEST_ADDRESS && m.permission == Permission::Owner));
        });
    }

    #[test]
    fn adds_public_reader_when_unencrypted() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("public.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"open");

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_chmod(&ctx, path.to_str().unwrap(), &[], &[], &["public".to_string()], &[]).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let pub_member = m.members.iter().find(|m| m.address == "*").unwrap();
            assert_eq!(pub_member.permission, Permission::Read);
            assert!(pub_member.key.is_none());
        });
    }

    #[test]
    fn rejects_public_on_encrypted_file() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("enc.bin");
            write_encrypted_test_file(&path, &identity, &secret_key, b"plaintext");

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = cmd_chmod(&ctx, path.to_str().unwrap(), &[], &[], &["public".to_string()], &[]).unwrap_err();
            assert!(err.to_string().contains("public member to encrypted"), "msg was {}", err);
        });
    }

    #[test]
    fn adds_reader_to_encrypted_file() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let cache_dir = account_dir.join(".ark").join("identities");

            let (bob_identity, bob_secret_key) = crate::identity::create_identity("bob@example.com").unwrap();
            write_identity(&cache_dir.join("bob@example.com.json"), &bob_identity).unwrap();

            let path = account_dir.join("enc.bin");
            write_encrypted_test_file(&path, &identity, &secret_key, b"plaintext");

            let owner_wrapped = read_metadata_attributes(&path).unwrap().members[0].key.clone().unwrap();
            let file_key = crate::crypto::decrypt_bytes(
                &Key { algorithm: owner_wrapped.algorithm.clone(), value: secret_key.value.clone() },
                &owner_wrapped.value,
            ).unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_chmod(&ctx, path.to_str().unwrap(), &[], &[], &["bob@example.com".to_string()], &[]).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let bob = m.members.iter().find(|m| m.address == "bob@example.com").unwrap();
            assert_eq!(bob.permission, Permission::Read);
            let bob_wrapped = bob.key.as_ref().expect("bob's wrapped key");
            let recovered = crate::crypto::decrypt_bytes(
                &Key { algorithm: bob_wrapped.algorithm.clone(), value: bob_secret_key.value.clone() },
                &bob_wrapped.value,
            ).unwrap();
            assert_eq!(recovered, file_key, "bob unwraps to same file key");
        });
    }

    #[test]
    fn upgrades_existing_member_permission() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);

            let path = account_dir.join("doc.txt");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"body").unwrap();
            let mut m = create_metadata(&identity.address, None);
            m.members.push(Member {
                address: "sam@example.com".to_string(),
                permission: Permission::Read,
                key: None,
            });
            sign_metadata(&secret_key, &mut m, Some(b"body")).unwrap();
            write_metadata_attributes(&path, &m).unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_chmod(&ctx, path.to_str().unwrap(), &[], &["sam@example.com".to_string()], &[], &[]).unwrap();

            let m2 = read_metadata_attributes(&path).unwrap();
            let sam = m2.members.iter().find(|m| m.address == "sam@example.com").unwrap();
            assert_eq!(sam.permission, Permission::Write);
        });
    }

    #[test]
    fn drops_member() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);

            let path = account_dir.join("doc.txt");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"body").unwrap();
            let mut m = create_metadata(&identity.address, None);
            m.members.push(Member {
                address: "sam@example.com".to_string(),
                permission: Permission::Read,
                key: None,
            });
            sign_metadata(&secret_key, &mut m, Some(b"body")).unwrap();
            write_metadata_attributes(&path, &m).unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_chmod(&ctx, path.to_str().unwrap(), &[], &[], &[], &["sam@example.com".to_string()]).unwrap();

            let m2 = read_metadata_attributes(&path).unwrap();
            assert!(!m2.members.iter().any(|m| m.address == "sam@example.com"));
        });
    }

    #[test]
    fn rejects_dropping_last_owner() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("doc.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"body");

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = cmd_chmod(&ctx, path.to_str().unwrap(), &[], &[], &[], &[TEST_ADDRESS.to_string()]).unwrap_err();
            assert!(err.to_string().contains("at least one owner"), "msg was {}", err);
        });
    }

    #[test]
    fn rejects_non_owner_caller() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);

            let path = account_dir.join("doc.txt");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"body").unwrap();
            let mut m = create_metadata(&identity.address, None);
            m.members[0].permission = Permission::Write;
            m.members.push(Member {
                address: "boss@example.com".to_string(),
                permission: Permission::Owner,
                key: None,
            });
            sign_metadata(&secret_key, &mut m, Some(b"body")).unwrap();
            write_metadata_attributes(&path, &m).unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = cmd_chmod(&ctx, path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[]).unwrap_err();
            assert!(err.to_string().contains("only an owner"), "msg was {}", err);
        });
    }

    #[test]
    fn cmd_chmod_missing_input_errors() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (_identity, _secret_key, account_dir) = setup(temp_dir);
            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let missing = account_dir.join("nope.txt");
            let err = cmd_chmod(&ctx, missing.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[]).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(format!("{}", err).contains("input does not exist"));
        });
    }

    #[test]
    fn re_signs_metadata_so_body_hash_matches() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("doc.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"body");

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_chmod(&ctx, path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[]).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let body = fs::read(&path).unwrap();
            verify_metadata(&identity.public_key, &m, Some(&body)).unwrap();
        });
    }
}
