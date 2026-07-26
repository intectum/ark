use std::env::current_dir;
use std::fs;
use std::io;
use std::path::Path;

use super::put;
use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, DEFAULT_HASH_ALGORITHM, encrypt_bytes};
use crate::types::IdentityContext;
use crate::identity::resolve_identity;
use crate::metadata::{create_metadata, extract_key_from_metadata, get_member, has_metadata_attributes, read_metadata_attributes, sign_metadata, verify_metadata_signature, write_local_metadata_attributes, write_metadata_attributes};
use crate::types::{Hash, Key, LocalMetadata, Member, Permission};
use crate::util::{io_err, io_invalid_input, now_iso, sha256};

const PUBLIC_CLI: &str = "public";
const PUBLIC_WIRE: &str = "*";

/// Change members and permissions on a local file or directory.
///
/// Adds or promotes each address in `owners`/`writers`/`readers` to the
/// matching permission; removes each address in `drops`. The literal
/// `"public"` maps to the wildcard address `*` (rejected for encrypted files).
///
/// If the target has no metadata yet, seeds fresh metadata with the current
/// account as sole owner before applying the requested changes.
/// `encryption_algorithm` is only consulted when seeding: `Some("none")` =
/// plaintext, `None` = default (AES-256-GCM), any other value = named
/// algorithm. Directories reject any `encryption_algorithm`. When metadata
/// already exists, the caller must be an owner and `encryption_algorithm` must
/// be `None`.
///
/// With `local_only = false` (the default), the change is uploaded via
/// [`put`](super::put) after xattrs are written. With `local_only = true`,
/// only the local xattrs are updated; a later [`put`](super::put) or
/// [`sync`](super::sync) will propagate the change.
///
/// At least one owner must remain.
pub fn chmod(
    ctx: &IdentityContext,
    path: &str,
    owners: &[String],
    writers: &[String],
    readers: &[String],
    drops: &[String],
    local_only: bool,
    encryption_algorithm: Option<&str>,
) -> io::Result<()> {
    let input_path = Path::new(path);
    if !fs::exists(input_path)? {
        return Err(io_invalid_input("input does not exist"));
    }

    let creating = !has_metadata_attributes(input_path)?;
    let is_dir = input_path.is_dir();

    if !creating && encryption_algorithm.is_some() {
        return Err(io_invalid_input("--encryption-algorithm only allowed when seeding metadata"));
    }
    if input_path.is_dir() && encryption_algorithm.is_some() {
        return Err(io_invalid_input("--encryption-algorithm not supported for directories"));
    }

    let mut metadata = if creating {
        let algorithm = if input_path.is_dir() {
            None
        } else {
            match encryption_algorithm {
                Some("none") => None,
                Some(a) => Some(a),
                None => Some(DEFAULT_ENCRYPTION_ALGORITHM),
            }
        };
        create_metadata(&ctx.identity.address, algorithm)
    } else {
        let m = read_metadata_attributes(input_path)?;
        let modifier_identity = resolve_identity(ctx, &m.modified_by)?;
        verify_metadata_signature(&modifier_identity.public_key, &m)?;

        match get_member(&m.members, &ctx.identity.address) {
            Some(mem) if mem.permission == Permission::Owner => {}
            _ => return Err(io_err("only an owner can change permissions")),
        }

        m
    };

    let encrypted = metadata.encryption_algorithm.is_some();

    let file_key = if !creating && encrypted {
        extract_key_from_metadata(ctx, &metadata)?
    } else {
        None
    };

    apply_changes(ctx, &mut metadata.members, owners, Permission::Owner, encrypted, file_key.as_deref())?;
    apply_changes(ctx, &mut metadata.members, writers, Permission::Writer, encrypted, file_key.as_deref())?;
    apply_changes(ctx, &mut metadata.members, readers, Permission::Reader, encrypted, file_key.as_deref())?;

    for addr in drops {
        let wire = cli_address_to_wire(addr);
        metadata.members.retain(|m| m.address != wire);
    }

    if !metadata.members.iter().any(|m| m.permission == Permission::Owner) {
        return Err(io_invalid_input("at least one owner must remain"));
    }

    metadata.modified = now_iso();
    metadata.modified_by = ctx.identity.address.clone();

    let secret_key = ctx.identity_key.as_ref().expect("client context missing identity_key");
    if creating && !is_dir {
        let body = fs::read(input_path)?;
        sign_metadata(secret_key, &mut metadata, Some(&body))?;
        write_metadata_attributes(input_path, &metadata)?;
        write_local_metadata_attributes(input_path, &LocalMetadata {
            encrypted: Some(false),
            sync_body_hash: Some(Hash { algorithm: DEFAULT_HASH_ALGORITHM.to_string(), value: sha256(&body) }),
            sync_modified: Some(metadata.modified.clone()),
        })?;
    } else {
        sign_metadata(secret_key, &mut metadata, None)?;
        write_metadata_attributes(input_path, &metadata)?;
    }

    if !local_only {
        let url_path = url_path_for(ctx, input_path)?;
        put(ctx, &url_path, Some(path), None, !creating)?;
    }

    Ok(())
}

fn apply_changes(
    ctx: &IdentityContext,
    members: &mut Vec<Member>,
    addresses: &[String],
    permission: Permission,
    encrypted: bool,
    file_key: Option<&[u8]>,
) -> io::Result<()> {
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

fn url_path_for(ctx: &IdentityContext, input_path: &Path) -> io::Result<String> {
    let absolute = if input_path.is_absolute() {
        input_path.to_path_buf()
    } else {
        current_dir()?.join(input_path)
    };
    let relative = absolute.strip_prefix(&ctx.root)
        .map_err(|_| io_err("path is not within this account"))?;
    Ok(format!("/{}", relative.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use std::env::set_current_dir;
    use std::fs;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::context::create_client_context;
    use crate::crypto::decrypt_bytes;
    use crate::identity::{create_identity, write_identity};
    use crate::metadata::{create_metadata, read_local_metadata_attributes, sign_metadata, verify_metadata, write_metadata_attributes};
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

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[], true, None).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let john = m.members.iter().find(|m| m.address == "john@example.com").unwrap();
            assert_eq!(john.permission, Permission::Reader);
            assert!(m.members.iter().any(|m| m.address == TEST_ADDRESS && m.permission == Permission::Owner));
        });
    }

    #[test]
    fn adds_public_reader_when_unencrypted() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("public.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"open");

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &[], &["public".to_string()], &[], true, None).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let pub_member = m.members.iter().find(|m| m.address == "*").unwrap();
            assert_eq!(pub_member.permission, Permission::Reader);
            assert!(pub_member.key.is_none());
        });
    }

    #[test]
    fn rejects_public_on_encrypted_file() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("enc.bin");
            write_encrypted_test_file(&path, &identity, &secret_key, b"plaintext");

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = chmod(&ctx, path.to_str().unwrap(), &[], &[], &["public".to_string()], &[], true, None).unwrap_err();
            assert!(err.to_string().contains("public member to encrypted"), "msg was {}", err);
        });
    }

    #[test]
    fn adds_reader_to_encrypted_file() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let cache_dir = account_dir.join(".ark").join("identities");

            let (bob_identity, bob_secret_key) = create_identity("bob@example.com").unwrap();
            write_identity(&cache_dir.join("bob@example.com.json"), &bob_identity).unwrap();

            let path = account_dir.join("enc.bin");
            write_encrypted_test_file(&path, &identity, &secret_key, b"plaintext");

            let owner_wrapped = read_metadata_attributes(&path).unwrap().members[0].key.clone().unwrap();
            let file_key = decrypt_bytes(
                &Key { algorithm: owner_wrapped.algorithm.clone(), value: secret_key.value.clone() },
                &owner_wrapped.value,
            ).unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &[], &["bob@example.com".to_string()], &[], true, None).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let bob = m.members.iter().find(|m| m.address == "bob@example.com").unwrap();
            assert_eq!(bob.permission, Permission::Reader);
            let bob_wrapped = bob.key.as_ref().expect("bob's wrapped key");
            let recovered = decrypt_bytes(
                &Key { algorithm: bob_wrapped.algorithm.clone(), value: bob_secret_key.value.clone() },
                &bob_wrapped.value,
            ).unwrap();
            assert_eq!(recovered, file_key, "bob unwraps to same file key");
        });
    }

    #[test]
    fn adds_member_to_encrypted_file_without_wrapped_key() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let cache_dir = account_dir.join(".ark").join("identities");

            let (bob_identity, _bob_secret_key) = create_identity("bob@example.com").unwrap();
            write_identity(&cache_dir.join("bob@example.com.json"), &bob_identity).unwrap();

            let path = account_dir.join("enc.bin");
            fs::write(&path, b"body").unwrap();
            let mut m = create_metadata(&identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            sign_metadata(&secret_key, &mut m, Some(b"body")).unwrap();
            write_metadata_attributes(&path, &m).unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &[], &["bob@example.com".to_string()], &[], true, None).unwrap();

            let m2 = read_metadata_attributes(&path).unwrap();
            let bob = m2.members.iter().find(|m| m.address == "bob@example.com").unwrap();
            assert_eq!(bob.permission, Permission::Reader);
            assert!(bob.key.is_none(), "key wrapping deferred to first put");
            let owner = m2.members.iter().find(|m| m.address == TEST_ADDRESS).unwrap();
            assert!(owner.key.is_none(), "owner key still unwrapped");
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
                permission: Permission::Reader,
                key: None,
            });
            sign_metadata(&secret_key, &mut m, Some(b"body")).unwrap();
            write_metadata_attributes(&path, &m).unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &["sam@example.com".to_string()], &[], &[], true, None).unwrap();

            let m2 = read_metadata_attributes(&path).unwrap();
            let sam = m2.members.iter().find(|m| m.address == "sam@example.com").unwrap();
            assert_eq!(sam.permission, Permission::Writer);
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
                permission: Permission::Reader,
                key: None,
            });
            sign_metadata(&secret_key, &mut m, Some(b"body")).unwrap();
            write_metadata_attributes(&path, &m).unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &[], &[], &["sam@example.com".to_string()], true, None).unwrap();

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

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = chmod(&ctx, path.to_str().unwrap(), &[], &[], &[], &[TEST_ADDRESS.to_string()], true, None).unwrap_err();
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
            m.members[0].permission = Permission::Writer;
            m.members.push(Member {
                address: "boss@example.com".to_string(),
                permission: Permission::Owner,
                key: None,
            });
            sign_metadata(&secret_key, &mut m, Some(b"body")).unwrap();
            write_metadata_attributes(&path, &m).unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = chmod(&ctx, path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[], true, None).unwrap_err();
            assert!(err.to_string().contains("only an owner"), "msg was {}", err);
        });
    }

    #[test]
    fn chmod_missing_input_errors() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (_identity, _secret_key, account_dir) = setup(temp_dir);
            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let missing = account_dir.join("nope.txt");
            let err = chmod(&ctx, missing.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[], true, None).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert!(format!("{}", err).contains("input does not exist"));
        });
    }

    #[test]
    fn re_signs_metadata_so_body_hash_matches() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("doc.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"body");

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[], true, None).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let body = fs::read(&path).unwrap();
            verify_metadata(&identity.public_key, &m, Some(&body)).unwrap();
        });
    }

    #[test]
    fn seeds_metadata_on_untracked_file() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (_, _, account_dir) = setup(temp_dir);
            let path = account_dir.join("fresh.txt");
            fs::write(&path, b"hello").unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &[], &[], &[], true, None).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            assert_eq!(m.encryption_algorithm.as_deref(), Some(DEFAULT_ENCRYPTION_ALGORITHM));
            assert_eq!(m.members.len(), 1);
            assert_eq!(m.members[0].address, TEST_ADDRESS);
            assert_eq!(m.members[0].permission, Permission::Owner);
            assert!(m.members[0].key.is_none(), "key deferred to first put");

            let local = read_local_metadata_attributes(&path).unwrap();
            assert_eq!(local.sync_body_hash.as_ref().unwrap().value, sha256(b"hello"));
        });
    }

    #[test]
    fn seeds_metadata_on_untracked_dir() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (_, _, account_dir) = setup(temp_dir);
            let dir = account_dir.join("shared");
            fs::create_dir_all(&dir).unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, dir.to_str().unwrap(), &[], &[], &[], &[], true, None).unwrap();

            let m = read_metadata_attributes(&dir).unwrap();
            assert_eq!(m.encryption_algorithm, None);
            assert!(m.body_hash.is_none());
            assert_eq!(m.members[0].permission, Permission::Owner);
        });
    }

    #[test]
    fn seeds_plaintext_when_encryption_none() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (_, _, account_dir) = setup(temp_dir);
            let path = account_dir.join("plain.txt");
            fs::write(&path, b"raw").unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            chmod(&ctx, path.to_str().unwrap(), &[], &[], &[], &[], true, Some("none")).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            assert_eq!(m.encryption_algorithm, None);
        });
    }

    #[test]
    fn rejects_encryption_algorithm_when_already_tracked() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (identity, secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("doc.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"body");

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = chmod(&ctx, path.to_str().unwrap(), &[], &[], &[], &[], true, Some("none")).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn rejects_encryption_algorithm_on_dir() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (_, _, account_dir) = setup(temp_dir);
            let dir = account_dir.join("shared");
            fs::create_dir_all(&dir).unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = chmod(&ctx, dir.to_str().unwrap(), &[], &[], &[], &[], true, Some(DEFAULT_ENCRYPTION_ALGORITHM)).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
        });
    }
}
