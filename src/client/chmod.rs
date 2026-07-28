use std::env::current_dir;
use std::fs;
use std::io;
use std::path::Path;

use super::put;
use crate::types::IdentityContext;
use crate::identity::resolve_identity;
use crate::metadata::{apply_permissions, extract_key_from_metadata, get_member, has_metadata_attributes, read_metadata_attributes, sign_metadata, verify_metadata_signature, write_metadata_attributes};
use crate::timestamp;
use crate::types::{Permission, Permissions};
use crate::util::{io_err, io_invalid_input};

/// Change members and permissions on a tracked local file or directory.
///
/// Adds or promotes each address in `permissions.owners`/`writers`/`readers`;
/// removes each address in `permissions.drops`. The literal `"public"` maps
/// to the wildcard address `*` (rejected for encrypted files).
///
/// Requires the target to already carry local ark metadata (via a previous
/// [`put`](super::put) or [`get`](super::get)); use `put` for the initial
/// upload with permissions. The caller must be an owner. For encrypted files,
/// the existing file key is unwrapped and re-wrapped for any newly-added
/// member (removing a member does not rotate the key — the next
/// [`put`](super::put) will).
///
/// With `local_only = false` (the default), the change is pushed via a
/// metadata-only [`put`](super::put). With `local_only = true`, only the
/// local xattrs are updated; a later [`put`](super::put) or
/// [`sync`](super::sync) will propagate the change.
///
/// At least one owner must remain.
pub fn chmod(
    ctx: &IdentityContext,
    path: &str,
    permissions: &Permissions,
    local_only: bool,
) -> io::Result<()> {
    let input_path = Path::new(path);
    if !fs::exists(input_path)? {
        return Err(io_invalid_input("input does not exist"));
    }

    if !has_metadata_attributes(input_path)? {
        return Err(io_invalid_input("no ark metadata: use put instead"));
    }

    let mut metadata = read_metadata_attributes(input_path)?;
    let modifier_identity = resolve_identity(ctx, &metadata.modified_by)?;
    verify_metadata_signature(&modifier_identity.public_key, &metadata)?;

    match get_member(&metadata.members, &ctx.identity.address) {
        Some(mem) if mem.permission == Permission::Owner => {}
        _ => return Err(io_err("only an owner can change permissions")),
    }

    let file_key = if metadata.encryption_algorithm.is_some() {
        extract_key_from_metadata(ctx, &metadata)?
    } else {
        None
    };

    apply_permissions(ctx, &mut metadata, permissions, file_key.as_deref())?;

    metadata.modified = timestamp::now();
    metadata.modified_by = ctx.identity.address.clone();

    let secret_key = ctx.identity_key.as_ref().expect("client context missing identity_key");
    sign_metadata(secret_key, &mut metadata, None)?;
    write_metadata_attributes(input_path, &metadata)?;

    if !local_only {
        let url_path = url_path_for(ctx, input_path)?;
        put(ctx, &url_path, Some(path), &Permissions::default(), None, true)?;
    }

    Ok(())
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
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, decrypt_bytes};
    use crate::identity::{create_identity, write_identity};
    use crate::metadata::{create_metadata, drop, reader, sign_metadata, writer, write_metadata_attributes};
    use crate::types::{Identity, Key, Member};
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
            chmod(&ctx, path.to_str().unwrap(), &reader("john@example.com"), true).unwrap();

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
            chmod(&ctx, path.to_str().unwrap(), &reader("public"), true).unwrap();

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
            let err = chmod(&ctx, path.to_str().unwrap(), &reader("public"), true).unwrap_err();
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
            chmod(&ctx, path.to_str().unwrap(), &reader("bob@example.com"), true).unwrap();

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
            chmod(&ctx, path.to_str().unwrap(), &reader("bob@example.com"), true).unwrap();

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
            chmod(&ctx, path.to_str().unwrap(), &writer("sam@example.com"), true).unwrap();

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
            chmod(&ctx, path.to_str().unwrap(), &drop("sam@example.com"), true).unwrap();

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
            let err = chmod(&ctx, path.to_str().unwrap(), &drop(TEST_ADDRESS), true).unwrap_err();
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
            let err = chmod(&ctx, path.to_str().unwrap(), &reader("john@example.com"), true).unwrap_err();
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
            let err = chmod(&ctx, missing.to_str().unwrap(), &reader("john@example.com"), true).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert!(format!("{}", err).contains("input does not exist"));
        });
    }

    #[test]
    fn chmod_untracked_file_errors() {
        in_test_dir("ark_chmod_test", |temp_dir| {
            let (_identity, _secret_key, account_dir) = setup(temp_dir);
            let path = account_dir.join("fresh.txt");
            fs::write(&path, b"hello").unwrap();

            set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = chmod(&ctx, path.to_str().unwrap(), &Permissions::default(), true).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert!(err.to_string().contains("no ark metadata"), "msg was {}", err);
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
            chmod(&ctx, path.to_str().unwrap(), &reader("john@example.com"), true).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            let body = fs::read(&path).unwrap();
            crate::metadata::verify_metadata(&identity.public_key, &m, Some(&body)).unwrap();
        });
    }
}
