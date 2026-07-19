use std::fs;
use std::path::Path;

use crate::crypto::DEFAULT_ENCRYPTION_ALGORITHM;
use crate::metadata::{create_metadata, sign_metadata, write_local_metadata_attributes, write_metadata_attributes};
use crate::types::{IdentityContext, LocalMetadata};
use crate::util::{io_err, io_invalid_input, sha256};

pub fn cmd_track(ctx: &IdentityContext, path: &str, encryption_algorithm: Option<&str>) -> std::io::Result<()> {
    let target = Path::new(path);
    if !fs::exists(target)? {
        return Err(io_invalid_input("path does not exist"));
    }

    if xattr::get(target, "user.ark.id")?.is_some() {
        return Err(io_err("metadata already exists"));
    }

    let body = if target.is_dir() { None } else { Some(fs::read(target)?) };

    let encryption_algorithm = if target.is_dir() {
        if encryption_algorithm.is_some() {
            return Err(io_invalid_input("--encryption-algorithm not supported for directories"));
        }

        None
    } else {
        match encryption_algorithm {
            Some("none") => None,
            Some(a) => Some(a),
            None => Some(DEFAULT_ENCRYPTION_ALGORITHM),
        }
    };

    let mut metadata = create_metadata(&ctx.identity.address, encryption_algorithm);

    let identity_key = ctx.identity_key.as_ref().expect("client context missing identity_key");
    sign_metadata(identity_key, &mut metadata, body.as_deref())?;

    write_metadata_attributes(target, &metadata)?;

    if let Some(body_bytes) = body.as_deref() {
        write_local_metadata_attributes(target, &LocalMetadata {
            encrypted: Some(false),
            sync_hash: Some(sha256(body_bytes)),
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;

    use super::*;
    use crate::context::create_client_context;
    use crate::metadata::{read_local_metadata_attributes, read_metadata_attributes};
    use crate::types::Permission;
    use crate::util::test::{create_test_account, in_test_dir, TEST_ADDRESS};

    #[test]
    fn tracks_file_with_default_encryption() {
        in_test_dir("ark_track_test", |temp_dir| {
            let (_, _, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let path = account_dir.join("notes.txt");
            fs::write(&path, b"hello").unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_track(&ctx, path.to_str().unwrap(), None).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            assert_eq!(m.modified_by, TEST_ADDRESS);
            assert_eq!(m.encryption_algorithm.as_deref(), Some(DEFAULT_ENCRYPTION_ALGORITHM));
            assert!(m.members[0].key.is_none(), "key deferred to first put");
            assert!(m.body_hash.is_some(), "body hash signed");

            let local = read_local_metadata_attributes(&path).unwrap();
            assert_eq!(local.encrypted, Some(false));
            assert_eq!(local.sync_hash.as_deref(), Some(sha256(b"hello").as_slice()));

            let on_disk = fs::read(&path).unwrap();
            assert_eq!(on_disk, b"hello", "local file stays plain");
        });
    }

    #[test]
    fn tracks_file_with_encryption_none() {
        in_test_dir("ark_track_test", |temp_dir| {
            let (_, _, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let path = account_dir.join("plain.txt");
            fs::write(&path, b"raw").unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_track(&ctx, path.to_str().unwrap(), Some("none")).unwrap();

            let m = read_metadata_attributes(&path).unwrap();
            assert_eq!(m.encryption_algorithm, None);
            assert!(m.members[0].key.is_none());
        });
    }

    #[test]
    fn tracks_dir_without_encryption() {
        in_test_dir("ark_track_test", |temp_dir| {
            let (_, _, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let dir = account_dir.join("shared");
            fs::create_dir_all(&dir).unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_track(&ctx, dir.to_str().unwrap(), None).unwrap();

            let m = read_metadata_attributes(&dir).unwrap();
            assert_eq!(m.modified_by, TEST_ADDRESS);
            assert_eq!(m.encryption_algorithm, None);
            assert!(m.members[0].key.is_none());
            assert!(m.body_hash.is_none());
            assert_eq!(m.members[0].permission, Permission::Owner);
        });
    }

    #[test]
    fn rejects_dir_with_encryption_algorithm() {
        in_test_dir("ark_track_test", |temp_dir| {
            let (_, _, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let dir = account_dir.join("shared");
            fs::create_dir_all(&dir).unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let err = cmd_track(&ctx, dir.to_str().unwrap(), Some(DEFAULT_ENCRYPTION_ALGORITHM)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn rejects_missing_path() {
        in_test_dir("ark_track_test", |temp_dir| {
            let (_, _, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            let missing = account_dir.join("nope");
            let err = cmd_track(&ctx, missing.to_str().unwrap(), None).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn rejects_already_tracked() {
        in_test_dir("ark_track_test", |temp_dir| {
            let (_, _, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let path = account_dir.join("notes.txt");
            fs::write(&path, b"hello").unwrap();

            env::set_current_dir(&account_dir).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_track(&ctx, path.to_str().unwrap(), None).unwrap();

            let err = cmd_track(&ctx, path.to_str().unwrap(), None).unwrap_err();
            assert!(err.to_string().contains("already exists"), "msg was {}", err);
        });
    }
}
