use std::io;
use std::io::{Read, Write};

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, DEFAULT_HASH_ALGORITHM, create_secret_key, encrypt_bytes};
use crate::metadata::{apply_key_to_metadata, create_metadata, has_metadata_attributes, read_local_metadata_attributes, read_metadata_attributes, resolve_key_from_members};
use crate::storage::{Body, read, write_atomic_with_metadata};
use crate::types::{Context, Hash, Key, LocalMetadata, Metadata};
use crate::util::sha256;

/// Encrypt the account's copy of `path` in place.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`).
///
/// If the file carries ark metadata, its file key and algorithm are reused and
/// `encryption_algorithm` must be absent. Otherwise a fresh file key is
/// generated, wrapped for the current account, and `encryption_algorithm`
/// selects the algorithm (default AES-256-GCM).
///
/// Signed metadata is stored as `user.ark.*` xattrs plus local metadata as
/// `user.ark_local.*` xattrs (including `encrypted=true`). Refuses to run when
/// `user.ark_local.encrypted=true`.
pub fn encrypt(ctx: &Context, path: &str, encryption_algorithm: Option<&str>) -> io::Result<()> {
    let has_metadata = has_metadata_attributes(ctx, path)?;

    if has_metadata && encryption_algorithm.is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "encryption-algortihm cannot override existing metadata"));
    }

    if let Some(true) = read_local_metadata_attributes(ctx, path)?.encrypted {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "file is already encrypted"));
    }

    let plaintext_bytes = read(ctx, path)?;

    let metadata = if has_metadata {
        read_metadata_attributes(ctx, path)?
    } else {
        let encryption_algorithm = encryption_algorithm.unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM);
        let file_key = create_secret_key(encryption_algorithm)?;

        let mut metadata = create_metadata(&ctx.identity.address, Some(encryption_algorithm));
        apply_key_to_metadata(ctx, &mut metadata, &file_key)?;

        metadata
    };

    let mut ciphertext_bytes: Vec<u8> = Vec::new();
    encrypt_stream(ctx, &metadata, &mut plaintext_bytes.as_slice(), &mut ciphertext_bytes)?;

    let local_metadata = LocalMetadata {
        encrypted: Some(true),
        sync_body_hash: Some(Hash { algorithm: DEFAULT_HASH_ALGORITHM.to_string(), value: sha256(&plaintext_bytes) }),
        sync_modified: Some(metadata.modified),
    };

    write_atomic_with_metadata(ctx, path, Body::Bytes(&ciphertext_bytes), &metadata, Some(&local_metadata))
}

/// Encrypt `plaintext` to `ciphertext` using the file key wrapped in
/// `metadata` for the current account. The algorithm is taken from
/// `metadata.encryption_algorithm`.
pub fn encrypt_stream(
    ctx: &Context,
    metadata: &Metadata,
    plaintext: &mut dyn Read,
    ciphertext: &mut dyn Write,
) -> io::Result<()> {
    let file_key = resolve_key_from_members(ctx, &metadata.members)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, format!("no key for {}", ctx.identity.address)))?;

    let encryption_algorithm = metadata.encryption_algorithm.clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "metadata missing encryption_algorithm"))?;

    let mut plaintext_bytes = Vec::new();
    plaintext.read_to_end(&mut plaintext_bytes)?;

    let (_, ciphertext_bytes) = encrypt_bytes(&Key { algorithm: encryption_algorithm, value: file_key }, &plaintext_bytes)?;
    ciphertext.write_all(&ciphertext_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env::set_current_dir;
    use std::fs;
    use std::io::ErrorKind;
    use std::path::Path;

    use super::*;

    use crate::client::decrypt;
    use crate::context::create_client_context;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, decrypt_bytes};
    use crate::metadata::{read_local_metadata_attributes, read_metadata_attributes, write_local_metadata_attributes};
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_test_account, in_test_dir, write_encrypted_test_file, write_plain_test_file};

    fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        decrypt_bytes(&Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: key.to_vec() }, ciphertext).unwrap()
    }

    fn unwrap_first_member_key(path: &Path, identity_seed: &[u8]) -> Vec<u8> {
        let (context, account_path) = account_context(path);
        let m = read_metadata_attributes(&context, &account_path).unwrap();
        let key = m.members[0].key.as_ref().expect("key set");
        decrypt_bytes(&Key { algorithm: key.algorithm.clone(), value: identity_seed.to_vec() }, &key.value).unwrap()
    }

    #[test]
    fn encrypt_replaces_body_and_marks_encrypted() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("file.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"data");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            decrypt(&ctx, "file.bin").unwrap();

            encrypt(&ctx, "file.bin", None).unwrap();

            let ciphertext = fs::read(&p).unwrap();
            assert_ne!(ciphertext, b"data");
            assert_eq!(
                xattr::get(&p, "user.ark_local.encrypted").unwrap().as_deref(),
                Some(b"true".as_slice())
            );
            assert_eq!(
                xattr::get(&p, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(DEFAULT_ENCRYPTION_ALGORITHM.as_bytes())
            );
            let file_key = unwrap_first_member_key(&p, &secret_key.value);
            assert_eq!(aes_decrypt(&file_key, &ciphertext), b"data");
        });
    }

    #[test]
    fn encrypt_ark_absolute_path_resolves_under_account_root() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("notes").join("file.bin");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            write_encrypted_test_file(&p, &identity, &secret_key, b"data");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            decrypt(&ctx, "/notes/file.bin").unwrap();

            encrypt(&ctx, "/notes/file.bin", None).unwrap();

            assert_ne!(fs::read(&p).unwrap(), b"data");
        });
    }

    #[test]
    fn encrypt_generates_file_key_when_no_metadata() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("in.bin");
            fs::write(&p, b"plain").unwrap();
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            encrypt(&ctx, "in.bin", None).unwrap();

            let ciphertext = fs::read(&p).unwrap();
            assert_ne!(ciphertext, b"plain");
            assert_eq!(
                xattr::get(&p, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(DEFAULT_ENCRYPTION_ALGORITHM.as_bytes())
            );
            let file_key = unwrap_first_member_key(&p, &secret_key.value);
            assert_eq!(aes_decrypt(&file_key, &ciphertext), b"plain");
        });
    }

    #[test]
    fn encrypt_algorithm_with_metadata_errors() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("in.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"x");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            decrypt(&ctx, "in.bin").unwrap();

            let err = encrypt(&ctx, "in.bin", Some(DEFAULT_ENCRYPTION_ALGORITHM)).unwrap_err();
            assert!(err.to_string().contains("cannot override existing metadata"), "msg was {}", err);
        });
    }

    #[test]
    fn encrypt_unsupported_algorithm_errors() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            fs::write(acc.join("in.bin"), b"x").unwrap();
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            let err = encrypt(&ctx, "in.bin", Some("chacha20-poly1305")).unwrap_err();
            assert!(err.to_string().contains("unsupported algorithm"), "msg was {}", err);
        });
    }

    #[test]
    fn encrypt_refuses_when_encrypted_flag_true() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("in.bin");
            write_plain_test_file(&p, &identity, &secret_key, b"x");
            let (account_ctx, account_path) = account_context(&p);
            let local = LocalMetadata { encrypted: Some(true), sync_body_hash: None, sync_modified: None };
            write_local_metadata_attributes(&account_ctx, &account_path, &local).unwrap();
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            let err = encrypt(&ctx, "in.bin", None).unwrap_err();
            assert!(err.to_string().contains("already encrypted"), "msg was {}", err);
        });
    }

    #[test]
    fn encrypt_reuses_file_key_from_source_metadata() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("orig.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"hello");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let original_file_key = unwrap_first_member_key(&p, &secret_key.value);

            decrypt(&ctx, "orig.bin").unwrap();
            assert_eq!(fs::read(&p).unwrap(), b"hello");

            encrypt(&ctx, "orig.bin", None).unwrap();

            let re_ct = fs::read(&p).unwrap();
            let re_key = unwrap_first_member_key(&p, &secret_key.value);
            assert_eq!(re_key, original_file_key);
            assert_eq!(aes_decrypt(&re_key, &re_ct), b"hello");
        });
    }

    #[test]
    fn encrypt_sets_sync_body_hash_over_plaintext() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("in.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"plain");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            decrypt(&ctx, "in.bin").unwrap();

            encrypt(&ctx, "in.bin", None).unwrap();

            let local = read_local_metadata_attributes(&ctx, "in.bin").unwrap();
            assert_eq!(local.sync_body_hash.as_ref().unwrap().value, sha256(b"plain"));
            assert_eq!(local.encrypted, Some(true));
        });
    }

    #[test]
    fn encrypt_missing_file_errors() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            let err = encrypt(&ctx, "nope.bin", None).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::NotFound);
        });
    }
}
