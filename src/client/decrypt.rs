use std::io;
use std::io::{Read, Write};

use crate::crypto::{DEFAULT_HASH_ALGORITHM, decrypt_bytes};
use crate::metadata::{has_metadata_attributes, read_local_metadata_attributes, read_metadata_attributes, resolve_key_from_members};
use crate::storage::{Body, read, write_atomic_with_metadata};
use crate::types::{Context, Hash, Key, LocalMetadata, Metadata};
use crate::util::sha256;

/// Decrypt the account's copy of `path` in place, with its own ark file key.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). The file must carry ark metadata; its file key and
/// algorithm are reused. To decrypt under a key of your own, build the
/// metadata and call [`decrypt_stream`].
///
/// Signed metadata is stored as `user.ark.*` xattrs plus local metadata as
/// `user.ark_local.*` xattrs (including `encrypted=false`). Refuses to run
/// when `user.ark_local.encrypted=false`.
pub fn decrypt(ctx: &Context, path: &str) -> io::Result<()> {
    if !has_metadata_attributes(ctx, path)? {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "file has no ark metadata"));
    }

    if let Some(false) = read_local_metadata_attributes(ctx, path)?.encrypted {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "file is already plaintext"));
    }

    let ciphertext_bytes = read(ctx, path)?;
    let metadata = read_metadata_attributes(ctx, path)?;

    let mut plaintext_bytes: Vec<u8> = Vec::new();
    decrypt_stream(ctx, &metadata, &mut ciphertext_bytes.as_slice(), &mut plaintext_bytes)?;

    let local_metadata = LocalMetadata {
        encrypted: Some(false),
        sync_body_hash: Some(Hash { algorithm: DEFAULT_HASH_ALGORITHM.to_string(), value: sha256(&plaintext_bytes) }),
        sync_modified: Some(metadata.modified),
    };

    write_atomic_with_metadata(ctx, path, Body::Bytes(&plaintext_bytes), &metadata, Some(&local_metadata))
}

/// Decrypt `ciphertext` to `plaintext` using the file key wrapped in
/// `metadata` for the current account. The algorithm is taken from
/// `metadata.encryption_algorithm`.
pub fn decrypt_stream(
    ctx: &Context,
    metadata: &Metadata,
    ciphertext: &mut dyn Read,
    plaintext: &mut dyn Write,
) -> io::Result<()> {
    let file_key = resolve_key_from_members(ctx, &metadata.members)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, format!("no key for {}", ctx.identity.address)))?;

    let encryption_algorithm = metadata.encryption_algorithm.clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "metadata missing encryption_algorithm"))?;

    let mut ciphertext_bytes = Vec::new();
    ciphertext.read_to_end(&mut ciphertext_bytes)?;

    let plaintext_bytes = decrypt_bytes(&Key { algorithm: encryption_algorithm, value: file_key }, &ciphertext_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{} — input may already be plaintext or the key may be wrong", e)))?;
    plaintext.write_all(&plaintext_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env::set_current_dir;
    use std::fs;
    use std::io::ErrorKind;

    use super::*;

    use crate::context::create_client_context;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, encrypt_bytes};
    use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_test_account, in_test_dir, write_encrypted_test_file};

    #[test]
    fn decrypt_replaces_body_and_marks_unencrypted() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("file.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"data");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            decrypt(&ctx, "file.bin").unwrap();

            assert_eq!(fs::read(&p).unwrap(), b"data");
            assert_eq!(
                xattr::get(&p, "user.ark_local.encrypted").unwrap().as_deref(),
                Some(b"false".as_slice())
            );
            assert_eq!(
                xattr::get(&p, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(DEFAULT_ENCRYPTION_ALGORITHM.as_bytes())
            );
            assert!(xattr::get(&p, "user.ark.member_0_key_value").unwrap().is_some());
        });
    }

    #[test]
    fn decrypt_ark_absolute_path_resolves_under_account_root() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("notes").join("file.bin");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            write_encrypted_test_file(&p, &identity, &secret_key, b"data");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            decrypt(&ctx, "/notes/file.bin").unwrap();

            assert_eq!(fs::read(&p).unwrap(), b"data");
        });
    }

    #[test]
    fn decrypt_without_metadata_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let ciphertext = encrypt_bytes(&Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: vec![1u8; 32] }, b"x").unwrap().1;
            fs::write(acc.join("in.bin"), ciphertext).unwrap();
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            let err = decrypt(&ctx, "in.bin").unwrap_err();
            assert!(err.to_string().contains("no ark metadata"), "msg was {}", err);
        });
    }

    #[test]
    fn decrypt_refuses_when_encrypted_flag_false() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("in.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"x");
            xattr::set(&p, "user.ark_local.encrypted", b"false").unwrap();
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            let err = decrypt(&ctx, "in.bin").unwrap_err();
            assert!(err.to_string().contains("already plaintext"), "msg was {}", err);
        });
    }

    #[test]
    fn decrypt_proceeds_when_encrypted_flag_true() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("in.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"hi");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            decrypt(&ctx, "in.bin").unwrap();

            assert_eq!(fs::read(&p).unwrap(), b"hi");
        });
    }

    #[test]
    fn decrypt_aead_failure_includes_hint() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = acc.join("plain.bin");
            let body = vec![0u8; 42];
            fs::write(&p, &body).unwrap();
            let mut m = create_metadata(&identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            let (wrap_alg, wrapped) = encrypt_bytes(&identity.public_key, &[0u8; 32]).unwrap();
            m.members[0].key = Some(Key { algorithm: wrap_alg, value: wrapped });
            sign_metadata(&secret_key, &mut m, Some(&body)).unwrap();
            let local = LocalMetadata { encrypted: Some(true), sync_body_hash: None, sync_modified: None };
            let (account_ctx, account_path) = account_context(&p);
            write_metadata_attributes(&account_ctx, &account_path, &m, Some(&local)).unwrap();
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            let err = decrypt(&ctx, "plain.bin").unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("may already be plaintext"), "msg was {}", msg);
            assert!(msg.contains("key may be wrong"), "msg was {}", msg);
        });
    }

    #[test]
    fn decrypt_missing_file_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();

            let err = decrypt(&ctx, "nope.bin").unwrap_err();
            assert_eq!(err.kind(), ErrorKind::NotFound);
        });
    }
}
