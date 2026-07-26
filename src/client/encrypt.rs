use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::Path;

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, DEFAULT_HASH_ALGORITHM, encrypt_bytes};
use crate::metadata::{apply_key_to_metadata, create_metadata, extract_key_from_metadata, has_metadata_attributes, read_local_metadata_attributes, read_metadata_attributes, validate_metadata, write_local_metadata_attributes, write_metadata_attributes};
use crate::types::{Hash, IdentityContext, Key, LocalMetadata, Metadata};
use crate::util::{decode_base64url, io_err, io_invalid_input, sha256};

/// Encrypt a file with an ark file key.
///
/// Rewrites `in_place` or reads `input` → writes `output` (each side defaults
/// to stdio when the corresponding option is `None`). `in_place` is mutually
/// exclusive with `input`/`output`.
///
/// If the source file has ark metadata, its file key and algorithm are reused
/// and `key`/`encryption_algorithm` must be absent. Otherwise `key` (base64url,
/// 32 bytes) is required; `encryption_algorithm` defaults to AES-256-GCM.
///
/// When writing to a file path, signed metadata is stored as `user.ark.*`
/// xattrs plus local metadata as `user.ark_local.*` xattrs (including
/// `encrypted=true`). Refuses to run when `user.ark_local.encrypted=true` on
/// the source.
pub fn encrypt(
    ctx: &IdentityContext,
    input: Option<&str>,
    output: Option<&str>,
    in_place: Option<&str>,
    key: Option<&str>,
    encryption_algorithm: Option<&str>,
) -> io::Result<()> {
    if in_place.is_some() && (input.is_some() || output.is_some()) {
        return Err(io_err("--in-place is mutually exclusive with -i/--input and -o/--output"));
    }

    let source: Option<&str> = in_place.or(input);
    let destination: Option<&str> = in_place.or(output);
    if let Some(p) = source {
        if !fs::exists(Path::new(p))? {
            return Err(io_invalid_input("input does not exist"));
        }
    }

    let source_has_metadata = match source {
        Some(p) => has_metadata_attributes(Path::new(p))?,
        None => false,
    };

    // TODO: probably should be possible
    if source_has_metadata && (key.is_some() || encryption_algorithm.is_some()) {
        return Err(io_err("-k/--key and -e/--encryption-algortihm cannot override existing metadata"));
    }

    if !source_has_metadata && key.is_none() {
        return Err(io_err("no file key available: pass --key or use -i/--in-place on a file with metadata"));
    }

    let plaintext_bytes = match source {
        Some(p) => fs::read(p)?,
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };

    let metadata = match source {
        Some(p) if source_has_metadata => read_metadata_attributes(Path::new(p))?,
        _ => {
            let key = Key {
                algorithm: encryption_algorithm.map(str::to_string).unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM.to_string()),
                value: decode_base64url(key.expect("key presence checked above").trim())
                    .map_err(|e| io_err(&format!("--key decode: {}", e)))?
            };

            let mut metadata = create_metadata(&ctx.identity.address, Some(&key.algorithm));
            apply_key_to_metadata(ctx, &mut metadata, &key)?;

            validate_metadata(&metadata)?;
            metadata
        }
    };

    let local_metadata = match source {
        Some(p) => read_local_metadata_attributes(Path::new(p))?,
        None => LocalMetadata::default(),
    };

    if let Some(true) = local_metadata.encrypted {
        return Err(io_err("file is already encrypted"));
    }

    let mut ciphertext_bytes: Vec<u8> = Vec::new();
    encrypt_stream(ctx, &metadata, &mut plaintext_bytes.as_slice(), &mut ciphertext_bytes)?;

    match destination {
        Some(d) => {
            let destination_path = Path::new(d);
            fs::write(destination_path, &ciphertext_bytes)?;
            write_metadata_attributes(destination_path, &metadata)?;
            write_local_metadata_attributes(destination_path, &LocalMetadata {
                encrypted: Some(true),
                sync_body_hash: Some(Hash { algorithm: DEFAULT_HASH_ALGORITHM.to_string(), value: sha256(&plaintext_bytes) }),
                sync_modified: Some(metadata.modified.clone()),
            })?;
        }
        None => io::stdout().write_all(&ciphertext_bytes)?,
    }

    Ok(())
}

/// Encrypt `plaintext` to `ciphertext` using the file key wrapped in
/// `metadata` for the current account. The algorithm is taken from
/// `metadata.encryption_algorithm`.
pub fn encrypt_stream(
    ctx: &IdentityContext,
    metadata: &Metadata,
    plaintext: &mut dyn Read,
    ciphertext: &mut dyn Write,
) -> io::Result<()> {
    let file_key = extract_key_from_metadata(ctx, metadata)?
        .ok_or_else(|| io_err(&format!("no key for {}", ctx.identity.address)))?;

    let encryption_algorithm = metadata.encryption_algorithm.clone()
        .ok_or_else(|| io_err("metadata missing encryption_algorithm"))?;

    let mut plaintext_bytes = Vec::new();
    plaintext.read_to_end(&mut plaintext_bytes)?;

    let (_, ciphertext_bytes) = encrypt_bytes(&Key { algorithm: encryption_algorithm, value: file_key }, &plaintext_bytes)?;
    ciphertext.write_all(&ciphertext_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env::set_current_dir;
    use std::io::ErrorKind;

    use super::*;
    use crate::crypto::decrypt_bytes;
    use crate::context::create_client_context;
    use crate::util::encode_base64url;
    use crate::client::decrypt;
    use crate::util::test::{TEST_ADDRESS, create_test_account, in_test_dir, write_encrypted_test_file, write_plain_test_file};

    fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        decrypt_bytes(&Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: key.to_vec() }, ciphertext).unwrap()
    }

    fn unwrap_first_member_key(path: &Path, identity_seed: &[u8]) -> Vec<u8> {
        let m = read_metadata_attributes(path).unwrap();
        let key = m.members[0].key.as_ref().expect("key set");
        decrypt_bytes(&Key { algorithm: key.algorithm.clone(), value: identity_seed.to_vec() }, &key.value).unwrap()
    }

    #[test]
    fn encrypt_input_to_output_produces_decryptable_ciphertext() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let in_path = temp_dir.join("in.bin");
            fs::write(&in_path, b"hello world").unwrap();
            let out_path = temp_dir.join("out.bin");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let k = encode_base64url([7u8; 32]);
            encrypt(&ctx, Some(in_path.to_str().unwrap()), Some(out_path.to_str().unwrap()), None, Some(&k), None).unwrap();
            let ciphertext = fs::read(&out_path).unwrap();
            assert_ne!(ciphertext, b"hello world");
            let file_key = unwrap_first_member_key(&out_path, &secret_key.value);
            assert_eq!(aes_decrypt(&file_key, &ciphertext), b"hello world");
        });
    }

    #[test]
    fn encrypt_in_place_replaces_body_and_marks_encrypted() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("file.bin");
            fs::write(&p, b"data").unwrap();
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let k = encode_base64url([3u8; 32]);
            encrypt(&ctx, None, None, Some(p.to_str().unwrap()), Some(&k), None).unwrap();
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
    fn encrypt_in_place_conflicts_with_input() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let x = temp_dir.join("x");
            let err = encrypt(&ctx, Some("a"), None, Some(x.to_str().unwrap()), None, None).unwrap_err();
            assert!(err.to_string().contains("mutually exclusive"));
        });
    }

    #[test]
    fn encrypt_explicit_key_used_for_body() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let raw_key = [42u8; 32];
            let in_path = temp_dir.join("in.bin");
            fs::write(&in_path, b"secret").unwrap();
            let out_path = temp_dir.join("out.bin");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let k = encode_base64url(raw_key);
            encrypt(&ctx, Some(in_path.to_str().unwrap()), Some(out_path.to_str().unwrap()), None, Some(&k), None).unwrap();
            let ciphertext = fs::read(&out_path).unwrap();
            assert_eq!(aes_decrypt(&raw_key, &ciphertext), b"secret");
            let wrapped = unwrap_first_member_key(&out_path, &secret_key.value);
            assert_eq!(wrapped, raw_key.to_vec());
        });
    }

    #[test]
    fn encrypt_stdin_without_key_or_output_errors() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let _ = temp_dir;
            let err = encrypt(&ctx, None, None, None, None, None).unwrap_err();
            assert!(err.to_string().contains("no file key available"), "msg was {}", err);
        });
    }

    #[test]
    fn encrypt_refuses_when_encrypted_flag_true() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("in.bin");
            write_plain_test_file(&p, &identity, &secret_key, b"x");
            write_local_metadata_attributes(&p, &LocalMetadata { encrypted: Some(true), sync_body_hash: None, sync_modified: None }).unwrap();
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let err = encrypt(&ctx, Some(p.to_str().unwrap()), None, None, None, None).unwrap_err();
            assert!(err.to_string().contains("already encrypted"), "msg was {}", err);
        });
    }

    #[test]
    fn encrypt_reuses_file_key_from_source_metadata() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);

            let ct_path = temp_dir.join("orig.bin");
            write_encrypted_test_file(&ct_path, &identity, &secret_key, b"hello");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let original_file_key = unwrap_first_member_key(&ct_path, &secret_key.value);

            decrypt(&ctx, None, None, Some(ct_path.to_str().unwrap()), None, None).unwrap();
            assert_eq!(fs::read(&ct_path).unwrap(), b"hello");

            encrypt(&ctx, None, None, Some(ct_path.to_str().unwrap()), None, None).unwrap();

            let re_ct = fs::read(&ct_path).unwrap();
            let re_key = unwrap_first_member_key(&ct_path, &secret_key.value);
            assert_eq!(re_key, original_file_key);
            assert_eq!(aes_decrypt(&re_key, &re_ct), b"hello");
        });
    }

    #[test]
    fn encrypt_sets_sync_body_hash_over_plaintext() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let in_path = temp_dir.join("in.bin");
            fs::write(&in_path, b"plain").unwrap();
            let out_path = temp_dir.join("out.bin");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let k = encode_base64url([9u8; 32]);
            encrypt(&ctx, Some(in_path.to_str().unwrap()), Some(out_path.to_str().unwrap()), None, Some(&k), None).unwrap();
            let local = read_local_metadata_attributes(&out_path).unwrap();
            assert_eq!(local.sync_body_hash.as_ref().unwrap().value, sha256(b"plain"));
            assert_eq!(local.encrypted, Some(true));
        });
    }

    #[test]
    fn encrypt_missing_input_errors() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let missing = temp_dir.join("nope.bin");
            let err = encrypt(&ctx, Some(missing.to_str().unwrap()), None, None, None, None).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert!(format!("{}", err).contains("input does not exist"));
        });
    }

    #[test]
    fn encrypt_unsupported_algorithm_errors() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let in_path = temp_dir.join("in.bin");
            fs::write(&in_path, b"x").unwrap();
            let out_path = temp_dir.join("out.bin");
            set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let k = encode_base64url([1u8; 32]);
            let err = encrypt(&ctx, Some(in_path.to_str().unwrap()), Some(out_path.to_str().unwrap()), None, Some(&k), Some("chacha20-poly1305")).unwrap_err();
            assert!(err.to_string().contains("unsupported encryption algorithm"), "msg was {}", err);
        });
    }
}
