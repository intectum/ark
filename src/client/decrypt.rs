use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::Path;

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, decrypt_bytes};
use crate::metadata::{apply_key_to_metadata, create_metadata, extract_key_from_metadata, read_local_metadata_attributes, read_metadata_attributes, validate_metadata, write_local_metadata_attributes, write_metadata_attributes};
use crate::types::{IdentityContext, Key, LocalMetadata, Metadata};
use crate::util::{decode_base64url, io_err, io_invalid_input, sha256};

/// Decrypt `ciphertext` to `plaintext` using the file key wrapped in
/// `metadata` for the current account. The metadata's `encryption_algorithm`
/// selects the AEAD.
pub fn decrypt(
    ctx: &IdentityContext,
    metadata: &Metadata,
    ciphertext: &mut dyn Read,
    plaintext: &mut dyn Write,
) -> io::Result<()> {
    let file_key = extract_key_from_metadata(ctx, metadata)?;

    let encryption_algorithm = metadata.encryption_algorithm.clone()
        .ok_or_else(|| io_err("metadata missing encryption_algorithm"))?;

    let mut ciphertext_bytes = Vec::new();
    ciphertext.read_to_end(&mut ciphertext_bytes)?;

    let plaintext_bytes = decrypt_bytes(&Key { algorithm: encryption_algorithm, value: file_key }, &ciphertext_bytes)
        .map_err(|e| io_err(&format!("{} — input may already be plaintext or the key may be wrong", e)))?;
    plaintext.write_all(&plaintext_bytes)?;

    Ok(())
}

/// CLI-shaped [`decrypt`]. Rewrites `in_place` or reads `input` → writes
/// `output` (each side defaults to stdio when the corresponding option is
/// `None`). `in_place` is mutually exclusive with `input`/`output`.
///
/// If the source file has ark metadata, its file key and algorithm are reused
/// and `key`/`encryption_algorithm` must be absent. Otherwise `key` (base64url,
/// 32 bytes) is required; `encryption_algorithm` defaults to AES-256-GCM.
///
/// Refuses to run when `user.ark_local.encrypted=false` on the source.
pub fn decrypt_io(
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
        Some(p) => xattr::get(Path::new(p), "user.ark.id")?.is_some(),
        None => false,
    };

    // TODO: probably should be possible
    if source_has_metadata && (key.is_some() || encryption_algorithm.is_some()) {
        return Err(io_err("-k/--key and -e/--encryption-algortihm cannot override existing metadata"));
    }

    if !source_has_metadata && key.is_none() {
        return Err(io_err("no file key available: pass --key or use -i/--in-place on a file with metadata"));
    }

    let ciphertext_bytes = match source {
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

    if let Some(false) = local_metadata.encrypted {
        return Err(io_err("file is already plaintext"));
    }

    let mut plaintext_bytes: Vec<u8> = Vec::new();
    decrypt(ctx, &metadata, &mut ciphertext_bytes.as_slice(), &mut plaintext_bytes)?;

    match destination {
        Some(d) => {
            let destination_path = Path::new(d);
            fs::write(destination_path, &plaintext_bytes)?;
            write_metadata_attributes(destination_path, &metadata)?;
            write_local_metadata_attributes(destination_path, &LocalMetadata {
                encrypted: Some(false),
                sync_hash: Some(sha256(&plaintext_bytes)),
            })?;
        }
        None => io::stdout().write_all(&plaintext_bytes)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::crypto::{decrypt_bytes, encrypt_bytes};
    use crate::context::create_client_context;
    use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
    use crate::util::encode_base64url;
    use crate::util::test::{TEST_ADDRESS, create_test_account, in_test_dir, write_encrypted_test_file};

    fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        encrypt_bytes(&Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: key.to_vec() }, plaintext).unwrap().1
    }

    #[test]
    fn decrypt_input_to_output() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let in_path = temp_dir.join("in.bin");
            write_encrypted_test_file(&in_path, &identity, &secret_key, b"hello world");
            let out_path = temp_dir.join("out.bin");
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            decrypt_io(&ctx, Some(in_path.to_str().unwrap()), Some(out_path.to_str().unwrap()), None, None, None).unwrap();
            assert_eq!(fs::read(&out_path).unwrap(), b"hello world");
        });
    }

    #[test]
    fn decrypt_in_place_replaces_body_and_marks_unencrypted() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("file.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"data");
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            decrypt_io(&ctx, None, None, Some(p.to_str().unwrap()), None, None).unwrap();
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
    fn decrypt_in_place_conflicts_with_input() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let x = temp_dir.join("x");
            let err = decrypt_io(&ctx, Some("a"), None, Some(x.to_str().unwrap()), None, None).unwrap_err();
            assert!(err.to_string().contains("mutually exclusive"));
        });
    }

    #[test]
    fn decrypt_explicit_key_with_metadata_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("in.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"x");
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let k = encode_base64url([13u8; 32]);
            let err = decrypt_io(&ctx, Some(p.to_str().unwrap()), None, None, Some(&k), None).unwrap_err();
            assert!(err.to_string().contains("cannot override existing metadata"), "msg was {}", err);
        });
    }

    #[test]
    fn decrypt_missing_key_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("in.bin");
            let ct = aes_encrypt(&[1u8; 32], b"x");
            fs::write(&p, &ct).unwrap();
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let err = decrypt_io(&ctx, Some(p.to_str().unwrap()), None, None, None, None).unwrap_err();
            assert!(err.to_string().contains("no file key"));
        });
    }

    #[test]
    fn decrypt_explicit_key_no_meta_writes_wrapped_key_to_output() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let file_key = [77u8; 32];
            let ct = aes_encrypt(&file_key, b"secret");
            let p = temp_dir.join("in.bin");
            fs::write(&p, &ct).unwrap();
            let out = temp_dir.join("out.bin");

            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let k = encode_base64url(file_key);
            decrypt_io(&ctx, Some(p.to_str().unwrap()), Some(out.to_str().unwrap()), None, Some(&k), None).unwrap();

            assert_eq!(fs::read(&out).unwrap(), b"secret");
            let m = crate::metadata::read_metadata_attributes(&out).unwrap();
            let wrapped = m.members[0].key.as_ref().expect("key populated");
            assert_eq!(wrapped.algorithm, "hpke-x25519-hkdf-sha256-aes256gcm");
            let recovered = decrypt_bytes(&Key { algorithm: wrapped.algorithm.to_string(), value: secret_key.value.to_vec() }, &wrapped.value).unwrap();
            assert_eq!(recovered, file_key);
        });
    }

    #[test]
    fn decrypt_refuses_when_encrypted_flag_false() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("in.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"x");
            xattr::set(&p, "user.ark_local.encrypted", b"false").unwrap();
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let err = decrypt_io(&ctx, Some(p.to_str().unwrap()), None, None, None, None).unwrap_err();
            assert!(err.to_string().contains("already plaintext"), "msg was {}", err);
        });
    }

    #[test]
    fn decrypt_proceeds_when_encrypted_flag_true() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("in.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"hi");
            let out = temp_dir.join("out.bin");
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            decrypt_io(&ctx, Some(p.to_str().unwrap()), Some(out.to_str().unwrap()), None, None, None).unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"hi");
        });
    }

    #[test]
    fn decrypt_aead_failure_includes_hint() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("plain.bin");
            let body = vec![0u8; 42];
            fs::write(&p, &body).unwrap();
            let mut m = create_metadata(&identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            let (wrap_alg, wrapped) = encrypt_bytes(&identity.public_key, &[0u8; 32]).unwrap();
            m.members[0].key = Some(Key { algorithm: wrap_alg, value: wrapped });
            sign_metadata(&secret_key, &mut m, Some(&body)).unwrap();
            write_metadata_attributes(&p, &m).unwrap();
            write_local_metadata_attributes(&p, &LocalMetadata { encrypted: Some(true), sync_hash: None }).unwrap();
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let err = decrypt_io(&ctx, Some(p.to_str().unwrap()), None, None, None, None).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("may already be plaintext"), "msg was {}", msg);
            assert!(msg.contains("key may be wrong"), "msg was {}", msg);
        });
    }

    #[test]
    fn decrypt_to_stdout_succeeds() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("in.bin");
            write_encrypted_test_file(&p, &identity, &secret_key, b"plain");
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            decrypt_io(&ctx, Some(p.to_str().unwrap()), None, None, None, None).unwrap();
        });
    }

    #[test]
    fn decrypt_missing_input_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let missing = temp_dir.join("nope.bin");
            let err = decrypt_io(&ctx, Some(missing.to_str().unwrap()), None, None, None, None).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(format!("{}", err).contains("input does not exist"));
        });
    }

    #[test]
    fn decrypt_missing_in_place_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let missing = temp_dir.join("nope.bin");
            let err = decrypt_io(&ctx, None, None, Some(missing.to_str().unwrap()), None, None).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(format!("{}", err).contains("input does not exist"));
        });
    }

    #[test]
    fn decrypt_unsupported_algorithm_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let key = [14u8; 32];
            let p = temp_dir.join("raw.bin");
            let ct = aes_encrypt(&key, b"x");
            fs::write(&p, &ct).unwrap();
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let k = encode_base64url(key);
            let err = decrypt_io(&ctx, Some(p.to_str().unwrap()), None, None, Some(&k), Some("chacha20-poly1305")).unwrap_err();
            assert!(err.to_string().contains("unsupported encryption algorithm"), "msg was {}", err);
        });
    }
}
