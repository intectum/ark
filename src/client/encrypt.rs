use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, decrypt_bytes, encrypt_bytes};
use crate::types::{IdentityContext, Key, LocalMetadata};
use crate::metadata::{apply_key_to_metadata, create_metadata, get_member, read_local_metadata_attributes, read_metadata_attributes, validate_metadata, write_local_metadata_attributes, write_metadata_attributes};
use crate::util::{decode_base64url, io_err, io_invalid_input, sha256};

pub struct EncryptArgs {
    pub input: Option<String>,
    pub output: Option<String>,
    pub in_place: Option<String>,
    pub key: Option<String>,
    pub encryption_algorithm: Option<String>,
}

pub fn cmd_encrypt(ctx: &IdentityContext, args: EncryptArgs) -> std::io::Result<()> {
    if args.in_place.is_some() && (args.input.is_some() || args.output.is_some()) {
        return Err(io_err("--in-place is mutually exclusive with -i/--input and -o/--output"));
    }

    let source_path: Option<&str> = args.in_place.as_deref().or(args.input.as_deref());
    let dest_path: Option<&str> = args.in_place.as_deref().or(args.output.as_deref());
    if let Some(p) = source_path {
        if !fs::exists(Path::new(p))? {
            return Err(io_invalid_input("input does not exist"));
        }
    }

    let source_has_metadata = match source_path {
        Some(p) => xattr::get(Path::new(p), "user.ark.id")?.is_some(),
        None => false,
    };

    // TODO: probably should be possible
    if source_has_metadata && (args.key.is_some() || args.encryption_algorithm.is_some()) {
        return Err(io_err("-k/--key and -e/--encryption-algortihm cannot override existing metadata"));
    }

    if !source_has_metadata && args.key.is_none() {
        return Err(io_err("no file key available: pass --key or use -i/--in-place on a file with metadata"));
    }

    let plaintext = match source_path {
        Some(p) => fs::read(p)?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };

    let metadata = match source_path {
        Some(p) if source_has_metadata => read_metadata_attributes(Path::new(p))?,
        _ => {
            let key = Key {
                algorithm: args.encryption_algorithm.clone().unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM.to_string()),
                value: decode_base64url(args.key.as_ref().expect("key presence checked above").trim())
                    .map_err(|e| io_err(&format!("--key decode: {}", e)))?
            };

            let mut metadata = create_metadata(&ctx.identity.address, Some(&key.algorithm));
            apply_key_to_metadata(ctx, &mut metadata, &key)?;

            validate_metadata(&metadata)?;
            metadata
        }
    };

    let local_metadata = match source_path {
        Some(p) => read_local_metadata_attributes(Path::new(p))?,
        None => LocalMetadata::default(),
    };

    if let Some(true) = local_metadata.encrypted {
        return Err(io_err("file is already encrypted"));
    }

    let member = get_member(&metadata.members, &ctx.identity.address)
        .ok_or_else(|| io_err("no member entry for current account"))?;
    let encrypted_file_key = member.key.as_ref()
        .ok_or_else(|| io_err("no file key for current account"))?;
    let file_key = decrypt_bytes(
        &Key {
            algorithm: encrypted_file_key.algorithm.clone(),
            value: ctx.identity_key.as_ref().expect("client context missing identity_key").value.clone()
        },
        &encrypted_file_key.value,
    )?;

    let encryption_algorithm = metadata.encryption_algorithm.clone()
        .ok_or_else(|| io_err("encryption_algorithm is missing"))?;
    let (_, ciphertext) = encrypt_bytes(&Key { algorithm: encryption_algorithm, value: file_key }, &plaintext)?;

    match dest_path {
        Some(p) => {
            let path = Path::new(p);
            fs::write(path, &ciphertext)?;
            write_metadata_attributes(path, &metadata)?;
            write_local_metadata_attributes(path, &LocalMetadata {
                encrypted: Some(true),
                sync_hash: Some(sha256(&plaintext)),
            })?;
        }
        None => std::io::stdout().write_all(&ciphertext)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::crypto::decrypt_bytes;
    use crate::context::create_client_context;
    use crate::util::encode_base64url;
    use crate::util::test::{TEST_ADDRESS, create_test_account, in_test_dir, write_plain_test_file};

    fn args() -> EncryptArgs {
        EncryptArgs { input: None, output: None, in_place: None, key: None, encryption_algorithm: None }
    }

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
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let raw_key = [7u8; 32];
            cmd_encrypt(&ctx, EncryptArgs {
                input: Some(in_path.to_string_lossy().into_owned()),
                output: Some(out_path.to_string_lossy().into_owned()),
                key: Some(encode_base64url(raw_key)),
                ..args()
            }).unwrap();
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
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let raw_key = [3u8; 32];
            cmd_encrypt(&ctx, EncryptArgs {
                in_place: Some(p.to_string_lossy().into_owned()),
                key: Some(encode_base64url(raw_key)),
                ..args()
            }).unwrap();
            let ciphertext = fs::read(&p).unwrap();
            assert_ne!(ciphertext, b"data");
            assert_eq!(
                xattr::get(&p, "user.ark_local.encrypted").unwrap().as_deref(),
                Some(b"true".as_slice())
            );
            assert_eq!(
                xattr::get(&p, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(b"aes-256-gcm".as_slice())
            );
            let file_key = unwrap_first_member_key(&p, &secret_key.value);
            assert_eq!(aes_decrypt(&file_key, &ciphertext), b"data");
        });
    }

    #[test]
    fn encrypt_in_place_conflicts_with_input() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let err = cmd_encrypt(&ctx, EncryptArgs {
                input: Some("a".to_string()),
                in_place: Some(temp_dir.join("x").to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
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
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_encrypt(&ctx, EncryptArgs {
                input: Some(in_path.to_string_lossy().into_owned()),
                output: Some(out_path.to_string_lossy().into_owned()),
                key: Some(encode_base64url(raw_key)),
                ..args()
            }).unwrap();
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
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let _ = temp_dir;
            let err = cmd_encrypt(&ctx, args()).unwrap_err();
            assert!(err.to_string().contains("no file key available"), "msg was {}", err);
        });
    }

    #[test]
    fn encrypt_refuses_when_encrypted_flag_true() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = temp_dir.join("in.bin");
            write_plain_test_file(&p, &identity, &secret_key, b"x");
            write_local_metadata_attributes(&p, &LocalMetadata { encrypted: Some(true), sync_hash: None }).unwrap();
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let err = cmd_encrypt(&ctx, EncryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
            assert!(err.to_string().contains("already encrypted"), "msg was {}", err);
        });
    }

    #[test]
    fn encrypt_reuses_file_key_from_source_metadata() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);

            let ct_path = temp_dir.join("orig.bin");
            crate::util::test::write_encrypted_test_file(&ct_path, &identity, &secret_key, b"hello");
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let original_file_key = unwrap_first_member_key(&ct_path, &secret_key.value);

            crate::client::cmd_decrypt(&ctx, crate::client::DecryptArgs {
                in_place: Some(ct_path.to_string_lossy().into_owned()),
                input: None, output: None, key: None, encryption_algorithm: None,
            }).unwrap();
            assert_eq!(fs::read(&ct_path).unwrap(), b"hello");

            cmd_encrypt(&ctx, EncryptArgs {
                in_place: Some(ct_path.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();

            let re_ct = fs::read(&ct_path).unwrap();
            let re_key = unwrap_first_member_key(&ct_path, &secret_key.value);
            assert_eq!(re_key, original_file_key);
            assert_eq!(aes_decrypt(&re_key, &re_ct), b"hello");
        });
    }

    #[test]
    fn encrypt_sets_sync_hash_over_plaintext() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let in_path = temp_dir.join("in.bin");
            fs::write(&in_path, b"plain").unwrap();
            let out_path = temp_dir.join("out.bin");
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            cmd_encrypt(&ctx, EncryptArgs {
                input: Some(in_path.to_string_lossy().into_owned()),
                output: Some(out_path.to_string_lossy().into_owned()),
                key: Some(encode_base64url([9u8; 32])),
                ..args()
            }).unwrap();
            let local = read_local_metadata_attributes(&out_path).unwrap();
            assert_eq!(local.sync_hash.as_deref(), Some(sha256(b"plain").as_slice()));
            assert_eq!(local.encrypted, Some(true));
        });
    }

    #[test]
    fn encrypt_missing_input_errors() {
        in_test_dir("ark_encrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let missing = temp_dir.join("nope.bin");
            let err = cmd_encrypt(&ctx, EncryptArgs {
                input: Some(missing.to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
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
            env::set_current_dir(&acc).unwrap();
            let ctx = create_client_context().unwrap();
            let err = cmd_encrypt(&ctx, EncryptArgs {
                input: Some(in_path.to_string_lossy().into_owned()),
                output: Some(out_path.to_string_lossy().into_owned()),
                key: Some(encode_base64url([1u8; 32])),
                encryption_algorithm: Some("chacha20-poly1305".to_string()),
                ..args()
            }).unwrap_err();
            assert!(err.to_string().contains("unsupported encryption algorithm"), "msg was {}", err);
        });
    }
}
