use std::env::current_dir;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, decrypt_bytes};
use crate::identity::{read_identity, read_identity_key};
use crate::metadata::{apply_key_to_metadata, create_metadata, get_member, read_metadata_attributes, validate_metadata, write_metadata_attributes};
use crate::types::Key;
use crate::util::{decode_base64url, find_root, io_err, io_invalid_input};

pub struct DecryptArgs {
    pub input: Option<String>,
    pub output: Option<String>,
    pub in_place: Option<String>,
    pub key: Option<String>,
    pub encryption_algorithm: Option<String>,
}

pub fn cmd_decrypt(args: DecryptArgs) -> std::io::Result<()> {
    if args.in_place.is_some() && (args.input.is_some() || args.output.is_some()) {
        return Err(io_err("--in-place is mutually exclusive with -i/--input and -o/--output"));
    }

    let root = find_root(&current_dir()?)?;
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;

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

    let ciphertext = match source_path {
        Some(p) => fs::read(p)?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };

    // TODO: Should key/alg override when source metadata exists? I think yes (but allow without? what if no internet? Maybe if to stdout or noew file? makes sense)
    let mut metadata = match source_path {
        Some(p) if source_has_metadata => read_metadata_attributes(Path::new(p))?,
        _ => {
            let key = match &args.key {
                Some(k) => Key {
                    algorithm: args.encryption_algorithm.clone().unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM.to_string()),
                    value: decode_base64url(k.trim()).map_err(|e| io_err(&format!("--key decode: {}", e)))?
                },
                None => return Err(io_err("no file key available: pass --key or use -i/--in-place on a file with metadata"))
            };

            let mut metadata = create_metadata(&identity.address, Some(&key.algorithm));
            apply_key_to_metadata(&mut metadata, &key)?;

            validate_metadata(&metadata)?;
            metadata
        }
    };

    if let Some(false) = metadata.encrypted {
        return Err(io_err("file is already plaintext (user.ark.encrypted=false); refusing to decrypt"));
    }

    let file_key: Vec<u8> = if let Some(k) = &args.key {
        decode_base64url(k.trim()).map_err(|e| io_err(&format!("--key decode: {}", e)))?
    } else {
        let member = get_member(&metadata.members, &identity.address)
            .ok_or_else(|| io_err("no member entry for current account"))?;
        let encrypted_file_key = member.key.as_ref()
            .ok_or_else(|| io_err("no file key for current account"))?;
        let identity_key = read_identity_key(&root.join(".ark").join("identity.key"))?;
        decrypt_bytes(&Key { algorithm: encrypted_file_key.algorithm.clone(), value: identity_key }, &encrypted_file_key.value)?
    };

    let encryption_algorithm = metadata.encryption_algorithm.clone()
        .ok_or_else(|| io_err("file is not encrypted"))?;
    let plaintext = decrypt_bytes(&Key { algorithm: encryption_algorithm, value: file_key }, &ciphertext)
        .map_err(|e| io_err(&format!("{} — input may already be plaintext or the key may be wrong", e)))?;

    match dest_path {
        Some(p) => {
            fs::write(p, &plaintext)?;
            metadata.encrypted = Some(false);
            write_metadata_attributes(Path::new(p), &metadata)?;
        }
        None => std::io::stdout().write_all(&plaintext)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::crypto::{decrypt_bytes, encrypt_bytes};
    use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
    use crate::util::encode_base64url;
    use crate::util::test::{TEST_ADDRESS, create_test_account, in_test_dir, write_encrypted_test_file};

    fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        encrypt_bytes(&Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: key.to_vec() }, plaintext).unwrap().1
    }

    fn args() -> DecryptArgs {
        DecryptArgs { input: None, output: None, in_place: None, key: None, encryption_algorithm: None }
    }

    #[test]
    fn decrypt_input_to_output() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let in_path = temp_dir.join("in.bin");
            write_encrypted_test_file(&in_path, &identity, &secret_key, b"hello world");
            let out_path = temp_dir.join("out.bin");
            env::set_current_dir(&acc).unwrap();
            cmd_decrypt(DecryptArgs {
                input: Some(in_path.to_string_lossy().into_owned()),
                output: Some(out_path.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();
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
            cmd_decrypt(DecryptArgs {
                in_place: Some(p.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();
            assert_eq!(fs::read(&p).unwrap(), b"data");
            assert_eq!(
                xattr::get(&p, "user.ark.encrypted").unwrap().as_deref(),
                Some(b"false".as_slice())
            );
            assert_eq!(
                xattr::get(&p, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(b"aes-256-gcm".as_slice())
            );
            assert!(xattr::get(&p, "user.ark.member_0_key_value").unwrap().is_some());
        });
    }

    #[test]
    fn decrypt_in_place_conflicts_with_input() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let err = cmd_decrypt(DecryptArgs {
                input: Some("a".to_string()),
                in_place: Some(temp_dir.join("x").to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
            assert!(err.to_string().contains("mutually exclusive"));
        });
    }

    #[test]
    fn decrypt_explicit_key_overrides_meta() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (identity, secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            let real_key = [13u8; 32];
            let p = temp_dir.join("in.bin");
            let ct = aes_encrypt(&real_key, b"x");
            fs::write(&p, &ct).unwrap();
            let mut wrong_meta = create_metadata(&identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            let (wrap_alg, wrong_wrap) = encrypt_bytes(&identity.public_key, &[99u8; 32]).unwrap();
            wrong_meta.members[0].key = Some(Key { algorithm: wrap_alg, value: wrong_wrap });
            wrong_meta.encrypted = Some(true);
            sign_metadata(&secret_key, &mut wrong_meta, Some(&ct)).unwrap();
            write_metadata_attributes(&p, &wrong_meta).unwrap();
            let out = temp_dir.join("out.bin");
            env::set_current_dir(&acc).unwrap();
            cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                output: Some(out.to_string_lossy().into_owned()),
                key: Some(encode_base64url(real_key)),
                ..args()
            }).unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"x");
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
            let err = cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
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
            cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                output: Some(out.to_string_lossy().into_owned()),
                key: Some(encode_base64url(file_key)),
                ..args()
            }).unwrap();

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
            xattr::set(&p, "user.ark.encrypted", b"false").unwrap();
            env::set_current_dir(&acc).unwrap();
            let err = cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
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
            cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                output: Some(out.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();
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
            m.encrypted = Some(true);
            sign_metadata(&secret_key, &mut m, Some(&body)).unwrap();
            write_metadata_attributes(&p, &m).unwrap();
            env::set_current_dir(&acc).unwrap();
            let err = cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
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
            cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();
        });
    }

    #[test]
    fn decrypt_missing_input_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            env::set_current_dir(&acc).unwrap();
            let missing = temp_dir.join("nope.bin");
            let err = cmd_decrypt(DecryptArgs {
                input: Some(missing.to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(format!("{}", err).contains("input does not exist"));
        });
    }

    #[test]
    fn decrypt_missing_in_place_errors() {
        in_test_dir("ark_decrypt_test", |temp_dir| {
            let (_identity, _secret_key, acc) = create_test_account(temp_dir, TEST_ADDRESS);
            env::set_current_dir(&acc).unwrap();
            let missing = temp_dir.join("nope.bin");
            let err = cmd_decrypt(DecryptArgs {
                in_place: Some(missing.to_string_lossy().into_owned()),
                ..args()
            }).unwrap_err();
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
            let err = cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                key: Some(encode_base64url(key)),
                encryption_algorithm: Some("chacha20-poly1305".to_string()),
                ..args()
            }).unwrap_err();
            assert!(err.to_string().contains("unsupported encryption algorithm"), "msg was {}", err);
        });
    }
}
