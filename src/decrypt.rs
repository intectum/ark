use std::env::current_dir;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use uuid::Uuid;

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, DEFAULT_SIGNING_ALGORITHM, decrypt_bytes};
use crate::identity::read_identity;
use crate::metadata::{get_member, read_metadata_attributes, validate_metadata, write_metadata_attributes};
use crate::types::{Hash, Member, Metadata, Signature};
use crate::util::{decode_base64url, find_root, io_err, now_iso};

pub struct DecryptArgs {
    pub input: Option<String>,
    pub output: Option<String>,
    pub in_place: Option<String>,
    pub key: Option<String>,
    pub algorithm: Option<String>,
}

pub fn cmd_decrypt(args: DecryptArgs) -> std::io::Result<()> {
    if args.in_place.is_some() && (args.input.is_some() || args.output.is_some()) {
        return Err(io_err("--in-place is mutually exclusive with -i/--input and -o/--output"));
    }

    let root = find_root(&current_dir()?)?;
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;

    let source_path: Option<&str> = args.in_place.as_deref().or(args.input.as_deref());
    let dest_path: Option<&str> = args.in_place.as_deref().or(args.output.as_deref());

    let source_has_metadata = match source_path {
        Some(p) => xattr::get(Path::new(p), "user.ark.encryption")?.is_some(),
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

    let mut metadata = match source_path {
        Some(p) if source_has_metadata => read_metadata_attributes(Path::new(p))?,
        _ => {
            let file_key = match &args.key {
                Some(k) => decode_base64url(k.trim()).map_err(|e| io_err(&format!("--key decode: {}", e)))?,
                None => return Err(io_err("no file key available: pass --key or use -i/--in-place on a file with metadata"))
            };

            let now = now_iso();
            let metadata = Metadata {
                id: Uuid::new_v4().to_string(),
                created: now.clone(),
                modified: now,
                modified_by: identity.address.clone(),
                encryption: args.algorithm.clone().unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM.to_string()),
                members: vec![Member {
                    address: identity.address.clone(),
                    permission: "owner".to_string(),
                    wrapped_key: Some(file_key),
                }],
                body_hash: Hash { algorithm: String::new(), value: Vec::new() },
                signature: Signature { algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(), value: Vec::new() },
                encrypted: Some(true),
            };

            validate_metadata(&metadata)?;
            metadata
        }
    };

    if let Some(false) = metadata.encrypted {
        return Err(io_err("file is already plaintext (user.ark.encrypted=false); refusing to decrypt"));
    }

    let wrapped_key: Vec<u8> = if let Some(k) = &args.key {
        decode_base64url(k.trim()).map_err(|e| io_err(&format!("--key decode: {}", e)))?
    } else {
        match get_member(&metadata.members, &identity.address) {
            Some(m) => m.wrapped_key.clone()
                .ok_or_else(|| io_err("no wrapped key for current account"))?,
            None => return Err(io_err("no member entry for current account"))
        }
    };

    let plaintext = decrypt_bytes(&wrapped_key, &ciphertext).map_err(|e| {
        io_err(&format!(
            "{} — input may already be plaintext or the key may be wrong",
            e
        ))
    })?;

    match dest_path {
        Some(p) => {
            fs::write(p, &plaintext)?;
            let path = Path::new(p);
            metadata.encrypted = Some(false);
            write_metadata_attributes(path, &metadata)?;
        }
        None => std::io::stdout().write_all(&plaintext)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_key;
    use crate::crypto::encrypt_bytes;
    use crate::metadata::write_metadata_attributes;
    use crate::util::encode_base64url;
    use crate::util::test::{get_default_test_metadata, TempDir, TEST_ADDRESS, with_cwd};

    fn setup(td: &TempDir, key_byte: u8) -> std::path::PathBuf {
        create_account_with_key(&td.0, TEST_ADDRESS, &[key_byte; 32]).unwrap();
        td.0.join("ark/test")
    }

    fn encrypted_file(td: &TempDir, name: &str, plaintext: &[u8], key: &[u8]) -> std::path::PathBuf {
        let p = td.0.join(name);
        let ct = encrypt_bytes(key, plaintext).unwrap();
        fs::write(&p, &ct).unwrap();
        let mut meta = get_default_test_metadata(&[1u8; 32], TEST_ADDRESS, &ct);
        meta.members[0].wrapped_key = Some(key.to_vec());
        meta.encrypted = Some(true);
        write_metadata_attributes(&p, &meta).unwrap();
        p
    }

    fn args() -> DecryptArgs {
        DecryptArgs { input: None, output: None, in_place: None, key: None, algorithm: None }
    }

    #[test]
    fn decrypt_input_to_output() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 11);
        let key = [11u8; 32];
        let in_path = encrypted_file(&td, "in.bin", b"hello world", &key);
        let out_path = td.0.join("out.bin");
        with_cwd(&acc, || {
            cmd_decrypt(DecryptArgs {
                input: Some(in_path.to_string_lossy().into_owned()),
                output: Some(out_path.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();
        });
        assert_eq!(fs::read(&out_path).unwrap(), b"hello world");
    }

    #[test]
    fn decrypt_in_place_replaces_body_and_marks_unencrypted() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 12);
        let key = [12u8; 32];
        let p = encrypted_file(&td, "file.bin", b"data", &key);
        with_cwd(&acc, || {
            cmd_decrypt(DecryptArgs {
                in_place: Some(p.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();
        });
        assert_eq!(fs::read(&p).unwrap(), b"data");
        assert_eq!(
            xattr::get(&p, "user.ark.encrypted").unwrap().as_deref(),
            Some(b"false".as_slice())
        );
        assert_eq!(
            xattr::get(&p, "user.ark.encryption").unwrap().as_deref(),
            Some(b"aes-256-gcm".as_slice())
        );
        // per-member xattr preserved
        assert!(xattr::get(&p, "user.ark.member_0_wrapped_key").unwrap().is_some());
    }

    #[test]
    fn decrypt_in_place_conflicts_with_input() {
        let td = TempDir::new("ark_decrypt_test");
        let err = cmd_decrypt(DecryptArgs {
            input: Some("a".to_string()),
            in_place: Some(td.0.join("x").to_string_lossy().into_owned()),
            ..args()
        }).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn decrypt_explicit_key_overrides_meta() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 13);
        let real_key = [13u8; 32];
        let p = encrypted_file(&td, "in.bin", b"x", &real_key);
        // overwrite member with wrong key — explicit --key should still win
        let ct = fs::read(&p).unwrap();
        let mut wrong_meta = get_default_test_metadata(&[1u8; 32], TEST_ADDRESS, &ct);
        wrong_meta.members[0].wrapped_key = Some([99u8; 32].to_vec());
        wrong_meta.encrypted = Some(true);
        write_metadata_attributes(&p, &wrong_meta).unwrap();
        let out = td.0.join("out.bin");
        with_cwd(&acc, || {
            cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                output: Some(out.to_string_lossy().into_owned()),
                key: Some(encode_base64url(real_key)),
                ..args()
            }).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"x");
    }

    #[test]
    fn decrypt_missing_key_errors() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 17);
        let p = td.0.join("in.bin");
        let ct = encrypt_bytes(&[1u8; 32], b"x").unwrap();
        fs::write(&p, &ct).unwrap();
        // no xattrs, no --key
        let err = with_cwd(&acc, || cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            ..args()
        }).unwrap_err());
        assert!(err.to_string().contains("no file key"));
    }

    #[test]
    fn decrypt_refuses_when_encrypted_flag_false() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 15);
        let key = [15u8; 32];
        let p = encrypted_file(&td, "in.bin", b"x", &key);
        // mark file as already-decrypted
        xattr::set(&p, "user.ark.encrypted", b"false").unwrap();
        let err = with_cwd(&acc, || cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            ..args()
        }).unwrap_err());
        assert!(err.to_string().contains("already plaintext"), "msg was {}", err);
    }

    #[test]
    fn decrypt_proceeds_when_encrypted_flag_true() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 16);
        let key = [16u8; 32];
        let p = encrypted_file(&td, "in.bin", b"hi", &key);
        // encrypted_file already sets encrypted=true via Metadata
        let out = td.0.join("out.bin");
        with_cwd(&acc, || {
            cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                output: Some(out.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"hi");
    }

    #[test]
    fn decrypt_aead_failure_includes_hint() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 18);
        let p = td.0.join("plain.bin");
        // 42 bytes of plaintext masquerading as ciphertext
        let body = vec![0u8; 42];
        fs::write(&p, &body).unwrap();
        let mut m = get_default_test_metadata(&[1u8; 32], TEST_ADDRESS, &body);
        m.members[0].wrapped_key = Some([0u8; 32].to_vec());
        write_metadata_attributes(&p, &m).unwrap();
        // no encrypted flag → decrypt attempts and fails
        let err = with_cwd(&acc, || cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            ..args()
        }).unwrap_err());
        let msg = err.to_string();
        assert!(msg.contains("may already be plaintext"), "msg was {}", msg);
        assert!(msg.contains("key may be wrong"), "msg was {}", msg);
    }

    #[test]
    fn decrypt_to_stdout_succeeds() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 19);
        let key = [19u8; 32];
        let p = encrypted_file(&td, "in.bin", b"plain", &key);
        with_cwd(&acc, || {
            cmd_decrypt(DecryptArgs {
                input: Some(p.to_string_lossy().into_owned()),
                ..args()
            }).unwrap();
        });
    }

    #[test]
    fn decrypt_unsupported_algorithm_errors() {
        let td = TempDir::new("ark_decrypt_test");
        let acc = setup(&td, 14);
        let key = [14u8; 32];
        let p = td.0.join("raw.bin");
        let ct = encrypt_bytes(&key, b"x").unwrap();
        fs::write(&p, &ct).unwrap();
        let err = with_cwd(&acc, || cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            key: Some(encode_base64url(key)),
            algorithm: Some("chacha20-poly1305".to_string()),
            ..args()
        }).unwrap_err());
        assert!(err.to_string().contains("unsupported encryption algorithm"), "msg was {}", err);
    }
}
