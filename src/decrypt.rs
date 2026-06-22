use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use base64::Engine;

use crate::crypto::{ENCRYPTION_ALGORITHM, decrypt_body_with};
use crate::metadata::{Metadata, read_metadata_attributes, write_metadata_attributes};
use crate::util::{B64, io_err};

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

    let source_path: Option<&str> = args.in_place.as_deref().or(args.input.as_deref());
    let dest_path: Option<&str> = args.in_place.as_deref().or(args.output.as_deref());

    let (ciphertext, meta) = match source_path {
        Some(p) => {
            let path = Path::new(p);
            let data = fs::read(path)?;
            let m = read_metadata_attributes(path)?;
            (data, m)
        }
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            (buf, Metadata::default())
        }
    };

    if let Some(false) = meta.encrypted {
        return Err(io_err("file is already plaintext (user.ark.encrypted=false); refusing to decrypt"));
    }

    let algorithm = args
        .algorithm
        .or(meta.encryption)
        .unwrap_or_else(|| ENCRYPTION_ALGORITHM.to_string());
    if algorithm != ENCRYPTION_ALGORITHM {
        return Err(io_err(&format!("unsupported algorithm: {}", algorithm)));
    }

    let file_key = match args.key {
        Some(k) => {
            let bytes = B64
                .decode(k.trim())
                .map_err(|e| io_err(&format!("--key decode: {}", e)))?;
            bytes
                .try_into()
                .map_err(|_| io_err("--key wrong length (need 32 bytes)"))?
        }
        None => meta.file_key.ok_or_else(|| {
            io_err("no file key available: pass --key or use -i/--in-place on a file with metadata")
        })?,
    };

    let plaintext = decrypt_body_with(&ciphertext, &file_key).map_err(|e| {
        io_err(&format!(
            "{} — input may already be plaintext or the key may be wrong",
            e
        ))
    })?;

    match dest_path {
        Some(p) => {
            fs::write(p, &plaintext)?;
            if args.in_place.is_some() {
                let path = Path::new(p);
                let mut m = read_metadata_attributes(path)?;
                m.encrypted = Some(false);
                write_metadata_attributes(path, &m)?;
            }
        }
        None => std::io::stdout().write_all(&plaintext)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_body_with;
    use crate::metadata::{Metadata, write_metadata_attributes};
    use crate::util::testutil::TempDir;

    fn encrypted_file(td: &TempDir, name: &str, plaintext: &[u8], key: &[u8; 32]) -> std::path::PathBuf {
        let p = td.0.join(name);
        let nonce = [3u8; 12];
        let ct = encrypt_body_with(plaintext, key, &nonce).unwrap();
        fs::write(&p, &ct).unwrap();
        let meta = Metadata { encryption: Some(ENCRYPTION_ALGORITHM.to_string()), file_key: Some(*key), encrypted: Some(true) };
        write_metadata_attributes(&p, &meta).unwrap();
        p
    }

    fn args() -> DecryptArgs {
        DecryptArgs { input: None, output: None, in_place: None, key: None, algorithm: None }
    }

    #[test]
    fn decrypt_input_to_output() {
        let td = TempDir::new("ark_decrypt_test");
        let key = [11u8; 32];
        let in_path = encrypted_file(&td, "in.bin", b"hello world", &key);
        let out_path = td.0.join("out.bin");
        cmd_decrypt(DecryptArgs {
            input: Some(in_path.to_string_lossy().into_owned()),
            output: Some(out_path.to_string_lossy().into_owned()),
            ..args()
        }).unwrap();
        assert_eq!(fs::read(&out_path).unwrap(), b"hello world");
    }

    #[test]
    fn decrypt_in_place_replaces_body_and_marks_unencrypted() {
        let td = TempDir::new("ark_decrypt_test");
        let key = [12u8; 32];
        let p = encrypted_file(&td, "file.bin", b"data", &key);
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
            xattr::get(&p, "user.ark.encryption").unwrap().as_deref(),
            Some(b"aes-256-gcm".as_slice())
        );
        assert!(xattr::get(&p, "user.ark.filekey").unwrap().is_some());
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
        let real_key = [13u8; 32];
        let p = encrypted_file(&td, "in.bin", b"x", &real_key);
        // overwrite xattr filekey with wrong key — explicit --key should still win
        xattr::set(&p, "user.ark.filekey", B64.encode([99u8; 32]).as_bytes()).unwrap();
        let out = td.0.join("out.bin");
        cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            output: Some(out.to_string_lossy().into_owned()),
            key: Some(B64.encode(real_key)),
            ..args()
        }).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"x");
    }

    #[test]
    fn decrypt_missing_key_errors() {
        let td = TempDir::new("ark_decrypt_test");
        let p = td.0.join("in.bin");
        let ct = encrypt_body_with(b"x", &[1u8; 32], &[2u8; 12]).unwrap();
        fs::write(&p, &ct).unwrap();
        // no xattrs, no --key
        let err = cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            ..args()
        }).unwrap_err();
        assert!(err.to_string().contains("no file key"));
    }

    #[test]
    fn decrypt_refuses_when_encrypted_flag_false() {
        let td = TempDir::new("ark_decrypt_test");
        let key = [15u8; 32];
        let p = encrypted_file(&td, "in.bin", b"x", &key);
        // mark file as already-decrypted
        xattr::set(&p, "user.ark.encrypted", b"false").unwrap();
        let err = cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            ..args()
        }).unwrap_err();
        assert!(err.to_string().contains("already plaintext"), "msg was {}", err);
    }

    #[test]
    fn decrypt_proceeds_when_encrypted_flag_true() {
        let td = TempDir::new("ark_decrypt_test");
        let key = [16u8; 32];
        let p = encrypted_file(&td, "in.bin", b"hi", &key);
        // encrypted_file already sets encrypted=true via Metadata
        let out = td.0.join("out.bin");
        cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            output: Some(out.to_string_lossy().into_owned()),
            ..args()
        }).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"hi");
    }

    #[test]
    fn decrypt_aead_failure_includes_hint() {
        let td = TempDir::new("ark_decrypt_test");
        let p = td.0.join("plain.bin");
        // 42 bytes of plaintext masquerading as ciphertext
        fs::write(&p, vec![0u8; 42]).unwrap();
        xattr::set(&p, "user.ark.encryption", b"aes-256-gcm").unwrap();
        xattr::set(&p, "user.ark.filekey", B64.encode([0u8; 32]).as_bytes()).unwrap();
        // no encrypted flag → decrypt attempts and fails
        let err = cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            ..args()
        }).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("may already be plaintext"), "msg was {}", msg);
        assert!(msg.contains("key may be wrong"), "msg was {}", msg);
    }

    #[test]
    fn decrypt_unsupported_algorithm_errors() {
        let td = TempDir::new("ark_decrypt_test");
        let key = [14u8; 32];
        let p = encrypted_file(&td, "in.bin", b"x", &key);
        let err = cmd_decrypt(DecryptArgs {
            input: Some(p.to_string_lossy().into_owned()),
            algorithm: Some("chacha20-poly1305".to_string()),
            ..args()
        }).unwrap_err();
        assert!(err.to_string().contains("unsupported algorithm"));
    }
}
