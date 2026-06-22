use std::fs;
use std::io::Read;
use std::path::PathBuf;

use crate::crypto::{ENCRYPTION_ALGORITHM, encrypt_body_with};
use crate::metadata::{Metadata, read_metadata_attributes, write_metadata_attributes, write_metadata_headers};
use crate::request::request_ark;
use crate::util::io_err;

pub fn cmd_put(arg: &str, input: Option<&str>) -> std::io::Result<()> {
    let input_path: Option<PathBuf> = input.map(PathBuf::from);
    let plaintext = match &input_path {
        Some(p) => fs::read(p)?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };
    let existing = match input_path.as_deref() {
        Some(p) => read_metadata_attributes(p)?,
        None => Metadata::default(),
    };
    let algorithm = existing.encryption.unwrap_or_else(|| ENCRYPTION_ALGORITHM.to_string());
    let file_key = match existing.file_key {
        Some(k) => k,
        None => random_key()?,
    };
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| io_err(&e.to_string()))?;
    let ciphertext = encrypt_body_with(&plaintext, &file_key, &nonce)?;
    let meta = Metadata { encryption: Some(algorithm), file_key: Some(file_key), encrypted: Some(false) };
    let header_strs = write_metadata_headers(&meta);
    let extra: Vec<(&str, &str)> = header_strs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (code, _, resp) = request_ark("PUT", arg, &ciphertext, &extra)?;
    if code != 201 && code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&resp))));
    }
    if let Some(p) = input_path.as_deref() {
        write_metadata_attributes(p, &meta)?;
    }
    Ok(())
}

fn random_key() -> std::io::Result<[u8; 32]> {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).map_err(|e| io_err(&e.to_string()))?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_seed;
    use crate::crypto::decrypt_body_with;
    use crate::server::start_test_server;
    use crate::util::B64;
    use crate::util::testutil::{TempDir, with_cwd};
    use base64::Engine;

    fn put_via_cmd(td: &TempDir, arg: &str, plaintext: &[u8], cwd_subpath: &str) -> PathBuf {
        let input = td.0.join("input.bin");
        fs::write(&input, plaintext).unwrap();
        let cwd = td.0.join(cwd_subpath);
        with_cwd(&cwd, || {
            cmd_put(arg, Some(input.to_str().unwrap())).unwrap();
        });
        input
    }

#[test]
    fn cmd_put_encrypts_body_and_stores_meta_xattr() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [130u8; 32]).unwrap();

        put_via_cmd(&td, "notes.txt", b"plaintext", "ark/gyan");

        let server_path = td.0.join("ark/gyan/notes.txt");
        let on_disk = fs::read(&server_path).unwrap();
        assert_ne!(on_disk, b"plaintext");

        let alg = xattr::get(&server_path, "user.ark.encryption").unwrap();
        assert_eq!(alg.as_deref(), Some(b"aes-256-gcm".as_slice()));
        let key_b64 = xattr::get(&server_path, "user.ark.filekey").unwrap().unwrap();
        let key_bytes = B64.decode(&key_b64).unwrap();
        let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
        let decrypted = decrypt_body_with(&on_disk, &key_arr).unwrap();
        assert_eq!(decrypted, b"plaintext");
    }

    #[test]
    fn cmd_put_writes_metadata_back_to_input_file() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [131u8; 32]).unwrap();

        let input = put_via_cmd(&td, "out.bin", b"hello", "ark/gyan");
        assert_eq!(
            xattr::get(&input, "user.ark.encryption").unwrap().as_deref(),
            Some(b"aes-256-gcm".as_slice())
        );
        let key_b64 = xattr::get(&input, "user.ark.filekey").unwrap().unwrap();
        let key_bytes = B64.decode(&key_b64).unwrap();
        assert_eq!(key_bytes.len(), 32);
    }

    #[test]
    fn cmd_put_reuses_existing_filekey_on_input() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [132u8; 32]).unwrap();

        let preset_key = [77u8; 32];
        let preset_key_b64 = B64.encode(preset_key);
        let input = td.0.join("input.bin");
        fs::write(&input, b"hello").unwrap();
        xattr::set(&input, "user.ark.encryption", b"aes-256-gcm").unwrap();
        xattr::set(&input, "user.ark.filekey", preset_key_b64.as_bytes()).unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_put("notes.txt", Some(input.to_str().unwrap())).unwrap();
        });

        let server_path = td.0.join("ark/gyan/notes.txt");
        let server_key = xattr::get(&server_path, "user.ark.filekey").unwrap().unwrap();
        assert_eq!(server_key, preset_key_b64.as_bytes());

        let ciphertext = fs::read(&server_path).unwrap();
        let plaintext = decrypt_body_with(&ciphertext, &preset_key).unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn cmd_put_second_put_keeps_same_filekey() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [133u8; 32]).unwrap();

        let input = td.0.join("input.bin");
        fs::write(&input, b"v1").unwrap();
        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_put("notes.txt", Some(input.to_str().unwrap())).unwrap();
        });
        let key1 = xattr::get(&input, "user.ark.filekey").unwrap().unwrap();

        fs::write(&input, b"v2").unwrap();
        with_cwd(&account_dir, || {
            cmd_put("notes.txt", Some(input.to_str().unwrap())).unwrap();
        });
        let key2 = xattr::get(&input, "user.ark.filekey").unwrap().unwrap();

        assert_eq!(key1, key2);

        let server_path = td.0.join("ark/gyan/notes.txt");
        let key_bytes = B64.decode(&key2).unwrap();
        let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
        let ciphertext = fs::read(&server_path).unwrap();
        let plaintext = decrypt_body_with(&ciphertext, &key_arr).unwrap();
        assert_eq!(plaintext, b"v2");
    }

    #[test]
    fn cmd_put_creates_at_relative_path() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [134u8; 32]).unwrap();

        put_via_cmd(&td, "notes.txt", b"hello", "ark/gyan");

        assert!(td.0.join("ark/gyan/notes.txt").exists());
    }

    #[test]
    fn cmd_put_overwrites_existing_file() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [135u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/x.txt"), b"old").unwrap();

        put_via_cmd(&td, "x.txt", b"new plaintext", "ark/gyan");

        let on_disk = fs::read(td.0.join("ark/gyan/x.txt")).unwrap();
        assert_ne!(on_disk, b"old");
        assert_ne!(on_disk, b"new plaintext");
    }

    #[test]
    fn cmd_put_from_subdir_uses_relative_path() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [136u8; 32]).unwrap();
        let notes = td.0.join("ark/gyan/notes");
        fs::create_dir_all(&notes).unwrap();

        put_via_cmd(&td, "todo.txt", b"buy milk", "ark/gyan/notes");

        assert!(td.0.join("ark/gyan/notes/todo.txt").exists());
    }

    #[test]
    fn cmd_put_absolute_url_path() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [137u8; 32]).unwrap();

        put_via_cmd(&td, "/ark/gyan/sub/file.txt", b"absolute", "ark/gyan");

        assert!(td.0.join("ark/gyan/sub/file.txt").exists());
    }

    #[test]
    fn cmd_put_via_explicit_address_form() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [138u8; 32]).unwrap();

        let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
        put_via_cmd(&td, &arg, b"via address", "ark/gyan");

        assert!(td.0.join("ark/gyan/explicit.txt").exists());
    }

    #[test]
    fn cmd_put_missing_identity_errors() {
        let td = TempDir::new("ark_put_test");
        let input = td.0.join("input.bin");
        fs::write(&input, b"x").unwrap();
        let err = with_cwd(&td.0, || cmd_put("anything", Some(input.to_str().unwrap())).unwrap_err());
        let msg = format!("{}", err);
        assert!(msg.contains("no .ark"), "msg was {}", msg);
    }
}
