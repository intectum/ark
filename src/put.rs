use std::fs;
use std::io::Read;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::request::request_ark;
use crate::util::io_err;

pub const ENCRYPTION_ALGORITHM: &str = "aes-256-gcm";

pub fn cmd_put(arg: &str, input: Option<&str>) -> std::io::Result<()> {
    let plaintext = match input {
        Some(f) => fs::read(f)?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };
    let (ciphertext, _key) = encrypt_body(&plaintext)?;
    let extra = [("X-Ark-Meta-Encryption", ENCRYPTION_ALGORITHM)];
    let (code, _, resp) = request_ark("PUT", arg, &ciphertext, &extra)?;
    if code != 201 && code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&resp))));
    }
    Ok(())
}

pub fn encrypt_body(plaintext: &[u8]) -> std::io::Result<(Vec<u8>, [u8; 32])> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| io_err(&e.to_string()))?;
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| io_err(&e.to_string()))?;
    let ciphertext = encrypt_body_with(plaintext, &key, &nonce)?;
    Ok((ciphertext, key))
}

pub fn encrypt_body_with(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> std::io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| io_err(&format!("encrypt: {}", e)))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(test)]
pub fn decrypt_body_with(ciphertext: &[u8], key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(io_err("ciphertext too short"));
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|e| io_err(&format!("decrypt: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_seed;
    use crate::server::serve;
    use crate::util::testutil::{TempDir, bind_local, with_cwd};
    use std::thread;

    fn put_via_cmd(td: &TempDir, arg: &str, plaintext: &[u8], cwd_subpath: &str) {
        let input = td.0.join("input.bin");
        fs::write(&input, plaintext).unwrap();
        let cwd = td.0.join(cwd_subpath);
        with_cwd(&cwd, || {
            cmd_put(arg, Some(input.to_str().unwrap())).unwrap();
        });
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [9u8; 32];
        let nonce = [3u8; 12];
        let plaintext = b"secret payload";
        let ct = encrypt_body_with(plaintext, &key, &nonce).unwrap();
        assert_eq!(&ct[..12], &nonce);
        assert_ne!(&ct[12..], plaintext);
        let pt = decrypt_body_with(&ct, &key).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_body_generates_unique_keys_and_nonces() {
        let (ct1, k1) = encrypt_body(b"same").unwrap();
        let (ct2, k2) = encrypt_body(b"same").unwrap();
        assert_ne!(k1, k2);
        assert_ne!(ct1, ct2);
        assert_ne!(&ct1[..12], &ct2[..12]);
    }

    #[test]
    fn cmd_put_encrypts_body_and_stores_meta_xattr() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [130u8; 32]).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        put_via_cmd(&td, "notes.txt", b"plaintext", "ark/gyan");

        let on_disk = fs::read(td.0.join("ark/gyan/notes.txt")).unwrap();
        assert_ne!(on_disk, b"plaintext");
        assert!(on_disk.len() >= 12 + b"plaintext".len() + 16);

        let xattr_val = xattr::get(td.0.join("ark/gyan/notes.txt"), "user.ark.encryption").unwrap();
        assert_eq!(xattr_val.as_deref(), Some(b"aes-256-gcm".as_slice()));
    }

    #[test]
    fn cmd_put_creates_at_relative_path() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [131u8; 32]).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        put_via_cmd(&td, "notes.txt", b"hello", "ark/gyan");

        assert!(td.0.join("ark/gyan/notes.txt").exists());
    }

    #[test]
    fn cmd_put_overwrites_existing_file() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [132u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/x.txt"), b"old").unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        put_via_cmd(&td, "x.txt", b"new plaintext", "ark/gyan");

        let on_disk = fs::read(td.0.join("ark/gyan/x.txt")).unwrap();
        assert_ne!(on_disk, b"old");
        assert_ne!(on_disk, b"new plaintext");
    }

    #[test]
    fn cmd_put_from_subdir_uses_relative_path() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [133u8; 32]).unwrap();
        let notes = td.0.join("ark/gyan/notes");
        fs::create_dir_all(&notes).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        put_via_cmd(&td, "todo.txt", b"buy milk", "ark/gyan/notes");

        assert!(td.0.join("ark/gyan/notes/todo.txt").exists());
    }

    #[test]
    fn cmd_put_absolute_url_path() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [134u8; 32]).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        put_via_cmd(&td, "/ark/gyan/sub/file.txt", b"absolute", "ark/gyan");

        assert!(td.0.join("ark/gyan/sub/file.txt").exists());
    }

    #[test]
    fn cmd_put_via_explicit_address_form() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [135u8; 32]).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

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
