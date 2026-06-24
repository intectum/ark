use std::fs;
use std::io::Read;
use std::path::PathBuf;

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, encrypt_bytes};
use crate::identity::read_nearest_identity;
use crate::metadata::{get_member, read_metadata_attributes, write_metadata_attributes, write_metadata_headers};
use crate::request::ark_request;
use crate::types::{Member, Metadata};
use crate::util::io_err;

pub fn cmd_put(arg: &str, input: Option<&str>, no_encrypt: bool) -> std::io::Result<()> {
    let input_path: Option<PathBuf> = input.map(PathBuf::from);

    let body = match &input_path {
        Some(p) => fs::read(p)?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };

    let (identity, _) = read_nearest_identity()?;

    let has_existing_metadata = match input_path.as_deref() {
        Some(p) => xattr::get(p, "user.ark.encryption")?.is_some(),
        None => false,
    };

    let metadata = if has_existing_metadata {
        read_metadata_attributes(input_path.as_deref().unwrap())?
    } else {
        Metadata {
            encryption: DEFAULT_ENCRYPTION_ALGORITHM.to_string(),
            encrypted: Some(false),
            members: vec![Member {
                address: identity.address.clone(),
                identity_key: identity.key.public_key.clone(),
                permission: "owner".to_string(),
                wrapped_file_key: random_key()?
            }]
        }
    };

    let member = match get_member(&metadata.members, &identity.address) {
        Some(m) => m,
        None => return Err(io_err("no member entry for current account"))
    };

    let final_body = if metadata.encrypted != Some(true) && !no_encrypt {
        encrypt_bytes(&member.wrapped_file_key, &body)?
    } else {
        body
    };

    let metadata_headers = write_metadata_headers(&metadata);
    let extra_headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();

    let (response_code, _, response_body) = ark_request("PUT", arg, &final_body, &extra_headers)?;
    if response_code != 201 && response_code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", response_code, String::from_utf8_lossy(&response_body))));
    }

    if let Some(p) = input_path.as_deref() {
        if !no_encrypt || has_existing_metadata {
            write_metadata_attributes(p, &metadata)?;
        }
    }

    Ok(())
}

fn random_key() -> std::io::Result<Vec<u8>> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| io_err(&e.to_string()))?;
    Ok(key.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_key;
    use crate::crypto::decrypt_bytes;
    use crate::metadata::read_metadata_attributes;
    use crate::server::start_test_server;
    use crate::util::test::{TempDir, with_cwd};

    fn read_file_key(path: &std::path::Path) -> Vec<u8> {
        let m = read_metadata_attributes(path).unwrap();
        m.members
            .iter()
            .next()
            .expect("file key in members").wrapped_file_key.clone()
    }

    fn put_via_cmd(td: &TempDir, arg: &str, plaintext: &[u8], cwd_subpath: &str) -> PathBuf {
        let input = td.0.join("input.bin");
        fs::write(&input, plaintext).unwrap();
        let cwd = td.0.join(cwd_subpath);
        with_cwd(&cwd, || {
            cmd_put(arg, Some(input.to_str().unwrap()), false).unwrap();
        });
        input
    }

#[test]
    fn cmd_put_encrypts_body_and_stores_meta_xattr() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[130u8; 32]).unwrap();

        put_via_cmd(&td, "notes.txt", b"plaintext", "ark/gyan");

        let server_path = td.0.join("ark/gyan/notes.txt");
        let on_disk = fs::read(&server_path).unwrap();
        assert_ne!(on_disk, b"plaintext");

        let alg = xattr::get(&server_path, "user.ark.encryption").unwrap();
        assert_eq!(alg.as_deref(), Some(b"aes-256-gcm".as_slice()));
        let key = read_file_key(&server_path);
        let decrypted = decrypt_bytes(&key, &on_disk).unwrap();
        assert_eq!(decrypted, b"plaintext");
    }

    #[test]
    fn cmd_put_writes_metadata_back_to_input_file() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[131u8; 32]).unwrap();

        let input = put_via_cmd(&td, "out.bin", b"hello", "ark/gyan");
        assert_eq!(
            xattr::get(&input, "user.ark.encryption").unwrap().as_deref(),
            Some(b"aes-256-gcm".as_slice())
        );
        let _key = read_file_key(&input);
    }

    #[test]
    fn cmd_put_reuses_existing_filekey_on_input() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[132u8; 32]).unwrap();

        let preset_key = [77u8; 32];
        let input = td.0.join("input.bin");
        fs::write(&input, b"hello").unwrap();
        let owner = Member {
            address: format!("gyan@127.0.0.1:{}", port),
            identity_key: [0u8; 32].to_vec(),
            permission: "owner".to_string(),
            wrapped_file_key: preset_key.to_vec(),
        };
        let preset_meta = Metadata { encryption: "aes-256-gcm".to_string(), encrypted: None, members: vec![owner] };
        write_metadata_attributes(&input, &preset_meta).unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_put("notes.txt", Some(input.to_str().unwrap()), false).unwrap();
        });

        let server_path = td.0.join("ark/gyan/notes.txt");
        let server_key = read_file_key(&server_path);
        assert_eq!(server_key, preset_key);

        let ciphertext = fs::read(&server_path).unwrap();
        let plaintext = decrypt_bytes(&preset_key, &ciphertext).unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn cmd_put_second_put_keeps_same_filekey() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[133u8; 32]).unwrap();

        let input = td.0.join("input.bin");
        fs::write(&input, b"v1").unwrap();
        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_put("notes.txt", Some(input.to_str().unwrap()), false).unwrap();
        });
        let key1 = read_file_key(&input);

        fs::write(&input, b"v2").unwrap();
        with_cwd(&account_dir, || {
            cmd_put("notes.txt", Some(input.to_str().unwrap()), false).unwrap();
        });
        let key2 = read_file_key(&input);

        assert_eq!(key1, key2);

        let server_path = td.0.join("ark/gyan/notes.txt");
        let ciphertext = fs::read(&server_path).unwrap();
        let plaintext = decrypt_bytes(&key2, &ciphertext).unwrap();
        assert_eq!(plaintext, b"v2");
    }

    #[test]
    fn cmd_put_creates_at_relative_path() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[134u8; 32]).unwrap();

        put_via_cmd(&td, "notes.txt", b"hello", "ark/gyan");

        assert!(td.0.join("ark/gyan/notes.txt").exists());
    }

    #[test]
    fn cmd_put_overwrites_existing_file() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[135u8; 32]).unwrap();
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
        create_account_with_key(&td.0, &address, &[136u8; 32]).unwrap();
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
        create_account_with_key(&td.0, &address, &[137u8; 32]).unwrap();

        put_via_cmd(&td, "/sub/file.txt", b"absolute", "ark/gyan");

        assert!(td.0.join("ark/gyan/sub/file.txt").exists());
    }

    #[test]
    fn cmd_put_via_explicit_address_form() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[138u8; 32]).unwrap();

        let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
        put_via_cmd(&td, &arg, b"via address", "ark/gyan");

        assert!(td.0.join("ark/gyan/explicit.txt").exists());
    }

    #[test]
    fn cmd_put_sends_already_encrypted_body_unchanged() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[150u8; 32]).unwrap();

        // pre-encrypted input
        let key = [88u8; 32];
        let ciphertext = encrypt_bytes(&key, b"hidden").unwrap();
        let input = td.0.join("input.bin");
        fs::write(&input, &ciphertext).unwrap();
        let owner = Member {
            address: format!("gyan@127.0.0.1:{}", port),
            identity_key: [0u8; 32].to_vec(),
            permission: "owner".to_string(),
            wrapped_file_key: key.to_vec(),
        };
        write_metadata_attributes(&input, &Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: Some(true),
            members: vec![owner],
        }).unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_put("file.bin", Some(input.to_str().unwrap()), false).unwrap();
        });

        let server_path = td.0.join("ark/gyan/file.bin");
        let server_body = fs::read(&server_path).unwrap();
        assert_eq!(server_body, ciphertext, "server received raw input bytes");
        // input encrypted flag preserved
        assert_eq!(
            xattr::get(&input, "user.ark.encrypted").unwrap().as_deref(),
            Some(b"true".as_slice())
        );
        // decryption with same key recovers original plaintext
        assert_eq!(decrypt_bytes(&key, &server_body).unwrap(), b"hidden");
    }

    #[test]
    fn cmd_put_marks_input_encrypted_false_after_fresh_encrypt() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[151u8; 32]).unwrap();

        let input = put_via_cmd(&td, "out.bin", b"plain", "ark/gyan");
        assert_eq!(
            xattr::get(&input, "user.ark.encrypted").unwrap().as_deref(),
            Some(b"false".as_slice())
        );
    }

    #[test]
    fn cmd_put_no_encrypt_sends_raw_body() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[160u8; 32]).unwrap();

        let input = td.0.join("input.bin");
        fs::write(&input, b"plain bytes").unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_put("raw.bin", Some(input.to_str().unwrap()), true).unwrap();
        });

        let server_path = td.0.join("ark/gyan/raw.bin");
        assert_eq!(fs::read(&server_path).unwrap(), b"plain bytes");
        // server has default metadata (invariant); input file left untouched
        assert!(xattr::get(&server_path, "user.ark.encryption").unwrap().is_some());
        assert_eq!(xattr::get(&input, "user.ark.member_0_address").unwrap(), None);
    }

    #[test]
    fn cmd_put_no_encrypt_passes_through_existing_metadata() {
        let td = TempDir::new("ark_put_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[161u8; 32]).unwrap();

        let key = [55u8; 32];
        let ct = encrypt_bytes(&key, b"secret").unwrap();
        let input = td.0.join("input.bin");
        fs::write(&input, &ct).unwrap();
        let owner = Member {
            address: format!("gyan@127.0.0.1:{}", port),
            identity_key: [0u8; 32].to_vec(),
            permission: "owner".to_string(),
            wrapped_file_key: key.to_vec(),
        };
        write_metadata_attributes(&input, &Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![owner],
        }).unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_put("file.bin", Some(input.to_str().unwrap()), true).unwrap();
        });

        let server_path = td.0.join("ark/gyan/file.bin");
        assert_eq!(fs::read(&server_path).unwrap(), ct);
        // metadata forwarded to server
        assert_eq!(read_file_key(&server_path), key);
    }

    #[test]
    fn cmd_put_missing_identity_errors() {
        let td = TempDir::new("ark_put_test");
        let input = td.0.join("input.bin");
        fs::write(&input, b"x").unwrap();
        let err = with_cwd(&td.0, || cmd_put("anything", Some(input.to_str().unwrap()), false).unwrap_err());
        let msg = format!("{}", err);
        assert!(msg.contains("no .ark"), "msg was {}", msg);
    }
}
