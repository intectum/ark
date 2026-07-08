use std::env::current_dir;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_key, encrypt_bytes};
use crate::identity::{read_identity, read_identity_key};
use crate::metadata::{apply_key_to_metadata, create_metadata, get_member, read_metadata_attributes, sign_metadata, write_metadata_attributes, write_metadata_headers};
use crate::client::ark_request;
use crate::types::Key;
use crate::util::{find_root, io_err, now_iso, resolve_url};

pub fn cmd_put(path: &str, input: Option<&str>, encryption_algorithm: Option<&str>) -> std::io::Result<()> {
    let root = find_root(&current_dir()?)?;
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;
    let url = resolve_url(path, &identity.address, &root, false)?;

    let input_path: Option<PathBuf> = input.map(PathBuf::from);

    let body = match &input_path {
        Some(p) => fs::read(p)?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };


    let has_existing_metadata = match input_path.as_deref() {
        Some(p) => xattr::get(p, "user.ark.id")?.is_some(),
        None => false,
    };

    let mut metadata = if has_existing_metadata {
        let mut m = read_metadata_attributes(input_path.as_deref().unwrap())?;
        if let Some(alg) = encryption_algorithm {
            m.encryption_algorithm = Some(alg.to_string());
        }
        m
    } else {
        create_metadata(&identity.address, Some(encryption_algorithm.unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM)))
    };

    if get_member(&metadata.members, &identity.address).is_none() {
        return Err(io_err("no member entry for current account"));
    }

    let skip_encrypt = metadata.encryption_algorithm.is_none();
    let already_encrypted = metadata.encrypted == Some(true);

    let final_body = if already_encrypted || skip_encrypt {
        if skip_encrypt {
            for member in metadata.members.iter_mut() {
                member.key = None;
            }
        }
        body
    } else {
        let encryption_algorithm = metadata.encryption_algorithm.as_deref().unwrap();
        let file_key = create_key(encryption_algorithm)?;
        let (_, ciphertext) = encrypt_bytes(&file_key, &body)?;
        apply_key_to_metadata(&mut metadata, &file_key)?;
        metadata.encrypted = Some(false);
        ciphertext
    };

    metadata.modified = now_iso();
    metadata.modified_by = identity.address.clone();

    let signing_key = read_identity_key(&root.join(".ark").join("identity.key"))?;
    sign_metadata(&Key { algorithm: identity.public_key.algorithm, value: signing_key }, &mut metadata, &final_body)?;

    let metadata_headers = write_metadata_headers(&metadata);
    let headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();

    let (response_code, _, response_body) = ark_request(&root, &url, "PUT", &headers, &final_body)?;
    if response_code != 201 && response_code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", response_code, String::from_utf8_lossy(&response_body))));
    }

    if let Some(p) = input_path.as_deref() {
        if !skip_encrypt || has_existing_metadata {
            write_metadata_attributes(p, &metadata)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::client::create_account;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, decrypt_bytes};
    use crate::identity::read_identity_key;
    use crate::server::start_test_server;
    use crate::util::test::{in_test_dir, write_plain_test_file};

    fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        decrypt_bytes(&Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: key.to_vec() }, ciphertext)
    }

    fn put_via_cmd(temp_dir: &Path, arg: &str, plaintext: &[u8], cwd_subpath: &str) -> PathBuf {
        let input = temp_dir.join("input.bin");
        fs::write(&input, plaintext).unwrap();
        std::env::set_current_dir(temp_dir.join(cwd_subpath)).unwrap();
        cmd_put(arg, Some(input.to_str().unwrap()), None).unwrap();
        input
    }

    fn unwrap_first_member_key(path: &Path, identity_seed: &[u8]) -> Vec<u8> {
        let m = read_metadata_attributes(path).unwrap();
        let key = m.members[0].key.as_ref().expect("key set");
        decrypt_bytes(&Key { algorithm: key.algorithm.clone(), value: identity_seed.to_vec() }, &key.value).expect("unwrap")
    }

    #[test]
    fn cmd_put_encrypts_body_and_stores_meta_xattr() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();

            put_via_cmd(temp_dir, "notes.txt", b"plaintext", "ark/gyan");

            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let on_disk = fs::read(&server_path).unwrap();
            assert_ne!(on_disk, b"plaintext");

            let alg = xattr::get(&server_path, "user.ark.encryption_algorithm").unwrap();
            assert_eq!(alg.as_deref(), Some(b"aes-256-gcm".as_slice()));
            let identity_seed = read_identity_key(&temp_dir.join("ark/gyan/.ark/identity.key")).unwrap();
            let file_key = unwrap_first_member_key(&server_path, &identity_seed);
            let decrypted = aes_decrypt(&file_key, &on_disk).unwrap();
            assert_eq!(decrypted, b"plaintext");
        });
    }

    #[test]
    fn cmd_put_writes_metadata_back_to_input_file() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();

            let input = put_via_cmd(temp_dir, "out.bin", b"hello", "ark/gyan");
            assert_eq!(
                xattr::get(&input, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(b"aes-256-gcm".as_slice())
            );
            let identity_seed = read_identity_key(&temp_dir.join("ark/gyan/.ark/identity.key")).unwrap();
            let _file_key = unwrap_first_member_key(&input, &identity_seed);
        });
    }

    #[test]
    fn cmd_put_rotates_filekey_over_existing_metadata() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();

            let input = temp_dir.join("input.bin");
            write_plain_test_file(&input, &identity, &secret_key, b"hello");
            let mut preset_meta = create_metadata(&identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            let preset_file_key = create_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
            apply_key_to_metadata(&mut preset_meta, &preset_file_key).unwrap();
            sign_metadata(&secret_key, &mut preset_meta, b"hello").unwrap();
            write_metadata_attributes(&input, &preset_meta).unwrap();

            let account_dir = temp_dir.join("ark/gyan");
            std::env::set_current_dir(&account_dir).unwrap();
            cmd_put("notes.txt", Some(input.to_str().unwrap()), None).unwrap();

            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let server_key = unwrap_first_member_key(&server_path, &secret_key.value);
            assert_ne!(server_key, preset_file_key.value);

            let ciphertext = fs::read(&server_path).unwrap();
            let plaintext = aes_decrypt(&server_key, &ciphertext).unwrap();
            assert_eq!(plaintext, b"hello");
        });
    }

    #[test]
    fn cmd_put_rotates_filekey_on_every_put() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let account_key = create_account(temp_dir, &address).unwrap().1.value;

            let input = temp_dir.join("input.bin");
            fs::write(&input, b"v1").unwrap();
            let account_dir = temp_dir.join("ark/gyan");
            std::env::set_current_dir(&account_dir).unwrap();
            cmd_put("notes.txt", Some(input.to_str().unwrap()), None).unwrap();
            let key1 = unwrap_first_member_key(&input, &account_key);

            fs::write(&input, b"v2").unwrap();
            std::env::set_current_dir(&account_dir).unwrap();
            cmd_put("notes.txt", Some(input.to_str().unwrap()), None).unwrap();
            let key2 = unwrap_first_member_key(&input, &account_key);

            assert_ne!(key1, key2);

            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let ciphertext = fs::read(&server_path).unwrap();
            let plaintext = aes_decrypt(&key2, &ciphertext).unwrap();
            assert_eq!(plaintext, b"v2");
        });
    }

    #[test]
    fn cmd_put_creates_at_relative_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();

            put_via_cmd(temp_dir, "notes.txt", b"hello", "ark/gyan");

            assert!(temp_dir.join("ark/gyan/notes.txt").exists());
        });
    }

    #[test]
    fn cmd_put_overwrites_existing_file() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();
            fs::write(temp_dir.join("ark/gyan/x.txt"), b"old").unwrap();

            put_via_cmd(temp_dir, "x.txt", b"new plaintext", "ark/gyan");

            let on_disk = fs::read(temp_dir.join("ark/gyan/x.txt")).unwrap();
            assert_ne!(on_disk, b"old");
            assert_ne!(on_disk, b"new plaintext");
        });
    }

    #[test]
    fn cmd_put_from_subdir_uses_relative_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();
            let notes = temp_dir.join("ark/gyan/notes");
            fs::create_dir_all(&notes).unwrap();

            put_via_cmd(temp_dir, "todo.txt", b"buy milk", "ark/gyan/notes");

            assert!(temp_dir.join("ark/gyan/notes/todo.txt").exists());
        });
    }

    #[test]
    fn cmd_put_absolute_url_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();

            put_via_cmd(temp_dir, "/sub/file.txt", b"absolute", "ark/gyan");

            assert!(temp_dir.join("ark/gyan/sub/file.txt").exists());
        });
    }

    #[test]
    fn cmd_put_via_explicit_address_form() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();

            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            put_via_cmd(temp_dir, &arg, b"via address", "ark/gyan");

            assert!(temp_dir.join("ark/gyan/explicit.txt").exists());
        });
    }

    #[test]
    fn cmd_put_sends_already_encrypted_body_unchanged() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();

            let file_key = create_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
            let ciphertext = encrypt_bytes(&file_key, b"hidden").unwrap().1;
            let input = temp_dir.join("input.bin");
            fs::write(&input, &ciphertext).unwrap();
            let mut m = create_metadata(&identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            apply_key_to_metadata(&mut m, &file_key).unwrap();
            m.encrypted = Some(true);
            sign_metadata(&secret_key, &mut m, &ciphertext).unwrap();
            write_metadata_attributes(&input, &m).unwrap();

            let account_dir = temp_dir.join("ark/gyan");
            std::env::set_current_dir(&account_dir).unwrap();
            cmd_put("file.bin", Some(input.to_str().unwrap()), None).unwrap();

            let server_path = temp_dir.join("ark/gyan/file.bin");
            let server_body = fs::read(&server_path).unwrap();
            assert_eq!(server_body, ciphertext, "server received raw input bytes");
            assert_eq!(
                xattr::get(&input, "user.ark.encrypted").unwrap().as_deref(),
                Some(b"true".as_slice())
            );
            let unwrapped = unwrap_first_member_key(&input, &secret_key.value);
            assert_eq!(aes_decrypt(&unwrapped, &server_body).unwrap(), b"hidden");
        });
    }

    #[test]
    fn cmd_put_marks_input_encrypted_false_after_fresh_encrypt() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();

            let input = put_via_cmd(temp_dir, "out.bin", b"plain", "ark/gyan");
            assert_eq!(
                xattr::get(&input, "user.ark.encrypted").unwrap().as_deref(),
                Some(b"false".as_slice())
            );
        });
    }

    #[test]
    fn cmd_put_encryption_none_sends_raw_body() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();

            let input = temp_dir.join("input.bin");
            fs::write(&input, b"plain bytes").unwrap();
            let mut m = create_metadata(&identity.address, None);
            sign_metadata(&secret_key, &mut m, b"plain bytes").unwrap();
            write_metadata_attributes(&input, &m).unwrap();

            let account_dir = temp_dir.join("ark/gyan");
            std::env::set_current_dir(&account_dir).unwrap();
            cmd_put("raw.bin", Some(input.to_str().unwrap()), None).unwrap();

            let server_path = temp_dir.join("ark/gyan/raw.bin");
            assert_eq!(fs::read(&server_path).unwrap(), b"plain bytes");
            // metadata records no encryption_algorithm; wrapped keys dropped
            assert_eq!(xattr::get(&server_path, "user.ark.encryption_algorithm").unwrap(), None);
            assert_eq!(xattr::get(&input, "user.ark.member_0_key_value").unwrap(), None);
        });
    }

    #[test]
    fn cmd_put_missing_identity_errors() {
        in_test_dir("ark_put_test", |temp_dir| {
            let input = temp_dir.join("input.bin");
            fs::write(&input, b"x").unwrap();
            std::env::set_current_dir(temp_dir).unwrap();
            let err = cmd_put("anything", Some(input.to_str().unwrap()), None).unwrap_err();
            let msg = format!("{}", err);
            assert!(msg.contains("no .ark"), "msg was {}", msg);
        });
    }
}
