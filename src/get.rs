use std::env::current_dir;
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::crypto::{decrypt_bytes};
use crate::identity::{read_identity, read_identity_key, resolve_identity};
use crate::metadata::{get_member, read_metadata_headers, verify_metadata, write_metadata_attributes};
use crate::request::ark_request;
use crate::types::Key;
use crate::util::{find_root, io_err, resolve_url};

pub fn cmd_get(path: &str, output: Option<&str>, decrypt: bool) -> std::io::Result<()> {
    let root = find_root(&current_dir()?)?;
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;
    let url = resolve_url(path, &identity.address, &root, false)?;

    let (code, headers, body) = ark_request(&root, &url, "GET", &[], &[])?;
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    let mut metadata = read_metadata_headers(&headers)?;

    let modifier_identity = resolve_identity(&metadata.modified_by)?;
    verify_metadata(&modifier_identity.public_key, &metadata, &body)?;

    let final_body = if decrypt {
        let member = match get_member(&metadata.members, &identity.address) {
            Some(m) => m,
            None => return Err(io_err("no member entry for current account"))
        };
        let encrypted_file_key = member.key.as_ref()
            .ok_or_else(|| io_err("no file key for current account"))?;
        let identity_key = read_identity_key(&root.join(".ark").join("identity.key"))?;
        let file_key = decrypt_bytes(&Key { algorithm: encrypted_file_key.algorithm.clone(), value: identity_key }, &encrypted_file_key.value)?;

        decrypt_bytes(&Key { algorithm: metadata.encryption.clone(), value: file_key }, &body).map_err(|e| {
            io_err(&format!(
                "{} — server data may not be encrypted or the key may be wrong",
                e
            ))
        })?
    } else {
        body
    };

    match output {
        Some(file) => {
            fs::write(file, &final_body)?;
            metadata.encrypted = Some(!decrypt);
            write_metadata_attributes(Path::new(file), &metadata)?;
        }
        None => std::io::stdout().write_all(&final_body)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::create_account::create_account;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_key, encrypt_bytes};
    use crate::identity::{create_identity, write_identity};
    use crate::metadata::{create_metadata, read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::server::start_test_server;
    use crate::types::Key;
    use crate::util::test::{in_test_dir, write_encrypted_test_file, write_plain_test_file};

    #[test]
    fn get_file_via_cmd_get_writes_to_output() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            write_plain_test_file(&temp_dir.join("ark/gyan/hello.txt"), &identity, &secret_key, b"hi from server");

            let out = temp_dir.join("out.bin");
            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            cmd_get("hello.txt", Some(out.to_str().unwrap()), false).unwrap();

            assert_eq!(fs::read(&out).unwrap(), b"hi from server");
        });
    }

    #[test]
    fn get_from_subdir_uses_relative_path() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            let notes = temp_dir.join("ark/gyan/notes");
            fs::create_dir_all(&notes).unwrap();
            write_plain_test_file(&notes.join("todo.txt"), &identity, &secret_key, b"buy milk");

            let out = temp_dir.join("out.bin");
            env::set_current_dir(&notes).unwrap();
            cmd_get("todo.txt", Some(out.to_str().unwrap()), false).unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"buy milk");
        });
    }

    #[test]
    fn get_absolute_url_path() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            let subdir = temp_dir.join("ark/gyan/sub");
            fs::create_dir_all(&subdir).unwrap();
            write_plain_test_file(&subdir.join("file.txt"), &identity, &secret_key, b"absolute");

            let out = temp_dir.join("out.bin");
            env::set_current_dir(&subdir).unwrap();
            cmd_get("/sub/file.txt", Some(out.to_str().unwrap()), false).unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"absolute");
        });
    }

    #[test]
    fn get_via_explicit_address_form() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            write_plain_test_file(&temp_dir.join("ark/gyan/explicit.txt"), &identity, &secret_key, b"via address");

            let out = temp_dir.join("out.bin");
            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            cmd_get(&arg, Some(out.to_str().unwrap()), false).unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"via address");
        });
    }

    #[test]
    fn get_writes_metadata_xattrs_from_response_headers() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            let server_file = temp_dir.join("ark/gyan/secret");
            write_encrypted_test_file(&server_file, &identity, &secret_key, b"plaintext");
            let expected_ciphertext = fs::read(&server_file).unwrap();
            let expected_key_value = read_metadata_attributes(&server_file).unwrap()
                .members[0].key.as_ref().unwrap().value.clone();

            let out = temp_dir.join("out.bin");
            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            cmd_get("secret", Some(out.to_str().unwrap()), false).unwrap();

            assert_eq!(fs::read(&out).unwrap(), expected_ciphertext);
            let m = read_metadata_attributes(&out).unwrap();
            assert_eq!(m.encryption, "aes-256-gcm");
            assert_eq!(m.members.iter().next().unwrap().key.as_ref().unwrap().value, expected_key_value);
        });
    }

    #[test]
    fn get_with_decrypt_returns_plaintext() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();

            let file_key = create_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
            let (_, ct) = encrypt_bytes(&file_key, b"clear text").unwrap();
            let server_file = temp_dir.join("ark/gyan/secret");
            fs::write(&server_file, &ct).unwrap();
            let mut m = create_metadata(&address, DEFAULT_ENCRYPTION_ALGORITHM);
            let (wrap_alg, wrapped) = encrypt_bytes(&identity.public_key, &file_key.value).unwrap();
            m.members[0].key = Some(Key {
                algorithm: wrap_alg,
                value: wrapped,
            });
            sign_metadata(&secret_key, &mut m, &ct).unwrap();
            write_metadata_attributes(&server_file, &m).unwrap();

            let out = temp_dir.join("out.bin");
            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            cmd_get("secret", Some(out.to_str().unwrap()), true).unwrap();

            assert_eq!(fs::read(&out).unwrap(), b"clear text");
            assert_eq!(
                xattr::get(&out, "user.ark.encrypted").unwrap().as_deref(),
                Some(b"false".as_slice())
            );
        });
    }

    #[test]
    fn get_with_decrypt_errors_when_no_key_in_response() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();
            let (other_identity, other_key) = create_identity("other@example.com").unwrap();
            write_plain_test_file(&temp_dir.join("ark/gyan/plain"), &other_identity, &other_key, b"raw");

            let account_dir = temp_dir.join("ark/gyan");
            let identities_dir = account_dir.join(".ark").join("identities");
            fs::create_dir_all(&identities_dir).unwrap();
            write_identity(&identities_dir.join("other@example.com.json"), &other_identity).unwrap();

            let out = temp_dir.join("out.bin");
            env::set_current_dir(&account_dir).unwrap();
            let err = cmd_get("plain", Some(out.to_str().unwrap()), true).unwrap_err();
            assert!(err.to_string().contains("no member entry"), "msg was {}", err);
        });
    }

    #[test]
    fn cmd_get_to_stdout_succeeds() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            write_plain_test_file(&temp_dir.join("ark/gyan/stdout.txt"), &identity, &secret_key, b"to stdout");

            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            cmd_get("stdout.txt", None, false).unwrap();
        });
    }

    #[test]
    fn get_missing_identity_errors() {
        in_test_dir("ark_get_test", |_temp_dir| {
            let err = cmd_get("anything", None, false).unwrap_err();
            let msg = format!("{}", err);
            assert!(msg.contains("no .ark"), "msg was {}", msg);
        });
    }
}
