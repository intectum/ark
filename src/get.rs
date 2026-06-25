use std::fs;
use std::io::Write;
use std::path::Path;

use crate::crypto::{decrypt_bytes};
use crate::identity::read_nearest_identity;
use crate::metadata::{get_member, read_metadata_headers, verify_metadata, write_metadata_attributes};
use crate::request::ark_request;
use crate::util::io_err;

pub fn cmd_get(arg: &str, output: Option<&str>, decrypt: bool) -> std::io::Result<()> {
    let (code, headers, body) = ark_request("GET", arg, &[], &[])?;
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    let mut metadata = read_metadata_headers(&headers)?;

    let modifier = match get_member(&metadata.members, &metadata.modified_by) {
        Some(m) => m,
        None => return Err(io_err("modifier not in member list")),
    };
    verify_metadata(&modifier.identity_key, &metadata, &body)?;

    let final_body = if decrypt {
        let (identity, _) = read_nearest_identity()?;

        let member = match get_member(&metadata.members, &identity.address) {
            Some(m) => m,
            None => return Err(io_err("no member entry for current account"))
        };

        decrypt_bytes(&member.wrapped_file_key, &body).map_err(|e| {
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
    use super::*;
    use crate::create_account::create_account_with_key;
    use crate::crypto::encrypt_bytes;
    use crate::metadata::{read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::server::start_test_server;
    use crate::util::test::{TempDir, get_default_test_metadata, with_cwd, write_file_with_default_test_metadata};

    #[test]
    fn get_file_via_cmd_get_writes_to_output() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[200u8; 32]).unwrap();
        write_file_with_default_test_metadata(&td.0.join("ark/gyan/hello.txt"), &[200u8; 32], &address, b"hi from server");

        let account_dir = td.0.join("ark").join("gyan");
        let out = td.0.join("out.bin");

        with_cwd(&account_dir, || {
            cmd_get("hello.txt", Some(out.to_str().unwrap()), false).unwrap();
        });

        assert_eq!(fs::read(&out).unwrap(), b"hi from server");
    }

    #[test]
    fn get_from_subdir_uses_relative_path() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[201u8; 32]).unwrap();
        let notes = td.0.join("ark/gyan/notes");
        fs::create_dir_all(&notes).unwrap();
        write_file_with_default_test_metadata(&notes.join("todo.txt"), &[201u8; 32], &address, b"buy milk");

        let out = td.0.join("out.bin");
        with_cwd(&notes, || {
            cmd_get("todo.txt", Some(out.to_str().unwrap()), false).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"buy milk");
    }

    #[test]
    fn get_absolute_url_path() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[202u8; 32]).unwrap();
        let subdir = td.0.join("ark/gyan/sub");
        fs::create_dir_all(&subdir).unwrap();
        write_file_with_default_test_metadata(&subdir.join("file.txt"), &[202u8; 32], &address, b"absolute");

        let out = td.0.join("out.bin");
        let cwd = td.0.join("ark/gyan/sub");
        with_cwd(&cwd, || {
            cmd_get("/sub/file.txt", Some(out.to_str().unwrap()), false).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"absolute");
    }

    #[test]
    fn get_via_explicit_address_form() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[203u8; 32]).unwrap();
        write_file_with_default_test_metadata(&td.0.join("ark/gyan/explicit.txt"), &[203u8; 32], &address, b"via address");

        let out = td.0.join("out.bin");
        let cwd = td.0.join("ark/gyan");
        let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
        with_cwd(&cwd, || {
            cmd_get(&arg, Some(out.to_str().unwrap()), false).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"via address");
    }

    #[test]
    fn get_writes_metadata_xattrs_from_response_headers() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        let account_key = [210u8; 32];
        create_account_with_key(&td.0, &address, &account_key).unwrap();
        let server_file = td.0.join("ark/gyan/secret");
        fs::write(&server_file, b"ciphertext").unwrap();
        let key = [11u8; 32];
        let mut m = get_default_test_metadata(&account_key, &address, b"ciphertext");
        m.members[0].wrapped_file_key = key.to_vec();
        sign_metadata(&account_key, &mut m, b"ciphertext");
        write_metadata_attributes(&server_file, &m).unwrap();

        let account_dir = td.0.join("ark").join("gyan");
        let out = td.0.join("out.bin");
        with_cwd(&account_dir, || {
            cmd_get("secret", Some(out.to_str().unwrap()), false).unwrap();
        });

        assert_eq!(fs::read(&out).unwrap(), b"ciphertext");
        let m = read_metadata_attributes(&out).unwrap();
        assert_eq!(m.encryption,"aes-256-gcm");
        assert_eq!(m.members.iter().next().unwrap().wrapped_file_key, key);
    }

    #[test]
    fn get_with_decrypt_returns_plaintext() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        let account_key = [220u8; 32];
        create_account_with_key(&td.0, &address, &account_key).unwrap();

        let key = [44u8; 32];
        let ct = encrypt_bytes(&key, b"clear text").unwrap();
        let server_file = td.0.join("ark/gyan/secret");
        fs::write(&server_file, &ct).unwrap();
        let mut m = get_default_test_metadata(&account_key, &address, &ct);
        m.members[0].wrapped_file_key = key.to_vec();
        sign_metadata(&account_key, &mut m, &ct);
        write_metadata_attributes(&server_file, &m).unwrap();

        let account_dir = td.0.join("ark").join("gyan");
        let out = td.0.join("out.bin");
        with_cwd(&account_dir, || {
            cmd_get("secret", Some(out.to_str().unwrap()), true).unwrap();
        });

        assert_eq!(fs::read(&out).unwrap(), b"clear text");
        assert_eq!(
            xattr::get(&out, "user.ark.encrypted").unwrap().as_deref(),
            Some(b"false".as_slice())
        );
    }

    #[test]
    fn get_with_decrypt_errors_when_no_key_in_response() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[221u8; 32]).unwrap();
        write_file_with_default_test_metadata(&td.0.join("ark/gyan/plain"), &[99u8; 32], "other@example.com", b"raw");

        let account_dir = td.0.join("ark").join("gyan");
        let out = td.0.join("out.bin");
        let err = with_cwd(&account_dir, || {
            cmd_get("plain", Some(out.to_str().unwrap()), true).unwrap_err()
        });
        assert!(err.to_string().contains("no member entry"), "msg was {}", err);
    }

    #[test]
    fn cmd_get_to_stdout_succeeds() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[230u8; 32]).unwrap();
        write_file_with_default_test_metadata(&td.0.join("ark/gyan/stdout.txt"), &[230u8; 32], &address, b"to stdout");

        let account_dir = td.0.join("ark").join("gyan");
        with_cwd(&account_dir, || {
            cmd_get("stdout.txt", None, false).unwrap();
        });
    }

    #[test]
    fn get_missing_identity_errors() {
        let td = TempDir::new("ark_get_test");
        let err = with_cwd(&td.0, || cmd_get("anything", None, false).unwrap_err());
        let msg = format!("{}", err);
        assert!(msg.contains("no .ark"), "msg was {}", msg);
    }
}
