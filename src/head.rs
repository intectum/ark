use std::env::current_dir;
use std::io::Write;

use crate::identity::{read_identity, resolve_identity};
use crate::metadata::{read_metadata_headers, verify_metadata_signature};
use crate::request::ark_request;
use crate::util::{find_root, io_err, resolve_url};

pub fn cmd_head(path: &str) -> std::io::Result<()> {
    let root = find_root(&current_dir()?)?;
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;
    let url = resolve_url(path, &identity.address, &root, false)?;

    let (code, headers, body) = ark_request(&root, &url, "HEAD", &[], &[])?;
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    let metadata = read_metadata_headers(&headers)?;

    let modifier_identity = resolve_identity(&metadata.modified_by)?;
    verify_metadata_signature(&modifier_identity.public_key, &metadata)?;

    let mut stdout = std::io::stdout().lock();
    for (name, value) in &headers {
        writeln!(stdout, "{}: {}", name, value)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::create_account::create_account;
    use crate::metadata::read_metadata_attributes;
    use crate::server::start_test_server;
    use crate::util::encode_base64url;
    use crate::util::test::{in_test_dir, write_encrypted_test_file, write_plain_test_file};

    #[test]
    fn head_returns_headers_without_body() {
        in_test_dir("ark_head_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            write_plain_test_file(&temp_dir.join("ark/gyan/file.bin"), &identity, &secret_key, b"hello world");

            let account_dir = temp_dir.join("ark/gyan");
            env::set_current_dir(&account_dir).unwrap();
            let identity = read_identity(&account_dir.join(".ark").join("identity.json")).unwrap();
            let url = resolve_url("file.bin", &identity.address, &account_dir, false).unwrap();
            let (code, headers, body) = ark_request(&account_dir, &url, "HEAD", &[], &[]).unwrap();
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert!(
                headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-length") && v == "11"),
                "headers: {:?}", headers
            );
        });
    }

    #[test]
    fn head_returns_metadata_headers() {
        in_test_dir("ark_head_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            let f = temp_dir.join("ark/gyan/secret");
            write_encrypted_test_file(&f, &identity, &secret_key, b"plaintext");
            let expected_key_b64 = encode_base64url(&read_metadata_attributes(&f).unwrap()
                .members[0].key.as_ref().unwrap().value);

            let account_dir = temp_dir.join("ark/gyan");
            env::set_current_dir(&account_dir).unwrap();
            let identity = read_identity(&account_dir.join(".ark").join("identity.json")).unwrap();
            let url = resolve_url("secret", &identity.address, &account_dir, false).unwrap();
            let (code, headers, body) = ark_request(&account_dir, &url, "HEAD", &[], &[]).unwrap();
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-encryption-algorithm") && v == "aes-256-gcm"));
            assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-member-0-permission") && v == "owner"));
            assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-member-0-key-value") && v == &expected_key_b64));
        });
    }

    #[test]
    fn cmd_head_succeeds_against_real_server() {
        in_test_dir("ark_head_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let (identity, secret_key) = create_account(temp_dir, &address).unwrap();
            write_plain_test_file(&temp_dir.join("ark/gyan/x"), &identity, &secret_key, b"abc");

            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            cmd_head("x").unwrap();
        });
    }

    #[test]
    fn cmd_head_missing_file_errors() {
        in_test_dir("ark_head_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();

            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            let err = cmd_head("nope").unwrap_err();
            assert!(err.to_string().contains("HTTP 404"), "msg was {}", err);
        });
    }
}
