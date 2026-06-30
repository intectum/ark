use std::env::current_dir;
use std::io::Write;

use crate::identity::{read_identity, resolve_identity_client};
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

    let modifier_identity = resolve_identity_client(&root, &identity, &metadata.modified_by)?;
    verify_metadata_signature(&modifier_identity.public_key.value, &metadata)?;

    let mut stdout = std::io::stdout().lock();
    for (name, value) in &headers {
        writeln!(stdout, "{}: {}", name, value)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::create_account::create_account_with_key;
    use crate::metadata::{sign_metadata, write_metadata_attributes};
    use crate::server::start_test_server;
    use crate::util::encode_base64url;
    use crate::util::test::{TempDir, get_default_test_metadata, with_cwd, write_file_with_default_test_metadata};

    #[test]
    fn head_returns_headers_without_body() {
        let td = TempDir::new("ark_head_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[240u8; 32]).unwrap();
        write_file_with_default_test_metadata(&td.0.join("ark/gyan/file.bin"), &[240u8; 32], &address, b"hello world");

        let account_dir = td.0.join("ark/gyan");
        let (code, headers, body) = with_cwd(&account_dir, || {
            let identity = read_identity(&account_dir.join(".ark").join("identity.json")).unwrap();
            let url = resolve_url("file.bin", &identity.address, &account_dir, false).unwrap();
            ark_request(&account_dir, &url, "HEAD", &[], &[]).unwrap()
        });
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert!(
            headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-length") && v == "11"),
            "headers: {:?}", headers
        );
    }

    #[test]
    fn head_returns_metadata_headers() {
        let td = TempDir::new("ark_head_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        let account_key = [241u8; 32];
        create_account_with_key(&td.0, &address, &account_key).unwrap();
        let f = td.0.join("ark/gyan/secret");
        fs::write(&f, b"ciphertext").unwrap();
        let key = [6u8; 32];
        let key_b64 = encode_base64url(key);
        let mut m = get_default_test_metadata(&account_key, &address, b"ciphertext");
        m.members[0].wrapped_key = key.to_vec();
        sign_metadata(&account_key, &mut m, b"ciphertext");
        write_metadata_attributes(&f, &m).unwrap();

        let account_dir = td.0.join("ark/gyan");
        let (code, headers, body) = with_cwd(&account_dir, || {
            let identity = read_identity(&account_dir.join(".ark").join("identity.json")).unwrap();
            let url = resolve_url("secret", &identity.address, &account_dir, false).unwrap();
            ark_request(&account_dir, &url, "HEAD", &[], &[]).unwrap()
        });
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-encryption") && v == "aes-256-gcm"));
        assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-member-0-permission") && v == "owner"));
        assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-member-0-wrapped-key") && v == &key_b64));
    }

    #[test]
    fn cmd_head_succeeds_against_real_server() {
        let td = TempDir::new("ark_head_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[242u8; 32]).unwrap();
        write_file_with_default_test_metadata(&td.0.join("ark/gyan/x"), &[242u8; 32], &address, b"abc");

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || cmd_head("x").unwrap());
    }

    #[test]
    fn cmd_head_missing_file_errors() {
        let td = TempDir::new("ark_head_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_key(&td.0, &address, &[243u8; 32]).unwrap();

        let account_dir = td.0.join("ark/gyan");
        let err = with_cwd(&account_dir, || cmd_head("nope").unwrap_err());
        assert!(err.to_string().contains("HTTP 404"), "msg was {}", err);
    }
}
