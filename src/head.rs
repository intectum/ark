use std::io::Write;

use crate::request::request_ark;
use crate::util::io_err;

pub fn cmd_head(arg: &str) -> std::io::Result<()> {
    let (code, headers, body) = request_ark("HEAD", arg, &[], &[])?;
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }
    let mut stdout = std::io::stdout().lock();
    for (k, v) in &headers {
        writeln!(stdout, "{}: {}", k, v)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_seed;
    use crate::request::request_ark;
    use crate::server::start_test_server;
    use crate::util::testutil::{TempDir, with_cwd};
    use std::fs;

    #[test]
    fn head_returns_headers_without_body() {
        let td = TempDir::new("ark_head_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [240u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/file.bin"), b"hello world").unwrap();

        let account_dir = td.0.join("ark/gyan");
        let (code, headers, body) = with_cwd(&account_dir, || {
            request_ark("HEAD", "file.bin", &[], &[]).unwrap()
        });
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert!(
            headers.iter().any(|(k, v)| k == "content-length" && v == "11"),
            "headers: {:?}", headers
        );
    }

    #[test]
    fn head_returns_metadata_headers() {
        use base64::Engine;
        let td = TempDir::new("ark_head_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [241u8; 32]).unwrap();
        let f = td.0.join("ark/gyan/secret");
        fs::write(&f, b"ciphertext").unwrap();
        let key_b64 = crate::util::B64.encode([6u8; 32]);
        xattr::set(&f, "user.ark.encryption", b"aes-256-gcm").unwrap();
        xattr::set(&f, "user.ark.filekey", key_b64.as_bytes()).unwrap();

        let account_dir = td.0.join("ark/gyan");
        let (code, headers, body) = with_cwd(&account_dir, || {
            request_ark("HEAD", "secret", &[], &[]).unwrap()
        });
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert!(headers.iter().any(|(k, v)| k == "x-ark-meta-encryption" && v == "aes-256-gcm"));
        assert!(headers.iter().any(|(k, v)| k == "x-ark-meta-filekey" && v == &key_b64));
    }

    #[test]
    fn cmd_head_succeeds_against_real_server() {
        let td = TempDir::new("ark_head_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [242u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/x"), b"abc").unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || cmd_head("x").unwrap());
    }

    #[test]
    fn cmd_head_missing_file_errors() {
        let td = TempDir::new("ark_head_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [243u8; 32]).unwrap();

        let account_dir = td.0.join("ark/gyan");
        let err = with_cwd(&account_dir, || cmd_head("nope").unwrap_err());
        assert!(err.to_string().contains("HTTP 404"), "msg was {}", err);
    }
}
