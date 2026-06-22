use std::fs;
use std::io::Write;
use std::path::Path;

use crate::metadata::{read_metadata_headers, write_metadata_attributes};
use crate::request::request_ark;
use crate::util::io_err;

pub fn cmd_get(arg: &str, output: Option<&str>) -> std::io::Result<()> {
    let (code, headers, body) = request_ark("GET", arg, &[], &[])?;
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }
    match output {
        Some(f) => {
            fs::write(f, &body)?;
            let meta = read_metadata_headers(&headers);
            write_metadata_attributes(Path::new(f), &meta)?;
        }
        None => std::io::stdout().write_all(&body)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_seed;
    use crate::server::start_test_server;
    use crate::util::testutil::{TempDir, with_cwd};

    #[test]
    fn get_file_via_cmd_get_writes_to_output() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [200u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/hello.txt"), b"hi from server").unwrap();

        let account_dir = td.0.join("ark").join("gyan");
        let out = td.0.join("out.bin");

        with_cwd(&account_dir, || {
            cmd_get("hello.txt", Some(out.to_str().unwrap())).unwrap();
        });

        assert_eq!(fs::read(&out).unwrap(), b"hi from server");
    }

    #[test]
    fn get_from_subdir_uses_relative_path() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [201u8; 32]).unwrap();
        let notes = td.0.join("ark/gyan/notes");
        fs::create_dir_all(&notes).unwrap();
        fs::write(notes.join("todo.txt"), b"buy milk").unwrap();

        let out = td.0.join("out.bin");
        with_cwd(&notes, || {
            cmd_get("todo.txt", Some(out.to_str().unwrap())).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"buy milk");
    }

    #[test]
    fn get_absolute_url_path() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [202u8; 32]).unwrap();
        let subdir = td.0.join("ark/gyan/sub");
        fs::create_dir_all(&subdir).unwrap();
        fs::write(subdir.join("file.txt"), b"absolute").unwrap();

        let out = td.0.join("out.bin");
        let cwd = td.0.join("ark/gyan/sub");
        with_cwd(&cwd, || {
            cmd_get("/ark/gyan/sub/file.txt", Some(out.to_str().unwrap())).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"absolute");
    }

    #[test]
    fn get_via_explicit_address_form() {
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [203u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/explicit.txt"), b"via address").unwrap();

        let out = td.0.join("out.bin");
        let cwd = td.0.join("ark/gyan");
        let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
        with_cwd(&cwd, || {
            cmd_get(&arg, Some(out.to_str().unwrap())).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"via address");
    }

    #[test]
    fn get_writes_metadata_xattrs_from_response_headers() {
        use base64::Engine;
        let td = TempDir::new("ark_get_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [210u8; 32]).unwrap();
        let server_file = td.0.join("ark/gyan/secret");
        fs::write(&server_file, b"ciphertext").unwrap();
        let key_b64 = crate::util::B64.encode([11u8; 32]);
        xattr::set(&server_file, "user.ark.encryption", b"aes-256-gcm").unwrap();
        xattr::set(&server_file, "user.ark.filekey", key_b64.as_bytes()).unwrap();

        let account_dir = td.0.join("ark").join("gyan");
        let out = td.0.join("out.bin");
        with_cwd(&account_dir, || {
            cmd_get("secret", Some(out.to_str().unwrap())).unwrap();
        });

        assert_eq!(fs::read(&out).unwrap(), b"ciphertext");
        assert_eq!(
            xattr::get(&out, "user.ark.encryption").unwrap().as_deref(),
            Some(b"aes-256-gcm".as_slice())
        );
        assert_eq!(
            xattr::get(&out, "user.ark.filekey").unwrap().as_deref(),
            Some(key_b64.as_bytes())
        );
    }

    #[test]
    fn get_missing_identity_errors() {
        let td = TempDir::new("ark_get_test");
        let err = with_cwd(&td.0, || cmd_get("anything", None).unwrap_err());
        let msg = format!("{}", err);
        assert!(msg.contains("no .ark"), "msg was {}", msg);
    }
}
