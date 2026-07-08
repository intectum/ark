use std::env::current_dir;

use crate::identity::read_identity;
use crate::client::ark_request;
use crate::util::{find_root, io_err, resolve_url};

pub fn cmd_delete(arg: &str) -> std::io::Result<()> {
    let root = find_root(&current_dir()?)?;
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;
    let url = resolve_url(arg, &identity.address, &root, false)?;

    let (code, _, body) = ark_request(&root, &url, "DELETE", &[], &[])?;
    if code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;

    use super::*;
    use crate::client::create_account;
    use crate::server::start_test_server;
    use crate::util::test::in_test_dir;

    #[test]
    fn cmd_delete_removes_file() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();
            let f = temp_dir.join("ark/gyan/x.txt");
            fs::write(&f, b"bye").unwrap();

            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            cmd_delete("x.txt").unwrap();

            assert!(!f.exists());
        });
    }

    #[test]
    fn cmd_delete_removes_directory_recursively() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();
            let d = temp_dir.join("ark/gyan/sub");
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("inner"), b"data").unwrap();

            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            cmd_delete("sub").unwrap();

            assert!(!d.exists());
        });
    }

    #[test]
    fn cmd_delete_missing_file_errors() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();

            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            let err = cmd_delete("nope").unwrap_err();
            assert!(err.to_string().contains("HTTP 404"), "msg was {}", err);
        });
    }

    #[test]
    fn cmd_delete_via_address_form() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            create_account(temp_dir, &address).unwrap();
            let f = temp_dir.join("ark/gyan/explicit.txt");
            fs::write(&f, b"gone").unwrap();

            env::set_current_dir(temp_dir.join("ark/gyan")).unwrap();
            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            cmd_delete(&arg).unwrap();

            assert!(!f.exists());
        });
    }
}
