use crate::request::request_ark;
use crate::util::io_err;

pub fn cmd_delete(arg: &str) -> std::io::Result<()> {
    let (code, _, body) = request_ark("DELETE", arg, &[], &[])?;
    if code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_seed;
    use crate::server::start_test_server;
    use crate::util::testutil::{TempDir, with_cwd};
    use std::fs;

    #[test]
    fn cmd_delete_removes_file() {
        let td = TempDir::new("ark_delete_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [250u8; 32]).unwrap();
        let f = td.0.join("ark/gyan/x.txt");
        fs::write(&f, b"bye").unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || cmd_delete("x.txt").unwrap());

        assert!(!f.exists());
    }

    #[test]
    fn cmd_delete_removes_directory_recursively() {
        let td = TempDir::new("ark_delete_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [251u8; 32]).unwrap();
        let d = td.0.join("ark/gyan/sub");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("inner"), b"data").unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || cmd_delete("sub").unwrap());

        assert!(!d.exists());
    }

    #[test]
    fn cmd_delete_missing_file_errors() {
        let td = TempDir::new("ark_delete_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [252u8; 32]).unwrap();

        let account_dir = td.0.join("ark/gyan");
        let err = with_cwd(&account_dir, || cmd_delete("nope").unwrap_err());
        assert!(err.to_string().contains("HTTP 404"), "msg was {}", err);
    }

    #[test]
    fn cmd_delete_via_address_form() {
        let td = TempDir::new("ark_delete_test");
        let port = start_test_server(td.0.clone());
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [253u8; 32]).unwrap();
        let f = td.0.join("ark/gyan/explicit.txt");
        fs::write(&f, b"gone").unwrap();

        let cwd = td.0.join("ark/gyan");
        let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
        with_cwd(&cwd, || cmd_delete(&arg).unwrap());

        assert!(!f.exists());
    }
}
