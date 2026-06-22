use std::fs;
use std::io::Read;

use crate::request::request_ark;
use crate::util::io_err;

pub fn cmd_put(arg: &str, input: Option<&str>) -> std::io::Result<()> {
    let body = match input {
        Some(f) => fs::read(f)?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };
    put_bytes(arg, &body)
}

pub fn put_bytes(arg: &str, body: &[u8]) -> std::io::Result<()> {
    let (code, resp) = request_ark("PUT", arg, body)?;
    if code != 201 && code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&resp))));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_seed;
    use crate::server::serve;
    use crate::util::testutil::{TempDir, bind_local, with_cwd};
    use std::thread;

    #[test]
    fn put_creates_new_file() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [120u8; 32]).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let account_dir = td.0.join("ark").join("gyan");
        with_cwd(&account_dir, || {
            put_bytes("notes.txt", b"hello world").unwrap();
        });

        assert_eq!(fs::read(td.0.join("ark/gyan/notes.txt")).unwrap(), b"hello world");
    }

    #[test]
    fn put_overwrites_existing_file() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [121u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/x.txt"), b"old").unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let account_dir = td.0.join("ark").join("gyan");
        with_cwd(&account_dir, || {
            put_bytes("x.txt", b"new").unwrap();
        });

        assert_eq!(fs::read(td.0.join("ark/gyan/x.txt")).unwrap(), b"new");
    }

    #[test]
    fn put_from_subdir_uses_relative_path() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [122u8; 32]).unwrap();
        let notes = td.0.join("ark/gyan/notes");
        fs::create_dir_all(&notes).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        with_cwd(&notes, || {
            put_bytes("todo.txt", b"buy milk").unwrap();
        });

        assert_eq!(fs::read(td.0.join("ark/gyan/notes/todo.txt")).unwrap(), b"buy milk");
    }

    #[test]
    fn put_absolute_url_path() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [123u8; 32]).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let cwd = td.0.join("ark/gyan");
        with_cwd(&cwd, || {
            put_bytes("/ark/gyan/sub/file.txt", b"absolute").unwrap();
        });

        assert_eq!(fs::read(td.0.join("ark/gyan/sub/file.txt")).unwrap(), b"absolute");
    }

    #[test]
    fn put_via_explicit_address_form() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [124u8; 32]).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let cwd = td.0.join("ark/gyan");
        let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
        with_cwd(&cwd, || {
            put_bytes(&arg, b"via address").unwrap();
        });

        assert_eq!(fs::read(td.0.join("ark/gyan/explicit.txt")).unwrap(), b"via address");
    }

    #[test]
    fn cmd_put_reads_from_input_file() {
        let td = TempDir::new("ark_put_test");
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [125u8; 32]).unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let input_path = td.0.join("input.bin");
        fs::write(&input_path, b"file content").unwrap();

        let account_dir = td.0.join("ark").join("gyan");
        with_cwd(&account_dir, || {
            cmd_put("uploaded.txt", Some(input_path.to_str().unwrap())).unwrap();
        });

        assert_eq!(fs::read(td.0.join("ark/gyan/uploaded.txt")).unwrap(), b"file content");
    }

    #[test]
    fn put_missing_identity_errors() {
        let td = TempDir::new("ark_put_test");
        let err = with_cwd(&td.0, || put_bytes("anything", b"x").unwrap_err());
        let msg = format!("{}", err);
        assert!(msg.contains("no .ark"), "msg was {}", msg);
    }
}
