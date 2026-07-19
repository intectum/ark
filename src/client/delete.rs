use std::io;

use crate::client::request;
use crate::types::IdentityContext;
use crate::util::{io_err, resolve_client_url};

/// Delete a file or directory (recursive) at `path`. Requires the account to
/// have `write` or `owner` permission on the target.
pub fn delete(ctx: &IdentityContext, path: &str) -> io::Result<()> {
    let url = resolve_client_url(ctx, path)?;

    let (code, _, body) = request(Some(ctx), "DELETE", &url, &[], &[])?;
    if code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::server::start_test_server;
    use crate::util::test::{in_test_dir, init_with_server, write_plain_test_file};

    #[test]
    fn delete_removes_file() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let f = temp_dir.join("ark/gyan/x.txt");
            write_plain_test_file(&f, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"bye");

            delete(&ctx, "x.txt").unwrap();

            assert!(!f.exists());
        });
    }

    #[test]
    fn delete_removes_directory_recursively() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let d = temp_dir.join("ark/gyan/sub");
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("inner"), b"data").unwrap();

            delete(&ctx, "sub").unwrap();

            assert!(!d.exists());
        });
    }

    #[test]
    fn delete_missing_file_errors() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let err = delete(&ctx, "nope").unwrap_err();
            assert!(err.to_string().contains("HTTP 404"), "msg was {}", err);
        });
    }

    #[test]
    fn delete_via_address_form() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let f = temp_dir.join("ark/gyan/explicit.txt");
            write_plain_test_file(&f, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"gone");

            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            delete(&ctx, &arg).unwrap();

            assert!(!f.exists());
        });
    }
}
