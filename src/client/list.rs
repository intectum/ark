use std::io;

use super::request;
use crate::types::{DirEntry, IdentityContext};
use crate::util::{io_err, resolve_client_url};

/// List the entries of a directory at `path`.
///
/// `path` accepts relative, absolute account, or address form. See the
/// [module documentation](../index.html) for path resolution details. The
/// server returns the JSON listing produced for directory GETs; each entry
/// carries its `name` and `kind` (dir / file / symlink). A missing directory
/// (`404`) is treated as an empty listing.
pub fn list(ctx: &IdentityContext, path: &str) -> io::Result<Vec<DirEntry>> {
    let url = resolve_client_url(ctx, path)?;

    let (code, _, body) = request(Some(ctx), "GET", &url, &[], &[])?;
    if code == 404 {
        return Ok(Vec::new());
    }
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    serde_json::from_slice(&body)
        .map_err(|e| io_err(&format!("dir listing: {}", e)))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::server::start_test_server;
    use crate::types::DirEntryKind;
    use crate::util::test::{in_test_dir, init_with_server, write_plain_test_file};

    #[test]
    fn list_returns_dir_entries() {
        in_test_dir("ark_list_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let dir = temp_dir.join("ark/gyan/notes");
            fs::create_dir_all(&dir).unwrap();
            write_plain_test_file(&dir.join("a.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"a");
            write_plain_test_file(&dir.join("b.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"b");

            let entries = list(&ctx, "notes").unwrap();
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"a.txt"));
            assert!(names.contains(&"b.txt"));
            assert!(entries.iter().all(|e| matches!(e.kind, DirEntryKind::File)));
        });
    }

    #[test]
    fn list_missing_dir_is_empty() {
        in_test_dir("ark_list_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let entries = list(&ctx, "nope").unwrap();
            assert!(entries.is_empty());
        });
    }
}
