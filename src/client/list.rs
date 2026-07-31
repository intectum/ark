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
///
/// When `prefix` is `Some`, only entries whose name starts with the given
/// string are returned. Filtering happens server-side, so unmatched entries
/// never cross the wire.
pub fn list(ctx: &IdentityContext, path: &str, prefix: Option<&str>) -> io::Result<Vec<DirEntry>> {
    let mut url = resolve_client_url(ctx, path)?;
    if let Some(p) = prefix {
        url.query_pairs_mut().append_pair("prefix", p);
    }

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

    use crate::testing::fs::{in_test_dir, init_with_server, write_plain_test_file};
    use crate::testing::http::start_test_server;
    use crate::types::DirEntryKind;

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

            let entries = list(&ctx, "notes", None).unwrap();
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"a.txt"));
            assert!(names.contains(&"b.txt"));
            assert!(entries.iter().all(|e| matches!(e.kind, DirEntryKind::File)));
        });
    }

    #[test]
    fn list_prefix_filters_server_side() {
        in_test_dir("ark_list_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let dir = temp_dir.join("ark/gyan/mixed");
            fs::create_dir_all(&dir).unwrap();
            write_plain_test_file(&dir.join("PUT_403_a.http"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"a");
            write_plain_test_file(&dir.join("PUT_201_b.http"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"b");
            write_plain_test_file(&dir.join("PUT_403_c.http"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"c");

            let entries = list(&ctx, "mixed", Some("PUT_403_")).unwrap();
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names.len(), 2);
            assert!(names.contains(&"PUT_403_a.http"));
            assert!(names.contains(&"PUT_403_c.http"));
        });
    }

    #[test]
    fn list_missing_dir_is_empty() {
        in_test_dir("ark_list_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let entries = list(&ctx, "nope", None).unwrap();
            assert!(entries.is_empty());
        });
    }
}
