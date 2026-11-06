use std::io;

use crate::client::request;
use crate::http::check_response_code;
use crate::metadata::{has_metadata_attributes, read_metadata_attributes, sign_metadata, write_metadata_headers};
use crate::paths::to_url;
use crate::storage::exists;
use crate::timestamp;
use crate::types::Context;
use crate::versions::{read_versions, to_version, version_path_for, write_version};

/// Delete a file or directory (recursive) at `path`. Requires the account to
/// have `writer` or `owner` permission on the target, and on everything
/// beneath it carrying members of its own. Deletes are relayed to co-members.
///
/// Like a write, the delete is made against the metadata the account last saw:
/// that of its copy of `path`, or where the copy is already gone, the newest
/// version of `path` it stored. Errors with `NotFound` where it holds neither.
/// The delete is stored as a version of `path` in the account's own store, as a
/// write is.
///
/// The local copy is left alone — the account root is the working tree, and
/// what is in it is the caller's to remove.
pub fn delete(ctx: &Context, path: &str) -> io::Result<()> {
    let mut metadata = if exists(ctx, path) && has_metadata_attributes(ctx, path)? {
        read_metadata_attributes(ctx, path)?
    } else if let Some(version) = read_versions(ctx, path)?.iter().find(|version| !version.deleted) {
        read_metadata_attributes(ctx, &version_path_for(ctx, path, &version.id)?)?
    } else {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no metadata of {} to delete against", path)));
    };

    let mut url = to_url(ctx, path)?;
    url.set_query(Some("relay=full"));

    metadata.parent_version = Some(to_version(&metadata));
    metadata.author = ctx.identity.address.clone();
    metadata.author_date = timestamp::now();
    metadata.deleted = true;

    sign_metadata(ctx.identity_key.as_ref().expect("client context missing identity_key"), &mut metadata, None)?;

    write_version(ctx, path, &[], &metadata)?;

    let metadata_headers = write_metadata_headers(&metadata);
    let headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();

    let (code, _, body) = request(Some(ctx), "DELETE", &url, &headers, &[])?;
    check_response_code(code, &body)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use std::env::{current_dir, set_current_dir};
    use std::thread::sleep;
    use std::time::{Duration as StdDuration, Instant};

    use super::*;

    use crate::client::{init, put};
    use crate::context::create_client_context;
    use crate::metadata::read_metadata_headers;
    use crate::testing::fs::{account_context, in_test_dir, init_with_server, write_plain_test_file};
    use crate::testing::http::start_test_server;
    use crate::types::Permissions;
    use crate::util::parse_request_entry;

    #[test]
    fn delete_removes_file() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            fs::write(temp_dir.join("x.txt"), b"bye").unwrap();
            put(&ctx, "x.txt", &Permissions::default(), Some("none"), false).unwrap();

            delete(&ctx, "x.txt").unwrap();

            assert!(!temp_dir.join("ark/gyan/x.txt").exists());
        });
    }

    #[test]
    fn delete_is_kept_as_a_version_by_the_client_and_the_server_alike() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            fs::write(temp_dir.join("x.txt"), b"bye").unwrap();
            put(&ctx, "x.txt", &Permissions::default(), Some("none"), false).unwrap();
            let written_version = to_version(&read_metadata_attributes(&ctx, "x.txt").unwrap());

            delete(&ctx, "x.txt").unwrap();

            let stored = read_versions(&ctx, "x.txt").unwrap();
            assert_eq!(stored.len(), 2);
            assert!(stored[0].deleted);
            let (server_ctx, server_path) = account_context(&temp_dir.join("ark/gyan/x.txt"));
            assert_eq!(read_versions(&server_ctx, &server_path).unwrap()[0].id, stored[0].id, "both name the delete the same");

            // Sent again, it is made against the write, not the delete.
            fs::remove_file(temp_dir.join("x.txt")).unwrap();
            let err = delete(&ctx, "x.txt").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound, "the server holds nothing to delete");
            let delete_metadata = read_metadata_attributes(&ctx, &version_path_for(&ctx, "x.txt", &read_versions(&ctx, "x.txt").unwrap()[0].id).unwrap()).unwrap();
            assert_eq!(delete_metadata.parent_version, Some(written_version));
        });
    }

    #[test]
    fn delete_removes_directory_recursively() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            fs::create_dir_all(temp_dir.join("sub")).unwrap();
            put(&ctx, "sub/", &Permissions::default(), None, false).unwrap();
            fs::write(temp_dir.join("sub/inner"), b"data").unwrap();
            put(&ctx, "sub/inner", &Permissions::default(), Some("none"), false).unwrap();

            delete(&ctx, "sub").unwrap();

            assert!(!temp_dir.join("ark/gyan/sub").exists());
        });
    }

    #[test]
    fn delete_of_what_the_account_never_held_errors() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let f = temp_dir.join("ark/gyan/x.txt");
            write_plain_test_file(&f, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"unseen");

            let err = delete(&ctx, "x.txt").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound, "msg was {}", err);
            assert!(f.exists());
        });
    }

    #[test]
    fn delete_of_a_copy_already_removed_is_made_against_the_version_kept() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let client_dir = temp_dir.join("client");
            fs::create_dir_all(&client_dir).unwrap();
            set_current_dir(&client_dir).unwrap();
            init(&current_dir().unwrap(), &format!("gyan@127.0.0.1:{}", port), None, false).unwrap();
            let ctx = create_client_context().unwrap();

            fs::write(client_dir.join("x.txt"), b"bye").unwrap();
            put(&ctx, "x.txt", &Permissions::default(), Some("none"), false).unwrap();
            let seen_version = to_version(&read_metadata_attributes(&ctx, "x.txt").unwrap());
            fs::remove_file(client_dir.join("x.txt")).unwrap();

            delete(&ctx, "x.txt").unwrap();

            assert!(!temp_dir.join("ark/gyan/x.txt").exists());
            // The server logs a request once it has answered it.
            let deadline = Instant::now() + StdDuration::from_secs(5);
            let log_entry = loop {
                let found = fs::read_dir(temp_dir.join("ark/gyan/.ark/requests")).unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| path.file_name().unwrap().to_string_lossy().starts_with("DELETE_204"));
                if let Some(path) = found { break path; }
                assert!(Instant::now() < deadline, "the delete was never logged");
                sleep(StdDuration::from_millis(20));
            };
            let entry = parse_request_entry(&fs::read(log_entry).unwrap()).unwrap();
            let delete_metadata = read_metadata_headers(&entry.request_headers).unwrap();
            assert_eq!(delete_metadata.parent_version, Some(seen_version), "made against the version the client stored");
        });
    }

    #[test]
    fn delete_via_address_form() {
        in_test_dir("ark_delete_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            fs::write(temp_dir.join("explicit.txt"), b"gone").unwrap();
            put(&ctx, "explicit.txt", &Permissions::default(), Some("none"), false).unwrap();

            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            delete(&ctx, &arg).unwrap();

            assert!(!temp_dir.join("ark/gyan/explicit.txt").exists());
        });
    }
}
