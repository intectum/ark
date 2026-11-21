use std::io::{self, Write};
use std::path::Path;

use super::auth::authorize;

use crate::http::{write_response, write_text};
use crate::metadata::{read_metadata_attributes, write_metadata_headers};
use crate::paths::file_name;
use crate::storage::{exists, is_dir, is_symlink, read, read_dir, size};
use crate::types::{Context, DirEntry, DirEntryKind, Identity};

// A directory listing holds only the entries `requestor_identity` may read,
// with their metadata, or every entry of a directory of versions, which
// answers to the path it is the history of as a whole.
pub fn serve_get(server_ctx: &Context, ctx: &Context, path: &str, stream: &mut dyn Write, send_body: bool, prefix: Option<&str>, requestor_identity: Option<&Identity>, lists_versions: bool) -> io::Result<()> {
    if !exists(ctx, path) {
        return write_text(stream, 404, b"not found");
    }

    if is_dir(ctx, path) {
        let body = list_dir(server_ctx, ctx, path, prefix, requestor_identity, lists_versions)?;
        let content_length = body.len().to_string();
        let metadata_headers = read_metadata_attributes(ctx, path).ok()
            .map(|m| write_metadata_headers(&m))
            .unwrap_or_default();
        let mut headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        headers.push(("Content-Type", "application/json"));
        headers.push(("Content-Length", content_length.as_str()));
        headers.push(("Connection", "close"));
        return write_response(stream, 200, &headers, if send_body { body.as_bytes() } else { &[] });
    }

    let metadata = match read_metadata_attributes(ctx, path) {
        Ok(m) => m,
        Err(e) => return write_text(stream, 500, e.to_string().as_bytes()),
    };

    let metadata_headers = write_metadata_headers(&metadata);
    let content_length = size(ctx, path)?.to_string();
    let mut headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    headers.push(("Content-Type", content_type(path)));
    headers.push(("Content-Length", &content_length));
    headers.push(("Connection", "close"));

    write_response(stream, 200, &headers, &[])?;
    if send_body {
        stream.write_all(&read(ctx, path)?)?;
    }

    Ok(())
}

fn list_dir(server_ctx: &Context, ctx: &Context, path: &str, prefix: Option<&str>, requestor_identity: Option<&Identity>, lists_versions: bool) -> io::Result<String> {
    let mut items = Vec::new();
    for entry in read_dir(ctx, path)? {
        let name = file_name(&entry);
        if prefix.is_some_and(|prefix| !name.starts_with(prefix)) { continue; }
        if lists_versions && name.starts_with('.') { continue; }
        if is_symlink(ctx, &entry) { continue; }

        let is_dir = is_dir(ctx, &entry);

        let metadata = match read_metadata_attributes(ctx, &entry) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound && is_dir => None,
            Err(_) => continue,
        };

        let visible = match (&metadata, requestor_identity) {
            (None, _) => true,
            _ if lists_versions => true,
            (Some(metadata), Some(identity)) => authorize(server_ctx, ctx, identity, None, Some(&metadata.members)).is_ok(),
            (Some(metadata), None) => metadata.members.iter().any(|member| member.address == "*"),
        };

        if !visible { continue; }

        let kind = if is_dir { DirEntryKind::Dir } else { DirEntryKind::File };
        items.push(DirEntry { kind, name: name.to_string(), metadata });
    }

    serde_json::to_string(&items).map_err(|e| io::Error::other(e.to_string()))
}

fn content_type(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" | "md" => "text/plain; charset=utf-8",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use crate::crypto::DEFAULT_ENCRYPTION_ALGORITHM;
    use crate::metadata::read_metadata_attributes;
    use crate::paths::{join_path, to_path_segment, version_dir_for};
    use crate::storage::write_atomic_without_metadata;
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_test_account, in_test_dir, write_encrypted_test_file, write_plain_test_file};
    use crate::testing::http::*;
    use crate::testing::http::start_test_server;
    use crate::types::{DirEntry, DirEntryKind, Identity, Key, Member, Metadata, Permission};
    use crate::versions::{copy_versioned_with_metadata, to_version};

    #[test]
    fn get_file_returns_content() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            write_plain_test_file(&account_dir.join("hello.txt"), &identity, &secret_key, b"hi there");
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/hello.txt", &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"hi there");
            assert_eq!(header(&headers, "content-length"), Some("8"));
        });
    }

    #[test]
    fn get_missing_file_404() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/nope.txt", &[]);
            assert_eq!(code, 404);
        });
    }

    #[test]
    fn get_dir_returns_json_listing() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            write_plain_test_file(&account_dir.join("a.txt"), &identity, &secret_key, b"hello");
            fs::create_dir(account_dir.join("sub")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "content-type"), Some("application/json"));

            let entries: Vec<DirEntry> = serde_json::from_slice(&body).unwrap();
            let file = entries.iter().find(|e| e.name == "a.txt").unwrap();
            assert!(matches!(file.kind, DirEntryKind::File));
            let dir = entries.iter().find(|e| e.name == "sub").unwrap();
            assert!(matches!(dir.kind, DirEntryKind::Dir));
        });
    }

    #[test]
    fn get_dir_lists_only_entries_the_requester_may_read() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);
            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/shared/open.txt", b"open", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);
            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/shared/private.txt", b"private", vec![]);
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, body, _) = signed_request(port, &reader_identity, &reader_key, "GET", "/ark/owner/shared/", &[]);
            assert_eq!(code, 200);
            let entries: Vec<DirEntry> = serde_json::from_slice(&body).unwrap();
            assert!(entries.iter().find(|e| e.name == "open.txt").unwrap().metadata.is_some());
            assert!(!entries.iter().any(|e| e.name == "private.txt"), "the owner's alone");

            let (_, body, _) = signed_request(port, &owner_identity, &owner_key, "GET", "/ark/owner/shared/", &[]);
            let entries: Vec<DirEntry> = serde_json::from_slice(&body).unwrap();
            assert_eq!(entries.len(), 2);
            assert!(entries.iter().all(|e| e.metadata.is_some()));
        });
    }

    #[test]
    fn get_public_dir_lists_only_public_entries_without_signing_in() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let public = || vec![Member { address: "*".to_string(), permission: Permission::Reader, key: None }];

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/site", public());
            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/site/index.html", b"hi", public());
            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/site/draft.html", b"wip", vec![]);
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, body, _) = request(port, "GET", "/ark/owner/site/", &[], &[]);
            assert_eq!(code, 200);
            let entries: Vec<DirEntry> = serde_json::from_slice(&body).unwrap();
            assert!(entries.iter().find(|e| e.name == "index.html").unwrap().metadata.is_some());
            assert!(!entries.iter().any(|e| e.name == "draft.html"));

            let (_, body, _) = signed_request(port, &owner_identity, &owner_key, "GET", "/ark/owner/site/", &[]);
            let entries: Vec<DirEntry> = serde_json::from_slice(&body).unwrap();
            assert!(entries.iter().any(|e| e.name == "draft.html"), "signed in, the owner reads it");
        });
    }

    #[test]
    fn get_public_dir_with_a_bad_signature_is_401() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/site", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = request(port, "GET", "/ark/owner/site/", &[], &[("Authorization", "bogus")]);
            assert_eq!(code, 401);
        });
    }

    #[test]
    fn get_dir_empty_returns_empty_array() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            fs::create_dir(account_dir.join("empty")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/empty/", &[]);
            assert_eq!(code, 200);
            let entries: Vec<DirEntry> = serde_json::from_slice(&body).unwrap();
            assert!(entries.is_empty());
        });
    }

    #[cfg(unix)]
    #[test]
    fn get_dir_leaves_out_symlinks() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            fs::write(&target, b"hi").unwrap();
            symlink(&target, account_dir.join("link")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/", &[]);
            assert_eq!(code, 200);
            let entries: Vec<DirEntry> = serde_json::from_slice(&body).unwrap();
            assert!(!entries.iter().any(|e| e.name == "link"));
        });
    }

    #[test]
    fn head_file_no_body_with_length() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            write_plain_test_file(&account_dir.join("x"), &identity, &secret_key, b"abcde");
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "HEAD", "/ark/test/x", &[]);
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert_eq!(header(&headers, "content-length"), Some("5"));
        });
    }

    #[test]
    fn get_dir_returns_metadata_headers_when_present() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            seed_shared_dir(temp_dir, &identity, &secret_key, "ark/test/shared", vec![
                Member { address: "friend@example.com".to_string(), permission: Permission::Writer, key: None },
            ]);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/shared/", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "x-ark-meta-member-0-address"), Some(TEST_ADDRESS));
            assert_eq!(header(&headers, "x-ark-meta-member-1-address"), Some("friend@example.com"));
        });
    }

    #[test]
    fn get_dir_no_metadata_headers_when_absent() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            fs::create_dir(account_dir.join("bare")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/bare/", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "x-ark-meta-id"), None);
        });
    }

    #[test]
    fn head_dir_no_body_with_json_type() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "HEAD", "/ark/test/", &[]);
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert_eq!(header(&headers, "content-type"), Some("application/json"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_get_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            write_plain_test_file(&target, &identity, &secret_key, b"secret");
            symlink(&target, account_dir.join("link")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/link", &[]);
            assert_eq!(code, 403);
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_head_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            write_plain_test_file(&target, &identity, &secret_key, b"secret");
            symlink(&target, account_dir.join("link")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "HEAD", "/ark/test/link", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn get_returns_metadata_headers_from_xattr() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("secret");
            write_encrypted_test_file(&file, &identity, &secret_key, b"plaintext");
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _body, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/secret", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "x-ark-meta-encryption-algorithm"), Some(DEFAULT_ENCRYPTION_ALGORITHM));
            assert_eq!(header(&headers, "x-ark-meta-member-0-address"), Some(TEST_ADDRESS));
        });
    }

    #[test]
    fn get_ignores_unknown_user_ark_xattrs() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("file");
            write_plain_test_file(&file, &identity, &secret_key, b"data");
            xattr::set(&file, "user.ark.foo", b"bar").unwrap();
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/file", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "x-ark-meta-foo"), None);
        });
    }

    #[test]
    fn get_file_without_xattr_returns_500() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            fs::write(account_dir.join("plain"), b"raw").unwrap();
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/plain", &[]);
            assert_eq!(code, 500);
        });
    }

    #[test]
    fn get_by_read_only_member_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"secret", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &reader_identity, &reader_key, "GET", "/ark/owner/file.txt", &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"secret");
        });
    }

    #[test]
    fn get_by_non_member_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (stranger_identity, stranger_key, _) = create_test_account(temp_dir, "stranger@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"secret", vec![]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &stranger_identity, &stranger_key, "GET", "/ark/owner/file.txt", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn get_public_file_no_auth_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = request(port, "GET", "/ark/owner/public.txt", &[], &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"open");
        });
    }

    #[test]
    fn head_public_file_no_auth_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = request(port, "HEAD", "/ark/owner/public.txt", &[], &[]);
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert_eq!(header(&headers, "content-length"), Some("4"));
        });
    }

    #[test]
    fn get_public_file_ignores_bad_auth() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let auth = format_authorization_header("nobody@x", 0, "AAAA");
            let (code, body, _) = request(port, "GET", "/ark/owner/public.txt", &[], &[
                ("Authorization", &auth),
            ]);
            assert_eq!(code, 200);
            assert_eq!(body, b"open");
        });
    }

    // Stores what `file` holds as a version, as the server would have had it
    // come through a put.
    fn store(file: &Path) -> Metadata {
        let (account_ctx, account_path) = account_context(file);
        let metadata = read_metadata_attributes(&account_ctx, &account_path).unwrap();
        copy_versioned_with_metadata(&account_ctx, &account_path, &account_path, &metadata).unwrap();
        metadata
    }

    // Where the versions of `path` in `account` are reached.
    fn versions_target(account: &str, path: &str) -> String {
        format!("/ark/{}/.ark/versions/{}", account, to_path_segment(path))
    }

    fn version_target(account: &str, path: &str, id: &str) -> String {
        format!("{}/{}", versions_target(account, path), id)
    }

    fn list(port: u16, identity: &Identity, secret_key: &Key, target: &str) -> Vec<DirEntry> {
        let (code, body, _) = signed_request(port, identity, secret_key, "GET", target, &[]);
        assert_eq!(code, 200);
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn a_version_answers_to_the_members_its_own_metadata_lists() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"removed", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);
            let removed = store(&file);
            fs::remove_file(&file).unwrap();

            // Written again as an entry of its own, which leaves the reader
            // out.
            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"recreated", vec![]);
            let recreated = store(&file);

            let port = start_test_server(temp_dir.to_path_buf());

            let (code, body, _) = signed_request(port, &reader_identity, &reader_key, "GET", &version_target("owner", "/file.txt", &to_version(&removed)), &[]);
            assert_eq!(code, 200, "the version's own metadata lists the reader");
            assert_eq!(body, b"removed");

            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &version_target("owner", "/file.txt", &to_version(&recreated)), &[]);
            assert_eq!(code, 403);

            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &versions_target("owner", "/file.txt"), &[]);
            assert_eq!(code, 403, "the history is listed to those the path lets read it now");

            assert_eq!(list(port, &owner_identity, &owner_key, &versions_target("owner", "/file.txt")).len(), 2);
        });
    }

    #[test]
    fn a_member_added_since_sees_the_whole_history_but_not_its_bodies() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"before", vec![]);
            let before = store(&file);
            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"after", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);
            store(&file);

            let port = start_test_server(temp_dir.to_path_buf());

            let listed = list(port, &reader_identity, &reader_key, &versions_target("owner", "/file.txt"));
            assert_eq!(listed.len(), 2);
            assert!(listed.iter().all(|entry| entry.metadata.is_some()), "the metadata is the path's to show");
            assert_eq!(listed[0].name, to_version(&before));

            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &version_target("owner", "/file.txt", &to_version(&before)), &[]);
            assert_eq!(code, 403, "the body is the version's own members' alone");
        });
    }

    #[test]
    fn a_version_can_only_be_read() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x.txt");
            write_plain_test_file(&file, &identity, &secret_key, b"kept");
            let target = version_target("test", "/x.txt", &to_version(&store(&file)));

            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &identity, &secret_key, "PUT", &target, b"over");
            assert_eq!(code, 405);
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", &target, &[]);
            assert_eq!(code, 405);
            let (code, _, _) = signed_request(port, &identity, &secret_key, "PUT", &version_target("test", "/x.txt", "planted"), b"planted");
            assert_eq!(code, 405);
            assert_eq!(list(port, &identity, &secret_key, &versions_target("test", "/x.txt")).len(), 1, "the version is untouched");
        });
    }

    #[test]
    fn a_name_set_aside_beside_the_versions_is_not_listed() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x.txt");
            write_plain_test_file(&file, &identity, &secret_key, b"kept");
            store(&file);

            let (account_ctx, _) = account_context(&file);
            write_atomic_without_metadata(&account_ctx, &join_path(&version_dir_for("/x.txt"), ".previous"), b"").unwrap();

            let port = start_test_server(temp_dir.to_path_buf());

            let listed = list(port, &identity, &secret_key, &versions_target("test", "/x.txt"));
            assert_eq!(listed.len(), 1);
            assert!(!listed[0].name.starts_with('.'));
        });
    }

    #[test]
    fn a_directory_of_versions_named_for_no_path_is_refused() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/.ark/versions/!!", &[]);
            assert_eq!(code, 400);
        });
    }

    #[test]
    fn a_public_path_shows_its_history_without_signing_in() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);
            let id = to_version(&store(&file));

            let port = start_test_server(temp_dir.to_path_buf());

            let (code, body, _) = request(port, "GET", &version_target("owner", "/public.txt", &id), &[], &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"open");

            let (code, body, _) = request(port, "GET", &versions_target("owner", "/public.txt"), &[], &[]);
            assert_eq!(code, 200);
            let listed: Vec<DirEntry> = serde_json::from_slice(&body).unwrap();
            assert_eq!(listed.len(), 1);
            assert!(listed[0].metadata.is_some());
        });
    }

    #[test]
    fn a_member_of_the_directory_above_sees_nothing_of_a_removed_path() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);
            // A file of the owner's alone, inside a directory the reader can
            // read.
            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/shared/private.txt", b"private", vec![]);
            let private = store(&file);
            fs::remove_file(&file).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &versions_target("owner", "/shared/private.txt"), &[]);
            assert_eq!(code, 403, "a removed path is read as its newest version left it");

            let target = version_target("owner", "/shared/private.txt", &to_version(&private));
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &target, &[]);
            assert_eq!(code, 403, "the version's own metadata governs it, not the directory's");
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "HEAD", &target, &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn a_version_is_listed_and_served_with_the_metadata_its_author_signed() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x.txt");
            write_plain_test_file(&file, &identity, &secret_key, b"old");
            let existing = store(&file);
            write_plain_test_file(&file, &identity, &secret_key, b"new");

            let port = start_test_server(temp_dir.to_path_buf());

            let listed = list(port, &identity, &secret_key, &versions_target("test", "/x.txt"));
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].name, to_version(&existing));
            assert_eq!(listed[0].metadata.as_ref().unwrap().id, existing.id);

            let (code, body, headers) = signed_request(port, &identity, &secret_key, "GET", &version_target("test", "/x.txt", &listed[0].name), &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"old");
            assert_eq!(header(&headers, "x-ark-meta-id"), Some(existing.id.hyphenated().to_string().as_str()));
        });
    }

    #[test]
    fn a_version_that_is_not_there_returns_404() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x.txt");
            write_plain_test_file(&file, &identity, &secret_key, b"only");
            store(&file);
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", &version_target("test", "/x.txt", "nope"), &[]);
            assert_eq!(code, 404);
        });
    }

    #[test]
    fn a_member_dropped_from_the_live_path_still_reads_the_versions_that_list_them() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            // The version is written while the reader is a member, so its own
            // metadata lists them.
            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"secret", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);
            let id = to_version(&store(&file));

            // The live path then drops them.
            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"newer", vec![]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &reader_identity, &reader_key, "GET", &version_target("owner", "/file.txt", &id), &[]);
            assert_eq!(code, 200, "the version's own metadata still lists them");
            assert_eq!(body, b"secret");

            // The live path, and so its history, is theirs no longer.
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", "/ark/owner/file.txt", &[]);
            assert_eq!(code, 403);
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &versions_target("owner", "/file.txt"), &[]);
            assert_eq!(code, 403);
        });
    }
}
