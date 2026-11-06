use std::io::{self, Write};
use std::path::Path;

use crate::http::{error_response_code, write_text};
use crate::identity::validate_identity;
use crate::metadata::write_metadata_attributes_atomic;
use crate::paths::parent_path;
use crate::storage::{create_dir_all, exists};
use crate::types::{Context, Identity, Metadata};
use crate::validate::validate_entry;
use crate::versions::{copy_versioned_with_metadata, create_dir_version, read_versions, write_versioned_with_metadata};

pub fn serve_put_init(
    target_root: &Path,
    target_path: &str,
    stream: &mut dyn Write,
    body: &[u8],
    metadata: &Metadata,
) -> io::Result<()> {
    let body_identity: Identity = match serde_json::from_slice(body) {
        Ok(i) => i,
        Err(e) => return write_text(stream, 400, format!("identity json: {}", e).as_bytes()),
    };

    if let Err(e) = validate_identity(&body_identity) {
        return write_text(stream, 400, e.to_string().as_bytes());
    }

    let target_ctx = Context {
        root: target_root.to_path_buf(),
        identity: body_identity.clone(),
        identity_key: None,
    };

    serve_put(&target_ctx, &target_ctx, target_path, stream, body, metadata, false)?;

    Ok(())
}

pub fn serve_put(server_ctx: &Context, ctx: &Context, path: &str, stream: &mut dyn Write, body: &[u8], metadata: &Metadata, metadata_only: bool) -> io::Result<bool> {
    let is_dir = metadata.body_hash.is_none();

    if metadata.deleted {
        write_text(stream, 400, b"delete metadata is sent with DELETE")?;
        return Ok(false);
    }

    if is_dir && !body.is_empty() {
        write_text(stream, 400, b"dir put must have empty body")?;
        return Ok(false);
    }

    let update_body = if is_dir || metadata_only { None } else { Some(body) };
    if let Err(error) = validate_entry(ctx, path, metadata, update_body, None, Some(server_ctx)) {
        write_text(stream, error_response_code(&error), error.to_string().as_bytes())?;
        return Ok(false);
    }

    let mut current = Some(path);
    while let Some(current_path) = current {
        if read_versions(ctx, current_path)?.iter().any(|version| version.deleted && metadata.author_date < version.author_date) {
            write_text(stream, 409, b"author_date is older than a delete of the path")?;
            return Ok(false);
        }

        current = parent_path(current_path);
    }

    let status_code = if exists(ctx, path) { 204 } else { 201 };

    if is_dir {
        create_dir_all(ctx, path)?;
        create_dir_version(ctx, path, metadata)?;
        write_metadata_attributes_atomic(ctx, path, metadata, None)?;
    } else if metadata_only {
        copy_versioned_with_metadata(ctx, path, path, metadata)?;
    } else {
        if let Some(parent) = parent_path(path) {
            create_dir_all(ctx, parent)?;
        }

        write_versioned_with_metadata(ctx, path, body, metadata)?;
    }

    write_text(stream, status_code, &[])?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use crate::crypto::DEFAULT_ENCRYPTION_ALGORITHM;
    use crate::metadata::{create_metadata, read_metadata_attributes, sign_metadata, write_metadata_headers};
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_delete_test_metadata, create_encrypted_test_metadata, create_plain_test_metadata, create_test_account, in_test_dir, write_plain_test_file};
    use crate::testing::http::*;
    use crate::testing::http::start_test_server;
    use time::Duration;

    use crate::storage::read;
    use crate::timestamp::now_ms;
    use crate::types::{Member, Permission};
    use crate::versions::{read_versions, to_version, version_path_for};

    #[test]
    fn put_new_file_returns_201() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &identity, &secret_key, "/ark/test/new.txt", b"payload");
            assert_eq!(code, 201);
            assert_eq!(fs::read(temp_dir.join("ark/test/new.txt")).unwrap(), b"payload");
        });
    }

    #[test]
    fn put_overwrite_returns_204() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x");
            write_plain_test_file(&file, &identity, &secret_key, b"old");
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            let mut new_meta = create_plain_test_metadata(&identity, &secret_key, b"new content");
            new_meta.id = existing.id;
            new_meta.parent_version = Some(to_version(&existing));
            sign_metadata(&secret_key, &mut new_meta, Some(b"new content")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"new content", &new_meta);
            assert_eq!(code, 204);
            assert_eq!(fs::read(temp_dir.join("ark/test/x")).unwrap(), b"new content");
        });
    }

    #[test]
    fn put_of_delete_metadata_returns_400() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let mut metadata = create_plain_test_metadata(&identity, &secret_key, b"payload");
            metadata.deleted = true;
            sign_metadata(&secret_key, &mut metadata, Some(b"payload")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/new.txt", b"payload", &metadata);
            assert_eq!(code, 400);
            assert!(!temp_dir.join("ark/test/new.txt").exists());
        });
    }

    #[test]
    fn put_older_than_a_delete_of_the_path_409_and_newer_201() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x");
            write_plain_test_file(&file, &identity, &secret_key, b"old");
            let port = start_test_server(temp_dir.to_path_buf());
            let delete_metadata = create_delete_test_metadata(&file, &identity, &secret_key);
            assert_eq!(signed_delete_metadata(port, &identity, &secret_key, "/ark/test/x", &delete_metadata), 204);

            let mut late = create_plain_test_metadata(&identity, &secret_key, b"late");
            late.author_date = delete_metadata.author_date - Duration::seconds(1);
            sign_metadata(&secret_key, &mut late, Some(b"late")).unwrap();
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"late", &late);
            assert_eq!(code, 409, "a write that lost to the delete does not bring the path back");
            assert!(!file.exists());

            let recreated = create_plain_test_metadata(&identity, &secret_key, b"recreated");
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"recreated", &recreated);
            assert_eq!(code, 201, "a file of its own, newer than the delete");
        });
    }

    #[test]
    fn put_older_than_a_delete_of_a_directory_above_409() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            seed_shared_dir(temp_dir, &identity, &secret_key, "ark/test/notes", vec![]);
            let port = start_test_server(temp_dir.to_path_buf());
            let delete_metadata = create_delete_test_metadata(&account_dir.join("notes"), &identity, &secret_key);
            assert_eq!(signed_delete_metadata(port, &identity, &secret_key, "/ark/test/notes", &delete_metadata), 204);

            let mut late = create_plain_test_metadata(&identity, &secret_key, b"late");
            late.author_date = delete_metadata.author_date - Duration::seconds(1);
            sign_metadata(&secret_key, &mut late, Some(b"late")).unwrap();
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/notes/a.txt", b"late", &late);
            assert_eq!(code, 409);
            assert!(!account_dir.join("notes").exists());
        });
    }

    #[test]
    fn put_nested_path_creates_dirs() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &identity, &secret_key, "/ark/test/a/b/c.txt", b"deep");
            assert_eq!(code, 201);
            assert_eq!(fs::read(temp_dir.join("ark/test/a/b/c.txt")).unwrap(), b"deep");
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_put_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            write_plain_test_file(&target, &identity, &secret_key, b"original");
            symlink(&target, account_dir.join("link")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &identity, &secret_key, "/ark/test/link", b"clobber");
            assert_eq!(code, 403);
            assert_eq!(fs::read(&target).unwrap(), b"original");
        });
    }

    #[test]
    fn put_at_ark_root_405() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "PUT", "/ark/test", b"x");
            assert_eq!(code, 405);
        });
    }

    #[test]
    fn put_outside_ark_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = request(port, "PUT", "/oops.txt", b"x", &[]);
            assert_eq!(code, 403);
            assert!(!temp_dir.join("oops.txt").exists());
        });
    }

    #[test]
    fn put_signature_covers_body() {
        in_test_dir("ark_server_test", |temp_dir| {
            let key = [22u8; 32];
            create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let ts = now_ms();
            let signed_body = b"original";
            let sig = sign_request(&key, port, "PUT", "/ark/test/file", ts, signed_body);
            let auth = format_authorization_header("test@example.com", ts, &sig);
            let (code, _, _) = request(port, "PUT", "/ark/test/file", b"tampered", &[("Authorization", &auth)]);
            assert_eq!(code, 401);
            assert!(!temp_dir.join("ark/test/file").exists());
        });
    }

    #[test]
    fn put_stores_metadata_headers_as_xattr() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (m, ciphertext) = create_encrypted_test_metadata(&identity, &secret_key, b"plaintext");
            let sent_key = m.members[0].key.as_ref().unwrap().value.clone();
            let headers = write_metadata_headers(&m);
            let extra: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let (code, _, _) = signed_request_with_headers(port, &identity, &secret_key, "PUT", "/ark/test/secret", &ciphertext, &extra);
            assert_eq!(code, 201);
            let p = temp_dir.join("ark/test/secret");
            assert_eq!(
                xattr::get(&p, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(DEFAULT_ENCRYPTION_ALGORITHM.as_bytes())
            );
            let (account_ctx, account_path) = account_context(&p);
            let loaded = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            assert_eq!(loaded.members.len(), 1);
            assert_eq!(loaded.members[0].address, identity.address);
            assert_eq!(loaded.members[0].key.as_ref().unwrap().value, sent_key);
        });
    }

    #[test]
    fn put_ignores_unknown_meta_headers() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let meta = write_metadata_headers(&create_plain_test_metadata(&identity, &secret_key, b"x"));
            let mut extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            extra.push(("X-Ark-Meta-Foo", "bar"));
            let (code, _, _) = signed_request_with_headers(port, &identity, &secret_key, "PUT", "/ark/test/file", b"x", &extra);
            assert_eq!(code, 201);
            let p = temp_dir.join("ark/test/file");
            assert_eq!(xattr::get(&p, "user.ark.foo").unwrap(), None);
        });
    }

    #[test]
    fn put_without_meta_headers_returns_400() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "PUT", "/ark/test/plain", b"data");
            assert_eq!(code, 400);
            assert!(!temp_dir.join("ark/test/plain").exists());
        });
    }

    #[test]
    fn put_ignores_non_meta_custom_headers() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let meta = write_metadata_headers(&create_plain_test_metadata(&identity, &secret_key, b"x"));
            let mut extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            extra.push(("X-Custom-Foo", "bar"));
            let (code, _, _) = signed_request_with_headers(port, &identity, &secret_key, "PUT", "/ark/test/file", b"x", &extra);
            assert_eq!(code, 201);
            let p = temp_dir.join("ark/test/file");
            assert_eq!(xattr::get(&p, "user.ark.foo").unwrap(), None);
        });
    }

    #[test]
    fn put_by_write_member_updates_body() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"v2");
            new_meta.id = existing.id;
            new_meta.parent_version = Some(to_version(&existing));
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ];
            sign_metadata(&writer_key, &mut new_meta, Some(b"v2")).unwrap();

            let code = signed_put_metadata(port, &writer_identity, &writer_key, "/ark/owner/file.txt", b"v2", &new_meta);
            assert_eq!(code, 204);
            assert_eq!(fs::read(temp_dir.join("ark/owner/file.txt")).unwrap(), b"v2");
        });
    }

    #[test]
    fn put_by_write_member_of_a_change_authored_by_an_outsider_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");
            let (outsider_identity, outsider_key, _) = create_test_account(temp_dir, "outsider@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&outsider_identity, &outsider_key, b"v2");
            new_meta.id = existing.id;
            new_meta.parent_version = Some(to_version(&existing));
            new_meta.encryption_algorithm = None;
            new_meta.members = existing.members.clone();
            sign_metadata(&outsider_key, &mut new_meta, Some(b"v2")).unwrap();

            // The writer may write, but the change is the outsider's, who may
            // not.
            let code = signed_put_metadata(port, &writer_identity, &writer_key, "/ark/owner/file.txt", b"v2", &new_meta);
            assert_eq!(code, 403);
            assert_eq!(fs::read(temp_dir.join("ark/owner/file.txt")).unwrap(), b"v1");
        });
    }

    #[test]
    fn put_by_read_only_member_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&reader_identity, &reader_key, b"v2");
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ];
            sign_metadata(&reader_key, &mut new_meta, Some(b"v2")).unwrap();

            let code = signed_put_metadata(port, &reader_identity, &reader_key, "/ark/owner/file.txt", b"v2", &new_meta);
            assert_eq!(code, 403);
            assert_eq!(fs::read(temp_dir.join("ark/owner/file.txt")).unwrap(), b"v1");
        });
    }

    #[test]
    fn put_by_non_member_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (stranger_identity, stranger_key, _) = create_test_account(temp_dir, "stranger@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![]);

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&stranger_identity, &stranger_key, b"v2");
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
            ];
            sign_metadata(&stranger_key, &mut new_meta, Some(b"v2")).unwrap();

            let code = signed_put_metadata(port, &stranger_identity, &stranger_key, "/ark/owner/file.txt", b"v2", &new_meta);
            assert_eq!(code, 403);
            assert_eq!(fs::read(temp_dir.join("ark/owner/file.txt")).unwrap(), b"v1");
        });
    }

    #[test]
    fn put_member_change_by_write_member_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");
            let (outsider_identity, _, _) = create_test_account(temp_dir, "outsider@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"v2");
            new_meta.id = existing.id;
            new_meta.parent_version = Some(to_version(&existing));
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
                Member { address: outsider_identity.address.clone(), permission: Permission::Reader, key: None },
            ];
            sign_metadata(&writer_key, &mut new_meta, Some(b"v2")).unwrap();

            let code = signed_put_metadata(port, &writer_identity, &writer_key, "/ark/owner/file.txt", b"v2", &new_meta);
            assert_eq!(code, 403);
            assert_eq!(fs::read(temp_dir.join("ark/owner/file.txt")).unwrap(), b"v1");
        });
    }

    #[test]
    fn put_member_change_by_owner_member_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (co_owner_identity, co_owner_key, _) = create_test_account(temp_dir, "coowner@example.com");
            let (newbie_identity, _, _) = create_test_account(temp_dir, "newbie@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: co_owner_identity.address.clone(), permission: Permission::Owner, key: None },
            ]);
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&co_owner_identity, &co_owner_key, b"v2");
            new_meta.id = existing.id;
            new_meta.parent_version = Some(to_version(&existing));
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: co_owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: newbie_identity.address.clone(), permission: Permission::Reader, key: None },
            ];
            sign_metadata(&co_owner_key, &mut new_meta, Some(b"v2")).unwrap();

            let code = signed_put_metadata(port, &co_owner_identity, &co_owner_key, "/ark/owner/file.txt", b"v2", &new_meta);
            assert_eq!(code, 204);
            assert_eq!(fs::read(temp_dir.join("ark/owner/file.txt")).unwrap(), b"v2");
        });
    }

    #[test]
    fn put_dir_writes_metadata_xattr() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let mut meta = create_plain_test_metadata(&identity, &secret_key, b"");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            meta.body_hash = None;
            sign_metadata(&secret_key, &mut meta, None).unwrap();
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/notes/", b"", &meta);
            assert_eq!(code, 201);
            let dir = temp_dir.join("ark/test/notes");
            assert!(dir.is_dir());
            let (account_ctx, account_path) = account_context(&dir);
            let back = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            assert_eq!(back.id, meta.id);
        });
    }

    #[test]
    fn every_put_is_kept_as_a_version() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());

            let old_meta = create_plain_test_metadata(&identity, &secret_key, b"old");
            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"old", &old_meta), 201);

            let mut new_meta = create_plain_test_metadata(&identity, &secret_key, b"new");
            new_meta.id = old_meta.id;
            new_meta.parent_version = Some(to_version(&old_meta));
            new_meta.author_date = old_meta.author_date + Duration::milliseconds(1);
            sign_metadata(&secret_key, &mut new_meta, Some(b"new")).unwrap();
            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"new", &new_meta), 204);

            let file = account_dir.join("x");
            assert_eq!(fs::read(&file).unwrap(), b"new");

            let (account_ctx, account_path) = account_context(&file);
            let versions = read_versions(&account_ctx, &account_path).unwrap();
            assert_eq!(versions.len(), 2);
            assert_eq!(versions[0].id, to_version(&new_meta), "what the path holds now is a version too");
            assert_eq!(versions[1].id, to_version(&old_meta));

            let stored = version_path_for(&account_ctx, &account_path, &versions[1].id).unwrap();
            assert_eq!(read(&account_ctx, &stored).unwrap(), b"old");
        });
    }

    #[test]
    fn a_metadata_only_put_is_kept_as_a_version() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());

            let old_meta = create_plain_test_metadata(&identity, &secret_key, b"body");
            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"body", &old_meta), 201);

            let mut new_meta = create_plain_test_metadata(&identity, &secret_key, b"body");
            new_meta.id = old_meta.id;
            new_meta.parent_version = Some(to_version(&old_meta));
            new_meta.author_date = old_meta.author_date + Duration::milliseconds(1);
            new_meta.members.push(Member { address: "other@example.com".to_string(), permission: Permission::Reader, key: None });
            sign_metadata(&secret_key, &mut new_meta, Some(b"body")).unwrap();
            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/x?metadata", b"", &new_meta), 204);

            let (account_ctx, account_path) = account_context(&account_dir.join("x"));
            let versions = read_versions(&account_ctx, &account_path).unwrap();
            assert_eq!(versions.len(), 2);
            assert_eq!(versions[0].id, to_version(&new_meta));

            let stored = version_path_for(&account_ctx, &account_path, &versions[1].id).unwrap();
            let stored_metadata = read_metadata_attributes(&account_ctx, &stored).unwrap();
            assert_eq!(stored_metadata.members.len(), 1, "the version carries the member list it was written with");
            assert_eq!(read(&account_ctx, &stored).unwrap(), b"body");
        });
    }

    #[test]
    fn every_directory_put_is_kept_as_a_version() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());

            let mut meta = create_plain_test_metadata(&identity, &secret_key, b"");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            meta.body_hash = None;
            sign_metadata(&secret_key, &mut meta, None).unwrap();
            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/notes/", b"", &meta), 201);

            let mut second = meta.clone();
            second.parent_version = Some(to_version(&meta));
            second.author_date = meta.author_date + Duration::milliseconds(1);
            second.members.push(Member { address: "other@example.com".to_string(), permission: Permission::Reader, key: None });
            sign_metadata(&secret_key, &mut second, None).unwrap();
            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/notes/", b"", &second), 204);

            let (account_ctx, account_path) = account_context(&temp_dir.join("ark/test/notes"));
            let versions = read_versions(&account_ctx, &account_path).unwrap();
            assert_eq!(versions.len(), 2);
            assert_eq!(versions[0].id, to_version(&second));
            assert_eq!(versions[1].id, to_version(&meta));
        });
    }

    #[test]
    fn a_write_not_made_on_what_the_path_holds_409() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x");
            write_plain_test_file(&file, &identity, &secret_key, b"old");
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            // A parent naming a version this server never held.
            let mut forked = create_plain_test_metadata(&identity, &secret_key, b"forked");
            forked.id = existing.id;
            forked.parent_version = Some("2020-01-01T00-00-00.000Z_AAAAAAAA".to_string());
            sign_metadata(&secret_key, &mut forked, Some(b"forked")).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"forked", &forked), 409);
            assert_eq!(fs::read(&file).unwrap(), b"old");
        });
    }

    #[test]
    fn a_second_write_made_on_the_same_version_409() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x");
            write_plain_test_file(&file, &identity, &secret_key, b"v1");
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());

            let made_on_v1 = |body: &[u8], offset: i64| {
                let mut metadata = create_plain_test_metadata(&identity, &secret_key, body);
                metadata.id = existing.id;
                metadata.parent_version = Some(to_version(&existing));
                metadata.author_date = existing.author_date + Duration::seconds(offset);
                sign_metadata(&secret_key, &mut metadata, Some(body)).unwrap();
                metadata
            };

            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"first", &made_on_v1(b"first", 1)), 204);
            assert_eq!(signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"second", &made_on_v1(b"second", 2)), 409);
            assert_eq!(fs::read(&file).unwrap(), b"first");
        });
    }

    #[test]
    fn a_member_removed_since_cannot_write_on_a_version_from_before() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            let (account_ctx, account_path) = account_context(&file);
            let v1 = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());

            // The owner removes the writer.
            let mut v2 = v1.clone();
            v2.parent_version = Some(to_version(&v1));
            v2.author_date = v1.author_date + Duration::seconds(1);
            v2.members.retain(|member| member.address != writer_identity.address);
            sign_metadata(&owner_key, &mut v2, Some(b"v1")).unwrap();
            assert_eq!(signed_put_metadata(port, &owner_identity, &owner_key, "/ark/owner/file.txt", b"v1", &v2), 204);

            // The writer writes on v1, which still let them.
            let mut forked = create_plain_test_metadata(&writer_identity, &writer_key, b"late");
            forked.id = v1.id;
            forked.parent_version = Some(to_version(&v1));
            forked.encryption_algorithm = None;
            forked.members = v1.members.clone();
            forked.author_date = v2.author_date + Duration::seconds(1);
            sign_metadata(&writer_key, &mut forked, Some(b"late")).unwrap();
            let code = signed_put_metadata(port, &writer_identity, &writer_key, "/ark/owner/file.txt", b"late", &forked);
            assert_ne!(code, 204);
            assert_eq!(fs::read(&file).unwrap(), b"v1");
        });
    }

    #[test]
    fn put_dir_with_body_returns_400() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let mut meta = create_plain_test_metadata(&identity, &secret_key, b"");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            meta.body_hash = None;
            sign_metadata(&secret_key, &mut meta, None).unwrap();
            let headers = write_metadata_headers(&meta);
            let extra: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let (code, _, _) = signed_request_with_headers(port, &identity, &secret_key, "PUT", "/ark/test/notes", b"nonempty", &extra);
            assert_eq!(code, 400);
            assert!(!temp_dir.join("ark/test/notes").exists());
        });
    }

    #[test]
    fn put_file_by_dir_write_member_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &writer_identity, &writer_key, "/ark/owner/shared/new.txt", b"hi");
            assert_eq!(code, 201);
            assert!(temp_dir.join("ark/owner/shared/new.txt").exists());
        });
    }

    #[test]
    fn put_file_by_dir_read_member_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &reader_identity, &reader_key, "/ark/owner/shared/new.txt", b"hi");
            assert_eq!(code, 403);
            assert!(!temp_dir.join("ark/owner/shared/new.txt").exists());
        });
    }

    #[test]
    fn put_file_in_bare_dir_by_non_owner_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (stranger_identity, stranger_key, _) = create_test_account(temp_dir, "stranger@example.com");

            let bare_dir = temp_dir.join("ark/owner/bare");
            fs::create_dir_all(&bare_dir).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &stranger_identity, &stranger_key, "/ark/owner/bare/x.txt", b"hi");
            assert_eq!(code, 403);
            assert!(!bare_dir.join("x.txt").exists());

            let (code2, _, _) = signed_put_with_default_metadata(port, &owner_identity, &owner_key, "/ark/owner/bare/x.txt", b"hi");
            assert_eq!(code2, 201);
        });
    }

    #[test]
    fn put_dir_member_change_by_non_owner_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");
            let (outsider_identity, _, _) = create_test_account(temp_dir, "outsider@example.com");

            let dir = seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            let (account_ctx, account_path) = account_context(&dir);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"");
            new_meta.id = existing.id;
            new_meta.parent_version = Some(to_version(&existing));
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
                Member { address: outsider_identity.address.clone(), permission: Permission::Reader, key: None },
            ];
            sign_metadata(&writer_key, &mut new_meta, None).unwrap();
            let code = signed_put_metadata(port, &writer_identity, &writer_key, "/ark/owner/shared/", b"", &new_meta);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn put_file_in_ancestor_dir_walks_up_for_authz() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            fs::create_dir_all(temp_dir.join("ark/owner/shared/sub")).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &writer_identity, &writer_key, "/ark/owner/shared/sub/x.txt", b"hi");
            assert_eq!(code, 201);
            assert!(temp_dir.join("ark/owner/shared/sub/x.txt").exists());
        });
    }

    #[test]
    fn put_metadata_only_preserves_body_and_rewrites_xattrs() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x");
            write_plain_test_file(&file, &identity, &secret_key, b"body");
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            let mut new_meta = create_plain_test_metadata(&identity, &secret_key, b"body");
            new_meta.id = existing.id;
            new_meta.parent_version = Some(to_version(&existing));
            sign_metadata(&secret_key, &mut new_meta, Some(b"body")).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/x?metadata", b"", &new_meta);
            assert_eq!(code, 204);
            assert_eq!(fs::read(temp_dir.join("ark/test/x")).unwrap(), b"body");
            let after = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            assert_eq!(after.author_date, new_meta.author_date);
        });
    }

    #[test]
    fn put_metadata_only_rejects_body_hash_change() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x");
            write_plain_test_file(&file, &identity, &secret_key, b"body");
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            let mut new_meta = create_plain_test_metadata(&identity, &secret_key, b"different");
            new_meta.id = existing.id;
            sign_metadata(&secret_key, &mut new_meta, Some(b"different")).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/x?metadata", b"", &new_meta);
            assert_eq!(code, 400);
            assert_eq!(fs::read(temp_dir.join("ark/test/x")).unwrap(), b"body");
        });
    }

    #[test]
    fn put_dir_with_encryption_algorithm_returns_400() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);

            let mut dir_meta = create_metadata(&identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            dir_meta.members[0].key = None;
            sign_metadata(&secret_key, &mut dir_meta, None).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/shared", b"", &dir_meta);
            assert_eq!(code, 400);
            assert!(!temp_dir.join("ark/test/shared").exists());
        });
    }

    #[test]
    fn put_dir_over_existing_file_returns_409() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x");
            write_plain_test_file(&file, &identity, &secret_key, b"body");
            let (account_ctx, account_path) = account_context(&file);
            let existing_id = read_metadata_attributes(&account_ctx, &account_path).unwrap().id;

            let mut dir_meta = create_metadata(&identity.address, None);
            dir_meta.id = existing_id;
            dir_meta.members[0].key = None;
            sign_metadata(&secret_key, &mut dir_meta, None).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"", &dir_meta);
            assert_eq!(code, 409);
            assert_eq!(fs::read(temp_dir.join("ark/test/x")).unwrap(), b"body");
        });
    }

    #[test]
    fn put_metadata_only_on_nonexistent_returns_404() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let meta = create_plain_test_metadata(&identity, &secret_key, b"body");
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/missing?metadata", b"", &meta);
            assert_eq!(code, 404);
        });
    }

    #[test]
    fn put_public_file_no_auth_still_unauthorized() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = request(port, "PUT", "/ark/owner/public.txt", b"clobber", &[]);
            assert_eq!(code, 401);
            assert_eq!(fs::read(temp_dir.join("ark/owner/public.txt")).unwrap(), b"open");
        });
    }
}
