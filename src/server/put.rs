use std::io::{self, Write};
use std::path::Path;

use crate::http::{error_response_code, write_text};
use crate::identity::validate_identity;
use crate::metadata::{members_changed, write_metadata_attributes};
use crate::storage::{Body, create_dir_all, exists, parent_path, write_atomic_with_metadata};
use crate::types::{Context, Identity, Metadata, Permission};
use crate::util::validate_update;

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

    serve_put(&target_ctx, target_path, stream, body, metadata, &body_identity, None, Permission::Owner, false)?;

    Ok(())
}

pub fn serve_put(ctx: &Context, path: &str, stream: &mut dyn Write, body: &[u8], metadata: &Metadata, modifier_identity: &Identity, existing_metadata: Option<&Metadata>, permission: Permission, metadata_only: bool) -> io::Result<bool> {
    let is_dir = metadata.body_hash.is_none();

    if is_dir && !body.is_empty() {
        write_text(stream, 400, b"dir put must have empty body")?;
        return Ok(false);
    }

    let update_body = if is_dir || metadata_only { None } else { Some(body) };
    if let Err(error) = validate_update(&modifier_identity.public_key, metadata, existing_metadata, update_body) {
        write_text(stream, error_response_code(&error), error.to_string().as_bytes())?;
        return Ok(false);
    }

    if let Some(old) = existing_metadata {
        if members_changed(&old.members, &metadata.members) && permission != Permission::Owner {
            write_text(stream, 403, b"owner permission required to change members")?;
            return Ok(false);
        }
    }

    let status_code = if exists(ctx, path) { 204 } else { 201 };

    if is_dir {
        create_dir_all(ctx, path)?;
        write_metadata_attributes(ctx, path, metadata, None)?;
    } else if metadata_only {
        write_atomic_with_metadata(ctx, path, Body::CopyOf(path), metadata, None)?;
    } else {
        if let Some(parent) = parent_path(path) {
            create_dir_all(ctx, parent)?;
        }

        write_atomic_with_metadata(ctx, path, Body::Bytes(body), metadata, None)?;
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
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_encrypted_test_metadata, create_plain_test_metadata, create_test_account, in_test_dir, write_plain_test_file};
    use crate::testing::http::*;
    use crate::testing::http::start_test_server;
    use crate::timestamp::now_ms;
    use crate::types::{Member, Permission};

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
            let existing_id = read_metadata_attributes(&account_ctx, &account_path).unwrap().id;
            let mut new_meta = create_plain_test_metadata(&identity, &secret_key, b"new content");
            new_meta.id = existing_id;
            sign_metadata(&secret_key, &mut new_meta, Some(b"new content")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/x", b"new content", &new_meta);
            assert_eq!(code, 204);
            assert_eq!(fs::read(temp_dir.join("ark/test/x")).unwrap(), b"new content");
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
            let (alice_identity, alice_key, _) = create_test_account(temp_dir, "alice@example.com");
            let port = start_test_server(temp_dir.to_path_buf());
            let (m, ciphertext) = create_encrypted_test_metadata(&alice_identity, &alice_key, b"plaintext");
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
            assert_eq!(loaded.members[0].address, alice_identity.address);
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
            let existing_id = read_metadata_attributes(&account_ctx, &account_path).unwrap().id;

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"v2");
            new_meta.id = existing_id;
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
            let existing_id = read_metadata_attributes(&account_ctx, &account_path).unwrap().id;

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"v2");
            new_meta.id = existing_id;
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
            let existing_id = read_metadata_attributes(&account_ctx, &account_path).unwrap().id;

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&co_owner_identity, &co_owner_key, b"v2");
            new_meta.id = existing_id;
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
            let existing_id = read_metadata_attributes(&account_ctx, &account_path).unwrap().id;

            let port = start_test_server(temp_dir.to_path_buf());
            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"");
            new_meta.id = existing_id;
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
            sign_metadata(&secret_key, &mut new_meta, Some(b"body")).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let code = signed_put_metadata(port, &identity, &secret_key, "/ark/test/x?metadata", b"", &new_meta);
            assert_eq!(code, 204);
            assert_eq!(fs::read(temp_dir.join("ark/test/x")).unwrap(), b"body");
            let after = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            assert_eq!(after.modified, new_meta.modified);
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
