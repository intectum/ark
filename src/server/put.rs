use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;

use crate::identity::{resolve_identity, validate_identity};
use crate::metadata::{read_metadata_headers, verify_metadata, write_metadata_attributes};
use crate::types::{Identity, IdentityContext, Member, Permission};

use super::write_status;

pub fn serve_put_init(
    server_ctx: &IdentityContext,
    stream: &mut TcpStream,
    headers: &Vec<(String, String)>,
    body: &[u8],
    target_path: &Path,
) -> std::io::Result<()> {
    let body_identity: Identity = match serde_json::from_slice(body) {
        Ok(i) => i,
        Err(e) => return write_status(stream, 400, "Bad Request", format!("identity json: {}", e).as_bytes()),
    };

    if let Err(e) = validate_identity(&body_identity) {
        return write_status(stream, 400, "Bad Request", e.to_string().as_bytes());
    }

    serve_put(server_ctx, target_path, stream, body, headers, None, Permission::Owner, false, Some(&body_identity))
}

pub fn serve_put(server_ctx: &IdentityContext, fs_path: &Path, stream: &mut TcpStream, body: &[u8], headers: &[(String, String)], existing_members: Option<Vec<Member>>, permission: Permission, target_is_dir: bool, modifier_identity_override: Option<&Identity>) -> std::io::Result<()> {
    let metadata = match read_metadata_headers(headers) {
        Ok(m) => m,
        Err(e) => return write_status(stream, 400, "Bad Request", e.to_string().as_bytes()),
    };

    if target_is_dir {
        if !body.is_empty() {
            return write_status(stream, 400, "Bad Request", b"dir put must have empty body");
        }
        if metadata.encryption_algorithm.is_some() {
            return write_status(stream, 400, "Bad Request", b"dir metadata must not set encryption_algorithm");
        }
    }

    let modifier_identity = match modifier_identity_override {
        Some(i) => i.clone(),
        None => match resolve_identity(server_ctx, &metadata.modified_by) {
            Ok(i) => i,
            Err(e) => return write_status(stream, 403, "Forbidden", e.to_string().as_bytes()),
        },
    };

    let verify_body = if target_is_dir { None } else { Some(body) };
    if let Err(e) = verify_metadata(&modifier_identity.public_key, &metadata, verify_body) {
        return write_status(stream, 403, "Forbidden", e.to_string().as_bytes());
    }

    if let Some(old) = existing_members.as_deref() {
        if members_changed(old, &metadata.members) && permission != Permission::Owner {
            return write_status(stream, 403, "Forbidden", b"owner permission required to change members");
        }
    }

    let (status_code, status_msg) = if fs_path.exists() { (204, "No Content") } else { (201, "Created") };

    if target_is_dir {
        fs::create_dir_all(fs_path)?;
        write_metadata_attributes(fs_path, &metadata)?;
    } else {
        if let Some(parent) = fs_path.parent() { fs::create_dir_all(parent)?; }
        let mut file = fs::File::create(fs_path)?;
        write_metadata_attributes(fs_path, &metadata)?;
        file.write_all(body)?;
        drop(file);
    }

    write_status(stream, status_code, status_msg, &[])
}

fn members_changed(old: &[Member], new: &[Member]) -> bool {
    if old.len() != new.len() { return true; }
    let mut old_set: Vec<(&str, Permission)> = old.iter().map(|m| (m.address.as_str(), m.permission)).collect();
    let mut new_set: Vec<(&str, Permission)> = new.iter().map(|m| (m.address.as_str(), m.permission)).collect();
    old_set.sort_by(|a, b| a.0.cmp(b.0));
    new_set.sort_by(|a, b| a.0.cmp(b.0));
    old_set != new_set
}

#[cfg(test)]
mod tests {
    use super::super::start_test_server;
    use super::super::test_helpers::*;
    use crate::metadata::{read_metadata_attributes, sign_metadata, write_metadata_headers};
    use crate::types::{Member, Permission};
    use crate::util::now_seconds;
    use crate::util::test::{TEST_ADDRESS, create_encrypted_test_metadata, create_plain_test_metadata, create_test_account, in_test_dir, write_plain_test_file};
    use std::fs;

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
            write_plain_test_file(&account_dir.join("x"), &identity, &secret_key, b"old");
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &identity, &secret_key, "/ark/test/x", b"new content");
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
            std::os::unix::fs::symlink(&target, account_dir.join("link")).unwrap();
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
            let ts = now_seconds();
            let signed_body = b"original";
            let sig = sign(&key, "PUT", "/ark/test/file", ts, signed_body);
            let auth = build_auth("test@example.com", ts, &sig);
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
                Some(b"aes-256-gcm".as_slice())
            );
            let loaded = read_metadata_attributes(&p).unwrap();
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

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Write, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"v2");
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: writer_identity.address.clone(), permission: Permission::Write, key: None },
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
                Member { address: reader_identity.address.clone(), permission: Permission::Read, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&reader_identity, &reader_key, b"v2");
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: reader_identity.address.clone(), permission: Permission::Read, key: None },
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

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Write, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"v2");
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: writer_identity.address.clone(), permission: Permission::Write, key: None },
                Member { address: outsider_identity.address.clone(), permission: Permission::Read, key: None },
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

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: co_owner_identity.address.clone(), permission: Permission::Owner, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());

            let mut new_meta = create_plain_test_metadata(&co_owner_identity, &co_owner_key, b"v2");
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: co_owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: newbie_identity.address.clone(), permission: Permission::Read, key: None },
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
            sign_metadata(&secret_key, &mut meta, None).unwrap();
            let code = signed_put_dir_metadata(port, &identity, &secret_key, "/ark/test/notes/", &meta);
            assert_eq!(code, 201);
            let dir = temp_dir.join("ark/test/notes");
            assert!(dir.is_dir());
            let back = crate::metadata::read_metadata_attributes(&dir).unwrap();
            assert_eq!(back.id, meta.id);
        });
    }

    #[test]
    fn put_dir_with_body_returns_400() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let mut meta = create_plain_test_metadata(&identity, &secret_key, b"nonempty");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            sign_metadata(&secret_key, &mut meta, Some(b"nonempty")).unwrap();
            let headers = write_metadata_headers(&meta);
            let extra: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let (code, _, _) = signed_request_with_headers(port, &identity, &secret_key, "PUT", "/ark/test/notes/", b"nonempty", &extra);
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
                Member { address: writer_identity.address.clone(), permission: Permission::Write, key: None },
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
                Member { address: reader_identity.address.clone(), permission: Permission::Read, key: None },
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

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Write, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let mut new_meta = create_plain_test_metadata(&writer_identity, &writer_key, b"");
            new_meta.encryption_algorithm = None;
            new_meta.members = vec![
                Member { address: owner_identity.address.clone(), permission: Permission::Owner, key: None },
                Member { address: writer_identity.address.clone(), permission: Permission::Write, key: None },
                Member { address: outsider_identity.address.clone(), permission: Permission::Read, key: None },
            ];
            sign_metadata(&writer_key, &mut new_meta, None).unwrap();
            let code = signed_put_dir_metadata(port, &writer_identity, &writer_key, "/ark/owner/shared/", &new_meta);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn put_file_in_ancestor_dir_walks_up_for_authz() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Write, key: None },
            ]);
            fs::create_dir_all(temp_dir.join("ark/owner/shared/sub")).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &writer_identity, &writer_key, "/ark/owner/shared/sub/x.txt", b"hi");
            assert_eq!(code, 201);
            assert!(temp_dir.join("ark/owner/shared/sub/x.txt").exists());
        });
    }

    #[test]
    fn put_public_file_no_auth_still_unauthorized() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Read, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = request(port, "PUT", "/ark/owner/public.txt", b"clobber", &[]);
            assert_eq!(code, 401);
            assert_eq!(fs::read(temp_dir.join("ark/owner/public.txt")).unwrap(), b"open");
        });
    }
}
