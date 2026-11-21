use std::io::{self, Write};

use super::auth::authorize;

use crate::http::{error_response_code, write_text};
use crate::metadata::read_metadata_attributes;
use crate::storage::{exists, is_dir, is_symlink, read_dir, remove_dir_all, remove_file};
use crate::types::{Context, Identity, Metadata, Permission};
use crate::validation::validate_entry;
use crate::versions::{is_versioned, purge_stored_versions, write_version};

pub fn serve_delete(
    server_ctx: &Context,
    ctx: &Context,
    path: &str,
    stream: &mut dyn Write,
    metadata: &Metadata,
    requestor_identity: &Identity,
    author_identity: &Identity,
    existing_metadata: Option<&Metadata>,
) -> io::Result<bool> {
    if existing_metadata.is_none() {
        write_text(stream, 404, b"not found")?;
        return Ok(false);
    }

    if !metadata.deleted {
        write_text(stream, 400, b"a delete must carry delete metadata")?;
        return Ok(false);
    }

    if let Err(error) = validate_entry(ctx, path, metadata, None, None, Some(server_ctx)) {
        write_text(stream, error_response_code(&error), error.to_string().as_bytes())?;
        return Ok(false);
    }

    if is_dir(ctx, path) {
        let mut pending = read_dir(ctx, path)?;
        while let Some(entry) = pending.pop() {
            if is_symlink(ctx, &entry) { continue; }
            if is_dir(ctx, &entry) {
                pending.extend(read_dir(ctx, &entry)?);
            }

            let entry_metadata = match read_metadata_attributes(ctx, &entry) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    write_text(stream, 500, e.to_string().as_bytes())?;
                    return Ok(false);
                }
            };

            match authorize(server_ctx, ctx, requestor_identity, Some(author_identity), Some(&entry_metadata.members)) {
                Ok(permission) if permission != Permission::Reader => {}
                _ => {
                    write_text(stream, 403, format!("writer permission required on {}", entry).as_bytes())?;
                    return Ok(false);
                }
            }
        }
    }

    if is_versioned(ctx, path)? {
        write_version(ctx, path, &[], metadata)?;
    }

    let result = if is_dir(ctx, path) {
        remove_dir_all(ctx, path)
    } else {
        remove_file(ctx, path)
    };

    match result {
        Ok(_) => write_text(stream, 204, &[])?,
        Err(e) => {
            write_text(stream, 500, e.to_string().as_bytes())?;
            return Ok(false);
        }
    }

    Ok(true)
}

pub fn serve_purge_versions(ctx: &Context, path: &str, stream: &mut dyn Write) -> io::Result<()> {
    if exists(ctx, path) {
        return write_text(stream, 409, b"delete the path before purging its versions");
    }

    match purge_stored_versions(ctx, path) {
        Ok(_) => write_text(stream, 204, &[]),
        Err(e) => write_text(stream, 500, e.to_string().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use time::Duration;

    use crate::metadata::{read_metadata_attributes, sign_metadata};
    use crate::paths::to_path_segment;
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_delete_test_metadata, create_test_account, in_test_dir, write_plain_test_file};
    use crate::testing::http::*;
    use crate::testing::http::start_test_server;
    use crate::types::{Member, Permission};
    use crate::versions::{read_versions, to_version};

    #[test]
    fn deleting_a_path_keeps_what_it_held() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            seed_shared_dir(temp_dir, &identity, &secret_key, "ark/test/notes", vec![]);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_put_with_default_metadata(port, &identity, &secret_key, "/ark/test/notes/a.txt", b"inside");
            assert_eq!(code, 201);

            let metadata = create_delete_test_metadata(&account_dir.join("notes"), &identity, &secret_key);
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test/notes", &metadata);
            assert_eq!(code, 204);

            let (account_ctx, _) = account_context(&account_dir.join(".ark"));
            let versions = read_versions(&account_ctx, "/notes/a.txt").unwrap();
            assert_eq!(versions.len(), 1, "a path beneath a deleted directory keeps its versions too");
            assert!(!versions[0].metadata.deleted, "only the path deleted keeps the delete");

            let versions = read_versions(&account_ctx, "/notes").unwrap();
            assert!(versions[0].metadata.deleted, "the delete is the newest version of the path");
            assert_eq!(versions[0].id, to_version(&metadata));
        });
    }

    #[test]
    fn the_account_purges_the_versions_of_a_deleted_path_and_those_beneath_it() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            seed_shared_dir(temp_dir, &identity, &secret_key, "ark/test/notes", vec![]);
            let port = start_test_server(temp_dir.to_path_buf());
            signed_put_with_default_metadata(port, &identity, &secret_key, "/ark/test/notes/a.txt", b"inside");

            let history = format!("/ark/test/.ark/versions/{}", to_path_segment("/notes"));
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", &history, &[]);
            assert_eq!(code, 409, "versions go only once the path itself has");

            let metadata = create_delete_test_metadata(&account_dir.join("notes"), &identity, &secret_key);
            signed_delete_metadata(port, &identity, &secret_key, "/ark/test/notes", &metadata);
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", &history, &[]);
            assert_eq!(code, 204);

            let (account_ctx, _) = account_context(&account_dir.join(".ark"));
            assert!(read_versions(&account_ctx, "/notes/a.txt").unwrap().is_empty());
        });
    }

    #[test]
    fn only_the_account_purges_versions() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, owner_dir) = create_test_account(temp_dir, "owner@example.com");
            let (co_owner_identity, co_owner_key, _) = create_test_account(temp_dir, "coowner@example.com");

            seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: co_owner_identity.address.clone(), permission: Permission::Owner, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            signed_put_with_default_metadata(port, &owner_identity, &owner_key, "/ark/owner/shared/a.txt", b"kept");
            let metadata = create_delete_test_metadata(&owner_dir.join("shared/a.txt"), &owner_identity, &owner_key);
            signed_delete_metadata(port, &owner_identity, &owner_key, "/ark/owner/shared/a.txt", &metadata);

            let (code, _, _) = signed_request(port, &co_owner_identity, &co_owner_key, "DELETE", &format!("/ark/owner/.ark/versions/{}", to_path_segment("/shared/a.txt")), &[]);
            assert_eq!(code, 403);

            let (account_ctx, _) = account_context(&owner_dir.join(".ark"));
            assert_eq!(read_versions(&account_ctx, "/shared/a.txt").unwrap().len(), 2);
        });
    }

    #[test]
    fn delete_file_removes_and_returns_204() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = account_dir.join("d.txt");
            write_plain_test_file(&p, &identity, &secret_key, b"bye");
            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&p, &identity, &secret_key);
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test/d.txt", &metadata);
            assert_eq!(code, 204);
            assert!(!p.exists());
        });
    }

    #[test]
    fn delete_dir_recursively_removes_and_returns_204() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let d = seed_shared_dir(temp_dir, &identity, &secret_key, "ark/test/sub", vec![]);
            fs::write(d.join("inner"), b"x").unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&d, &identity, &secret_key);
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test/sub", &metadata);
            assert_eq!(code, 204);
            assert!(!d.exists());
        });
    }

    #[test]
    fn delete_dir_carrying_no_metadata_404() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let d = account_dir.join("sub");
            fs::create_dir(&d).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&d, &identity, &secret_key);
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test/sub", &metadata);
            assert_eq!(code, 404, "nothing was put there");
            assert!(d.exists());
        });
    }

    #[test]
    fn delete_missing_404() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&account_dir.join("nope"), &identity, &secret_key);
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test/nope", &metadata);
            assert_eq!(code, 404);
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_delete_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            write_plain_test_file(&target, &identity, &secret_key, b"keep");
            let link = account_dir.join("link");
            symlink(&target, &link).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&link, &identity, &secret_key);
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test/link", &metadata);
            assert_eq!(code, 403);
            assert!(link.exists());
            assert!(target.exists());
        });
    }

    #[test]
    fn delete_at_ark_root_405() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&account_dir, &identity, &secret_key);
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test", &metadata);
            assert_eq!(code, 405);
            assert!(temp_dir.join("ark/test").exists());
        });
    }

    #[test]
    fn delete_by_write_member_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&file, &writer_identity, &writer_key);
            let code = signed_delete_metadata(port, &writer_identity, &writer_key, "/ark/owner/file.txt", &metadata);
            assert_eq!(code, 204);
            assert!(!file.exists());
        });
    }

    #[test]
    fn delete_without_delete_metadata_400() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("d.txt");
            write_plain_test_file(&file, &identity, &secret_key, b"kept");
            let (account_ctx, account_path) = account_context(&file);
            let mut metadata = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", "/ark/test/d.txt", &[]);
            assert_eq!(code, 400, "no metadata at all");

            metadata.author_date += Duration::seconds(1);
            sign_metadata(&secret_key, &mut metadata, None).unwrap();
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test/d.txt", &metadata);
            assert_eq!(code, 400, "write metadata, not delete metadata");

            assert!(file.exists());
        });
    }

    #[test]
    fn delete_older_than_the_copy_held_409() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("d.txt");
            write_plain_test_file(&file, &identity, &secret_key, b"kept");
            let (account_ctx, account_path) = account_context(&file);
            let mut metadata = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());

            metadata.author_date -=Duration::seconds(1);
            metadata.deleted = true;
            sign_metadata(&secret_key, &mut metadata, None).unwrap();
            let code = signed_delete_metadata(port, &identity, &secret_key, "/ark/test/d.txt", &metadata);
            assert_eq!(code, 409, "a write newer than the delete wins");
            assert!(file.exists());
        });
    }

    #[test]
    fn delete_dir_holding_what_the_deleter_cannot_write_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");

            let dir = seed_shared_dir(temp_dir, &owner_identity, &owner_key, "ark/owner/shared", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            let private = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/shared/inner/private.txt", b"mine", vec![]);

            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&dir, &writer_identity, &writer_key);
            let code = signed_delete_metadata(port, &writer_identity, &writer_key, "/ark/owner/shared", &metadata);
            assert_eq!(code, 403);
            assert!(dir.exists());
            assert!(private.exists());
        });
    }

    #[test]
    fn delete_by_read_only_member_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let metadata = create_delete_test_metadata(&file, &reader_identity, &reader_key);
            let code = signed_delete_metadata(port, &reader_identity, &reader_key, "/ark/owner/file.txt", &metadata);
            assert_eq!(code, 403);
            assert!(file.exists());
        });
    }

    #[test]
    fn delete_public_file_no_auth_still_unauthorized() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = request(port, "DELETE", "/ark/owner/public.txt", &[], &[]);
            assert_eq!(code, 401);
            assert!(file.exists());
        });
    }
}
