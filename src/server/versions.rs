use std::io::{self, Write};

use super::auth::authorize;

use crate::http::{write_response, write_text};
use crate::metadata::read_metadata_attributes;
use crate::types::{Context, Identity, Member};
use crate::versions::{read_versions, version_path_for};

// Every version of `path` to anyone `path_members` lets read it; to anyone
// else only the versions whose own members let them.
pub fn serve_version_list(server_ctx: &Context, ctx: &Context, path: &str, stream: &mut dyn Write, send_body: bool, requestor_identity: &Identity, path_members: Option<&[Member]>) -> io::Result<()> {
    let reads_path = authorize(server_ctx, ctx, requestor_identity, None, path_members).is_ok();

    let versions = match read_versions(ctx, path) {
        Ok(v) => v,
        Err(e) => return write_text(stream, 500, e.to_string().as_bytes()),
    };

    let mut readable_versions = Vec::new();
    for version in versions {
        let version_path = match version_path_for(ctx, path, &version.id) {
            Ok(p) => p,
            Err(e) => return write_text(stream, 500, e.to_string().as_bytes()),
        };

        let metadata = match read_metadata_attributes(ctx, &version_path) {
            Ok(m) => m,
            Err(e) => return write_text(stream, 500, e.to_string().as_bytes()),
        };

        if reads_path || authorize(server_ctx, ctx, requestor_identity, None, Some(&metadata.members)).is_ok() {
            readable_versions.push(version);
        }
    }

    let body = serde_json::to_string(&readable_versions).map_err(|e| io::Error::other(e.to_string()))?;
    let content_length = body.len().to_string();
    let headers: Vec<(&str, &str)> = vec![
        ("Content-Type", "application/json"),
        ("Content-Length", content_length.as_str()),
        ("Connection", "close"),
    ];

    write_response(stream, 200, &headers, if send_body { body.as_bytes() } else { &[] })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::metadata::read_metadata_attributes;
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_test_account, in_test_dir, write_plain_test_file};
    use crate::testing::http::*;
    use crate::testing::http::start_test_server;
    use crate::types::{Identity, Key, Member, Metadata, Permission, VersionEntry};
    use crate::versions::{copy_versioned_with_metadata, to_version};

    // Stores what `file` holds as a version, as the server would have had it
    // come through a put.
    fn store(file: &Path) -> Metadata {
        let (account_ctx, account_path) = account_context(file);
        let metadata = read_metadata_attributes(&account_ctx, &account_path).unwrap();
        copy_versioned_with_metadata(&account_ctx, &account_path, &account_path, &metadata).unwrap();
        metadata
    }

    fn list(port: u16, identity: &Identity, secret_key: &Key, target: &str) -> Vec<VersionEntry> {
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

            let listed = list(port, &reader_identity, &reader_key, "/ark/owner/file.txt?versions");
            assert_eq!(listed.len(), 1, "listed only where the reader could read it");
            assert_eq!(listed[0].entry_id, removed.id);

            let target = format!("/ark/owner/file.txt?version={}", to_version(&removed));
            let (code, body, _) = signed_request(port, &reader_identity, &reader_key, "GET", &target, &[]);
            assert_eq!(code, 200, "the version's own metadata lists the reader");
            assert_eq!(body, b"removed");

            let target = format!("/ark/owner/file.txt?version={}", to_version(&recreated));
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &target, &[]);
            assert_eq!(code, 403);

            assert_eq!(list(port, &owner_identity, &owner_key, "/ark/owner/file.txt?versions").len(), 2);
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

            assert_eq!(list(port, &reader_identity, &reader_key, "/ark/owner/file.txt?versions").len(), 2);

            let target = format!("/ark/owner/file.txt?version={}", to_version(&before));
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "HEAD", &target, &[]);
            assert_eq!(code, 200, "the metadata is the path's to show");
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &target, &[]);
            assert_eq!(code, 403, "the body is the version's own members' alone");
        });
    }

    #[test]
    fn a_version_can_only_be_read_and_only_by_an_id_of_its_own() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x.txt");
            write_plain_test_file(&file, &identity, &secret_key, b"kept");
            let target = format!("/ark/test/x.txt?version={}", to_version(&store(&file)));

            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &identity, &secret_key, "PUT", &target, b"over");
            assert_eq!(code, 405);
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", &target, &[]);
            assert_eq!(code, 405);
            assert_eq!(list(port, &identity, &secret_key, "/ark/test/x.txt?versions").len(), 1, "the version is untouched");

            // Neither a name set aside beside the versions, nor a way out of
            // them.
            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/x.txt?version=.previous", &[]);
            assert_eq!(code, 400);
            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/x.txt?version=..%2F..%2F..%2Fx.txt", &[]);
            assert_eq!(code, 400);
        });
    }

    #[test]
    fn a_public_version_is_read_without_signing_in_but_not_listed() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);
            let target = format!("/ark/owner/public.txt?version={}", to_version(&store(&file)));

            let port = start_test_server(temp_dir.to_path_buf());

            let (code, body, _) = request(port, "GET", &target, &[], &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"open");

            let (code, _, _) = request(port, "GET", "/ark/owner/public.txt?versions", &[], &[]);
            assert_eq!(code, 401);
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

            assert!(list(port, &reader_identity, &reader_key, "/ark/owner/shared/private.txt?versions").is_empty());

            let target = format!("/ark/owner/shared/private.txt?version={}", to_version(&private));
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &target, &[]);
            assert_eq!(code, 403, "the version's own metadata governs it, not the directory's");
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "HEAD", &target, &[]);
            assert_eq!(code, 403, "a removed path is read as its newest version left it");
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

            let listed = list(port, &identity, &secret_key, "/ark/test/x.txt?versions");
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].id, to_version(&existing));
            assert_eq!(listed[0].size, 3);

            let target = format!("/ark/test/x.txt?version={}", listed[0].id);
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "GET", &target, &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"old");
            assert_eq!(header(&headers, "x-ark-meta-id"), Some(existing.id.hyphenated().to_string().as_str()));
        });
    }

    #[test]
    fn a_version_that_is_not_there_returns_404() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            write_plain_test_file(&account_dir.join("x.txt"), &identity, &secret_key, b"only");
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/x.txt?version=nope", &[]);
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
            let target = format!("/ark/owner/file.txt?version={}", id);
            let (code, body, _) = signed_request(port, &reader_identity, &reader_key, "GET", &target, &[]);
            assert_eq!(code, 200, "the version's own metadata still lists them");
            assert_eq!(body, b"secret");

            let listed = list(port, &reader_identity, &reader_key, "/ark/owner/file.txt?versions");
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].id, id);

            // The live path is theirs no longer.
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", "/ark/owner/file.txt", &[]);
            assert_eq!(code, 403);
        });
    }
}
