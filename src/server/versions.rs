use std::io::{self, Write};

use super::get::serve_get;

use crate::http::{write_response, write_text};
use crate::storage::exists;
use crate::types::Context;
use crate::versions::{read_versions, version_path_for};

pub fn serve_version_list(ctx: &Context, path: &str, stream: &mut dyn Write, send_body: bool) -> io::Result<()> {
    let versions = match read_versions(ctx, path) {
        Ok(v) => v,
        Err(e) => return write_text(stream, 500, e.to_string().as_bytes()),
    };

    let body = serde_json::to_string(&versions).map_err(|e| io::Error::other(e.to_string()))?;
    let content_length = body.len().to_string();
    let headers: Vec<(&str, &str)> = vec![
        ("Content-Type", "application/json"),
        ("Content-Length", content_length.as_str()),
        ("Connection", "close"),
    ];

    write_response(stream, 200, &headers, if send_body { body.as_bytes() } else { &[] })
}

pub fn serve_version(ctx: &Context, path: &str, stream: &mut dyn Write, send_body: bool, id: &str) -> io::Result<()> {
    let version_path = match version_path_for(ctx, path, id) {
        Ok(p) => p,
        Err(e) => return write_text(stream, 400, e.to_string().as_bytes()),
    };

    if !exists(ctx, &version_path) {
        return write_text(stream, 404, b"no such version");
    }

    serve_get(ctx, &version_path, stream, send_body, None)
}

#[cfg(test)]
mod tests {
    use crate::metadata::read_metadata_attributes;
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_test_account, in_test_dir, write_plain_test_file};
    use crate::testing::http::*;
    use crate::testing::http::start_test_server;
    use crate::types::{Member, Permission, VersionEntry};
    use crate::versions::{save_version, to_version};

    #[test]
    fn a_version_is_listed_and_served_with_the_record_its_author_signed() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("x.txt");
            write_plain_test_file(&file, &identity, &secret_key, b"old");
            let (account_ctx, account_path) = account_context(&file);
            let existing = read_metadata_attributes(&account_ctx, &account_path).unwrap();

            save_version(&account_ctx, &account_path, &existing).unwrap();
            write_plain_test_file(&file, &identity, &secret_key, b"new");

            let port = start_test_server(temp_dir.to_path_buf());

            let (code, body, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/x.txt?versions", &[]);
            assert_eq!(code, 200);
            let listed: Vec<VersionEntry> = serde_json::from_slice(&body).unwrap();
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
    fn a_member_dropped_from_the_live_path_cannot_reach_a_version_that_still_lists_them() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            // The version is written while the reader is a member, so its own
            // record lists them.
            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"secret", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);
            let (account_ctx, account_path) = account_context(&file);
            let shared = read_metadata_attributes(&account_ctx, &account_path).unwrap();
            save_version(&account_ctx, &account_path, &shared).unwrap();
            let id = to_version(&shared);

            // The live path then drops them.
            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"newer", vec![]);

            let port = start_test_server(temp_dir.to_path_buf());
            let target = format!("/ark/owner/file.txt?version={}", id);
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", &target, &[]);
            assert_eq!(code, 403, "membership is the live path's, not the version's");

            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "GET", "/ark/owner/file.txt?versions", &[]);
            assert_eq!(code, 403);

            // The owner still reaches it.
            let (code, body, _) = signed_request(port, &owner_identity, &owner_key, "GET", &target, &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"secret");
        });
    }
}
