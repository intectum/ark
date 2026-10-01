use std::io;

use super::{get_stream, request};

use crate::http::check_response_code;
use crate::metadata::{read_local_metadata_attributes, read_metadata_attributes};
use crate::paths::{parent_path, sidecar_path_for, to_url};
use crate::storage::{Body, create_dir_all, write_atomic_with_metadata};
use crate::types::{Context, LocalMetadata, VersionEntry};

/// The version history of the file or directory at `path`, newest first.
///
/// `path` accepts relative, absolute account, or address form. A path with no
/// history, or none the server kept, gives an empty list.
pub fn list_versions(ctx: &Context, path: &str) -> io::Result<Vec<VersionEntry>> {
    let mut url = to_url(ctx, path)?;
    url.query_pairs_mut().append_key_only("versions");

    let (code, _, body) = request(Some(ctx), "GET", &url, &[], &[])?;
    if code == 404 {
        return Ok(Vec::new());
    }
    check_response_code(code, &body)?;

    serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("version listing: {}", e)))
}

/// Download the version of `path` that `id` names, beside the account's own
/// copy of it.
///
/// `path` accepts relative, absolute account, or address form. The body is
/// written to a sibling named `<name>.version-<id>`; the account's own copy of
/// `path` is left as it is. When `decrypt` is true, unwraps the file key using
/// `ctx.identity_key` and decrypts the body before writing — which needs a
/// member entry on the version, not on `path`, so a member added since it was
/// written cannot read it.
///
/// Stores the version's signed metadata as `user.ark.*` xattrs on the written
/// file.
pub fn get_version(ctx: &Context, path: &str, id: &str, decrypt: bool) -> io::Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    let existing_metadata = read_metadata_attributes(ctx, path).ok();
    let (metadata, _) = get_stream(ctx, path, &mut buf, decrypt, existing_metadata.as_ref(), Some(id))?;

    let sidecar_path = sidecar_path_for(path, &format!("version-{}", id));
    if let Some(parent) = parent_path(&sidecar_path) {
        create_dir_all(ctx, parent)?;
    }

    let local_metadata = LocalMetadata { encrypted: Some(!decrypt), ..LocalMetadata::default() };
    write_atomic_with_metadata(ctx, &sidecar_path, Body::Bytes(&buf), &metadata, Some(&local_metadata))?;

    Ok(())
}

/// Put what the version of `path` that `id` names held back into the
/// account's own copy of `path`.
///
/// `path` accepts relative, absolute account, or address form. The account
/// must hold its own copy of `path`, and must be able to read the version:
/// its body is decrypted on the way in, so a member added after that version
/// was written cannot restore it.
///
/// Only the account's own copy is written. Like any other local change it
/// reaches the server through [`put`](super::put) or [`sync`](super::sync),
/// which is where the body is encrypted again under a fresh key wrapped for
/// whoever is a member now. The restore then lands as a new version, and the
/// version it came from stays in the history beside it.
pub fn restore_version(ctx: &Context, path: &str, id: &str) -> io::Result<()> {
    let current_metadata = read_metadata_attributes(ctx, path)?;
    let current_local_metadata = read_local_metadata_attributes(ctx, path)?;

    let mut buf: Vec<u8> = Vec::new();
    get_stream(ctx, path, &mut buf, true, Some(&current_metadata), Some(id))?;

    let local_metadata = LocalMetadata { encrypted: Some(false), ..current_local_metadata };
    write_atomic_with_metadata(ctx, path, Body::Bytes(&buf), &current_metadata, Some(&local_metadata))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    use std::path::Path;

    use crate::client::{put, put_permissions};
    use crate::identity::{create_identity, identity_cache_path, write_identity};
    use crate::metadata::read_local_metadata_attributes;
    use crate::permissions::reader;
    use crate::storage::read;
    use crate::testing::fs::{in_test_dir, init_with_server};
    use crate::testing::http::start_test_server;
    use crate::types::Permissions;
    use crate::util::sha256;
    use crate::versions::{read_versions, to_version, version_path_for};

    fn client(temp_dir: &Path) -> Context {
        let port = start_test_server(temp_dir.to_path_buf());
        let address = format!("gyan@127.0.0.1:{}", port);
        init_with_server(temp_dir, &address)
    }

    // The account's copy on the server, reached without going over the wire.
    fn server(ctx: &Context, temp_dir: &Path) -> Context {
        Context {
            root: temp_dir.join("ark/gyan"),
            identity: ctx.identity.clone(),
            identity_key: ctx.identity_key.clone(),
        }
    }

    #[test]
    fn a_path_overwritten_lists_what_it_held_before() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            assert!(list_versions(&ctx,"notes.txt").unwrap().is_empty(), "nothing replaced yet");

            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();

            let listed = list_versions(&ctx,"notes.txt").unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].modified_by, ctx.identity.address);
        });
    }

    #[test]
    fn a_version_is_fetched_beside_the_copy_it_belongs_to() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            let id = list_versions(&ctx,"notes.txt").unwrap()[0].id.clone();
            get_version(&ctx, "notes.txt", &id, true).unwrap();

            let sidecar = format!("notes.txt.version-{}", id);
            assert_eq!(fs::read(temp_dir.join(&sidecar)).unwrap(), b"one");
            assert_eq!(fs::read(temp_dir.join("notes.txt")).unwrap(), b"two", "the copy it belongs to is left alone");
        });
    }

    #[test]
    fn a_version_older_than_the_copy_held_is_not_refused_as_a_rollback() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            let id = list_versions(&ctx, "notes.txt").unwrap()[0].id.clone();
            let existing_metadata = read_metadata_attributes(&ctx, "notes.txt").unwrap();

            // Checked against the copy held, and older than it, which a plain
            // download would refuse.
            let mut buf = Vec::new();
            let (metadata, _) = get_stream(&ctx, "notes.txt", &mut buf, true, Some(&existing_metadata), Some(&id)).unwrap();
            assert_eq!(buf, b"one");
            assert_eq!(to_version(&metadata), id);

            let mut buf = Vec::new();
            assert!(get_stream(&ctx, "notes.txt", &mut buf, true, Some(&existing_metadata), None).is_ok(),
                "the current body still continues the copy held");
        });
    }

    #[test]
    fn a_version_of_some_other_file_is_refused() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"notes").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::write(temp_dir.join("other.txt"), b"other one").unwrap();
            put(&ctx, "other.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::write(temp_dir.join("other.txt"), b"other two").unwrap();
            put(&ctx, "other.txt", &Permissions::default(), Some("none"), false).unwrap();

            // A server listing another file's version under this path. The
            // record is genuine and signed by the same author, and the id is
            // the one asked for — only being some other file gives it away.
            let other_id = list_versions(&ctx, "other.txt").unwrap()[0].id.clone();
            let server_ctx = server(&ctx, temp_dir);
            let other_version = version_path_for(&server_ctx, "/other.txt", &other_id).unwrap();
            let planted = version_path_for(&server_ctx, "/notes.txt", &other_id).unwrap();
            create_dir_all(&server_ctx, parent_path(&planted).unwrap()).unwrap();
            let other_metadata = read_metadata_attributes(&server_ctx, &other_version).unwrap();
            write_atomic_with_metadata(&server_ctx, &planted, Body::Bytes(&read(&server_ctx, &other_version).unwrap()), &other_metadata, None).unwrap();

            let error = get_version(&ctx, "notes.txt", &other_id, true).unwrap_err();
            assert!(error.to_string().contains("id is wrong"), "{}", error);

            let error = restore_version(&ctx, "notes.txt", &other_id).unwrap_err();
            assert!(error.to_string().contains("id is wrong"), "{}", error);
            assert_eq!(fs::read(temp_dir.join("notes.txt")).unwrap(), b"notes", "the copy held is untouched");
        });
    }

    #[test]
    fn a_version_other_than_the_one_asked_for_is_refused() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            let id = list_versions(&ctx,"notes.txt").unwrap()[0].id.clone();

            // The id rides outside what the request signature covers, so a
            // server is free to answer with something else. Swapping the
            // stored body for the current one is that answer.
            let server_ctx = server(&ctx, temp_dir);
            let version_path = version_path_for(&server_ctx, "/notes.txt", &id).unwrap();
            let current = read(&server_ctx, "/notes.txt").unwrap();
            let current_metadata = read_metadata_attributes(&server_ctx, "/notes.txt").unwrap();
            write_atomic_with_metadata(&server_ctx, &version_path, Body::Bytes(&current), &current_metadata, None).unwrap();

            let mut buf = Vec::new();
            let error = match get_stream(&ctx, "notes.txt", &mut buf, true, None, Some(&id)) {
                Err(error) => error,
                Ok(_) => panic!("a version other than the one asked for must be refused"),
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("served version is not"), "{}", error);
        });
    }

    #[test]
    fn restoring_writes_the_copy_and_leaves_the_server_alone() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            let id = list_versions(&ctx, "notes.txt").unwrap()[0].id.clone();
            restore_version(&ctx, "notes.txt", &id).unwrap();

            assert_eq!(fs::read(temp_dir.join("notes.txt")).unwrap(), b"one");

            // Nothing went out, so the server still holds what it held and
            // the history has not grown.
            let server_ctx = server(&ctx, temp_dir);
            assert_eq!(read(&server_ctx, "/notes.txt").unwrap(), b"two");
            assert_eq!(list_versions(&ctx, "notes.txt").unwrap().len(), 1);

            // Putting it is what publishes the restore, as for any other
            // local change.
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            assert_eq!(read(&server_ctx, "/notes.txt").unwrap(), b"one");

            let listed = list_versions(&ctx, "notes.txt").unwrap();
            assert_eq!(listed.len(), 2);
            assert!(listed.iter().any(|v| v.id == id), "the version restored from is kept");
        });
    }

    #[test]
    fn restoring_keeps_the_copy_tracked_by_sync_and_marks_it_changed() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();

            let before = read_local_metadata_attributes(&ctx, "notes.txt").unwrap();
            let id = list_versions(&ctx, "notes.txt").unwrap()[0].id.clone();
            restore_version(&ctx, "notes.txt", &id).unwrap();

            let after = read_local_metadata_attributes(&ctx, "notes.txt").unwrap();

            // The sync marker is what opts a path into sync, so losing it
            // would drop the copy out of it silently.
            let hash = after.sync_body_hash.expect("sync marker kept");
            assert_eq!(hash.value, before.sync_body_hash.unwrap().value);
            assert_ne!(hash.value, sha256(b"one"), "and no longer matches the body, so sync sees a local change");

            // The body written is plaintext, whatever the copy carried before.
            assert_eq!(after.encrypted, Some(false));
        });
    }

    #[test]
    fn a_restored_body_is_readable_by_a_member_added_after_the_version_was_written() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();

            let id = list_versions(&ctx, "notes.txt").unwrap()[0].id.clone();

            // Someone joins only now, so the version's own wrap set leaves
            // them out.
            let (other, _) = create_identity("other@example.com", None).unwrap();
            create_dir_all(&ctx, "/.ark/identities").unwrap();
            write_identity(&ctx, &identity_cache_path(&other.address), &other).unwrap();
            put_permissions(&ctx, "notes.txt", &reader(&other.address)).unwrap();

            restore_version(&ctx, "notes.txt", &id).unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();

            let restored = read_metadata_attributes(&ctx, "notes.txt").unwrap();
            assert!(restored.members.iter().any(|m| m.address == other.address && m.key.is_some()),
                "the put wraps a fresh key for whoever is a member now");
            assert_eq!(read_local_metadata_attributes(&ctx, "notes.txt").unwrap().encrypted, Some(false));
        });
    }

    #[test]
    fn a_path_with_no_history_lists_nothing() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);
            assert!(list_versions(&ctx,"missing.txt").unwrap().is_empty());
        });
    }

    #[test]
    fn versions_kept_by_the_server_match_what_the_client_lists() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            let on_disk = read_versions(&server(&ctx, temp_dir), "/notes.txt").unwrap();
            let listed = list_versions(&ctx,"notes.txt").unwrap();

            assert_eq!(on_disk.len(), listed.len());
            assert_eq!(on_disk[0].id, listed[0].id);
        });
    }
}
