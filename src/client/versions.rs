use std::io;

use super::{decrypt_stream, get_stream, request};

use crate::http::check_response_code;
use crate::metadata::{read_local_metadata_attributes, read_metadata_attributes};
use crate::paths::to_url;
use crate::storage::{read, write_atomic_with_metadata};
use crate::types::{Context, LocalMetadata, Metadata, VersionEntry};
use crate::versions::{remove_versions, to_version, version_path_for};

/// The version history of the file or directory at `path`, newest first, what
/// it holds now included.
///
/// `path` accepts relative, absolute account, or address form. A path with no
/// history, or none the server kept, gives an empty list.
///
/// History outlives a delete of `path`, so it may span more than one file —
/// told apart by `entry_id`. Listed are only the versions whose own member
/// list admits the account, whoever `path` admits now.
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

/// The body and signed metadata of the version of `path` that `id` names.
///
/// `path` accepts relative, absolute account, or address form. Read from the
/// account's own version store where it holds the version, and otherwise
/// fetched from the server and kept there. The account's own copy of `path`
/// is left as it is. When `decrypt` is true the body is decrypted, which needs
/// a member entry on the version, not on `path`, so a member added since it
/// was written cannot read it.
///
/// `existing_metadata`: the metadata of the account's own copy of `path`, when
/// it has one. The version must then be a file where the copy is a file.
pub fn get_version(ctx: &Context, path: &str, id: &str, decrypt: bool, existing_metadata: Option<&Metadata>) -> io::Result<(Vec<u8>, Metadata)> {
    let version_path = version_path_for(ctx, path, id)?;

    let (body, metadata) = match read_metadata_attributes(ctx, &version_path) {
        // Verified when it was kept, as it is on the way in from the server.
        Ok(metadata) => (read(ctx, &version_path)?, metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut buf: Vec<u8> = Vec::new();
            let (metadata, _) = get_stream(ctx, path, &mut buf, decrypt, existing_metadata, Some(id))?;
            return Ok((buf, metadata));
        }
        Err(error) => return Err(error),
    };

    if let Some(existing_metadata) = existing_metadata {
        if existing_metadata.body_hash.is_none() != metadata.body_hash.is_none() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "existing is not the same kind as the version"));
        }
    }

    if !decrypt || metadata.encryption_algorithm.is_none() {
        return Ok((body, metadata));
    }

    let mut plaintext = Vec::new();
    decrypt_stream(ctx, &metadata, &mut body.as_slice(), &mut plaintext)?;

    Ok((plaintext, metadata))
}

/// The body and signed metadata of the newest version of `path` that both
/// `local_metadata` and `remote_metadata` descend from, which two sides of a
/// conflict can be merged against. `None` where their histories share none.
///
/// `path` accepts relative, absolute account, or address form. The local
/// history is read from the account's own store; the remote one is fetched
/// from the server only as far back as it meets the local one, and kept.
/// When `decrypt` is true the body is decrypted, as for [`get_version`].
pub fn get_merge_base_version(ctx: &Context, path: &str, local_metadata: &Metadata, remote_metadata: &Metadata, decrypt: bool) -> io::Result<Option<(Vec<u8>, Metadata)>> {
    let mut local_chain = vec![to_version(local_metadata)];
    let mut local_parent = local_metadata.parent_version.clone();
    while let Some(id) = local_parent {
        local_parent = match read_metadata_attributes(ctx, &version_path_for(ctx, path, &id)?) {
            Ok(metadata) => metadata.parent_version,
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        local_chain.push(id);
    }

    let mut remote_chain = vec![to_version(remote_metadata)];
    let mut remote_parent = remote_metadata.parent_version.clone();
    while let Some(id) = remote_parent {
        if local_chain.contains(remote_chain.last().unwrap()) { break; }
        remote_parent = match get_version(ctx, path, &id, false, None) {
            Ok((_, metadata)) => metadata.parent_version,
            Err(_) => None,
        };
        remote_chain.push(id);
    }

    let Some(base) = local_chain.iter().find(|id| remote_chain.contains(id)) else {
        return Ok(None);
    };

    Ok(Some(get_version(ctx, path, base, decrypt, None)?))
}

/// Put what the version of `path` that `id` names held back into the
/// account's own copy of `path`.
///
/// `path` accepts relative, absolute account, or address form. The account
/// must hold its own copy of `path`, and must be able to read the version:
/// its body is decrypted on the way in, so a member added after that version
/// was written cannot restore it. A version of a file `path` held before a
/// delete restores into the file `path` holds now, which keeps its own id.
///
/// Only the account's own copy is written. Like any other local change it
/// reaches the server through [`put`](super::put) or [`sync`](super::sync),
/// which is where the body is encrypted again under a fresh key wrapped for
/// whoever is a member now. The restore then lands as a new version, and the
/// version it came from stays in the history beside it.
///
/// Read from the account's own version store where it holds the version, and
/// from the server otherwise.
pub fn restore_version(ctx: &Context, path: &str, id: &str) -> io::Result<()> {
    let current_metadata = read_metadata_attributes(ctx, path)?;
    let current_local_metadata = read_local_metadata_attributes(ctx, path)?;

    let (buf, _) = get_version(ctx, path, id, true, Some(&current_metadata))?;

    let local_metadata = LocalMetadata { encrypted: Some(false), ..current_local_metadata };
    write_atomic_with_metadata(ctx, path, &buf, &current_metadata, Some(&local_metadata))?;

    Ok(())
}

/// Drop the version history of `path` and of everything beneath it, which a
/// delete keeps. Only the account can, and only once `path` itself is deleted
/// on the server.
///
/// `path` accepts relative, absolute account, or address form. Drops the
/// server's history, then the account's own store of it. The local copy is
/// left alone. Other devices keep the versions in their own stores.
pub fn purge_versions(ctx: &Context, path: &str) -> io::Result<()> {
    let mut url = to_url(ctx, path)?;
    url.query_pairs_mut().append_key_only("versions");

    let (code, _, body) = request(Some(ctx), "DELETE", &url, &[], &[])?;
    check_response_code(code, &body)?;

    remove_versions(ctx, path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    use std::path::Path;

    use crate::client::{delete, put, put_permissions};
    use crate::identity::{create_identity, identity_cache_path, write_identity};
    use crate::metadata::read_local_metadata_attributes;
    use crate::permissions::reader;
    use crate::storage::{create_dir_all, exists, read, remove_dir_all};
    use crate::testing::fs::{in_test_dir, init_with_server};
    use crate::testing::http::start_test_server;
    use crate::types::Permissions;
    use crate::util::sha256;
    use crate::versions::{read_versions, to_version, version_dir_for, version_path_for};

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
    fn every_put_is_listed_as_a_version() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            assert_eq!(list_versions(&ctx,"notes.txt").unwrap().len(), 1, "what the path holds now is a version too");

            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();

            let listed = list_versions(&ctx,"notes.txt").unwrap();
            assert_eq!(listed.len(), 2);
            assert_eq!(listed[1].author, ctx.identity.address);
        });
    }

    #[test]
    fn a_version_not_kept_is_fetched_into_the_version_store_and_the_copy_left_alone() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            let id = list_versions(&ctx,"notes.txt").unwrap()[1].id.clone();
            remove_dir_all(&ctx, &version_dir_for(&ctx, "notes.txt").unwrap()).unwrap();

            let (body, metadata) = get_version(&ctx, "notes.txt", &id, true, None).unwrap();

            assert_eq!(body, b"one");
            assert_eq!(to_version(&metadata), id);
            assert!(exists(&ctx, &version_path_for(&ctx, "notes.txt", &id).unwrap()), "the fetched version is kept");
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

            let id = list_versions(&ctx, "notes.txt").unwrap()[1].id.clone();
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
    fn a_version_of_the_file_a_path_held_before_a_removal_is_fetched_and_restored() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"removed").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            delete(&ctx, "notes.txt").unwrap();

            // Written again from scratch, so as a file of its own.
            fs::remove_file(temp_dir.join("notes.txt")).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"recreated").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            let listed = list_versions(&ctx, "notes.txt").unwrap();
            assert_eq!(listed.len(), 2);
            assert_ne!(listed[0].entry_id, listed[1].entry_id);

            let (body, _) = get_version(&ctx, "notes.txt", &listed[1].id, true, None).unwrap();
            assert_eq!(body, b"removed");

            restore_version(&ctx, "notes.txt", &listed[1].id).unwrap();
            assert_eq!(fs::read(temp_dir.join("notes.txt")).unwrap(), b"removed");
            assert_eq!(read_metadata_attributes(&ctx, "notes.txt").unwrap().id, listed[0].entry_id,
                "the copy stays the file the path holds now");
        });
    }

    #[test]
    fn a_version_the_account_kept_is_read_without_the_server() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();
            fs::write(temp_dir.join("notes.txt"), b"two").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();
            let id = list_versions(&ctx, "notes.txt").unwrap()[1].id.clone();

            // The server no longer has it to give.
            fs::remove_dir_all(temp_dir.join("ark/gyan/.ark/versions")).unwrap();

            restore_version(&ctx, "notes.txt", &id).unwrap();
            assert_eq!(fs::read(temp_dir.join("notes.txt")).unwrap(), b"one", "decrypted from the account's own store");
        });
    }

    #[test]
    fn the_versions_of_a_deleted_path_are_purged() {
        in_test_dir("ark_client_versions_test", |temp_dir| {
            let ctx = client(temp_dir);

            fs::write(temp_dir.join("notes.txt"), b"one").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            delete(&ctx, "notes.txt").unwrap();
            assert_eq!(list_versions(&ctx, "notes.txt").unwrap().len(), 1);
            assert!(exists(&ctx, &version_dir_for(&ctx, "notes.txt").unwrap()), "the account keeps its own store of the history");

            purge_versions(&ctx, "notes.txt").unwrap();
            assert!(list_versions(&ctx, "notes.txt").unwrap().is_empty());
            assert!(!exists(&ctx, &version_dir_for(&ctx, "notes.txt").unwrap()), "the account's own store of the history is dropped too");
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

            let id = list_versions(&ctx,"notes.txt").unwrap()[1].id.clone();

            // The id rides outside what the request signature covers, so a
            // server is free to answer with something else. Swapping the
            // stored body for the current one is that answer.
            let server_ctx = server(&ctx, temp_dir);
            let version_path = version_path_for(&server_ctx, "/notes.txt", &id).unwrap();
            let current = read(&server_ctx, "/notes.txt").unwrap();
            let current_metadata = read_metadata_attributes(&server_ctx, "/notes.txt").unwrap();
            write_atomic_with_metadata(&server_ctx, &version_path, &current, &current_metadata, None).unwrap();

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

            let id = list_versions(&ctx, "notes.txt").unwrap()[1].id.clone();
            restore_version(&ctx, "notes.txt", &id).unwrap();

            assert_eq!(fs::read(temp_dir.join("notes.txt")).unwrap(), b"one");

            // Nothing went out, so the server still holds what it held and
            // the history has not grown.
            let server_ctx = server(&ctx, temp_dir);
            assert_eq!(read(&server_ctx, "/notes.txt").unwrap(), b"two");
            assert_eq!(list_versions(&ctx, "notes.txt").unwrap().len(), 2);

            // Putting it is what publishes the restore, as for any other
            // local change.
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            assert_eq!(read(&server_ctx, "/notes.txt").unwrap(), b"one");

            let listed = list_versions(&ctx, "notes.txt").unwrap();
            assert_eq!(listed.len(), 3);
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
            let id = list_versions(&ctx, "notes.txt").unwrap()[1].id.clone();
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

            let id = list_versions(&ctx, "notes.txt").unwrap()[1].id.clone();

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
