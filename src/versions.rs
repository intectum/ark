//! What a path held before the writes that replaced it.
//!
//! A version is an ordinary ark entry at rest — the body bytes and the signed
//! record its author published, unchanged — so it is read back through the
//! same operations as anything else. Versions of one path live together in a
//! directory of their own under [`VERSIONS_DIR`], keyed by the path they
//! belong to.
//!
//! See `spec.md` §4.3 and the decision behind the design in `versions.md`.

use std::io;

use crate::metadata::read_metadata_attributes;
use crate::paths::{file_name, join_path, to_account_path, to_path_segment};
use crate::storage::{Body, create_dir_all, exists, is_dir, link, read_dir, remove_dir_all, size, write_atomic_with_metadata};
use crate::timestamp;
use crate::types::{Context, Metadata, VersionEntry};
use crate::util::encode_base64url;

pub const VERSIONS_DIR: &str = "/.ark/versions";

const ID_SIGNATURE_LENGTH: usize = 8;

/// The id naming the version `metadata` describes.
///
/// Derived from the record itself, so every host holding that version names it
/// the same — which is what lets two histories that drifted apart be compared.
/// Two records that differ in any field, including a member list moved without
/// touching the body, get ids of their own.
pub fn to_version(metadata: &Metadata) -> String {
    let signature: String = encode_base64url(&metadata.signature.value)
        .chars()
        .take(ID_SIGNATURE_LENGTH)
        .collect();

    format!("{}_{}", timestamp::format_fs_safe(metadata.modified), signature)
}

/// Where the versions of `path` are kept.
pub fn version_dir_for(ctx: &Context, path: &str) -> io::Result<String> {
    Ok(join_path(VERSIONS_DIR, &to_path_segment(&to_account_path(ctx, path)?)))
}

/// Where the version of `path` that `id` names is kept.
pub fn version_path_for(ctx: &Context, path: &str, id: &str) -> io::Result<String> {
    Ok(join_path(&version_dir_for(ctx, path)?, id))
}

/// Keep what `path` holds under `metadata` as a version of it.
///
/// Call this before replacing an entry, with the record that entry carries.
/// Keeping the same record twice leaves one version, so a write that stopped
/// before replacing anything costs nothing on the next attempt.
///
/// Nothing is dropped again: a path keeps a version per write it has taken,
/// for as long as it exists. Only [`remove_versions`] clears them.
pub fn save_version(ctx: &Context, path: &str, metadata: &Metadata) -> io::Result<()> {
    let account_path = to_account_path(ctx, path)?;
    if account_path == VERSIONS_DIR || account_path.starts_with(&format!("{}/", VERSIONS_DIR)) {
        return Ok(());
    }

    let version_dir = version_dir_for(ctx, path)?;
    create_dir_all(ctx, &version_dir)?;

    let version_path = join_path(&version_dir, &to_version(metadata));

    if is_dir(ctx, path) {
        write_atomic_with_metadata(ctx, &version_path, Body::Bytes(&[]), metadata, None)?;
    } else {
        match link(ctx, path, &version_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

/// The versions of `path`, newest first. Empty where it has none.
pub fn read_versions(ctx: &Context, path: &str) -> io::Result<Vec<VersionEntry>> {
    let version_dir = version_dir_for(ctx, path)?;
    if !exists(ctx, &version_dir) {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for version_path in read_dir(ctx, &version_dir)? {
        if file_name(&version_path).starts_with('.') { continue; }

        let metadata = read_metadata_attributes(ctx, &version_path)?;

        entries.push(VersionEntry {
            id: file_name(&version_path).to_string(),
            modified: metadata.modified,
            modified_by: metadata.modified_by,
            body_hash: metadata.body_hash,
            size: size(ctx, &version_path)?,
        });
    }

    entries.reverse();

    Ok(entries)
}

/// Drop every version of `path` and of the paths beneath it, along with
/// anything else kept beside them — including metadata a directory set aside
/// for a rewrite still under way, so call this only once `path` is gone.
pub fn remove_versions(ctx: &Context, path: &str) -> io::Result<()> {
    if !exists(ctx, VERSIONS_DIR) {
        return Ok(());
    }

    let account_path = to_account_path(ctx, path)?;
    let key = to_path_segment(&account_path);
    let child_key_prefix = to_path_segment(&format!("{}/", account_path.trim_end_matches('/')));

    for version_dir in read_dir(ctx, VERSIONS_DIR)? {
        let name = file_name(&version_dir);
        if name == key || name.starts_with(&child_key_prefix) {
            remove_dir_all(ctx, &version_dir)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    use crate::crypto::create_secret_key;
    use crate::identity::create_identity;
    use crate::metadata::{apply_key_to_metadata, create_metadata, sign_metadata, write_metadata_attributes};
    use crate::storage::{read, write_atomic_with_metadata, write_atomic_without_metadata};
    use crate::testing::fs::{TEST_ADDRESS, create_test_account, in_test_dir, write_plain_test_file};
    use crate::types::{Identity, Key, Member, Permission};

    fn account(temp_dir: &Path) -> (Context, Identity, Key) {
        let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
        let context = Context {
            root: account_dir,
            identity: identity.clone(),
            identity_key: Some(secret_key.clone()),
        };

        (context, identity, secret_key)
    }

    fn write(ctx: &Context, identity: &Identity, secret_key: &Key, path: &str, body: &[u8]) -> Metadata {
        write_plain_test_file(&ctx.root.join(path.trim_start_matches('/')), identity, secret_key, body);
        read_metadata_attributes(ctx, path).unwrap()
    }

    #[test]
    fn an_id_names_one_record_and_no_other() {
        let (identity, secret_key) = create_identity(TEST_ADDRESS, None).unwrap();

        let mut metadata = create_metadata(&identity.address, None);
        sign_metadata(&secret_key, &mut metadata, Some(b"body")).unwrap();
        let id = to_version(&metadata);

        assert_eq!(to_version(&metadata), id, "the same record names the same version");

        // A member change leaves the body, and so the body hash, alone.
        let mut changed = metadata.clone();
        changed.members.push(Member { address: "other@example.com".to_string(), permission: Permission::Reader, key: None });
        sign_metadata(&secret_key, &mut changed, Some(b"body")).unwrap();

        assert_ne!(to_version(&changed), id, "a record that differs names a version of its own");
    }

    #[test]
    fn keeping_what_a_path_holds_costs_no_copy_and_keeps_the_record() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let before = write(&context, &identity, &secret_key, "/a.txt", b"before");

            save_version(&context, "/a.txt", &before).unwrap();
            write_atomic_with_metadata(&context, "/a.txt", Body::Bytes(b"after"), &before, None).unwrap();

            let version_path = version_path_for(&context, "/a.txt", &to_version(&before)).unwrap();
            assert_eq!(read(&context, &version_path).unwrap(), b"before");
            assert_eq!(read_metadata_attributes(&context, &version_path).unwrap().id, before.id);
        });
    }

    #[test]
    fn keeping_the_same_record_twice_leaves_one_version() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let before = write(&context, &identity, &secret_key, "/a.txt", b"before");

            save_version(&context, "/a.txt", &before).unwrap();
            save_version(&context, "/a.txt", &before).unwrap();

            assert_eq!(read_versions(&context, "/a.txt").unwrap().len(), 1);
        });
    }

    #[test]
    fn a_directory_is_kept_as_its_record_alone() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            create_dir_all(&context, "/notes").unwrap();
            let mut metadata = create_metadata(&identity.address, None);
            sign_metadata(&secret_key, &mut metadata, None).unwrap();
            write_metadata_attributes(&context, "/notes", &metadata, None).unwrap();

            save_version(&context, "/notes", &metadata).unwrap();

            let versions = read_versions(&context, "/notes").unwrap();
            assert_eq!(versions.len(), 1);
            assert_eq!(versions[0].size, 0, "a directory version holds the record and no body");
            assert!(versions[0].body_hash.is_none());
        });
    }

    #[test]
    fn versions_are_read_back_newest_first_and_none_are_dropped() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);

            let mut ids = Vec::new();
            for index in 0..25 {
                let metadata = write(&context, &identity, &secret_key, "/a.txt", format!("body {}", index).as_bytes());
                ids.push(to_version(&metadata));
                save_version(&context, "/a.txt", &metadata).unwrap();
            }

            let versions = read_versions(&context, "/a.txt").unwrap();
            assert_eq!(versions.len(), ids.len(), "a path keeps a version per write it has taken");
            assert_eq!(versions[0].id, *ids.last().unwrap(), "newest first");
            assert_eq!(versions.last().unwrap().id, ids[0], "oldest last, and still there");
        });
    }

    #[test]
    fn a_rewrite_left_part_way_does_not_show_up_as_a_version() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let metadata = write(&context, &identity, &secret_key, "/a.txt", b"body");
            save_version(&context, "/a.txt", &metadata).unwrap();

            // What a stopped rewrite leaves beside the versions: an entry
            // carrying no record, which a version could never be.
            let marker = join_path(&version_dir_for(&context, "/a.txt").unwrap(), ".previous");
            write_atomic_without_metadata(&context, &marker, Body::Bytes(&[])).unwrap();

            let versions = read_versions(&context, "/a.txt").unwrap();
            assert_eq!(versions.len(), 1);
            assert_eq!(versions[0].id, to_version(&metadata));
        });
    }

    #[test]
    fn dropping_a_directorys_versions_drops_the_versions_beneath_it() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            create_dir_all(&context, "/notes").unwrap();
            create_dir_all(&context, "/notebook").unwrap();

            let inside = write(&context, &identity, &secret_key, "/notes/a.txt", b"inside");
            let beside = write(&context, &identity, &secret_key, "/notebook/b.txt", b"beside");
            save_version(&context, "/notes/a.txt", &inside).unwrap();
            save_version(&context, "/notebook/b.txt", &beside).unwrap();

            remove_versions(&context, "/notes").unwrap();

            assert!(read_versions(&context, "/notes/a.txt").unwrap().is_empty());
            // A key that merely starts with the same characters is a different
            // path, and keeps what it held.
            assert_eq!(read_versions(&context, "/notebook/b.txt").unwrap().len(), 1);
        });
    }

    #[test]
    fn the_version_store_is_not_versioned_itself() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            create_dir_all(&context, VERSIONS_DIR).unwrap();
            let metadata = write(&context, &identity, &secret_key, "/.ark/versions/planted", b"planted");

            save_version(&context, "/.ark/versions/planted", &metadata).unwrap();

            assert!(read_versions(&context, "/.ark/versions/planted").unwrap().is_empty());
        });
    }

    #[test]
    fn a_version_of_an_encrypted_file_keeps_the_key_it_was_wrapped_with() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);

            let mut metadata = create_metadata(&identity.address, Some("aes-256-gcm"));
            let file_key = create_secret_key("aes-256-gcm").unwrap();
            apply_key_to_metadata(&context, &mut metadata, &file_key).unwrap();
            sign_metadata(&secret_key, &mut metadata, Some(b"cipher")).unwrap();
            write_atomic_with_metadata(&context, "/a.txt", Body::Bytes(b"cipher"), &metadata, None).unwrap();

            save_version(&context, "/a.txt", &metadata).unwrap();

            let version_path = version_path_for(&context, "/a.txt", &to_version(&metadata)).unwrap();
            let kept = read_metadata_attributes(&context, &version_path).unwrap();
            assert_eq!(kept.members[0].key.as_ref().unwrap().value, metadata.members[0].key.as_ref().unwrap().value);
        });
    }
}
