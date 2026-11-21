//! Everything a path has held, what it holds now included.
//!
//! A version is an ordinary ark entry at rest — the body bytes and the signed
//! metadata its author published, unchanged — so it is read back through the
//! same operations as anything else. Versions of one path live together in a
//! directory of their own under [`VERSIONS_DIR`], keyed by the path they
//! belong to rather than the entry, so they outlive a removal of the path and
//! a path recreated after one carries on the same history.
//!
//! A delete is stored as a version too: the delete metadata, with no contents.
//! It marks where a history stops, and what a later write must be newer than.
//!
//! See `spec.md` §4.3.

use std::io;

use crate::metadata::{read_metadata_attributes, to_canonical_metadata_bytes};
use crate::paths::{VERSIONS_DIR, file_name, from_path_segment, is_request_log_entry_path, is_version_store_path, join_path, to_account_path, version_dir_for, version_path_for};
use crate::storage::{copy_atomic_with_metadata, create_dir_all, exists, link_atomic, read_dir, remove_dir_all, write_atomic_with_metadata};
use crate::timestamp;
use crate::types::{Context, Metadata, Version};
use crate::util::{encode_base64url, sha256};

const ID_HASH_LENGTH: usize = 8;

/// The id naming the version `metadata` describes.
///
/// Derived from what the metadata says, so every host holding that version
/// names it the same — which is what lets two histories that drifted apart be
/// compared. Metadata that differs in any field, including a member list
/// moved without touching the body, gets an id of its own. How the metadata
/// was signed plays no part.
pub fn to_version(metadata: &Metadata) -> String {
    let hash: String = encode_base64url(sha256(&to_canonical_metadata_bytes(metadata)))
        .chars()
        .take(ID_HASH_LENGTH)
        .collect();

    format!("{}_{}", timestamp::format_fs_safe(metadata.author_date), hash)
}

/// Write `contents` to the file `path` along with `metadata`, as a single
/// visible change, storing it as a version of `path` as it lands.
///
/// The version is the very entry `path` then names — no copy — and is there
/// before `path` changes, so what `path` holds is always among its versions.
/// A write that stopped part-way can leave a version `path` never held;
/// writing the same metadata again leaves one version and finishes the job.
///
/// Nothing is dropped again: a version is stored per write a path has taken,
/// through removals of it too. Only [`purge_stored_versions`] clears them.
///
/// `metadata` must be the metadata signed for `contents`: a version is named by
/// its metadata, so new contents under metadata already stored would take that
/// version's name and replace it.
///
/// `path`'s parent must exist, as it must for [`std::fs::write`].
pub fn write_versioned_with_metadata(ctx: &Context, path: &str, contents: &[u8], metadata: &Metadata) -> io::Result<()> {
    if !is_versioned(ctx, path)? {
        return write_atomic_with_metadata(ctx, path, contents, metadata, None);
    }

    let version_path = write_version(ctx, path, contents, metadata)?;
    link_atomic(ctx, &version_path, path)
}

/// Store `contents` and `metadata` as a version of `path`, leaving `path`
/// itself alone, and give back where the version is stored.
///
/// For a version made before `path` takes it — or that `path` never takes
/// where it stands, as on a client, whose own copy is edited in place. Keeping
/// the same metadata twice leaves one version.
///
/// `metadata` must be the metadata signed for `contents`, as for
/// [`write_versioned_with_metadata`]. A directory's version has no contents,
/// nor does a delete's.
pub fn write_version(ctx: &Context, path: &str, contents: &[u8], metadata: &Metadata) -> io::Result<String> {
    let version_dir = version_dir_for(&to_account_path(ctx, path)?);
    create_dir_all(ctx, &version_dir)?;

    let version_path = join_path(&version_dir, &to_version(metadata));
    write_atomic_with_metadata(ctx, &version_path, contents, metadata, None)?;

    Ok(version_path)
}

/// Copy the body of `from` to the file `to` along with `metadata`, as a
/// single visible change, storing it as a version of `to` as it lands.
///
/// For a change that alters only the metadata, `from` and `to` are the same
/// path. Otherwise as [`write_versioned_with_metadata`].
pub fn copy_versioned_with_metadata(ctx: &Context, from: &str, to: &str, metadata: &Metadata) -> io::Result<()> {
    if !is_versioned(ctx, to)? {
        return copy_atomic_with_metadata(ctx, from, to, metadata, None);
    }

    let version_dir = version_dir_for(&to_account_path(ctx, to)?);
    create_dir_all(ctx, &version_dir)?;

    let version_path = join_path(&version_dir, &to_version(metadata));
    copy_atomic_with_metadata(ctx, from, &version_path, metadata, None)?;

    link_atomic(ctx, &version_path, to)
}

/// Store `metadata` as a version of the directory `path`. Call this before
/// `path` takes that metadata, so what `path` carries is always among its
/// versions.
///
/// As for [`write_versioned_with_metadata`], storing the same metadata twice
/// leaves one version, and versions stay stored through removals of `path`.
pub fn create_dir_version(ctx: &Context, path: &str, metadata: &Metadata) -> io::Result<()> {
    if !is_versioned(ctx, path)? {
        return Ok(());
    }

    write_version(ctx, path, &[], metadata).map(|_| ())
}

/// Whether writes to `path` are stored as versions of it.
///
/// They are everywhere but in the version store itself, and the entries of the
/// request log, which a server writes once and never replaces.
pub fn is_versioned(ctx: &Context, path: &str) -> io::Result<bool> {
    let account_path = to_account_path(ctx, path)?;

    Ok(!is_version_store_path(&account_path) && !is_request_log_entry_path(&account_path))
}

/// The versions of `path`, newest first, what it holds now included. Empty
/// where it has none.
///
/// A path removed and written again keeps the versions it had before, so the
/// versions may be of more than one entry — told apart by their metadata's
/// `id`. A delete stored as a version has its metadata marked `deleted`.
pub fn read_versions(ctx: &Context, path: &str) -> io::Result<Vec<Version>> {
    let version_dir = version_dir_for(&to_account_path(ctx, path)?);
    if !exists(ctx, &version_dir) {
        return Ok(Vec::new());
    }

    let mut versions = Vec::new();
    for version_path in read_dir(ctx, &version_dir)? {
        if file_name(&version_path).starts_with('.') { continue; }

        versions.push(Version {
            id: file_name(&version_path).to_string(),
            metadata: read_metadata_attributes(ctx, &version_path)?,
        });
    }

    versions.reverse();

    Ok(versions)
}

/// The metadata of the version of `path` that `id` names, where `ctx`'s
/// version store holds it.
pub fn read_version_metadata_attributes(ctx: &Context, path: &str, id: &str) -> io::Result<Option<Metadata>> {
    match read_metadata_attributes(ctx, &version_path_for(&to_account_path(ctx, path)?, id)) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The ids of `metadata`'s version and of those it was made on, newest first,
/// as far back as `ctx`'s version store holds them. The version named by the
/// last one held is listed too, held or not.
pub fn get_version_chain(ctx: &Context, path: &str, metadata: &Metadata) -> io::Result<Vec<String>> {
    let mut chain = vec![to_version(metadata)];
    let mut parent = metadata.parent_version.clone();
    while let Some(id) = parent {
        parent = read_version_metadata_attributes(ctx, path, &id)?.and_then(|metadata| metadata.parent_version);
        chain.push(id);
    }

    Ok(chain)
}

/// Purge every version of `path` and of the paths beneath it from `ctx`'s own
/// store, along with anything else stored beside them — including what `path`
/// holds now and the metadata a directory sets aside for a rewrite still under
/// way, so call this only once `path` is gone.
pub fn purge_stored_versions(ctx: &Context, path: &str) -> io::Result<()> {
    if !exists(ctx, VERSIONS_DIR) {
        return Ok(());
    }

    let account_path = to_account_path(ctx, path)?;
    let child_prefix = format!("{}/", account_path.trim_end_matches('/'));

    for version_dir in read_dir(ctx, VERSIONS_DIR)? {
        let Ok(history_of) = from_path_segment(file_name(&version_dir)) else { continue; };
        if history_of == account_path || history_of.starts_with(&child_prefix) {
            remove_dir_all(ctx, &version_dir)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::thread;
    use std::time::Duration;

    use super::*;

    use crate::crypto::create_secret_key;
    use crate::identity::create_identity;
    use crate::metadata::{apply_key_to_metadata, create_metadata, sign_metadata, write_metadata_attributes};
    use crate::storage::{read, remove_file, write_atomic_without_metadata};
    use crate::testing::fs::{TEST_ADDRESS, create_plain_test_metadata, create_test_account, in_test_dir};
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
        // Versions are ordered by the millisecond they were written in, so
        // each write gets one of its own.
        thread::sleep(Duration::from_millis(2));

        let metadata = create_plain_test_metadata(identity, secret_key, body);
        write_versioned_with_metadata(ctx, path, body, &metadata).unwrap();
        metadata
    }

    #[test]
    fn an_id_names_one_metadata_and_no_other() {
        let (identity, secret_key) = create_identity(TEST_ADDRESS, None).unwrap();

        let mut metadata = create_metadata(&identity.address, None);
        sign_metadata(&secret_key, &mut metadata, Some(b"body")).unwrap();
        let id = to_version(&metadata);

        assert_eq!(to_version(&metadata), id, "the same metadata names the same version");

        // A member change leaves the body, and so the body hash, alone.
        let mut changed = metadata.clone();
        changed.members.push(Member { address: "other@example.com".to_string(), permission: Permission::Reader, key: None });
        sign_metadata(&secret_key, &mut changed, Some(b"body")).unwrap();

        assert_ne!(to_version(&changed), id, "metadata that differs names a version of its own");

        let mut signed_otherwise = metadata.clone();
        signed_otherwise.signature.value = vec![0; signed_otherwise.signature.value.len()];

        assert_eq!(to_version(&signed_otherwise), id, "the signature plays no part");
    }

    #[test]
    fn a_version_kept_aside_leaves_the_path_alone_and_reads_back_whole() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let metadata = create_plain_test_metadata(&identity, &secret_key, b"kept");

            write_version(&context, "/a.txt", b"kept", &metadata).unwrap();

            assert!(!exists(&context, "/a.txt"), "only the store is written");
            let version_path = version_path_for("/a.txt", &to_version(&metadata));
            assert_eq!(read(&context, &version_path).unwrap(), b"kept");
            assert_eq!(to_version(&read_metadata_attributes(&context, &version_path).unwrap()), to_version(&metadata));
        });
    }

    #[test]
    fn what_a_path_holds_is_its_newest_version_and_costs_no_copy() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let before = write(&context, &identity, &secret_key, "/a.txt", b"before");
            let after = write(&context, &identity, &secret_key, "/a.txt", b"after");

            let versions = read_versions(&context, "/a.txt").unwrap();
            assert_eq!(versions.len(), 2);
            assert_eq!(versions[0].id, to_version(&after));

            let before_path = version_path_for("/a.txt", &to_version(&before));
            assert_eq!(read(&context, &before_path).unwrap(), b"before");
            assert_eq!(read_metadata_attributes(&context, &before_path).unwrap().signature.value, before.signature.value);

            let after_path = version_path_for("/a.txt", &to_version(&after));
            let live_inode = fs::metadata(context.root.join("a.txt")).unwrap().ino();
            let version_inode = fs::metadata(context.root.join(after_path.trim_start_matches('/'))).unwrap().ino();
            assert_eq!(live_inode, version_inode, "the newest version is the live entry itself");
        });
    }

    #[test]
    fn writing_the_same_metadata_twice_leaves_one_version() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let metadata = write(&context, &identity, &secret_key, "/a.txt", b"body");

            write_versioned_with_metadata(&context, "/a.txt", b"body", &metadata).unwrap();

            assert_eq!(read_versions(&context, "/a.txt").unwrap().len(), 1);
            assert_eq!(read(&context, "/a.txt").unwrap(), b"body");
        });
    }

    #[test]
    fn versions_outlive_a_removal_and_carry_on_under_the_entry_written_after_it() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let removed = write(&context, &identity, &secret_key, "/a.txt", b"removed");
            remove_file(&context, "/a.txt").unwrap();

            assert_eq!(read_versions(&context, "/a.txt").unwrap().len(), 1, "a removal keeps the versions");

            let recreated = write(&context, &identity, &secret_key, "/a.txt", b"recreated");

            let versions = read_versions(&context, "/a.txt").unwrap();
            assert_eq!(versions.len(), 2);
            assert_eq!(versions[0].metadata.id, recreated.id);
            assert_eq!(versions[1].metadata.id, removed.id, "the entry removed is still in the history");

            let removed_path = version_path_for("/a.txt", &versions[1].id);
            assert_eq!(read(&context, &removed_path).unwrap(), b"removed");
        });
    }

    #[test]
    fn a_directory_is_kept_as_its_metadata_alone() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            create_dir_all(&context, "/notes").unwrap();
            let mut metadata = create_metadata(&identity.address, None);
            sign_metadata(&secret_key, &mut metadata, None).unwrap();
            create_dir_version(&context, "/notes", &metadata).unwrap();

            write_metadata_attributes(&context, "/notes", &metadata, None).unwrap();

            let versions = read_versions(&context, "/notes").unwrap();
            assert_eq!(versions.len(), 1);
            assert_eq!(read(&context, &version_path_for("/notes", &versions[0].id)).unwrap(), b"", "a directory version holds the metadata and no body");
            assert!(versions[0].metadata.body_hash.is_none());
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
            }

            let versions = read_versions(&context, "/a.txt").unwrap();
            assert_eq!(versions.len(), ids.len(), "a version is stored per write a path has taken");
            assert_eq!(versions[0].id, *ids.last().unwrap(), "newest first");
            assert_eq!(versions.last().unwrap().id, ids[0], "oldest last, and still there");
        });
    }

    #[test]
    fn a_rewrite_left_part_way_does_not_show_up_as_a_version() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let metadata = write(&context, &identity, &secret_key, "/a.txt", b"body");

            // What a stopped rewrite leaves beside the versions: an entry
            // carrying no metadata, which a version could never be.
            let marker = join_path(&version_dir_for("/a.txt"), ".previous");
            write_atomic_without_metadata(&context, &marker, &[]).unwrap();

            let versions = read_versions(&context, "/a.txt").unwrap();
            assert_eq!(versions.len(), 1);
            assert_eq!(versions[0].id, to_version(&metadata));
        });
    }

    #[test]
    fn purging_a_directorys_versions_purges_the_versions_beneath_it() {
        in_test_dir("ark_versions_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            create_dir_all(&context, "/notes").unwrap();
            create_dir_all(&context, "/notebook").unwrap();

            write(&context, &identity, &secret_key, "/notes/a.txt", b"inside");
            write(&context, &identity, &secret_key, "/notebook/b.txt", b"beside");

            purge_stored_versions(&context, "/notes").unwrap();

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
            write(&context, &identity, &secret_key, "/.ark/versions/planted", b"planted");

            assert_eq!(read(&context, "/.ark/versions/planted").unwrap(), b"planted");
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
            write_versioned_with_metadata(&context, "/a.txt", b"cipher", &metadata).unwrap();

            let version_path = version_path_for("/a.txt", &to_version(&metadata));
            let stored = read_metadata_attributes(&context, &version_path).unwrap();
            assert_eq!(stored.members[0].key.as_ref().unwrap().value, metadata.members[0].key.as_ref().unwrap().value);
        });
    }
}
