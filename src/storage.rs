//! The filesystem, reached by account path.
//!
//! Each operation here is its [`std::fs`] or [`xattr`] equivalent taking an
//! account path in place of a filesystem one, and differs from it only as its
//! own documentation says.
//!
//! Each path argument takes any of the forms
//! [`to_account_path`](crate::paths::to_account_path) accepts, and an
//! operation errors with `InvalidInput` rather than touching anything outside
//! the account root.
//!
//! A `_raw` variant takes the account root in place of a [`Context`], for a
//! caller running before its own can be built.

use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::metadata::{read_local_metadata_attributes, read_metadata_attributes, write_metadata_attributes};
use crate::paths::{is_temp_path, join_path, temp_path_for, to_account_path, to_fs_path, to_fs_path_raw};
use crate::types::{Context, LocalMetadata, Metadata};

/// The body of `path`, as [`std::fs::read`] gives it.
pub fn read(ctx: &Context, path: &str) -> io::Result<Vec<u8>> {
    fs::read(to_fs_path(ctx, path)?)
}

/// The body of `path` as text, as [`std::fs::read_to_string`] gives it.
pub fn read_to_string(ctx: &Context, path: &str) -> io::Result<String> {
    read_to_string_raw(&ctx.root, path)
}

/// As [`read_to_string`], for a caller holding only the account root — one
/// running before its [`Context`] can be built.
pub fn read_to_string_raw(root: &Path, path: &str) -> io::Result<String> {
    fs::read_to_string(to_fs_path_raw(root, path)?)
}

/// Move `from` to `to`, as [`std::fs::rename`] does.
///
/// The entry keeps the metadata it carries, and arrives whole, so a reader
/// sees either the previous `to` or the moved entry, never a partial write.
pub fn rename(ctx: &Context, from: &str, to: &str) -> io::Result<()> {
    fs::rename(to_fs_path(ctx, from)?, to_fs_path(ctx, to)?)
}

/// Create `link` as another name for the entry at `original`, as
/// [`std::fs::hard_link`] does.
///
/// The metadata is the entry's own rather than a copy each name carries, so a
/// change to it through either name is seen through both.
pub fn link(ctx: &Context, original: &str, link: &str) -> io::Result<()> {
    fs::hard_link(to_fs_path(ctx, original)?, to_fs_path(ctx, link)?)
}

/// Make `path` another name for the entry at `original`, as a single visible
/// change, replacing whatever `path` already holds.
///
/// As [`link`], the metadata is the entry's own. Where `path` is already there
/// a reader sees either it or the linked entry, never neither.
///
/// `path`'s parent must exist, as it must for [`std::fs::write`].
pub fn link_atomic(ctx: &Context, original: &str, path: &str) -> io::Result<()> {
    let target = to_fs_path(ctx, path)?;
    let temp = to_fs_path(ctx, &temp_path_for(path))?;

    let result = fs::hard_link(to_fs_path(ctx, original)?, &temp).and_then(|_| fs::rename(&temp, &target));

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

/// The names of the extended attributes of `path`, as [`xattr::list`] gives
/// them, each lossily converted to UTF-8.
pub fn list_attributes(ctx: &Context, path: &str) -> io::Result<Vec<String>> {
    Ok(xattr::list(to_fs_path(ctx, path)?)?.map(|name| name.to_string_lossy().into_owned()).collect())
}

/// The value of the `name` attribute of `path`, as [`xattr::get`] gives it.
pub fn read_attribute(ctx: &Context, path: &str, name: &str) -> io::Result<Option<Vec<u8>>> {
    xattr::get(to_fs_path(ctx, path)?, name)
}

/// Set the `name` attribute of `path`, as [`xattr::set`] does.
///
/// Written where the entry stands rather than as a single visible change, so
/// a reader can see it land on its own. Where that matters, use
/// [`crate::metadata::write_metadata_attributes_atomic`] — or, for a body and
/// the attributes that belong with it, [`write_atomic_with_metadata`].
pub fn write_attribute(ctx: &Context, path: &str, name: &str, value: &[u8]) -> io::Result<()> {
    xattr::set(to_fs_path(ctx, path)?, name, value)
}

/// Remove the `name` attribute of `path`, as [`xattr::remove`] does.
///
/// Removed where the entry stands rather than as a single visible change, so
/// a reader can see it go on its own. Where that matters, use
/// [`crate::metadata::write_metadata_attributes_atomic`] — or, for a body and
/// the attributes that belong with it, [`write_atomic_with_metadata`].
pub fn remove_attribute(ctx: &Context, path: &str, name: &str) -> io::Result<()> {
    xattr::remove(to_fs_path(ctx, path)?, name)
}

/// Create `path` as a directory, as [`std::fs::create_dir`] does.
pub fn create_dir(ctx: &Context, path: &str) -> io::Result<()> {
    fs::create_dir(to_fs_path(ctx, path)?)
}

/// Create `path` as a directory and every missing parent, as
/// [`std::fs::create_dir_all`] does.
pub fn create_dir_all(ctx: &Context, path: &str) -> io::Result<()> {
    create_dir_all_raw(&ctx.root, path)
}

/// As [`create_dir_all`], for a caller holding only the account root — one
/// running before its [`Context`] can be built.
pub fn create_dir_all_raw(root: &Path, path: &str) -> io::Result<()> {
    fs::create_dir_all(to_fs_path_raw(root, path)?)
}

/// The entries of the directory `path`, as [`std::fs::DirEntry::path`] gives
/// them.
///
/// Account-absolute whatever form `path` took, so an entry can be passed
/// straight back to any operation here.
///
/// Sorted by name in byte order, which [`std::fs::read_dir`] does not promise
/// — so a directory lists the same way on every host, and a listing served to
/// a peer or walked by sync is reproducible. Byte order, not collation:
/// uppercase sorts before lowercase.
///
/// Half-written temporary entries are never listed, nor are names that are
/// not UTF-8 — a name no account path can carry.
pub fn read_dir(ctx: &Context, path: &str) -> io::Result<Vec<String>> {
    let account_path = to_account_path(ctx, path)?;

    let mut paths: Vec<String> = Vec::new();
    for entry in fs::read_dir(ctx.root.join(account_path.trim_start_matches('/')))? {
        let entry = entry?;
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        if is_temp_path(&name) {
            continue;
        }
        paths.push(join_path(&account_path, &name));
    }

    // Every path here shares the parent prefix, so ordering them orders their
    // names. Names within a directory are unique, so stability buys nothing.
    paths.sort_unstable();

    Ok(paths)
}

/// Remove the file `path`, as [`std::fs::remove_file`] does.
pub fn remove_file(ctx: &Context, path: &str) -> io::Result<()> {
    fs::remove_file(to_fs_path(ctx, path)?)
}

/// Remove the empty directory `path`, as [`std::fs::remove_dir`] does.
pub fn remove_dir(ctx: &Context, path: &str) -> io::Result<()> {
    fs::remove_dir(to_fs_path(ctx, path)?)
}

/// Remove the directory `path` and everything in it, as
/// [`std::fs::remove_dir_all`] does.
pub fn remove_dir_all(ctx: &Context, path: &str) -> io::Result<()> {
    fs::remove_dir_all(to_fs_path(ctx, path)?)
}

/// Whether there is an entry at `path`, as [`std::path::Path::exists`]
/// answers.
///
/// False for a path that cannot be resolved at all, rather than an error.
pub fn exists(ctx: &Context, path: &str) -> bool {
    exists_raw(&ctx.root, path)
}

/// As [`exists`], for a caller holding only the account root — one running
/// before its [`Context`] can be built.
pub fn exists_raw(root: &Path, path: &str) -> bool {
    to_fs_path_raw(root, path).map(|target| target.exists()).unwrap_or(false)
}

/// Whether `path` is a directory, as [`std::path::Path::is_dir`] answers.
///
/// False for a path that cannot be resolved at all, rather than an error.
pub fn is_dir(ctx: &Context, path: &str) -> bool {
    to_fs_path(ctx, path).map(|target| target.is_dir()).unwrap_or(false)
}

/// Whether `path` is a file, as [`std::path::Path::is_file`] answers.
///
/// False for a path that cannot be resolved at all, rather than an error.
pub fn is_file(ctx: &Context, path: &str) -> bool {
    to_fs_path(ctx, path).map(|target| target.is_file()).unwrap_or(false)
}

/// Whether `path` is a symbolic link, as [`std::path::Path::is_symlink`]
/// answers.
///
/// False for a path that cannot be resolved at all, rather than an error.
pub fn is_symlink(ctx: &Context, path: &str) -> bool {
    to_fs_path(ctx, path).map(|target| target.is_symlink()).unwrap_or(false)
}

/// The size in bytes of `path`, the one part of [`std::fs::metadata`] used
/// here.
pub fn size(ctx: &Context, path: &str) -> io::Result<u64> {
    Ok(fs::metadata(to_fs_path(ctx, path)?)?.len())
}

/// Write `contents` to `path` as a single visible change, keeping the metadata
/// `path` already carries.
///
/// The file is built complete under a temporary sibling name and moved into
/// place, so a reader sees either the previous file or the whole new one,
/// never a partial write — including the metadata, which is a dozen separate
/// attributes and cannot be replaced atomically where it sits.
///
/// `path`'s parent must exist, as it must for [`std::fs::write`].
pub fn write_atomic(ctx: &Context, path: &str, contents: &[u8]) -> io::Result<()> {
    let metadata = read_metadata_attributes(ctx, path).ok();
    let local_metadata = read_local_metadata_attributes(ctx, path).ok();

    write_atomic_inner(ctx, path, contents, metadata.as_ref(), local_metadata.as_ref())
}

/// Write `contents` to `path` along with `metadata`, as a single visible change,
/// replacing the metadata `path` already carries.
///
/// Otherwise as [`write_atomic`].
pub fn write_atomic_with_metadata(ctx: &Context, path: &str, contents: &[u8], metadata: &Metadata, local_metadata: Option<&LocalMetadata>) -> io::Result<()> {
    write_atomic_inner(ctx, path, contents, Some(metadata), local_metadata)
}

/// Write `contents` to `path` as a single visible change, dropping the metadata
/// `path` already carries.
///
/// Otherwise as [`write_atomic`].
pub fn write_atomic_without_metadata(ctx: &Context, path: &str, contents: &[u8]) -> io::Result<()> {
    write_atomic_inner(ctx, path, contents, None, None)
}

/// As [`write_atomic_without_metadata`], for a caller holding only the account
/// root — one running before its [`Context`] can be built.
///
/// There is no raw form that lands metadata: the metadata at rest is written
/// through a [`Context`] (see [`write_metadata_attributes`]), so a caller
/// with a root alone can only write a body.
pub fn write_atomic_without_metadata_raw(root: &Path, path: &str, contents: &[u8]) -> io::Result<()> {
    let target = to_fs_path_raw(root, path)?;
    let temp = to_fs_path_raw(root, &temp_path_for(path))?;

    let result = fs::write(&temp, contents).and_then(|_| fs::rename(&temp, &target));

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

fn write_atomic_inner(ctx: &Context, path: &str, contents: &[u8], metadata: Option<&Metadata>, local_metadata: Option<&LocalMetadata>) -> io::Result<()> {
    let temp_path = temp_path_for(path);
    let temp = to_fs_path(ctx, &temp_path)?;

    let result = (|| {
        fs::write(&temp, contents)?;

        if let Some(metadata) = metadata {
            write_metadata_attributes(ctx, &temp_path, metadata, local_metadata)?;
        }

        fs::rename(&temp, to_fs_path(ctx, path)?)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

/// Write `body` to `path` as an entry no other user can read, as a single
/// visible change, keeping the metadata `path` already carries — for a secret
/// a reader would be able to act as the account with.
///
/// On a platform without unix permissions the body is readable as any other
/// entry's is.
///
/// Otherwise as [`write_atomic`].
pub fn write_private_atomic(ctx: &Context, path: &str, body: &[u8]) -> io::Result<()> {
    let metadata = read_metadata_attributes(ctx, path).ok();
    let local_metadata = read_local_metadata_attributes(ctx, path).ok();

    write_private_atomic_inner(ctx, path, body, metadata.as_ref(), local_metadata.as_ref())
}

/// Write `body` to `path` along with `metadata`, as a single visible change,
/// replacing the metadata `path` already carries.
///
/// Otherwise as [`write_private_atomic`].
pub fn write_private_atomic_with_metadata(ctx: &Context, path: &str, body: &[u8], metadata: &Metadata, local_metadata: Option<&LocalMetadata>) -> io::Result<()> {
    write_private_atomic_inner(ctx, path, body, Some(metadata), local_metadata)
}

/// Write `body` to `path` as a single visible change, dropping the metadata
/// `path` already carries.
///
/// Otherwise as [`write_private_atomic`].
pub fn write_private_atomic_without_metadata(ctx: &Context, path: &str, body: &[u8]) -> io::Result<()> {
    write_private_atomic_inner(ctx, path, body, None, None)
}

/// As [`write_private_atomic_without_metadata`], for a caller holding only the
/// account root — one running before its [`Context`] can be built.
///
/// There is no raw form that lands metadata, as for
/// [`write_atomic_without_metadata_raw`].
pub fn write_private_atomic_without_metadata_raw(root: &Path, path: &str, body: &[u8]) -> io::Result<()> {
    let target = to_fs_path_raw(root, path)?;
    let temp = to_fs_path_raw(root, &temp_path_for(path))?;

    let result = create_private(&temp, body).and_then(|_| fs::rename(&temp, &target));

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

fn write_private_atomic_inner(ctx: &Context, path: &str, body: &[u8], metadata: Option<&Metadata>, local_metadata: Option<&LocalMetadata>) -> io::Result<()> {
    let temp_path = temp_path_for(path);
    let temp = to_fs_path(ctx, &temp_path)?;

    let result = (|| {
        create_private(&temp, body)?;

        if let Some(metadata) = metadata {
            write_metadata_attributes(ctx, &temp_path, metadata, local_metadata)?;
        }

        fs::rename(&temp, to_fs_path(ctx, path)?)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

fn create_private(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    // The mode goes on as the entry is created rather than after it, so the
    // body never sits in an entry anyone else can open — a descriptor taken in
    // that gap would keep its read on the secret whatever the mode became.
    #[cfg(unix)]
    options.mode(0o600);

    options.open(path)?.write_all(body)
}

/// Copy the body of `from` to `to` as a single visible change, keeping the
/// metadata `to` already carries.
///
/// The body is copied rather than read, so its size does not matter. For a
/// change that alters only the metadata, `from` and `to` are the same path.
///
/// Otherwise as [`write_atomic`].
pub fn copy_atomic(ctx: &Context, from: &str, to: &str) -> io::Result<()> {
    let metadata = read_metadata_attributes(ctx, to).ok();
    let local_metadata = read_local_metadata_attributes(ctx, to).ok();

    copy_atomic_inner(ctx, from, to, metadata.as_ref(), local_metadata.as_ref())
}

/// Copy the body of `from` to `to` along with `metadata`, as a single visible
/// change, replacing the metadata `to` already carries.
///
/// Otherwise as [`copy_atomic`].
pub fn copy_atomic_with_metadata(ctx: &Context, from: &str, to: &str, metadata: &Metadata, local_metadata: Option<&LocalMetadata>) -> io::Result<()> {
    copy_atomic_inner(ctx, from, to, Some(metadata), local_metadata)
}

/// Copy the body of `from` to `to` as a single visible change, dropping the
/// metadata `to` already carries.
///
/// Otherwise as [`copy_atomic`].
pub fn copy_atomic_without_metadata(ctx: &Context, from: &str, to: &str) -> io::Result<()> {
    copy_atomic_inner(ctx, from, to, None, None)
}

/// As [`copy_atomic_without_metadata`], for a caller holding only the account
/// root — one running before its [`Context`] can be built.
///
/// There is no raw form that lands metadata, as for
/// [`write_atomic_without_metadata_raw`].
pub fn copy_atomic_without_metadata_raw(root: &Path, from: &str, to: &str) -> io::Result<()> {
    let source = to_fs_path_raw(root, from)?;
    let target = to_fs_path_raw(root, to)?;
    let temp = to_fs_path_raw(root, &temp_path_for(to))?;

    let result = fs::copy(&source, &temp).and_then(|_| fs::rename(&temp, &target));

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

fn copy_atomic_inner(ctx: &Context, from: &str, to: &str, metadata: Option<&Metadata>, local_metadata: Option<&LocalMetadata>) -> io::Result<()> {
    let temp_path = temp_path_for(to);
    let temp = to_fs_path(ctx, &temp_path)?;

    let result = (|| {
        fs::copy(to_fs_path(ctx, from)?, &temp)?;

        if let Some(metadata) = metadata {
            write_metadata_attributes(ctx, &temp_path, metadata, local_metadata)?;
        }

        fs::rename(&temp, to_fs_path(ctx, to)?)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::path::Path;
    use super::*;

    use crate::testing::fs::{TEST_ADDRESS, create_plain_test_metadata, create_test_account, in_test_dir, write_plain_test_file};
    use crate::types::{Identity, Key};

    fn account(temp_dir: &Path) -> (Context, Identity, Key) {
        let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
        let context = Context {
            root: account_dir,
            identity: identity.clone(),
            identity_key: Some(secret_key.clone()),
        };

        (context, identity, secret_key)
    }

    #[test]
    fn removing_a_directory_as_a_file_errors_and_the_other_way_round() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            fs::create_dir_all(context.root.join("notes")).unwrap();
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"account");

            assert_eq!(remove_file(&context, "/notes").unwrap_err().kind(), ErrorKind::IsADirectory);
            assert_eq!(remove_dir_all(&context, "/a.txt").unwrap_err().kind(), ErrorKind::NotADirectory);

            assert!(exists(&context, "/notes"), "a rejected removal removes nothing");
            assert!(exists(&context, "/a.txt"));
        });
    }

    #[test]
    fn rename_carries_the_metadata() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"account");
            let before = read_metadata_attributes(&context, "/a.txt").unwrap();

            rename(&context, "/a.txt", "/moved.txt").unwrap();

            assert_eq!(read(&context, "/moved.txt").unwrap(), b"account");
            assert_eq!(read_metadata_attributes(&context, "/moved.txt").unwrap().id, before.id);
            assert!(!exists(&context, "/a.txt"));
        });
    }

    #[test]
    fn write_private_atomic_with_metadata_lands_whole_and_private_over_a_readable_entry() {
        use std::os::unix::fs::PermissionsExt;

        in_test_dir("ark_storage_test", |context_dir| {
            let (context, identity, secret_key) = account(context_dir);
            let metadata = create_plain_test_metadata(&identity, &secret_key, b"secret");
            fs::write(context.root.join("a.key"), b"before").unwrap();
            fs::set_permissions(context.root.join("a.key"), fs::Permissions::from_mode(0o644)).unwrap();

            write_private_atomic_with_metadata(&context, "/a.key", b"secret", &metadata, None).unwrap();

            assert_eq!(read(&context, "/a.key").unwrap(), b"secret");
            assert_eq!(read_metadata_attributes(&context, "/a.key").unwrap().id, metadata.id);
            assert_eq!(fs::metadata(context.root.join("a.key")).unwrap().permissions().mode() & 0o777, 0o600);

            let names: Vec<String> = fs::read_dir(&context.root).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
            assert!(!names.iter().any(|name| is_temp_path(name)), "a temporary entry was left behind");
        });
    }

    #[test]
    fn write_atomic_without_metadata_raw_lands_whole_and_carries_nothing_over() {
        in_test_dir("ark_storage_test", |context_dir| {
            let (context, identity, secret_key) = account(context_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"before");

            write_atomic_without_metadata_raw(&context.root, "/a.txt", b"after").unwrap();

            assert_eq!(read(&context, "/a.txt").unwrap(), b"after");
            // The entry behind the name is a new one, so what the old entry
            // carried does not come with it. write_atomic is what keeps it.
            assert!(read_metadata_attributes(&context, "/a.txt").is_err());
        });
    }

    #[test]
    fn write_atomic_keeps_the_metadata_so_a_replaced_body_stays_the_same_file() {
        in_test_dir("ark_storage_test", |context_dir| {
            let (context, identity, secret_key) = account(context_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"before");
            let before = read_metadata_attributes(&context, "/a.txt").unwrap();

            write_atomic(&context, "/a.txt", b"after").unwrap();

            assert_eq!(read(&context, "/a.txt").unwrap(), b"after");
            assert_eq!(read_metadata_attributes(&context, "/a.txt").unwrap().id, before.id,
                "a put after this must continue the same file, not mint another");
        });
    }

    #[test]
    fn a_link_carries_the_metadata_and_keeps_what_it_held_when_the_original_is_replaced() {
        in_test_dir("ark_storage_test", |context_dir| {
            let (context, identity, secret_key) = account(context_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"before");
            let before = read_metadata_attributes(&context, "/a.txt").unwrap();

            link(&context, "/a.txt", "/kept.txt").unwrap();
            assert_eq!(read_metadata_attributes(&context, "/kept.txt").unwrap().id, before.id);

            // write_atomic replaces the name, not the entry the link also
            // reaches, so what was linked stays what it was.
            write_atomic_with_metadata(&context, "/a.txt", b"after", &before, None).unwrap();

            assert_eq!(read(&context, "/a.txt").unwrap(), b"after");
            assert_eq!(read(&context, "/kept.txt").unwrap(), b"before");
        });
    }

    #[test]
    fn linking_onto_a_name_already_taken_errors() {
        in_test_dir("ark_storage_test", |context_dir| {
            let (context, identity, secret_key) = account(context_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"a");
            write_plain_test_file(&context.root.join("b.txt"), &identity, &secret_key, b"b");

            assert_eq!(link(&context, "/a.txt", "/b.txt").unwrap_err().kind(), ErrorKind::AlreadyExists);
        });
    }

    #[test]
    fn both_ends_of_a_rename_are_checked_against_the_account_root() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"account");

            assert_eq!(rename(&context, "/a.txt", "/../outside.txt").unwrap_err().kind(), ErrorKind::InvalidInput);

            assert!(exists(&context, "/a.txt"), "a rejected move leaves the entry alone");
            assert!(!context.root.parent().unwrap().join("outside.txt").exists());
        });
    }

    #[test]
    fn a_directory_is_created_and_removed_on_its_own() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);

            create_dir(&context, "/notes").unwrap();
            assert!(is_dir(&context, "/notes"));
            assert_eq!(create_dir(&context, "/notes").unwrap_err().kind(), ErrorKind::AlreadyExists);

            write_plain_test_file(&context.root.join("notes/todo.txt"), &identity, &secret_key, b"buy milk");
            assert_eq!(remove_dir(&context, "/notes").unwrap_err().kind(), ErrorKind::DirectoryNotEmpty);

            remove_file(&context, "/notes/todo.txt").unwrap();
            remove_dir(&context, "/notes").unwrap();
            assert!(!exists(&context, "/notes"));
        });
    }

    #[test]
    fn read_dir_lists_account_absolute_entries_and_no_temporary_ones() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"account");
            fs::write(to_fs_path(&context, &temp_path_for("/b.txt")).unwrap(), b"half written").unwrap();

            let entries = read_dir(&context, "/").unwrap();

            // What `read_dir` hands back goes straight back in.
            assert!(entries.contains(&"/a.txt".to_string()));
            assert_eq!(read(&context, "/a.txt").unwrap(), b"account");
            assert!(entries.iter().all(|entry| !is_temp_path(entry)), "no temporary entries");
        });
    }

    #[test]
    fn write_atomic_with_metadata_replaces_body_and_metadata_together() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let path = context.root.join("notes.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"first");

            let metadata = create_plain_test_metadata(&identity, &secret_key, b"second");
            write_atomic_with_metadata(&context, "/notes.txt", b"second", &metadata, None).unwrap();

            assert_eq!(fs::read(&path).unwrap(), b"second");
            assert_eq!(read_metadata_attributes(&context, "/notes.txt").unwrap().id, metadata.id);
            assert_eq!(fs::read_dir(&context.root).unwrap().count(), 2, "nothing but .ark and the file itself");
        });
    }

    #[test]
    fn write_atomic_keeps_the_metadata_already_there() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let path = context.root.join("notes.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"first");
            let before = read_metadata_attributes(&context, "/notes.txt").unwrap();

            write_atomic(&context, "/notes.txt", b"second").unwrap();

            assert_eq!(fs::read(&path).unwrap(), b"second");
            assert_eq!(read_metadata_attributes(&context, "/notes.txt").unwrap().id, before.id);
        });
    }

    #[test]
    fn write_atomic_without_metadata_drops_what_was_there() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("notes.txt"), &identity, &secret_key, b"first");

            write_atomic_without_metadata(&context, "/notes.txt", b"second").unwrap();

            assert!(read_metadata_attributes(&context, "/notes.txt").is_err());
        });
    }

    #[test]
    fn copy_atomic_with_metadata_onto_itself_keeps_the_body() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let path = context.root.join("notes.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"body");
            let before = read_metadata_attributes(&context, "/notes.txt").unwrap();

            let metadata = create_plain_test_metadata(&identity, &secret_key, b"body");
            copy_atomic_with_metadata(&context, "/notes.txt", "/notes.txt", &metadata, None).unwrap();

            assert_eq!(fs::read(&path).unwrap(), b"body");
            assert_ne!(read_metadata_attributes(&context, "/notes.txt").unwrap().id, before.id);
        });
    }

    #[test]
    fn copy_atomic_keeps_the_metadata_already_on_the_destination() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let path = context.root.join("notes.txt");
            write_plain_test_file(&context.root.join("source.txt"), &identity, &secret_key, b"second");
            write_plain_test_file(&path, &identity, &secret_key, b"first");
            let before = read_metadata_attributes(&context, "/notes.txt").unwrap();

            copy_atomic(&context, "/source.txt", "/notes.txt").unwrap();

            assert_eq!(fs::read(&path).unwrap(), b"second");
            assert_eq!(read_metadata_attributes(&context, "/notes.txt").unwrap().id, before.id);
        });
    }

    #[test]
    fn copy_atomic_without_metadata_drops_what_was_there() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("notes.txt"), &identity, &secret_key, b"first");

            copy_atomic_without_metadata(&context, "/notes.txt", "/notes.txt").unwrap();

            assert_eq!(read(&context, "/notes.txt").unwrap(), b"first");
            assert!(read_metadata_attributes(&context, "/notes.txt").is_err());
        });
    }

    #[test]
    fn copy_atomic_without_metadata_raw_lands_whole_and_carries_nothing_over() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"before");

            copy_atomic_without_metadata_raw(&context.root, "/a.txt", "/b.txt").unwrap();

            assert_eq!(read(&context, "/b.txt").unwrap(), b"before");
            assert!(read_metadata_attributes(&context, "/b.txt").is_err());
        });
    }

    #[test]
    fn copy_atomic_leaves_nothing_behind_when_it_fails() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, _, _) = account(temp_dir);

            assert!(copy_atomic(&context, "/missing", "/notes.txt").is_err());

            assert!(!context.root.join("notes.txt").exists());
            assert_eq!(fs::read_dir(&context.root).unwrap().count(), 1, "nothing but .ark");
        });
    }

}
