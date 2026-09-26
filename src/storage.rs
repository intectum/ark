//! The filesystem, reached by account path.
//!
//! Each operation here is its [`std::fs`] or [`xattr`] equivalent taking an
//! account path in place of a filesystem one, and differs from it only as its
//! own documentation says.
//!
//! Each path argument takes any of the forms [`to_account_path`] accepts, and
//! an operation errors with `InvalidInput` rather than touching anything
//! outside the account root.
//!
//! A `_raw` variant takes the account root in place of a [`Context`], for a
//! caller running before its own can be built.

use std::env::current_dir;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use uuid::Uuid;

use crate::identity::parse_address;
use crate::metadata::{read_local_metadata_attributes, read_metadata_attributes, write_metadata_attributes};
use crate::types::{Context, LocalMetadata, Metadata};
use crate::util::parse_uuid;

const TEMP_INFIX: &str = ".tmp-";

// The separator must not survive into a name that stands as one entry, and the
// escape character has to be escaped alongside it — otherwise two names that
// differ could meet in the same entry, and one would be read under the other's
// key. Everything else is left readable.
const SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS.add(b'%').add(b'/');

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

/// Write `body` to `path`, as [`std::fs::write`] does.
///
/// `path` keeps the metadata it already carries, and a reader can see a
/// half-written body. Where either matters, use [`write_atomic`].
pub fn write(ctx: &Context, path: &str, body: &[u8]) -> io::Result<()> {
    write_raw(&ctx.root, path, body)
}

/// As [`write`], for a caller holding only the account root — one running
/// before its [`Context`] can be built.
pub fn write_raw(root: &Path, path: &str, body: &[u8]) -> io::Result<()> {
    fs::write(to_fs_path_raw(root, path)?, body)
}

/// Move `from` to `to`, as [`std::fs::rename`] does.
///
/// The entry keeps the metadata it carries, and arrives whole, so a reader
/// sees either the previous `to` or the moved entry, never a partial write.
pub fn rename(ctx: &Context, from: &str, to: &str) -> io::Result<()> {
    fs::rename(to_fs_path(ctx, from)?, to_fs_path(ctx, to)?)
}

/// Copy the body of `from` to `to`, as [`std::fs::copy`] does, and give back
/// the number of bytes copied.
///
/// Only the body is copied — `to` keeps the metadata it already carries, and
/// gets none where it is new. To copy a body and land metadata with it, use
/// [`write_atomic_with_metadata`] with [`Body::CopyOf`].
pub fn copy(ctx: &Context, from: &str, to: &str) -> io::Result<u64> {
    fs::copy(to_fs_path(ctx, from)?, to_fs_path(ctx, to)?)
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
/// a reader can see it land on its own. Where that matters, and for a body
/// and the attributes that belong with it, use [`write_atomic_with_metadata`]
/// — or, for a directory, [`crate::metadata::write_metadata_attributes`].
pub fn write_attribute(ctx: &Context, path: &str, name: &str, value: &[u8]) -> io::Result<()> {
    xattr::set(to_fs_path(ctx, path)?, name, value)
}

/// Remove the `name` attribute of `path`, as [`xattr::remove`] does.
///
/// Removed where the entry stands rather than as a single visible change, so
/// a reader can see it go on its own. Where that matters, and for a body and
/// the attributes that belong with it, use [`write_atomic_with_metadata`]
/// — or, for a directory, [`crate::metadata::write_metadata_attributes`].
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

/// The account-absolute form of a path argument, which every function here
/// resolves its argument to first.
///
/// Accepts the same forms as the client operations: relative (`team.json`),
/// account-absolute (`/groups/team.json`), or address (`bob@host/team.json`).
/// The relative form is taken against the working directory, so callers with
/// no meaningful one — the server — must pass the account-absolute form.
///
/// `.` and `..` are resolved here rather than left to the filesystem, so the
/// account path of an entry is the same however it was named.
///
/// Errors if the path lies outside the account root, `..` included. That check
/// is what keeps every operation here to the account tree, so it runs on every
/// call.
pub fn to_account_path(ctx: &Context, path: &str) -> io::Result<String> {
    to_account_path_raw(&ctx.root, path)
}

/// The account-absolute form of a path argument, taken against `root`.
///
/// As [`to_account_path`], for a caller holding only the account root — one
/// running before its [`Context`] can be built.
pub fn to_account_path_raw(root: &Path, path: &str) -> io::Result<String> {
    // The absolute form is settled before the address one, so an entry whose
    // own name carries an `@` is still addressable — an address never starts
    // with a `/`.
    let local_path = if let Some(relative) = path.strip_prefix('/') {
        root.join(relative)
    } else if path.contains('@') {
        let (_, _, path_part) = parse_address(path)?;
        root.join(path_part.trim_start_matches('/'))
    } else {
        current_dir()?.join(path)
    };

    let relative = local_path.strip_prefix(root)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path outside account root"))?;

    let outside = || io::Error::new(io::ErrorKind::InvalidInput, "path outside account root");

    let mut names: Vec<&str> = Vec::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => { names.pop().ok_or_else(outside)?; }
            Component::Normal(name) => names.push(name.to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not valid UTF-8"))?),
            _ => return Err(outside()),
        }
    }

    Ok(format!("/{}", names.join("/")))
}

/// Where `path` sits on the filesystem, the one place an account path becomes
/// one the standard library can take.
///
/// For a caller writing the body itself, or handing the entry to something
/// that works in filesystem paths; the functions above go through this.
pub fn to_fs_path(ctx: &Context, path: &str) -> io::Result<PathBuf> {
    to_fs_path_raw(&ctx.root, path)
}

/// As [`to_fs_path`], for a caller holding only the account root — one
/// running before its [`Context`] can be built.
pub fn to_fs_path_raw(root: &Path, path: &str) -> io::Result<PathBuf> {
    Ok(root.join(to_account_path_raw(root, path)?.trim_start_matches('/')))
}

/// The directory `path` sits in, or `None` when it names the account root or
/// carries no directory of its own.
pub fn parent_path(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches('/');

    match trimmed.rfind('/') {
        Some(0) => Some("/"),
        Some(slash) => Some(&trimmed[..slash]),
        None => None,
    }
}

/// `name` as an entry of the directory `path`.
pub fn join_path(path: &str, name: &str) -> String {
    format!("{}/{}", path.trim_end_matches('/'), name)
}

/// The last component of `path`, as [`std::path::Path::file_name`] gives it,
/// and empty where that gives nothing.
pub fn file_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');

    match trimmed.rfind('/') {
        Some(slash) => &trimmed[slash + 1..],
        None => trimmed,
    }
}

/// `name` as a single entry name, for a flat directory keyed by something that
/// is itself a path or an address.
///
/// Distinct names always give distinct entries, so nothing keyed this way can
/// be reached under another key's name.
pub fn to_path_segment(name: &str) -> String {
    utf8_percent_encode(name, SEGMENT_ENCODE_SET).to_string()
}

/// The body a [`write_atomic`] lands with.
pub enum Body<'a> {
    Bytes(&'a [u8]),
    /// The body of an existing entry, for a change that alters only the
    /// metadata. Copied rather than read, so the size does not matter.
    CopyOf(&'a str),
}

/// Write `body` to `path` as a single visible change, keeping the metadata
/// `path` already carries.
///
/// The file is built complete under a temporary sibling name and moved into
/// place, so a reader sees either the previous file or the whole new one,
/// never a partial write — including the metadata, which is a dozen separate
/// attributes and cannot be replaced atomically where it sits.
///
/// `path`'s parent must exist, as it must for [`std::fs::write`].
pub fn write_atomic(ctx: &Context, path: &str, body: Body) -> io::Result<()> {
    let metadata = read_metadata_attributes(ctx, path).ok();
    let local_metadata = read_local_metadata_attributes(ctx, path).ok();

    write_atomic_inner(ctx, path, body, metadata.as_ref(), local_metadata.as_ref())
}

/// Write `body` to `path` along with `metadata`, as a single visible change,
/// replacing the metadata `path` already carries.
///
/// The file is built complete under a temporary sibling name and moved into
/// place, so a reader sees either the previous file or the whole new one,
/// never a partial write — including the metadata, which is a dozen separate
/// attributes and cannot be replaced atomically where it sits.
///
/// `path`'s parent must exist, as it must for [`std::fs::write`].
pub fn write_atomic_with_metadata(ctx: &Context, path: &str, body: Body, metadata: &Metadata, local_metadata: Option<&LocalMetadata>) -> io::Result<()> {
    write_atomic_inner(ctx, path, body, Some(metadata), local_metadata)
}

/// Write `body` to `path` as a single visible change, dropping the metadata
/// `path` already carries.
///
/// The file is built complete under a temporary sibling name and moved into
/// place, so a reader sees either the previous file or the whole new one,
/// never a partial write — including the metadata, which is a dozen separate
/// attributes and cannot be replaced atomically where it sits.
///
/// `path`'s parent must exist, as it must for [`std::fs::write`].
pub fn write_atomic_without_metadata(ctx: &Context, path: &str, body: Body) -> io::Result<()> {
    write_atomic_inner(ctx, path, body, None, None)
}

fn write_atomic_inner(ctx: &Context, path: &str, body: Body, metadata: Option<&Metadata>, local_metadata: Option<&LocalMetadata>) -> io::Result<()> {
    let target = to_fs_path(ctx, path)?;
    let temp_path = temp_path_for(path);
    let temp = to_fs_path(ctx, &temp_path)?;

    let result = (|| {
        match body {
            Body::Bytes(bytes) => fs::write(&temp, bytes)?,
            Body::CopyOf(source) => { fs::copy(to_fs_path(ctx, source)?, &temp)?; }
        }

        if let Some(metadata) = metadata {
            write_metadata_attributes(ctx, &temp_path, metadata, local_metadata)?;
        }

        fs::rename(&temp, &target)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

/// A unique sibling name for a temporary version of `path`.
///
/// Named `.<name>.tmp-<uuid>`. The leading dot marks it internal.
pub fn temp_path_for(path: &str) -> String {
    let name = format!(".{}{}{}", file_name(path), TEMP_INFIX, Uuid::new_v4().hyphenated());

    match parent_path(path) {
        Some(parent) => join_path(parent, &name),
        None => name,
    }
}

/// Whether `path` names a temporary version of a file.
pub fn is_temp_path(path: &str) -> bool {
    let stem = match file_name(path).strip_prefix('.') {
        Some(s) => s,
        None => return false,
    };

    match stem.rfind(TEMP_INFIX) {
        Some(infix) => parse_uuid(&stem[infix + TEMP_INFIX.len()..]).is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::env::set_current_dir;
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
    fn rename_carries_the_metadata_and_copy_does_not() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"account");
            let before = read_metadata_attributes(&context, "/a.txt").unwrap();

            assert_eq!(copy(&context, "/a.txt", "/copy.txt").unwrap(), b"account".len() as u64);
            rename(&context, "/a.txt", "/moved.txt").unwrap();

            assert_eq!(read(&context, "/copy.txt").unwrap(), b"account");
            assert!(read_metadata_attributes(&context, "/copy.txt").is_err(), "a copy carries no metadata");

            assert_eq!(read(&context, "/moved.txt").unwrap(), b"account");
            assert_eq!(read_metadata_attributes(&context, "/moved.txt").unwrap().id, before.id);
            assert!(!exists(&context, "/a.txt"));
        });
    }

    #[test]
    fn both_ends_of_a_rename_or_copy_are_checked_against_the_account_root() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("a.txt"), &identity, &secret_key, b"account");

            assert_eq!(rename(&context, "/a.txt", "/../outside.txt").unwrap_err().kind(), ErrorKind::InvalidInput);
            assert_eq!(copy(&context, "/a.txt", "/../outside.txt").unwrap_err().kind(), ErrorKind::InvalidInput);

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
    fn to_account_path_address_without_path_is_the_account_root() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, _, _) = account(temp_dir);

            assert_eq!(to_account_path(&context, "bob@example.com").unwrap(), "/");
        });
    }

    #[test]
    fn to_account_path_address_with_path_is_under_the_account_root() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, _, _) = account(temp_dir);

            assert_eq!(to_account_path(&context, "bob@example.com/notes/todo.txt").unwrap(), "/notes/todo.txt");
        });
    }

    #[test]
    fn to_account_path_absolute_wins_over_an_at_in_the_name() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, _, _) = account(temp_dir);

            assert_eq!(to_account_path(&context, "/notes/mail@host.txt").unwrap(), "/notes/mail@host.txt");
        });
    }

    #[test]
    fn to_account_path_relative_is_under_the_working_directory() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, _, _) = account(temp_dir);
            let dir = context.root.join("notes");
            fs::create_dir_all(&dir).unwrap();
            set_current_dir(&dir).unwrap();

            assert_eq!(to_account_path(&context, "todo.txt").unwrap(), "/notes/todo.txt");
        });
    }

    #[test]
    fn a_path_climbing_out_of_the_account_root_errors() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, _, _) = account(temp_dir);

            let error = to_account_path(&context, "/../outside.txt").unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn a_path_outside_the_account_root_errors() {
        in_test_dir("ark_storage_test", |temp_dir| {
            let (context, _, _) = account(temp_dir);

            // The test's working directory is the server root, one above the
            // account's own.
            let error = to_account_path(&context, "outside.txt").unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn write_atomic_with_metadata_replaces_body_and_metadata_together() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let path = context.root.join("notes.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"first");

            let metadata = create_plain_test_metadata(&identity, &secret_key, b"second");
            write_atomic_with_metadata(&context, "/notes.txt", Body::Bytes(b"second"), &metadata, None).unwrap();

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

            write_atomic(&context, "/notes.txt", Body::Bytes(b"second")).unwrap();

            assert_eq!(fs::read(&path).unwrap(), b"second");
            assert_eq!(read_metadata_attributes(&context, "/notes.txt").unwrap().id, before.id);
        });
    }

    #[test]
    fn write_atomic_without_metadata_drops_what_was_there() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            write_plain_test_file(&context.root.join("notes.txt"), &identity, &secret_key, b"first");

            write_atomic_without_metadata(&context, "/notes.txt", Body::Bytes(b"second")).unwrap();

            assert!(read_metadata_attributes(&context, "/notes.txt").is_err());
        });
    }

    #[test]
    fn write_atomic_keeps_body_when_copying() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, identity, secret_key) = account(temp_dir);
            let path = context.root.join("notes.txt");
            write_plain_test_file(&path, &identity, &secret_key, b"body");
            let before = read_metadata_attributes(&context, "/notes.txt").unwrap();

            let metadata = create_plain_test_metadata(&identity, &secret_key, b"body");
            write_atomic_with_metadata(&context, "/notes.txt", Body::CopyOf("/notes.txt"), &metadata, None).unwrap();

            assert_eq!(fs::read(&path).unwrap(), b"body");
            assert_ne!(read_metadata_attributes(&context, "/notes.txt").unwrap().id, before.id);
        });
    }

    #[test]
    fn write_atomic_leaves_nothing_behind_when_it_fails() {
        in_test_dir("ark_write_atomic_test", |temp_dir| {
            let (context, _, _) = account(temp_dir);

            assert!(write_atomic(&context, "/notes.txt", Body::CopyOf("/missing")).is_err());

            assert!(!context.root.join("notes.txt").exists());
            assert_eq!(fs::read_dir(&context.root).unwrap().count(), 1, "nothing but .ark");
        });
    }

    #[test]
    fn temp_path_for_is_recognised_and_real_names_are_not() {
        let path = "/notes/todo.txt";
        let temp = temp_path_for(path);
        assert!(is_temp_path(&temp));
        assert_eq!(parent_path(&temp), parent_path(path));
        assert!(file_name(&temp).starts_with(".todo.txt.tmp-"));

        assert!(!is_temp_path(path));
        assert!(!is_temp_path("/notes/.todo.txt.tmp-notauuid"));
        assert!(!is_temp_path("/notes/todo.txt.tmp-1e2b34d0-0000-4000-8000-000000000000"));
        assert!(!is_temp_path("/notes/todo.txt.conflict-2026-08-10T00-00-00Z"));
    }

    #[test]
    fn path_parts_are_taken_account_absolute() {
        assert_eq!(parent_path("/notes/todo.txt"), Some("/notes"));
        assert_eq!(parent_path("/notes/"), Some("/"));
        assert_eq!(parent_path("/todo.txt"), Some("/"));
        assert_eq!(parent_path("todo.txt"), None);
        assert_eq!(parent_path("/"), None);

        assert_eq!(file_name("/notes/todo.txt"), "todo.txt");
        assert_eq!(file_name("/notes/"), "notes");
        assert_eq!(file_name("/"), "");

        assert_eq!(join_path("/", "notes"), "/notes");
        assert_eq!(join_path("/notes", "todo.txt"), "/notes/todo.txt");
        assert_eq!(join_path("/notes/", "todo.txt"), "/notes/todo.txt");
    }
}
