use std::io;

use super::{get_merge_base_version, head, put_content};

use crate::metadata::{read_local_metadata_attributes, read_metadata_attributes, write_metadata_attributes_atomic};
use crate::paths::{file_name, parent_path, sidecar_path_for};
use crate::storage::{is_dir, read, read_dir, remove_file, write_atomic_with_metadata};
use crate::timestamp;
use crate::types::{Context, Metadata};
use crate::util::sha256;
use crate::versions::to_version;

const BASE_SIDECAR_PREFIX: &str = "base-";
const REMOTE_SIDECAR_PREFIX: &str = "remote-";

/// Record a conflict on the file at `path`, where the account's own copy and
/// the server's have both changed, leaving the copy untouched.
///
/// `path` accepts relative, absolute account, or address form. `body` and
/// `metadata` are the server's copy, as [`get_stream`](super::get_stream)
/// returns it. Writes a `<name>.remote-<iso>` sidecar carrying the server's
/// copy (body plus metadata), and beside it a `<name>.base-<id>` sidecar
/// carrying the newest version both sides descend from, where they share one,
/// to merge against. Neither sidecar is sync-tracked itself, and they replace
/// any an earlier conflict on `path` left. `decrypt` controls whether the base
/// sidecar body is decrypted, and should match how `body` was fetched.
/// [`resolve_conflict`] publishes the merge.
pub fn write_conflict(ctx: &Context, path: &str, body: &[u8], metadata: &Metadata, decrypt: bool) -> io::Result<()> {
    let suffix = format!("{}{}", REMOTE_SIDECAR_PREFIX, timestamp::format_fs_safe(timestamp::now()));
    let mut written = vec![sidecar_path_for(path, &suffix)];
    write_atomic_with_metadata(ctx, &written[0], body, metadata, None)?;

    if let Ok(existing_metadata) = read_metadata_attributes(ctx, path) {
        if let Some((base_body, base_metadata)) = get_merge_base_version(ctx, path, &existing_metadata, metadata, decrypt)? {
            let suffix = format!("{}{}", BASE_SIDECAR_PREFIX, to_version(&base_metadata));
            written.push(sidecar_path_for(path, &suffix));
            write_atomic_with_metadata(ctx, &written[1], &base_body, &base_metadata, None)?;
        }
    }

    remove_sidecars(ctx, path, &written)
}

/// Record a conflict on the file at `path`, where the account's own copy
/// changed and another account deleted it on the server, leaving the copy
/// untouched.
///
/// `path` accepts relative, absolute account, or address form. Writes an
/// empty `<name>.remote-<iso>` sidecar carrying `delete_metadata`, the
/// metadata of the delete that took `path`, by itself or with a directory
/// above it. It replaces any sidecars an earlier conflict on `path` left.
/// [`resolve_conflict`] puts the copy again; to take the delete instead,
/// remove the copy and the sidecar.
pub fn write_delete_conflict(ctx: &Context, path: &str, delete_metadata: &Metadata) -> io::Result<()> {
    let suffix = format!("{}{}", REMOTE_SIDECAR_PREFIX, timestamp::format_fs_safe(timestamp::now()));
    let sidecar_path = sidecar_path_for(path, &suffix);
    write_atomic_with_metadata(ctx, &sidecar_path, &[], delete_metadata, None)?;

    remove_sidecars(ctx, path, &[sidecar_path])
}

/// Whether the file at `path` has a conflict recorded on it that is not yet
/// resolved with [`resolve_conflict`].
///
/// `path` accepts relative, absolute account, or address form.
pub fn has_conflict(ctx: &Context, path: &str) -> io::Result<bool> {
    let parent = parent_path(path).unwrap_or("/");
    let remote_prefix = format!("{}.{}", file_name(path), REMOTE_SIDECAR_PREFIX);
    Ok(read_dir(ctx, parent)?.iter().any(|entry| file_name(entry).starts_with(&remote_prefix)))
}

/// Publish the account's own copy of the file at `path` as the resolution of
/// a conflict [`write_conflict`] or [`write_delete_conflict`] recorded on it,
/// and drop the sidecars it wrote.
///
/// `path` accepts relative, absolute account, or address form. The copy is
/// put as a change to what the server holds now, so the version it lands as
/// names the server's as its parent — the history records the merge — and the
/// server's member list carries over. Where the server deleted `path`, the
/// copy is put again as it stands. Merge into the copy first: its body is
/// what is published, as it stands.
pub fn resolve_conflict(ctx: &Context, path: &str) -> io::Result<()> {
    match head(ctx, path) {
        Ok((_, remote_metadata)) => {
            let mut local_metadata = read_local_metadata_attributes(ctx, path)?;
            local_metadata.sync_author_date = Some(remote_metadata.author_date);
            write_metadata_attributes_atomic(ctx, path, &remote_metadata, Some(&local_metadata))?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    put_content(ctx, path)?;

    remove_sidecars(ctx, path, &[])
}

/// Whether the body changed since it was last synced; `None` where untracked.
pub fn is_modified(ctx: &Context, path: &str) -> io::Result<Option<bool>> {
    let local_metadata = read_local_metadata_attributes(ctx, path)?;

    if is_dir(ctx, path) {
        return Ok(local_metadata.sync_author_date.map(|_| false));
    }

    match &local_metadata.sync_body_hash {
        Some(h) => Ok(Some(h.value != sha256(&read(ctx, path)?))),
        None => Ok(None),
    }
}

/// Remove the sidecars a conflict on `path` left, other than those in `keep`.
pub fn remove_sidecars(ctx: &Context, path: &str, keep: &[String]) -> io::Result<()> {
    let parent = parent_path(path).unwrap_or("/");
    let remote_prefix = format!("{}.{}", file_name(path), REMOTE_SIDECAR_PREFIX);
    let base_prefix = format!("{}.{}", file_name(path), BASE_SIDECAR_PREFIX);
    for entry in read_dir(ctx, parent)? {
        let name = file_name(&entry);
        if keep.iter().any(|kept| file_name(kept) == name) { continue; }
        if name.starts_with(&remote_prefix) || name.starts_with(&base_prefix) {
            remove_file(ctx, &entry)?;
        }
    }

    Ok(())
}
