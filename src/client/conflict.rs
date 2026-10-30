use std::io;

use super::{get_merge_base_version, get_stream, head, put_content};

use crate::metadata::{read_local_metadata_attributes, read_metadata_attributes, write_metadata_attributes_atomic};
use crate::paths::{file_name, parent_path, sidecar_path_for};
use crate::storage::{read_dir, remove_file, write_atomic_with_metadata};
use crate::timestamp;
use crate::types::Context;
use crate::versions::to_version;

const BASE_SIDECAR_PREFIX: &str = "base-";
const REMOTE_SIDECAR_PREFIX: &str = "remote-";

/// Record a conflict on the file at `path`, where the account's own copy and
/// the server's have both changed, leaving the copy untouched.
///
/// `path` accepts relative, absolute account, or address form. Writes a
/// `<name>.remote-<iso>` sidecar carrying the server's copy (body plus
/// metadata), and beside it a `<name>.base-<id>` sidecar carrying the newest
/// version both sides descend from, where they share one, to merge against.
/// Neither sidecar is sync-tracked itself. `decrypt` controls whether the
/// sidecar bodies are decrypted. [`resolve_conflict`] publishes the merge.
///
/// Errors with `NotFound` where the server no longer holds `path`.
pub fn write_conflict(ctx: &Context, path: &str, decrypt: bool) -> io::Result<()> {
    let mut body: Vec<u8> = Vec::new();
    let existing_metadata = read_metadata_attributes(ctx, path).ok();
    let (metadata, _) = get_stream(ctx, path, &mut body, decrypt, existing_metadata.as_ref(), None)?;

    let suffix = format!("{}{}", REMOTE_SIDECAR_PREFIX, timestamp::format_fs_safe(timestamp::now()));
    write_atomic_with_metadata(ctx, &sidecar_path_for(path, &suffix), &body, &metadata, None)?;

    if let Some(existing_metadata) = existing_metadata {
        if let Some((base_body, base_metadata)) = get_merge_base_version(ctx, path, &existing_metadata, &metadata, decrypt)? {
            let suffix = format!("{}{}", BASE_SIDECAR_PREFIX, to_version(&base_metadata));
            write_atomic_with_metadata(ctx, &sidecar_path_for(path, &suffix), &base_body, &base_metadata, None)?;
        }
    }

    Ok(())
}

/// Publish the account's own copy of the file at `path` as the resolution of
/// a conflict [`write_conflict`] recorded on it, and drop the sidecars it
/// wrote.
///
/// `path` accepts relative, absolute account, or address form. The copy is
/// put as a change to what the server holds now, so the version it lands as
/// names the server's as its parent — the history records the merge — and the
/// server's member list carries over. Merge into the copy first: its body is
/// what is published, as it stands.
pub fn resolve_conflict(ctx: &Context, path: &str) -> io::Result<()> {
    let (_, remote_metadata) = head(ctx, path)?;

    let mut local_metadata = read_local_metadata_attributes(ctx, path)?;
    local_metadata.sync_author_date = Some(remote_metadata.author_date);
    write_metadata_attributes_atomic(ctx, path, &remote_metadata, Some(&local_metadata))?;

    put_content(ctx, path)?;

    let parent = parent_path(path).unwrap_or("/");
    let remote_prefix = format!("{}.{}", file_name(path), REMOTE_SIDECAR_PREFIX);
    let base_prefix = format!("{}.{}", file_name(path), BASE_SIDECAR_PREFIX);
    for entry in read_dir(ctx, parent)? {
        let name = file_name(&entry);
        if name.starts_with(&remote_prefix) || name.starts_with(&base_prefix) {
            remove_file(ctx, &entry)?;
        }
    }

    Ok(())
}
