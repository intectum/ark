use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;

use super::{get_stream, get_version, has_conflict, is_modified, list, put_content, watch_local, watch_remote, write_conflict, write_delete_conflict};

use crate::crypto::DEFAULT_HASH_ALGORITHM;
use crate::identity::parse_address;
use crate::metadata::{has_metadata_attributes, has_metadata_headers, read_local_metadata_attributes, read_metadata_attributes, read_metadata_headers, write_metadata_attributes_atomic};
use crate::paths::{is_protocol_path, join_path, parent_path, to_account_path, to_fs_path, to_path_segment, to_url};
use crate::storage::{create_dir_all, exists, is_dir, is_file, is_symlink, read_dir, read_to_string, remove_dir, remove_file, write_atomic_with_metadata, write_atomic_without_metadata};
use crate::types::{Context, DirEntryKind, EntryAction, EntryEvent, Hash, LocalMetadata, Metadata};
use crate::util::{parse_request_entry, sha256};
use crate::validation::{validate_entry, validate_made_on_copy};
use crate::versions::to_version;

/// Reconcile local and remote state under the directory `path` in a single
/// pass.
///
/// Remote changes are applied in the order they were made, then local changes
/// are pushed. Per tracked file/dir: pull if only remote changed; pull
/// metadata alone when only remote permissions/members changed; record a
/// conflict with [`write_conflict`] when both sides diverged, leaving the
/// local copy untouched; push if local changed. Remove what another account
/// deleted unless it changed locally, in which case record a conflict with
/// [`write_delete_conflict`]; a directory is removed only once nothing is left
/// in it. A file with a conflict recorded is not pushed until it is resolved
/// with [`resolve_conflict`](super::resolve_conflict).
///
/// Each remote change is pulled as the version it made, and checked as a
/// change to the local copy: its author must have been allowed to make it by
/// the version before. One that is not goes to `on_error` and is passed over.
/// Changes the current account made elsewhere are pulled like any other.
///
/// Only items with sync markers (seeded via a previous [`put`](super::put))
/// are considered. Symlinks, untracked local files, and files encrypted at rest
/// are left alone, as is everything under `/.ark/`, locally and remotely.
///
/// With `watch=true`, blocks and continues syncing as local FS events and
/// remote changes arrive, in addition to the initial pass. `decrypt` controls
/// whether pulled files are decrypted on write. `on_event` fires once per
/// reconciled entry; `on_error` receives non-fatal per-entry failures and
/// watch stream errors.
pub fn sync<F, G>(
    ctx: &Context,
    path: &str,
    watch: bool,
    decrypt: bool,
    on_event: F,
    on_error: G,
) -> io::Result<()>
where
    F: Fn(EntryEvent) -> bool + Send + Sync,
    G: Fn(io::Error) -> bool + Send + Sync,
{
    let target_path = to_account_path(ctx, path)?;
    let pull_lock = Mutex::new(());

    if watch {
        thread::scope(|s| {
            s.spawn(|| {
                if let Err(e) = pull_watch(ctx, &target_path, decrypt, &pull_lock, &on_event, &on_error) {
                    on_error(io::Error::other(format!("pull watch: {}", e)));
                }
            });
            s.spawn(|| {
                if let Err(e) = push_watch(ctx, &target_path, &on_event, &on_error) {
                    on_error(io::Error::other(format!("push watch: {}", e)));
                }
            });
            if let Err(e) = pull_and_push(ctx, &target_path, decrypt, &pull_lock, &on_event, &on_error) {
                on_error(io::Error::other(format!("pull and push: {}", e)));
            }
        });
    } else {
        pull_and_push(ctx, &target_path, decrypt, &pull_lock, &on_event, &on_error)?;
    }

    Ok(())
}

fn pull_watch<F, G>(ctx: &Context, path: &str, decrypt: bool, pull_lock: &Mutex<()>, on_event: &F, on_error: &G) -> io::Result<()>
where
    F: Fn(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    // Every remote change is logged, so a new log entry is the signal to pull.
    let url = to_url(ctx, "/.ark/requests/")?;

    watch_remote(ctx, &url, |event| {
        if !matches!(event.action, EntryAction::Created) || !event.path.to_string_lossy().ends_with(".http") { return false; }

        match pull(ctx, path, decrypt, pull_lock, on_event, on_error) {
            Ok(stop) => stop,
            Err(e) => {
                on_error(io::Error::other(format!("pull: {}", e)));
                false
            }
        }
    }, on_error)
}

fn push_watch<F, G>(ctx: &Context, path: &str, on_event: &F, on_error: &G) -> io::Result<()>
where
    F: Fn(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    watch_local(&to_fs_path(ctx, path)?, |event| {
        match event.action {
            EntryAction::Created | EntryAction::Modified => {}
            _ => return false,
        }

        let entry_path = join_path(path, &event.path.to_string_lossy());
        if !is_file(ctx, &entry_path) { return false; }

        match is_modified(ctx,&entry_path) {
            Ok(Some(true)) if !has_conflict(ctx, &entry_path).unwrap_or(false) => match put_content(ctx, &entry_path) {
                Ok(()) => return emit(ctx, &entry_path, EntryAction::Modified, false, on_event),
                Err(e) => { on_error(io::Error::other(format!("push failed for {}: {}", entry_path, e))); }
            },
            Ok(_) => {}
            Err(e) => { on_error(io::Error::other(format!("check {}: {}", entry_path, e))); }
        }

        false
    }, on_error)
}

fn pull_and_push<F, G>(ctx: &Context, path: &str, decrypt: bool, pull_lock: &Mutex<()>, on_event: &F, on_error: &G) -> io::Result<()>
where
    F: Fn(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    if pull(ctx, path, decrypt, pull_lock, on_event, on_error)? { return Ok(()); }
    push(ctx, path, on_event, on_error)?;

    Ok(())
}

// Apply the remote changes logged since the last pull, in order. `true` where
// `on_event` asked to stop.
fn pull<F, G>(ctx: &Context, path: &str, decrypt: bool, pull_lock: &Mutex<()>, on_event: &F, on_error: &G) -> io::Result<bool>
where
    F: Fn(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    let _pulling = pull_lock.lock().map_err(|_| io::Error::other("pull lock poisoned"))?;

    let marker_path = last_sync_request_path(path);
    let last_sync_request = match read_to_string(ctx, &marker_path) {
        Ok(s) => Some(s.trim().to_string()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };

    let rel_prefix = path.trim_start_matches('/');

    let mut entries = list(ctx, "/.ark/requests/", Some("PUT_2"))?;
    entries.extend(list(ctx, "/.ark/requests/", Some("DELETE_204"))?);
    entries.retain(|entry|
        matches!(entry.kind, DirEntryKind::File) && entry.name.ends_with(".http")
            && last_sync_request.as_ref().is_none_or(|cutoff| stamp_key(&entry.name) > stamp_key(cutoff)));
    entries.sort_by(|a, b| stamp_key(&a.name).cmp(stamp_key(&b.name)));

    let (account_name, _, _) = parse_address(&ctx.identity.address)?;
    let account_prefix = format!("/ark/{}/", account_name);

    let mut new_last_sync_request = last_sync_request.clone();
    let mut failed = false;
    let mut stopped = false;

    for entry in entries {
        let entry_path = format!("/.ark/requests/{}", entry.name);
        let mut entry_body: Vec<u8> = Vec::new();
        let parsed = match get_stream(ctx, &entry_path, &mut entry_body, false, None) {
            Ok(_) => parse_log_entry(&entry_body, &account_prefix),
            Err(_) => Ok(None),
        };

        let result = match parsed {
            Ok(Some((relative_path, metadata))) => {
                // A delete above the synced path takes what is beneath it too.
                let covers_path = metadata.deleted && under_prefix(rel_prefix, &relative_path);
                let applied = if !under_prefix(&relative_path, rel_prefix) && !covers_path || is_protocol_path(&relative_path) {
                    Ok(false)
                } else if metadata.deleted {
                    let target = if covers_path { rel_prefix } else { relative_path.as_str() };
                    apply_remote_delete(ctx, &join_path("/", &relative_path), &join_path("/", target), &metadata, on_event)
                } else {
                    apply_remote_put(ctx, &join_path("/", &relative_path), &metadata, decrypt, on_event)
                };
                applied.map_err(|e| io::Error::new(e.kind(), format!("sync failed for {}: {}", relative_path, e)))
            }
            Ok(None) => Ok(false),
            Err(e) => {
                on_error(io::Error::new(io::ErrorKind::InvalidData, format!("bad log entry: {}", e)));
                Ok(false)
            }
        };

        match result {
            Ok(stop) => {
                // Held back past a failed entry so it is retried on the next
                // pass.
                if !failed { new_last_sync_request = Some(entry.name); }
                if stop {
                    stopped = true;
                    break;
                }
            }
            // A change that does not verify, or was not made on the copy held,
            // never will, so it is passed over like one applied.
            Err(e) if matches!(e.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData | io::ErrorKind::AlreadyExists) => {
                if !failed { new_last_sync_request = Some(entry.name); }
                on_error(e);
            }
            // Anything else may apply on the next pass.
            Err(e) => {
                failed = true;
                on_error(e);
            }
        }
    }

    if let Some(l) = new_last_sync_request {
        create_dir_all(ctx, parent_path(&marker_path).unwrap_or("/"))?;
        write_atomic_without_metadata(ctx, &marker_path, l.as_bytes())?;
    }

    Ok(stopped)
}

// Put every tracked file under `path` whose body changed since it was last
// synced. `true` where `on_event` asked to stop.
fn push<F, G>(ctx: &Context, path: &str, on_event: &F, on_error: &G) -> io::Result<bool>
where
    F: Fn(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    for entry in read_dir(ctx, path)? {
        if is_symlink(ctx, &entry) { continue; }
        if is_protocol_path(&entry) { continue; }

        if is_dir(ctx, &entry) {
            if push(ctx, &entry, on_event, on_error)? { return Ok(true); }
            continue;
        }
        if !is_file(ctx, &entry) { continue; }

        match is_modified(ctx,&entry) {
            Ok(Some(true)) => {}
            Ok(_) => continue,
            Err(e) => {
                on_error(io::Error::other(format!("check {}: {}", entry, e)));
                continue;
            }
        }

        // Held back until the conflict is resolved, so it is not overwritten.
        if has_conflict(ctx, &entry)? { continue; }

        match put_content(ctx, &entry) {
            Ok(()) => {
                if emit(ctx, &entry, EntryAction::Modified, false, on_event) { return Ok(true); }
            }
            Err(e) => { on_error(io::Error::other(format!("sync failed for {}: {}", entry.trim_start_matches('/'), e))); }
        }
    }

    Ok(false)
}

fn apply_remote_put<F>(
    ctx: &Context,
    path: &str,
    metadata: &Metadata,
    decrypt: bool,
    on_event: &F,
) -> io::Result<bool>
where
    F: Fn(EntryEvent) -> bool,
{
    let is_dir = metadata.body_hash.is_none();
    let local_exists = exists(ctx, path);
    let has_local_metadata = local_exists && has_metadata_attributes(ctx, path)?;

    if !is_dir && local_exists && !has_local_metadata {
        return Ok(false);
    }

    let (local_body_hash, baseline) = if has_local_metadata {
        let m = read_metadata_attributes(ctx, path)?;
        let l = read_local_metadata_attributes(ctx, path)?;
        (m.body_hash.map(|h| h.value), Some(l.sync_author_date.unwrap_or(m.author_date)))
    } else {
        (None, None)
    };

    // Already taken in by an earlier pull of a newer version.
    if baseline.is_some_and(|b| b >= metadata.author_date) { return Ok(false); }

    let body_changed = !is_dir && local_body_hash.as_ref() != metadata.body_hash.as_ref().map(|h| &h.value);

    if body_changed && local_exists && is_modified(ctx,path)? == Some(true) {
        let mut remote_body = Vec::new();
        let remote_metadata = match get_stream(ctx, path, &mut remote_body, decrypt, None) {
            Ok((remote_metadata, _)) => remote_metadata,
            // Deleted on the server since.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        write_conflict(ctx, path, &remote_body, &remote_metadata, decrypt)?;
        return Ok(emit(ctx, path, EntryAction::Modified, true, on_event));
    }

    let existing_metadata = if has_local_metadata { Some(read_metadata_attributes(ctx, path)?) } else { None };
    let (body, version_metadata) = match get_version(ctx, path, &to_version(metadata), decrypt, existing_metadata.as_ref()) {
        Ok(version) => version,
        // Dropped from the history since, by a purge.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };

    validate_made_on_copy(ctx, path, &version_metadata, None)?;

    if is_dir {
        create_dir_all(ctx, path)?;
        let local_metadata = LocalMetadata { encrypted: None, sync_body_hash: None, sync_author_date: Some(version_metadata.author_date) };
        write_metadata_attributes_atomic(ctx, path, &version_metadata, Some(&local_metadata))?;
        return Ok(emit(ctx, path, EntryAction::Metadata, false, on_event));
    }

    // Only the members changed where the body did not, so a local edit is kept.
    if !body_changed {
        let local_metadata = LocalMetadata { sync_author_date: Some(version_metadata.author_date), ..read_local_metadata_attributes(ctx, path).unwrap_or_default() };
        write_metadata_attributes_atomic(ctx, path, &version_metadata, Some(&local_metadata))?;
        return Ok(emit(ctx, path, EntryAction::Metadata, false, on_event));
    }

    let is_plaintext = decrypt || version_metadata.encryption_algorithm.is_none();
    let local_metadata = LocalMetadata {
        encrypted: Some(!decrypt),
        sync_body_hash: is_plaintext.then(|| Hash { algorithm: DEFAULT_HASH_ALGORITHM.to_string(), value: sha256(&body) }),
        sync_author_date: Some(version_metadata.author_date),
    };
    if let Some(parent) = parent_path(path) {
        create_dir_all(ctx, parent)?;
    }
    write_atomic_with_metadata(ctx, path, &body, &version_metadata, Some(&local_metadata))?;

    Ok(emit(ctx, path, EntryAction::Modified, false, on_event))
}

// Remove what the delete of `deleted_path` took at and beneath `path`, once
// the delete checks out against the local copy of `deleted_path`.
fn apply_remote_delete<F>(
    ctx: &Context,
    deleted_path: &str,
    path: &str,
    delete_metadata: &Metadata,
    on_event: &F,
) -> io::Result<bool>
where
    F: Fn(EntryEvent) -> bool,
{
    // Written again since the delete.
    if read_metadata_attributes(ctx, deleted_path).is_ok_and(|existing_metadata| existing_metadata.author_date > delete_metadata.author_date) {
        return Ok(false);
    }

    validate_entry(ctx, deleted_path, delete_metadata, None, None, None)?;

    remove_deleted(ctx, path, delete_metadata, on_event)
}

fn remove_deleted<F>(ctx: &Context, path: &str, delete_metadata: &Metadata, on_event: &F) -> io::Result<bool>
where
    F: Fn(EntryEvent) -> bool,
{
    if is_symlink(ctx, path) || !exists(ctx, path) { return Ok(false); }

    let target_is_dir = is_dir(ctx, path);
    if target_is_dir {
        for entry in read_dir(ctx, path)? {
            if is_protocol_path(&entry) { continue; }
            if remove_deleted(ctx, &entry, delete_metadata, on_event)? { return Ok(true); }
        }
    }

    match is_modified(ctx,path)? {
        Some(false) => {}
        Some(true) => {
            write_delete_conflict(ctx, path, delete_metadata)?;
            return Ok(emit(ctx, path, EntryAction::Modified, true, on_event));
        }
        None => return Ok(false),
    }

    let result = if target_is_dir { remove_dir(ctx, path) } else { remove_file(ctx, path) };
    match result {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => return Ok(false),
        Err(e) => return Err(e),
    }

    Ok(on_event(EntryEvent {
        action: EntryAction::Deleted,
        kind: Some(if target_is_dir { DirEntryKind::Dir } else { DirEntryKind::File }),
        path: PathBuf::from(path.trim_start_matches('/')),
        conflict: false,
    }))
}

fn emit<F>(ctx: &Context, path: &str, action: EntryAction, conflict: bool, on_event: &F) -> bool
where
    F: Fn(EntryEvent) -> bool,
{
    let kind = if is_dir(ctx, path) { DirEntryKind::Dir } else { DirEntryKind::File };
    on_event(EntryEvent {
        action,
        kind: Some(kind),
        path: PathBuf::from(path.trim_start_matches('/')),
        conflict,
    })
}

/// Strip the `METHOD_STATUS_` prefix so entries sort and compare by timestamp.
fn stamp_key(name: &str) -> &str {
    name.splitn(3, '_').nth(2).unwrap_or(name)
}

fn parse_log_entry(entry_bytes: &[u8], account_prefix: &str) -> io::Result<Option<(String, Metadata)>> {
    let entry = parse_request_entry(entry_bytes)?;

    match (entry.method.as_str(), entry.status) {
        ("PUT", 201 | 204) | ("DELETE", 204) => {}
        _ => return Ok(None),
    }
    // A purge of a path's versions carries no metadata.
    if !has_metadata_headers(&entry.request_headers) { return Ok(None); }

    let target = entry.target.split_once('?').map(|(p, _)| p).unwrap_or(&entry.target);
    let Some(relative_path) = target.strip_prefix(account_prefix) else { return Ok(None); };

    let metadata = read_metadata_headers(&entry.request_headers)?;

    Ok(Some((relative_path.trim_end_matches('/').to_string(), metadata)))
}

fn last_sync_request_path(path: &str) -> String {
    join_path("/.ark/sync", &to_path_segment(path))
}

fn under_prefix(rel: &str, prefix: &str) -> bool {
    if prefix.is_empty() { return true; }
    rel == prefix || rel.starts_with(&format!("{}/", prefix))
}

#[cfg(test)]
mod tests {
    use std::env::{current_dir, set_current_dir};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use time::Duration;

    use super::*;

    use crate::client::{delete, get::get, get_version, init, put::{put, put_permissions}, resolve_conflict};
    use crate::metadata::{has_metadata_attributes, read_local_metadata_attributes, read_metadata_attributes, sign_metadata};
    use crate::context::create_client_context;
    use crate::permissions::{owner, reader, writer};
    use crate::testing::fs::{account_context, in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};
    use crate::testing::http::{plant_logged_put, seed_shared_dir, start_test_server};
    use crate::types::{Member, Permission, Permissions};
    use crate::paths::{file_name, temp_path_for};
    use crate::storage::write_atomic_with_metadata;
    use crate::versions::{read_versions, to_version};

    fn write_local(root: &Path, relative: &str, body: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
    }

    fn remote_sidecar(dir: &Path, name: &str) -> Option<PathBuf> {
        fs::read_dir(dir).unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with(&format!("{}.remote-", name)))
            .map(|e| e.path())
    }

    fn prime_plain(ctx: &Context, path: &Path, target: &str, body: &[u8]) {
        fs::write(path, body).unwrap();
        put(ctx, target, &Permissions::default(), Some("none"), false).unwrap();
    }

    fn init_two_accounts(temp_dir: &Path, port: u16) -> (Context, Context) {
        let alice_dir = temp_dir.join("alice_client");
        let bob_dir = temp_dir.join("bob_client");
        fs::create_dir_all(&alice_dir).unwrap();
        fs::create_dir_all(&bob_dir).unwrap();

        set_current_dir(&alice_dir).unwrap();
        init(&current_dir().unwrap(), &format!("alice@127.0.0.1:{}", port), None, false).unwrap();
        let alice_ctx = create_client_context().unwrap();

        set_current_dir(&bob_dir).unwrap();
        init(&current_dir().unwrap(), &format!("bob@127.0.0.1:{}", port), None, false).unwrap();
        let bob_ctx = create_client_context().unwrap();

        (alice_ctx, bob_ctx)
    }

    fn seed_shared_dir_with_writer(alice_dir: &Path, alice_ctx: &Context, writer_addr: &str) {
        let shared = alice_dir.join("shared");
        fs::create_dir(&shared).unwrap();
        put(alice_ctx, "shared/", &writer(writer_addr), None, false).unwrap();
    }

    #[test]
    fn sync_skips_untracked_files() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::write(temp_dir.join("bare.txt"), b"hi").unwrap();

            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert!(!temp_dir.join("ark/gyan/bare.txt").exists(), "untracked file should not upload");
        });
    }

    #[test]
    fn sync_walks_subdirs() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::create_dir_all(temp_dir.join("a/b")).unwrap();
            let local = temp_dir.join("a/b/c.txt");
            prime_plain(&ctx, &local, "a/b/c.txt", b"deep v1");

            fs::write(&local, b"deep v2").unwrap();
            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            let server_body = fs::read(temp_dir.join("ark/gyan/a/b/c.txt")).unwrap();
            assert_eq!(server_body, b"deep v2");
        });
    }

    #[test]
    fn sync_of_a_subdir_leaves_the_rest_of_the_account_alone() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::create_dir_all(temp_dir.join("a")).unwrap();
            let inside = temp_dir.join("a/c.txt");
            prime_plain(&ctx, &inside, "a/c.txt", b"inside v1");
            let outside = temp_dir.join("b.txt");
            prime_plain(&ctx, &outside, "b.txt", b"outside v1");

            fs::write(&inside, b"inside v2").unwrap();
            fs::write(&outside, b"outside v2").unwrap();
            sync(&ctx, "a", false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(temp_dir.join("ark/gyan/a/c.txt")).unwrap(), b"inside v2");
            assert_eq!(fs::read(temp_dir.join("ark/gyan/b.txt")).unwrap(), b"outside v1", "outside the synced dir");
        });
    }

    #[test]
    fn sync_ignores_a_temp_file_left_behind() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local = temp_dir.join("f.txt");
            prime_plain(&ctx, &local, "f.txt", b"v1");

            // A write that did not finish: attributes already written, never
            // renamed into place.
            let leftover = temp_path_for("/f.txt");
            let metadata = read_metadata_attributes(&ctx, "f.txt").unwrap();
            let local_metadata = read_local_metadata_attributes(&ctx, "f.txt").unwrap();
            write_atomic_with_metadata(&ctx, &leftover, b"half", &metadata, Some(&local_metadata)).unwrap();

            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert!(!temp_dir.join("ark/gyan").join(file_name(&leftover)).exists(), "temp file must not be pushed");
        });
    }

    #[test]
    fn sync_skips_when_content_unchanged() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local = temp_dir.join("f.txt");
            prime_plain(&ctx, &local, "f.txt", b"v1");

            let server_path = temp_dir.join("ark/gyan/f.txt");
            let before = fs::read(&server_path).unwrap();

            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            let after = fs::read(&server_path).unwrap();
            assert_eq!(before, after, "server file should be unchanged when content matches cached hash");
        });
    }

    #[test]
    fn sync_skips_when_rewritten_with_same_content() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local = temp_dir.join("f.txt");
            prime_plain(&ctx, &local, "f.txt", b"same");

            let server_path = temp_dir.join("ark/gyan/f.txt");
            let before = fs::read(&server_path).unwrap();

            fs::write(&local, b"same").unwrap();
            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            let after = fs::read(&server_path).unwrap();
            assert_eq!(before, after, "identical content should skip upload even after rewrite");
        });
    }

    #[test]
    fn sync_after_get_does_not_reupload() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let server_path = temp_dir.join("ark/gyan/pulled.txt");
            write_plain_test_file(&server_path, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"remote body");
            let before = fs::read(&server_path).unwrap();

            get(&ctx, "pulled.txt", false, false).unwrap();

            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            let after = fs::read(&server_path).unwrap();
            assert_eq!(before, after, "sync after get must not re-upload identical body");
        });
    }

    #[test]
    fn sync_uploads_when_content_changes() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local = temp_dir.join("f.txt");
            prime_plain(&ctx, &local, "f.txt", b"v1");

            fs::write(&local, b"v2").unwrap();
            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            let server_body = fs::read(temp_dir.join("ark/gyan/f.txt")).unwrap();
            assert_eq!(server_body, b"v2");
        });
    }

    #[test]
    fn sync_skips_symlinks() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let target = temp_dir.join("target.txt");
            prime_plain(&ctx, &target, "target.txt", b"v1");

            let link = temp_dir.join("link.txt");
            symlink(&target, &link).unwrap();

            fs::write(&target, b"v2").unwrap();
            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(temp_dir.join("ark/gyan/target.txt")).unwrap(), b"v2");
            assert!(!temp_dir.join("ark/gyan/link.txt").exists(), "symlink must not be uploaded");
        });
    }

    #[test]
    fn sync_refreshes_sync_body_hash_after_push() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local = temp_dir.join("f.txt");
            prime_plain(&ctx, &local, "f.txt", b"v1");

            fs::write(&local, b"v2").unwrap();
            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert_eq!(
                read_local_metadata_attributes(&ctx, "f.txt").unwrap().sync_body_hash.as_ref().unwrap().value,
                sha256(b"v2"),
                "sync_body_hash must track uploaded body after push"
            );

            let server_path = temp_dir.join("ark/gyan/f.txt");
            let before = fs::read(&server_path).unwrap();
            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();
            assert_eq!(fs::read(&server_path).unwrap(), before, "second sync must no-op");
        });
    }

    #[test]
    fn sync_skips_encrypted_at_rest_files() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let server_path = temp_dir.join("ark/gyan/secret");
            write_encrypted_test_file(&server_path, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"plaintext");

            let local = temp_dir.join("secret");
            get(&ctx, "secret", false, false).unwrap();
            assert_eq!(xattr::get(&local, "user.ark_local.encrypted").unwrap().as_deref(), Some(b"true".as_slice()));
            assert!(read_local_metadata_attributes(&ctx, "secret").unwrap().sync_body_hash.is_none(), "encrypted-at-rest file should not carry sync_body_hash");

            let before = fs::read(&server_path).unwrap();
            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();
            let after = fs::read(&server_path).unwrap();
            assert_eq!(before, after, "encrypted-at-rest file should be skipped by sync");
        });
    }

    #[test]
    fn sync_pulls_files_from_other_accounts_log_entries() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);

            set_current_dir(&bob_dir).unwrap();
            write_local(&bob_dir, "shared/foo.txt", b"hello alice");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            let pulled = alice_dir.join("shared/foo.txt");
            assert!(pulled.exists(), "sync should pull remote file");
            assert_eq!(fs::read(&pulled).unwrap(), b"hello alice");
        });
    }

    #[test]
    fn sync_pulls_file_metadata_only_when_body_unchanged() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);
            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            let shared = alice_dir.join("shared");
            fs::create_dir(&shared).unwrap();
            put(&alice_ctx, "shared/", &owner(bob_ctx.identity.address.clone()), None, false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            write_local(&bob_dir, "shared/foo.txt", b"v1");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            let pulled = alice_dir.join("shared/foo.txt");
            assert_eq!(fs::read(&pulled).unwrap(), b"v1");
            let members_before = read_metadata_attributes(&alice_ctx, "/shared/foo.txt").unwrap().members.len();
            let author_date_before = read_metadata_attributes(&alice_ctx, "/shared/foo.txt").unwrap().author_date;

            set_current_dir(&bob_dir).unwrap();
            put(&bob_ctx, &target, &reader("public"), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(&pulled).unwrap(), b"v1", "body should be unchanged");
            let m = read_metadata_attributes(&alice_ctx, "/shared/foo.txt").unwrap();
            assert!(m.members.iter().any(|mem| mem.address == "*"), "public member should be present after metadata sync");
            assert!(m.members.len() > members_before, "members count should grow after metadata sync");
            assert_ne!(m.author_date, author_date_before, "author_date should refresh after metadata sync");
        });
    }

    #[test]
    fn sync_pulls_dir_metadata_from_other_accounts_log_entries() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);
            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);

            set_current_dir(&bob_dir).unwrap();
            fs::create_dir_all(bob_dir.join("shared/sub")).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/sub", port);
            put(&bob_ctx, &target, &Permissions::default(), None, false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            let pulled_dir = alice_dir.join("shared/sub");
            assert!(pulled_dir.is_dir(), "sync should create dir locally");
            assert!(has_metadata_attributes(&alice_ctx, "/shared/sub").unwrap(), "dir metadata should be written locally");
            let m = read_metadata_attributes(&alice_ctx, "/shared/sub").unwrap();
            assert_eq!(m.author, bob_ctx.identity.address, "author should be bob");
        });
    }

    #[test]
    fn sync_writes_last_sync_request() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_dir = temp_dir.join("alice_client");
            fs::create_dir_all(&alice_dir).unwrap();
            set_current_dir(&alice_dir).unwrap();
            init(&current_dir().unwrap(), &format!("alice@127.0.0.1:{}", port), None, false).unwrap();
            let alice_ctx = create_client_context().unwrap();

            let local = alice_dir.join("notes.txt");
            fs::write(&local, b"body").unwrap();
            put(&alice_ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            let stamp = read_to_string(&alice_ctx, &last_sync_request_path("/")).expect("last_sync_request should be recorded after sync");
            assert!(stamp.ends_with(".http"), "last_sync_request should be a log entry filename, got {}", stamp);

            // Syncing a directory keeps its marker beside the others, not in
            // it.
            fs::create_dir_all(alice_dir.join("sub")).unwrap();
            fs::write(alice_dir.join("sub/a.txt"), b"a").unwrap();
            put(&alice_ctx, "sub/a.txt", &Permissions::default(), Some("none"), false).unwrap();
            sync(&alice_ctx, "sub", false, false, |_| false, |_| false).unwrap();

            assert!(read_to_string(&alice_ctx, &last_sync_request_path("/sub")).is_ok());
            assert!(!alice_dir.join("sub/.ark").exists());
        });
    }

    #[test]
    fn sync_leaves_what_the_server_keeps_under_ark_alone() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            // Bob, a writer on Alice's groups, puts a group file under her
            // `/.ark/` — logged on her server like any put.
            seed_shared_dir(temp_dir, &alice_ctx.identity, alice_ctx.identity_key.as_ref().unwrap(), "ark/alice/.ark/groups", vec![
                Member { address: bob_ctx.identity.address.clone(), permission: Permission::Writer, key: None },
            ]);

            set_current_dir(&bob_dir).unwrap();
            fs::create_dir_all(bob_dir.join(".ark/groups")).unwrap();
            fs::write(bob_dir.join(".ark/groups/team.json"), b"{}").unwrap();
            let target = format!("alice@127.0.0.1:{}/.ark/groups/team.json", port);
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert!(!alice_dir.join(".ark/groups/team.json").exists(), "a put under /.ark/ is not pulled as account content");
        });
    }

    #[test]
    fn sync_skips_log_entries_older_than_last_sync() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);

            set_current_dir(&bob_dir).unwrap();
            write_local(&bob_dir, "shared/foo.txt", b"first");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();
            assert_eq!(fs::read(alice_dir.join("shared/foo.txt")).unwrap(), b"first");

            fs::remove_file(alice_dir.join("shared/foo.txt")).unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();
            assert!(!alice_dir.join("shared/foo.txt").exists(), "already-processed log entry must not re-pull");
        });
    }

    #[test]
    fn sync_pulls_own_puts_in_log_like_any_other() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_dir = temp_dir.join("alice_client");
            fs::create_dir_all(&alice_dir).unwrap();
            set_current_dir(&alice_dir).unwrap();
            init(&current_dir().unwrap(), &format!("alice@127.0.0.1:{}", port), None, false).unwrap();
            let alice_ctx = create_client_context().unwrap();

            let local = alice_dir.join("notes.txt");
            fs::write(&local, b"self body").unwrap();
            put(&alice_ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            fs::remove_file(&local).unwrap();

            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            // As another device of the account would; a local delete is not
            // tracked, so nothing holds it back.
            assert_eq!(fs::read(&local).unwrap(), b"self body", "own puts are pulled like anyone's");
        });
    }

    fn seed_shared_file_with_writer(alice_dir: &Path, alice_ctx: &Context, writer_addr: &str, relative: &str, body: &[u8]) {
        write_local(alice_dir, relative, body);
        put(alice_ctx, relative, &Permissions::default(), Some("none"), false).unwrap();
        put_permissions(alice_ctx, relative, &writer(writer_addr)).unwrap();
    }

    #[test]
    fn sync_removes_files_other_accounts_deleted() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            seed_shared_file_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address, "shared/foo.txt", b"hello");

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            delete(&bob_ctx, &target).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert!(!alice_dir.join("shared/foo.txt").exists());
        });
    }

    #[test]
    fn sync_records_a_conflict_on_a_file_changed_locally_after_another_account_deleted_it() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            seed_shared_file_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address, "shared/foo.txt", b"hello");

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            delete(&bob_ctx, &target).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(alice_dir.join("shared/foo.txt"), b"edited").unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(alice_dir.join("shared/foo.txt")).unwrap(), b"edited", "local edit preserved");
            let sidecar = remote_sidecar(&alice_dir.join("shared"), "foo.txt").expect("sidecar file present");
            assert!(fs::read(&sidecar).unwrap().is_empty(), "the delete has no body");
            let (_, sidecar_account_path) = account_context(&sidecar);
            assert!(read_metadata_attributes(&alice_ctx, &sidecar_account_path).unwrap().deleted, "sidecar carries the delete");

            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();
            assert!(!temp_dir.join("ark/alice/shared/foo.txt").exists(), "not pushed while the conflict stands");

            resolve_conflict(&alice_ctx, "/shared/foo.txt").unwrap();
            assert_eq!(fs::read(temp_dir.join("ark/alice/shared/foo.txt")).unwrap(), b"edited", "resolving puts the copy again");
            assert!(remote_sidecar(&alice_dir.join("shared"), "foo.txt").is_none(), "sidecar removed");
        });
    }

    #[test]
    fn sync_keeps_only_the_newest_remote_side_of_a_conflict() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");
            let remote_sidecars = || fs::read_dir(alice_dir.join("shared")).unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("foo.txt.remote-"))
                .map(|e| e.path())
                .collect::<Vec<_>>();

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            seed_shared_file_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address, "shared/foo.txt", b"v1");

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            delete(&bob_ctx, &target).unwrap();
            write_local(&bob_dir, "shared/foo.txt", b"bob-v2");
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(alice_dir.join("shared/foo.txt"), b"alice").unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            let sidecars = remote_sidecars();
            assert_eq!(sidecars.len(), 1, "one remote side: {:?}", sidecars);
            assert_eq!(fs::read(&sidecars[0]).unwrap(), b"bob-v2", "the put after the delete, not the delete");

            set_current_dir(&bob_dir).unwrap();
            fs::write(bob_dir.join("shared/foo.txt"), b"bob-v3").unwrap();
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            let sidecars = remote_sidecars();
            assert_eq!(sidecars.len(), 1, "an earlier remote side is replaced: {:?}", sidecars);
            assert_eq!(fs::read(&sidecars[0]).unwrap(), b"bob-v3");
            assert_eq!(fs::read(alice_dir.join("shared/foo.txt")).unwrap(), b"alice", "local edit preserved");
        });
    }

    #[test]
    fn sync_records_a_conflict_on_a_file_changed_locally_in_a_directory_another_account_deleted() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            fs::create_dir(alice_dir.join("shared/sub")).unwrap();
            put(&alice_ctx, "shared/sub/", &writer(&bob_ctx.identity.address), None, false).unwrap();
            write_local(&alice_dir, "shared/sub/a.txt", b"v1");
            put(&alice_ctx, "shared/sub/a.txt", &writer(&bob_ctx.identity.address), Some("none"), false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/sub", port);
            get(&bob_ctx, &target, false, false).unwrap();
            delete(&bob_ctx, &target).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(alice_dir.join("shared/sub/a.txt"), b"edited").unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(alice_dir.join("shared/sub/a.txt")).unwrap(), b"edited", "local edit preserved");
            assert!(remote_sidecar(&alice_dir.join("shared/sub"), "a.txt").is_some(), "sidecar file present");
            assert!(!temp_dir.join("ark/alice/shared/sub/a.txt").exists(), "not pushed while the conflict stands");
        });
    }

    #[test]
    fn sync_removes_a_deleted_directory_only_once_it_is_empty() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            fs::create_dir(alice_dir.join("shared/sub")).unwrap();
            put(&alice_ctx, "shared/sub/", &writer(&bob_ctx.identity.address), None, false).unwrap();
            write_local(&alice_dir, "shared/sub/a.txt", b"tracked");
            put(&alice_ctx, "shared/sub/a.txt", &writer(&bob_ctx.identity.address), Some("none"), false).unwrap();
            write_local(&alice_dir, "shared/scratch.txt", b"untracked");

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared", port);
            get(&bob_ctx, &target, false, false).unwrap();
            delete(&bob_ctx, &target).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert!(!alice_dir.join("shared/sub").exists(), "a tracked directory left empty goes");
            assert!(alice_dir.join("shared/scratch.txt").exists(), "an untracked file stays");
        });
    }

    #[test]
    fn sync_of_a_subdir_removes_what_a_delete_above_it_took() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            write_local(&alice_dir, "shared/sub/a.txt", b"tracked");
            put(&alice_ctx, "shared/sub/a.txt", &writer(&bob_ctx.identity.address), Some("none"), false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared", port);
            get(&bob_ctx, &target, false, false).unwrap();
            delete(&bob_ctx, &target).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, "shared/sub", false, false, |_| false, |_| false).unwrap();

            assert!(!alice_dir.join("shared/sub/a.txt").exists());
        });
    }

    #[test]
    fn sync_removes_what_a_delete_took_when_the_directory_is_written_again() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            fs::create_dir(alice_dir.join("shared/sub")).unwrap();
            put(&alice_ctx, "shared/sub/", &writer(&bob_ctx.identity.address), None, false).unwrap();
            write_local(&alice_dir, "shared/sub/old.txt", b"old");
            put(&alice_ctx, "shared/sub/old.txt", &writer(&bob_ctx.identity.address), Some("none"), false).unwrap();
            write_local(&alice_dir, "shared/sub/scratch.txt", b"untracked");

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/sub", port);
            get(&bob_ctx, &target, false, false).unwrap();
            delete(&bob_ctx, &target).unwrap();
            fs::create_dir_all(bob_dir.join("shared/sub")).unwrap();
            put(&bob_ctx, &target, &Permissions::default(), None, false).unwrap();
            write_local(&bob_dir, "shared/sub/new.txt", b"new");
            put(&bob_ctx, &format!("{}/new.txt", target), &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert!(!alice_dir.join("shared/sub/old.txt").exists(), "the delete took it before the directory came back");
            assert_eq!(fs::read(alice_dir.join("shared/sub/new.txt")).unwrap(), b"new");
            assert!(alice_dir.join("shared/sub/scratch.txt").exists(), "an untracked file stays");
        });
    }

    #[test]
    fn sync_checks_each_change_against_the_one_before_it() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);
            let carol_dir = temp_dir.join("carol_client");
            fs::create_dir_all(&carol_dir).unwrap();
            set_current_dir(&carol_dir).unwrap();
            init(&current_dir().unwrap(), &format!("carol@127.0.0.1:{}", port), None, false).unwrap();
            let carol_ctx = create_client_context().unwrap();

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            write_local(&alice_dir, "shared/foo.txt", b"v1");
            put(&alice_ctx, "shared/foo.txt", &Permissions::default(), Some("none"), false).unwrap();
            put_permissions(&alice_ctx, "shared/foo.txt", &owner(bob_ctx.identity.address.clone())).unwrap();

            // Bob, a co-owner, lets Carol in, and Carol then edits: her edit
            // only checks out against the version that added her.
            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            put_permissions(&bob_ctx, &target, &writer(carol_ctx.identity.address.clone())).unwrap();

            // Carol checks Bob's change back through a version she was no
            // member of: its metadata is hers to read, its body is not.
            set_current_dir(&carol_dir).unwrap();
            get(&carol_ctx, &target, false, false).unwrap();
            let before_carol = read_metadata_attributes(&carol_ctx, "/shared/foo.txt").unwrap().parent_version.unwrap();
            let mut body = Vec::new();
            let result = get_stream(&carol_ctx, &target, &mut body, false, Some(&before_carol));
            assert!(matches!(result, Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied), "the earlier body is not hers");
            assert_eq!(read_versions(&carol_ctx, &target).unwrap().len(), 3, "her first get stores the history it was made on");
            let result = get_version(&carol_ctx, &target, &before_carol, false, None);
            assert!(matches!(result, Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied), "nor is it from her history");
            fs::write(carol_dir.join("shared/foo.txt"), b"carol").unwrap();
            put(&carol_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            let errors = Mutex::new(Vec::new());
            sync(&alice_ctx, ".", false, false, |_| false, |e| { errors.lock().unwrap().push(e.to_string()); false }).unwrap();

            assert!(errors.lock().unwrap().is_empty(), "{:?}", errors.lock().unwrap());
            assert_eq!(fs::read(alice_dir.join("shared/foo.txt")).unwrap(), b"carol");
        });
    }

    #[test]
    fn a_new_device_checks_what_it_pulls_back_to_the_account() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            seed_shared_file_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address, "shared/foo.txt", b"v1");

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            fs::write(bob_dir.join("shared/foo.txt"), b"bob").unwrap();
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();
            write_local(&bob_dir, "shared/new.txt", b"new");
            put(&bob_ctx, &format!("alice@127.0.0.1:{}/shared/new.txt", port), &Permissions::default(), Some("none"), false).unwrap();

            // Alice's identity and nothing else: every change is traced back
            // through the server's history.
            let device_dir = temp_dir.join("alice_device");
            fs::create_dir_all(device_dir.join(".ark")).unwrap();
            for name in ["identity.json", "identity.key"] {
                fs::copy(alice_dir.join(".ark").join(name), device_dir.join(".ark").join(name)).unwrap();
            }
            set_current_dir(&device_dir).unwrap();
            let device_ctx = create_client_context().unwrap();

            let errors = Mutex::new(Vec::new());
            sync(&device_ctx, ".", false, false, |_| false, |e| { errors.lock().unwrap().push(e.to_string()); false }).unwrap();

            assert!(errors.lock().unwrap().is_empty(), "{:?}", errors.lock().unwrap());
            assert_eq!(fs::read(device_dir.join("shared/foo.txt")).unwrap(), b"bob");
            assert_eq!(fs::read(device_dir.join("shared/new.txt")).unwrap(), b"new");
        });
    }

    #[test]
    fn a_conflict_takes_in_a_remote_side_made_by_a_member_added_since() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);
            let carol_dir = temp_dir.join("carol_client");
            fs::create_dir_all(&carol_dir).unwrap();
            set_current_dir(&carol_dir).unwrap();
            init(&current_dir().unwrap(), &format!("carol@127.0.0.1:{}", port), None, false).unwrap();
            let carol_ctx = create_client_context().unwrap();

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            write_local(&alice_dir, "shared/foo.txt", b"v1");
            put(&alice_ctx, "shared/foo.txt", &Permissions::default(), Some("none"), false).unwrap();
            put_permissions(&alice_ctx, "shared/foo.txt", &owner(bob_ctx.identity.address.clone())).unwrap();

            // Bob edits and lets Carol in at once, then Carol edits: the
            // copy Alice holds predates both.
            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            fs::write(bob_dir.join("shared/foo.txt"), b"bob").unwrap();
            put(&bob_ctx, &target, &writer(carol_ctx.identity.address.clone()), Some("none"), false).unwrap();

            set_current_dir(&carol_dir).unwrap();
            get(&carol_ctx, &target, false, false).unwrap();
            fs::write(carol_dir.join("shared/foo.txt"), b"carol").unwrap();
            put(&carol_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(alice_dir.join("shared/foo.txt"), b"alice").unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            let sidecar = remote_sidecar(&alice_dir.join("shared"), "foo.txt").expect("sidecar file present");
            assert_eq!(fs::read(&sidecar).unwrap(), b"carol", "the newest remote side, checked back to the copy");
            assert_eq!(fs::read(temp_dir.join("ark/alice/shared/foo.txt")).unwrap(), b"carol", "not overwritten");
        });
    }

    #[test]
    fn sync_refuses_a_change_whose_author_was_not_allowed_to_make_it() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");

            set_current_dir(&alice_dir).unwrap();
            fs::create_dir(alice_dir.join("shared")).unwrap();
            put(&alice_ctx, "shared/", &Permissions::default(), None, false).unwrap();
            write_local(&alice_dir, "shared/foo.txt", b"v1");
            put(&alice_ctx, "shared/foo.txt", &Permissions::default(), Some("none"), false).unwrap();
            let existing = read_metadata_attributes(&alice_ctx, "/shared/foo.txt").unwrap();

            // A change Bob signed, who is no member, that the server applied
            // and logged without checking it.
            let mut changed = existing.clone();
            changed.author = bob_ctx.identity.address.clone();
            changed.author_date = existing.author_date + Duration::seconds(1);
            changed.parent_version = Some(to_version(&existing));
            changed.body_hash = Some(Hash { algorithm: existing.body_hash.as_ref().unwrap().algorithm.clone(), value: sha256(b"bob") });
            sign_metadata(bob_ctx.identity_key.as_ref().unwrap(), &mut changed, Some(b"bob")).unwrap();
            plant_logged_put(temp_dir, "alice", "/shared/foo.txt", b"bob", &changed);

            let errors = Mutex::new(Vec::new());
            sync(&alice_ctx, ".", false, false, |_| false, |e| { errors.lock().unwrap().push(e.kind()); false }).unwrap();

            assert_eq!(fs::read(alice_dir.join("shared/foo.txt")).unwrap(), b"v1", "not pulled");
            assert!(errors.lock().unwrap().contains(&io::ErrorKind::PermissionDenied), "{:?}", errors.lock().unwrap());
        });
    }

    #[test]
    fn sync_passes_over_a_change_not_made_on_the_copy_held() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, _) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");

            set_current_dir(&alice_dir).unwrap();
            write_local(&alice_dir, "foo.txt", b"v1");
            put(&alice_ctx, "foo.txt", &Permissions::default(), Some("none"), false).unwrap();
            let v1 = read_metadata_attributes(&alice_ctx, "/foo.txt").unwrap();
            write_local(&alice_dir, "foo.txt", b"v2");
            put(&alice_ctx, "foo.txt", &Permissions::default(), Some("none"), false).unwrap();
            let v2 = read_metadata_attributes(&alice_ctx, "/foo.txt").unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            // Signed by the account, but made on v1 rather than on the copy.
            let mut forked = v2.clone();
            forked.parent_version = Some(to_version(&v1));
            forked.author_date = v2.author_date + Duration::seconds(1);
            forked.body_hash = Some(Hash { algorithm: v2.body_hash.as_ref().unwrap().algorithm.clone(), value: sha256(b"fork") });
            sign_metadata(alice_ctx.identity_key.as_ref().unwrap(), &mut forked, Some(b"fork")).unwrap();
            plant_logged_put(temp_dir, "alice", "/foo.txt", b"fork", &forked);

            let errors = Mutex::new(Vec::new());
            sync(&alice_ctx, ".", false, false, |_| false, |e| { errors.lock().unwrap().push(e.kind()); false }).unwrap();
            assert_eq!(fs::read(alice_dir.join("foo.txt")).unwrap(), b"v2", "not pulled");
            assert_eq!(*errors.lock().unwrap(), vec![io::ErrorKind::AlreadyExists]);

            let errors = Mutex::new(Vec::new());
            sync(&alice_ctx, ".", false, false, |_| false, |e| { errors.lock().unwrap().push(e.kind()); false }).unwrap();
            assert!(errors.lock().unwrap().is_empty(), "passed over, not retried: {:?}", errors.lock().unwrap());
        });
    }

    #[test]
    fn sync_applies_puts_and_deletes_of_a_path_in_order() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);
            seed_shared_file_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address, "shared/kept.txt", b"v1");

            set_current_dir(&bob_dir).unwrap();
            let gone = format!("alice@127.0.0.1:{}/shared/gone.txt", port);
            write_local(&bob_dir, "shared/gone.txt", b"short-lived");
            put(&bob_ctx, &gone, &Permissions::default(), Some("none"), false).unwrap();
            delete(&bob_ctx, &gone).unwrap();

            let kept = format!("alice@127.0.0.1:{}/shared/kept.txt", port);
            get(&bob_ctx, &kept, false, false).unwrap();
            delete(&bob_ctx, &kept).unwrap();
            write_local(&bob_dir, "shared/kept.txt", b"v2");
            put(&bob_ctx, &kept, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert!(!alice_dir.join("shared/gone.txt").exists(), "put then delete leaves nothing");
            assert_eq!(fs::read(alice_dir.join("shared/kept.txt")).unwrap(), b"v2", "delete then put leaves the new file");
        });
    }

    #[test]
    fn sync_applies_own_deletes_in_log_like_any_other() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_dir = temp_dir.join("alice_client");
            fs::create_dir_all(&alice_dir).unwrap();
            set_current_dir(&alice_dir).unwrap();
            init(&current_dir().unwrap(), &format!("alice@127.0.0.1:{}", port), None, false).unwrap();
            let alice_ctx = create_client_context().unwrap();

            let local = alice_dir.join("notes.txt");
            fs::write(&local, b"self body").unwrap();
            put(&alice_ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            delete(&alice_ctx, "notes.txt").unwrap();

            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert!(!local.exists(), "own deletes are applied like anyone's");
        });
    }

    #[test]
    fn sync_writes_conflict_sidecar_when_both_sides_diverge() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);

            let local = alice_dir.join("shared/foo.txt");
            fs::create_dir_all(local.parent().unwrap()).unwrap();
            fs::write(&local, b"alice-v1").unwrap();
            put(&alice_ctx, "/shared/foo.txt", &Permissions::default(), Some("none"), false).unwrap();
            put_permissions(&alice_ctx, "/shared/foo.txt", &writer(bob_ctx.identity.address.clone())).unwrap();

            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let bob_local = bob_dir.join("shared/foo.txt");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            fs::write(&bob_local, b"bob-v2").unwrap();
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(&local, b"alice-v2-unpushed").unwrap();

            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(&local).unwrap(), b"alice-v2-unpushed", "local edit preserved at original path");

            let entries: Vec<_> = fs::read_dir(alice_dir.join("shared")).unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            let sidecar = entries.iter().find(|n| n.starts_with("foo.txt.remote-")).expect("sidecar file present");
            let sidecar_path = alice_dir.join("shared").join(sidecar);
            assert_eq!(fs::read(&sidecar_path).unwrap(), b"bob-v2", "sidecar carries pulled remote body");
            let (_, sidecar_account_path) = account_context(&sidecar_path);
            assert!(has_metadata_attributes(&alice_ctx, &sidecar_account_path).unwrap(), "sidecar carries remote metadata for comparison");
            assert!(read_local_metadata_attributes(&alice_ctx, &sidecar_account_path).unwrap().sync_body_hash.is_none(), "sidecar must not be sync-tracked");
        });
    }

    #[test]
    fn a_conflict_comes_with_its_merge_base_and_resolves_into_a_merge() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);

            let local = alice_dir.join("shared/foo.txt");
            fs::create_dir_all(local.parent().unwrap()).unwrap();
            fs::write(&local, b"base").unwrap();
            put(&alice_ctx, "/shared/foo.txt", &Permissions::default(), Some("none"), false).unwrap();
            put_permissions(&alice_ctx, "/shared/foo.txt", &writer(bob_ctx.identity.address.clone())).unwrap();
            let base_id = to_version(&read_metadata_attributes(&alice_ctx, "/shared/foo.txt").unwrap());

            set_current_dir(&bob_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            fs::write(bob_dir.join("shared/foo.txt"), b"bob").unwrap();
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();
            let bob_id = to_version(&read_metadata_attributes(&bob_ctx, "/shared/foo.txt").unwrap());

            set_current_dir(&alice_dir).unwrap();
            fs::write(&local, b"alice").unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            let base = alice_dir.join(format!("shared/foo.txt.base-{}", base_id));
            assert_eq!(fs::read(&base).unwrap(), b"base", "the version both sides started from");

            fs::write(&local, b"alice and bob").unwrap();
            resolve_conflict(&alice_ctx, "/shared/foo.txt").unwrap();

            let server_file = temp_dir.join("ark/alice/shared/foo.txt");
            assert_eq!(fs::read(&server_file).unwrap(), b"alice and bob");
            let (server_ctx, server_path) = account_context(&server_file);
            let merged = read_metadata_attributes(&server_ctx, &server_path).unwrap();
            assert_eq!(merged.parent_version.as_deref(), Some(bob_id.as_str()), "the merge names the server's version as its parent");

            let entries: Vec<_> = fs::read_dir(alice_dir.join("shared")).unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            assert!(!entries.iter().any(|n| n.contains(".remote-") || n.contains(".base-")), "sidecars removed: {:?}", entries);
        });
    }

    #[test]
    fn sync_pushes_when_only_local_modified() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local = temp_dir.join("f.txt");
            prime_plain(&ctx, &local, "f.txt", b"v1");

            fs::write(&local, b"v2").unwrap();
            sync(&ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(temp_dir.join("ark/gyan/f.txt")).unwrap(), b"v2");
            let entries: Vec<_> = fs::read_dir(temp_dir).unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            assert!(!entries.iter().any(|n| n.contains(".remote-")), "no sidecar for pure local edit");
        });
    }

    #[test]
    fn sync_leaves_untracked_local_alone_when_remote_puts_same_path() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);

            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);

            fs::create_dir_all(alice_dir.join("shared")).unwrap();
            let local = alice_dir.join("shared/foo.txt");
            fs::write(&local, b"untracked local").unwrap();

            set_current_dir(&bob_dir).unwrap();
            write_local(&bob_dir, "shared/foo.txt", b"bob body");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(&local).unwrap(), b"untracked local", "untracked local must not be clobbered");
        });
    }


    #[test]
    fn sync_emits_events_for_push_and_conflict() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);
            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            seed_shared_dir_with_writer(&alice_dir, &alice_ctx, &bob_ctx.identity.address);

            let local = alice_dir.join("shared/foo.txt");
            fs::create_dir_all(local.parent().unwrap()).unwrap();
            fs::write(&local, b"v1").unwrap();
            put(&alice_ctx, "/shared/foo.txt", &Permissions::default(), Some("none"), false).unwrap();
            put_permissions(&alice_ctx, "/shared/foo.txt", &writer(bob_ctx.identity.address.clone())).unwrap();

            let events: Mutex<Vec<EntryEvent>> = Mutex::new(Vec::new());
            let capture = |e| { events.lock().unwrap().push(e); false };

            fs::write(&local, b"v2").unwrap();
            sync(&alice_ctx, ".", false, false,capture, |_| false).unwrap();
            let modified: Vec<_> = events.lock().unwrap().drain(..).collect();
            assert_eq!(modified.len(), 1, "one event for local body push");
            assert!(matches!(modified[0].action, EntryAction::Modified));
            assert!(!modified[0].conflict);

            set_current_dir(&bob_dir).unwrap();
            let bob_local = bob_dir.join("shared/foo.txt");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, false, false).unwrap();
            fs::write(&bob_local, b"bob-v3").unwrap();
            put(&bob_ctx, &target, &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(&local, b"alice-v3-unpushed").unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, ".", false, false,capture, |_| false).unwrap();
            let conflict: Vec<_> = events.lock().unwrap().drain(..).collect();
            assert_eq!(conflict.len(), 1, "one event for body divergence");
            assert!(matches!(conflict[0].action, EntryAction::Modified));
            assert!(conflict[0].conflict, "conflict flag set on sidecar write");
        });
    }
}
