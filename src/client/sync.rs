use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;

use super::{get, get_stream, head, list, put_content, watch_local, watch_remote};
use crate::identity::parse_address;
use crate::metadata::{has_metadata_attributes, read_local_metadata_attributes, read_metadata_attributes, read_metadata_headers, remove_local_metadata_attributes, write_local_metadata_attributes, write_metadata_attributes};
use crate::timestamp;
use crate::types::{DirEntryKind, EntryAction, EntryEvent, IdentityContext, Metadata};
use crate::util::{io_err, parse_request_entry, resolve_client_url, sha256};

struct SyncEntry {
    relative_path: String,
    modified_local_body: bool,
    modified_remote_body: bool,
    modified_remote_metadata: bool,
}

/// Reconcile local and remote state under `path` in a single pass. `path`
/// must be `ctx.root` or a descendant.
///
/// Per tracked file/dir: push if only local changed; pull if only remote
/// changed; pull metadata alone when only remote permissions/members changed;
/// write a `<name>.conflict-<iso>` sidecar carrying the remote copy (body plus
/// metadata) when both sides diverged, leaving the local copy untouched. The
/// sidecar is not sync-tracked itself.
///
/// Only items with sync markers (seeded via a previous [`put`](super::put))
/// are considered. Symlinks, untracked local files, and
/// files encrypted at rest are left alone. Remote changes authored by the
/// current account are ignored.
///
/// With `watch=true`, blocks and continues syncing as local FS events and
/// remote SSE events arrive under `path`, in addition to the initial pass.
/// `decrypt` controls whether pulled files are decrypted on write. `on_event`
/// fires once per reconciled entry; `on_error` receives non-fatal per-entry
/// failures and watch stream errors.
pub fn sync<F, G>(
    ctx: &IdentityContext,
    path: &Path,
    watch: bool,
    decrypt: bool,
    on_event: F,
    on_error: G,
) -> io::Result<()>
where
    F: Fn(EntryEvent) -> bool + Send + Sync,
    G: Fn(io::Error) -> bool + Send + Sync,
{
    if watch {
        thread::scope(|s| {
            s.spawn(|| {
                if let Err(e) = pull_watch(ctx, path, decrypt, &on_event, &on_error) {
                    on_error(io_err(&format!("pull watch: {}", e)));
                }
            });
            s.spawn(|| {
                if let Err(e) = push_watch(ctx, path, &on_event, &on_error) {
                    on_error(io_err(&format!("push watch: {}", e)));
                }
            });
            if let Err(e) = initial_sync(ctx, path, decrypt, &on_event, &on_error) {
                on_error(io_err(&format!("initial sync: {}", e)));
            }
        });
    } else {
        initial_sync(ctx, path, decrypt, &on_event, &on_error)?;
    }

    Ok(())
}

fn initial_sync<F, G>(ctx: &IdentityContext, path: &Path, decrypt: bool, on_event: &F, on_error: &G) -> io::Result<()>
where
    F: Fn(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    let (entries, last_sync_request) = check(ctx, path, on_error)?;

    for entry in entries {
        match sync_entry(ctx, &entry, decrypt, on_event) {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => { on_error(io_err(&format!("sync failed for {}: {}", entry.relative_path, e))); }
        }
    }

    if let Some(l) = last_sync_request {
        let ark_dir = path.join(".ark");
        fs::create_dir_all(&ark_dir)?;
        fs::write(ark_dir.join("last_sync_request"), &l)?;
    }

    Ok(())
}

fn pull_watch<F, G>(ctx: &IdentityContext, path: &Path, decrypt: bool, on_event: &F, on_error: &G) -> io::Result<()>
where
    F: Fn(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    let rel_prefix = to_relative_path(ctx, path)?;
    let url = resolve_client_url(ctx, &format!("/{}", rel_prefix))?;

    watch_remote(ctx, &url, |event| {
        let subpath = event.path.to_string_lossy();
        let relative_path = if rel_prefix.is_empty() {
            subpath.into_owned()
        } else if subpath.is_empty() {
            rel_prefix.clone()
        } else {
            format!("{}/{}", rel_prefix, subpath)
        };
        let is_dir = matches!(event.kind, Some(DirEntryKind::Dir));

        match event.action {
            EntryAction::Created | EntryAction::Modified => {
                let entry = SyncEntry {
                    relative_path: relative_path.clone(),
                    modified_local_body: false,
                    modified_remote_body: !is_dir,
                    modified_remote_metadata: true,
                };
                match sync_entry(ctx, &entry, decrypt, on_event) {
                    Ok(true) => return true,
                    Ok(false) => {}
                    Err(e) => { on_error(io_err(&format!("sync failed for {}: {}", relative_path, e))); }
                }
            }
            EntryAction::Deleted => {
                let local_path = ctx.root.join(&relative_path);
                if local_path.exists() && !is_dir {
                    match fs::remove_file(&local_path) {
                        Ok(()) => if on_event(EntryEvent {
                            action: EntryAction::Deleted,
                            kind: Some(DirEntryKind::File),
                            path: PathBuf::from(&relative_path),
                            conflict: false,
                        }) { return true; },
                        Err(e) => { on_error(io_err(&format!("pull delete {}: {}", relative_path, e))); }
                    }
                }
            }
            _ => {}
        }
        false
    }, on_error)
}

fn push_watch<F, G>(ctx: &IdentityContext, path: &Path, on_event: &F, on_error: &G) -> io::Result<()>
where
    F: Fn(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    watch_local(path, |event| {
        match event.action {
            EntryAction::Created | EntryAction::Modified => {}
            _ => return false,
        }

        let absolute = path.join(&event.path);
        if !absolute.is_file() { return false; }

        match check_entry(ctx, &absolute) {
            Ok(Some(entry)) => match sync_entry(ctx, &entry, false, on_event) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(e) => { on_error(io_err(&format!("push failed for {}: {}", absolute.display(), e))); }
            },
            Ok(None) => {}
            Err(e) => { on_error(io_err(&format!("check {}: {}", absolute.display(), e))); }
        }

        false
    }, on_error)
}

fn check<G>(ctx: &IdentityContext, path: &Path, on_error: &G) -> io::Result<(Vec<SyncEntry>, Option<String>)>
where
    G: Fn(io::Error) -> bool,
{
    let (log_map, last_sync_request) = fetch_log_map(ctx, path, on_error)?;

    let mut entries: HashMap<String, SyncEntry> = HashMap::new();
    check_dir(ctx, path, &mut entries, on_error)?;

    for (rel, log) in &log_map {
        if log.modified_by == ctx.identity.address { continue; }

        let is_dir = log.body_hash.is_none();
        let local_path = ctx.root.join(rel);
        let has_local_metadata = local_path.exists() && has_metadata_attributes(&local_path)?;

        if !is_dir && local_path.exists() && !has_local_metadata {
            continue;
        }

        let (local_modified, local_body_hash, sync_modified) = if has_local_metadata {
            let m = read_metadata_attributes(&local_path)?;
            let l = read_local_metadata_attributes(&local_path)?;
            (Some(m.modified), m.body_hash.map(|h| h.value), l.sync_modified)
        } else {
            (None, None, None)
        };

        let body_changed = if is_dir {
            false
        } else {
            let remote_body_hash = log.body_hash.as_ref().map(|h| &h.value);
            match (&local_body_hash, remote_body_hash) {
                (Some(l), Some(r)) if l == r => false,
                (None, None) => false,
                _ => true,
            }
        };
        let baseline = sync_modified.as_ref().or(local_modified.as_ref());
        let metadata_changed = baseline != Some(&log.modified);

        if !body_changed && !metadata_changed { continue; }

        entries.entry(rel.clone())
            .and_modify(|e| {
                e.modified_remote_body = body_changed;
                e.modified_remote_metadata = metadata_changed;
            })
            .or_insert(SyncEntry {
                relative_path: rel.clone(),
                modified_local_body: false,
                modified_remote_body: body_changed,
                modified_remote_metadata: metadata_changed,
            });
    }

    let list = entries.into_values()
        .filter(|e| e.modified_local_body || e.modified_remote_body || e.modified_remote_metadata)
        .collect();
    Ok((list, last_sync_request))
}

fn check_dir<G>(
    ctx: &IdentityContext,
    path: &Path,
    entries: &mut HashMap<String, SyncEntry>,
    on_error: &G,
) -> io::Result<()>
where
    G: Fn(io::Error) -> bool,
{
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() { continue; }

        let path = entry.path();

        if path.is_dir() {
            check_dir(ctx, &path, entries, on_error)?;
        }
        if path.is_dir() || path.is_file() {
            match check_entry(ctx, &path) {
                Ok(Some(e)) => { entries.insert(e.relative_path.clone(), e); }
                Ok(None) => {}
                Err(e) => { on_error(io_err(&format!("check {}: {}", path.display(), e))); }
            }
        }
    }

    Ok(())
}

fn check_entry(
    ctx: &IdentityContext,
    path: &Path,
) -> io::Result<Option<SyncEntry>> {
    let local = read_local_metadata_attributes(path)?;
    let is_dir = path.is_dir();

    if is_dir {
        if local.sync_modified.is_none() { return Ok(None); }
    } else if local.sync_body_hash.is_none() {
        return Ok(None);
    }

    let modified_local_body = match &local.sync_body_hash {
        Some(h) if !is_dir => h.value != sha256(&fs::read(path)?),
        _ => false,
    };

    Ok(Some(SyncEntry {
        relative_path: to_relative_path(ctx, path)?,
        modified_local_body,
        modified_remote_body: false,
        modified_remote_metadata: false,
    }))
}

fn sync_entry<F>(ctx: &IdentityContext, entry: &SyncEntry, decrypt: bool, on_event: &F) -> io::Result<bool>
where
    F: Fn(EntryEvent) -> bool,
{
    let local_path = ctx.root.join(&entry.relative_path);
    let target = format!("/{}", entry.relative_path);

    let emit = |action: EntryAction, conflict: bool| -> bool {
        let kind = if local_path.is_dir() { DirEntryKind::Dir } else { DirEntryKind::File };
        on_event(EntryEvent {
            action,
            kind: Some(kind),
            path: PathBuf::from(&entry.relative_path),
            conflict,
        })
    };

    if entry.modified_local_body && entry.modified_remote_body {
        let sidecar_path = sidecar_path_for(&local_path);
        get(ctx, &target, sidecar_path.to_str(), decrypt)?;
        remove_local_metadata_attributes(&sidecar_path)?;
        return Ok(emit(EntryAction::Modified, true));
    } else if entry.modified_local_body {
        put_content(ctx, &target)?;
        return Ok(emit(EntryAction::Modified, false));
    } else if entry.modified_remote_body {
        get(ctx, &target, local_path.to_str(), decrypt)?;
        return Ok(emit(EntryAction::Modified, false));
    } else if entry.modified_remote_metadata {
        let (_, metadata) = head(ctx, &target)?;

        if metadata.body_hash.is_none() {
            fs::create_dir_all(&local_path)?;
        }
        if !local_path.exists() {
            return Err(io_err(&format!("local path missing: {}", local_path.display())));
        }
        write_metadata_attributes(&local_path, &metadata)?;

        let mut local = read_local_metadata_attributes(&local_path).unwrap_or_default();
        local.sync_modified = Some(metadata.modified);
        write_local_metadata_attributes(&local_path, &local)?;
        return Ok(emit(EntryAction::Metadata, false));
    }

    Ok(false)
}

fn fetch_log_map<G>(ctx: &IdentityContext, path: &Path, on_error: &G) -> io::Result<(HashMap<String, Metadata>, Option<String>)>
where
    G: Fn(io::Error) -> bool,
{
    let last_sync_request = match fs::read_to_string(path.join(".ark").join("last_sync_request")) {
        Ok(s) => Some(s.trim().to_string()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };

    let rel_prefix = to_relative_path(ctx, path)?;

    let mut entries = list(ctx, "/.ark/requests/", Some("PUT_2"))?;
    entries.retain(|entry|
        matches!(entry.kind, DirEntryKind::File) && entry.name.ends_with(".http"));
    entries.sort_by(|a, b| stamp_key(&a.name).cmp(stamp_key(&b.name)));

    let (account_name, _, _) = parse_address(&ctx.identity.address)?;
    let account_prefix = format!("/ark/{}/", account_name);

    let mut map: HashMap<String, Metadata> = HashMap::new();
    let mut new_last_sync_request = last_sync_request.clone();

    for entry in entries {
        if let Some(cutoff) = &last_sync_request {
            if stamp_key(&entry.name) <= stamp_key(cutoff) {
                continue;
            }
        }

        new_last_sync_request = Some(entry.name.clone());

        let entry_path = format!("/.ark/requests/{}", entry.name);
        let mut entry_body: Vec<u8> = Vec::new();
        if get_stream(ctx, &entry_path, &mut entry_body, false).is_err() {
            continue;
        }

        let (relative_path, metadata) = match parse_put(&entry_body, &account_prefix) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => { on_error(io_err(&format!("bad log entry: {}", e))); continue; }
        };

        if !under_prefix(&relative_path, &rel_prefix) { continue; }

        match map.get(&relative_path) {
            Some(existing) if metadata.modified < existing.modified => {}
            _ => { map.insert(relative_path, metadata); }
        }
    }

    Ok((map, new_last_sync_request))
}

/// Strip the `METHOD_STATUS_` prefix so entries sort and compare by timestamp.
fn stamp_key(name: &str) -> &str {
    name.splitn(3, '_').nth(2).unwrap_or(name)
}

fn parse_put(entry_bytes: &[u8], account_prefix: &str) -> io::Result<Option<(String, Metadata)>> {
    let entry = parse_request_entry(entry_bytes)?;

    if entry.method != "PUT" { return Ok(None); }
    if entry.status != 201 && entry.status != 204 { return Ok(None); }

    let target = entry.target.split_once('?').map(|(p, _)| p).unwrap_or(&entry.target);
    let Some(relative_path) = target.strip_prefix(account_prefix) else { return Ok(None); };

    let metadata = read_metadata_headers(&entry.request_headers)?;

    Ok(Some((relative_path.trim_end_matches('/').to_string(), metadata)))
}

fn to_relative_path(ctx: &IdentityContext, path: &Path) -> io::Result<String> {
    Ok(path.strip_prefix(&ctx.root)
        .map_err(|_| io_err("path is not within this account"))?
        .to_string_lossy()
        .into_owned())
}

fn under_prefix(rel: &str, prefix: &str) -> bool {
    if prefix.is_empty() { return true; }
    rel == prefix || rel.starts_with(&format!("{}/", prefix))
}

fn sidecar_path_for(local_path: &Path) -> PathBuf {
    let file_name = local_path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "conflict".to_string());
    local_path.with_file_name(format!("{}.conflict-{}", file_name, timestamp::format_fs_safe(timestamp::now())))
}

#[cfg(test)]
mod tests {
    use std::env::{current_dir, set_current_dir};
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::client::{get::get, init, put::{put, put_permissions}};
    use crate::context::create_client_context;
    use crate::permissions::{owner, reader, writer};
    use crate::server::start_test_server;
    use crate::types::Permissions;
    use crate::util::test::{in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};

    fn prime_plain(ctx: &IdentityContext, path: &Path, target: &str, body: &[u8]) {
        fs::write(path, body).unwrap();
        put(ctx, target, path.to_str(), &Permissions::default(), Some("none"), false).unwrap();
    }

    fn init_two_accounts(temp_dir: &Path, port: u16) -> (IdentityContext, IdentityContext) {
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

    fn seed_shared_dir_with_writer(alice_dir: &Path, alice_ctx: &IdentityContext, writer_addr: &str) {
        let shared = alice_dir.join("shared");
        fs::create_dir(&shared).unwrap();
        put(alice_ctx, "shared/", Some(shared.to_str().unwrap()), &writer(writer_addr), None, false).unwrap();
    }

    #[test]
    fn sync_skips_untracked_files() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::write(temp_dir.join("bare.txt"), b"hi").unwrap();

            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            let server_body = fs::read(temp_dir.join("ark/gyan/a/b/c.txt")).unwrap();
            assert_eq!(server_body, b"deep v2");
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

            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

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

            let local = temp_dir.join("pulled.txt");
            get(&ctx, "pulled.txt", Some(local.to_str().unwrap()), false).unwrap();

            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            assert_eq!(
                read_local_metadata_attributes(&local).unwrap().sync_body_hash.as_ref().unwrap().value,
                sha256(b"v2"),
                "sync_body_hash must track uploaded body after push"
            );

            let server_path = temp_dir.join("ark/gyan/f.txt");
            let before = fs::read(&server_path).unwrap();
            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();
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
            get(&ctx, "secret", Some(local.to_str().unwrap()), false).unwrap();
            assert_eq!(xattr::get(&local, "user.ark_local.encrypted").unwrap().as_deref(), Some(b"true".as_slice()));
            assert!(read_local_metadata_attributes(&local).unwrap().sync_body_hash.is_none(), "encrypted-at-rest file should not carry sync_body_hash");

            let before = fs::read(&server_path).unwrap();
            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();
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
            let payload = bob_dir.join("payload.bin");
            fs::write(&payload, b"hello alice").unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, Some(payload.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

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
            put(&alice_ctx, "shared/", Some(shared.to_str().unwrap()), &owner(bob_ctx.identity.address.clone()), None, false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let bob_local = bob_dir.join("payload.bin");
            fs::write(&bob_local, b"v1").unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, Some(bob_local.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            let pulled = alice_dir.join("shared/foo.txt");
            assert_eq!(fs::read(&pulled).unwrap(), b"v1");
            let members_before = read_metadata_attributes(&pulled).unwrap().members.len();
            let modified_before = read_metadata_attributes(&pulled).unwrap().modified;

            set_current_dir(&bob_dir).unwrap();
            put(&bob_ctx, &target, Some(bob_local.to_str().unwrap()), &reader("public"), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(&pulled).unwrap(), b"v1", "body should be unchanged");
            let m = read_metadata_attributes(&pulled).unwrap();
            assert!(m.members.iter().any(|mem| mem.address == "*"), "public member should be present after metadata sync");
            assert!(m.members.len() > members_before, "members count should grow after metadata sync");
            assert_ne!(m.modified, modified_before, "modified stamp should refresh after metadata sync");
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
            let local_dir = bob_dir.join("sub");
            fs::create_dir_all(&local_dir).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/sub", port);
            put(&bob_ctx, &target, Some(local_dir.to_str().unwrap()), &Permissions::default(), None, false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            let pulled_dir = alice_dir.join("shared/sub");
            assert!(pulled_dir.is_dir(), "sync should create dir locally");
            assert!(has_metadata_attributes(&pulled_dir).unwrap(), "dir metadata should be written locally");
            let m = read_metadata_attributes(&pulled_dir).unwrap();
            assert_eq!(m.modified_by, bob_ctx.identity.address, "modifier should be bob");
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
            put(&alice_ctx, "notes.txt", Some(local.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();

            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            let last_sync_request = alice_dir.join(".ark/last_sync_request");
            assert!(last_sync_request.exists(), "last_sync_request should be recorded after sync");
            let stamp = fs::read_to_string(&last_sync_request).unwrap();
            assert!(stamp.ends_with(".http"), "last_sync_request should be a log entry filename, got {}", stamp);
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
            let payload = bob_dir.join("payload.bin");
            fs::write(&payload, b"first").unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, Some(payload.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();
            assert_eq!(fs::read(alice_dir.join("shared/foo.txt")).unwrap(), b"first");

            fs::remove_file(alice_dir.join("shared/foo.txt")).unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();
            assert!(!alice_dir.join("shared/foo.txt").exists(), "already-processed log entry must not re-pull");
        });
    }

    #[test]
    fn sync_ignores_own_puts_in_log() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_dir = temp_dir.join("alice_client");
            fs::create_dir_all(&alice_dir).unwrap();
            set_current_dir(&alice_dir).unwrap();
            init(&current_dir().unwrap(), &format!("alice@127.0.0.1:{}", port), None, false).unwrap();
            let alice_ctx = create_client_context().unwrap();

            let local = alice_dir.join("notes.txt");
            fs::write(&local, b"self body").unwrap();
            put(&alice_ctx, "notes.txt", Some(local.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();
            fs::remove_file(&local).unwrap();

            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            assert!(!local.exists(), "own PUTs must not be pulled back");
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
            put(&alice_ctx, "/shared/foo.txt", Some(local.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();
            put_permissions(&alice_ctx, "/shared/foo.txt", &writer(bob_ctx.identity.address.clone())).unwrap();

            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let bob_payload = bob_dir.join("payload.bin");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, Some(bob_payload.to_str().unwrap()), false).unwrap();
            fs::write(&bob_payload, b"bob-v2").unwrap();
            put(&bob_ctx, &target, Some(bob_payload.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(&local, b"alice-v2-unpushed").unwrap();

            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(&local).unwrap(), b"alice-v2-unpushed", "local edit preserved at original path");

            let entries: Vec<_> = fs::read_dir(alice_dir.join("shared")).unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            let sidecar = entries.iter().find(|n| n.starts_with("foo.txt.conflict-")).expect("sidecar file present");
            let sidecar_path = alice_dir.join("shared").join(sidecar);
            assert_eq!(fs::read(&sidecar_path).unwrap(), b"bob-v2", "sidecar carries pulled remote body");
            assert!(has_metadata_attributes(&sidecar_path).unwrap(), "sidecar carries remote metadata for comparison");
            assert!(read_local_metadata_attributes(&sidecar_path).unwrap().sync_body_hash.is_none(), "sidecar must not be sync-tracked");
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
            sync(&ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(temp_dir.join("ark/gyan/f.txt")).unwrap(), b"v2");
            let entries: Vec<_> = fs::read_dir(temp_dir).unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            assert!(!entries.iter().any(|n| n.contains(".conflict-")), "no sidecar for pure local edit");
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
            let payload = bob_dir.join("payload.bin");
            fs::write(&payload, b"bob body").unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, Some(payload.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, |_| false, |_| false).unwrap();

            assert_eq!(fs::read(&local).unwrap(), b"untracked local", "untracked local must not be clobbered");
        });
    }

    #[test]
    fn sync_emits_events_for_push_and_conflict() {
        use std::sync::Mutex;

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
            put(&alice_ctx, "/shared/foo.txt", Some(local.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();
            put_permissions(&alice_ctx, "/shared/foo.txt", &writer(bob_ctx.identity.address.clone())).unwrap();

            let events: Mutex<Vec<EntryEvent>> = Mutex::new(Vec::new());
            let capture = |e| { events.lock().unwrap().push(e); false };

            fs::write(&local, b"v2").unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, capture, |_| false).unwrap();
            let modified: Vec<_> = events.lock().unwrap().drain(..).collect();
            assert_eq!(modified.len(), 1, "one event for local body push");
            assert!(matches!(modified[0].action, EntryAction::Modified));
            assert!(!modified[0].conflict);

            set_current_dir(&bob_dir).unwrap();
            let bob_payload = bob_dir.join("payload.bin");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, Some(bob_payload.to_str().unwrap()), false).unwrap();
            fs::write(&bob_payload, b"bob-v3").unwrap();
            put(&bob_ctx, &target, Some(bob_payload.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(&local, b"alice-v3-unpushed").unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false, capture, |_| false).unwrap();
            let conflict: Vec<_> = events.lock().unwrap().drain(..).collect();
            assert_eq!(conflict.len(), 1, "one event for body divergence");
            assert!(matches!(conflict[0].action, EntryAction::Modified));
            assert!(conflict[0].conflict, "conflict flag set on sidecar write");
        });
    }
}
