use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;

use super::{get, get_stream, head, put, request, watch_local, watch_remote};
use crate::identity::parse_address;
use crate::metadata::{has_metadata_attributes, read_local_metadata_attributes, read_metadata_attributes, read_metadata_headers, remove_local_metadata_attributes, write_local_metadata_attributes, write_metadata_attributes};
use crate::types::{DirectoryEntry, DirectoryEntryKind, IdentityContext, Metadata, WatchAction};
use crate::util::{now_iso_fs, io_err, parse_request_entry, resolve_client_url, sha256};

struct SyncEntry {
    relative_path: String,
    modified_local_body: bool,
    modified_local_metadata: bool,
    modified_remote_body: bool,
    modified_remote_metadata: bool,
}

/// Reconcile local and remote state under `path` in a single pass. `path`
/// must be `ctx.root` or a descendant.
///
/// Per tracked file/dir: push if only local changed; pull if only remote
/// changed; pull metadata alone when only permissions/members diverged; write
/// a `<name>.conflict-<iso>` sidecar carrying the remote copy (body plus
/// metadata) when both sides diverged, leaving the local copy untouched. The
/// sidecar is not sync-tracked itself.
///
/// Only items with sync markers (seeded via [`chmod`](super::chmod) or a
/// previous [`put`](super::put)) are considered. Symlinks, untracked local files, and
/// files encrypted at rest are left alone. Remote changes authored by the
/// current account are ignored.
///
/// With `watch=true`, blocks and continues syncing as local FS events and
/// remote SSE events arrive under `path`, in addition to the initial pass.
/// `decrypt` controls whether pulled files are decrypted on write.
pub fn sync(ctx: &IdentityContext, path: &Path, watch: bool, decrypt: bool) -> io::Result<()> {
    if watch {
        thread::scope(|s| {
            s.spawn(|| {
                if let Err(e) = pull_watch(ctx, path, decrypt) {
                    eprintln!("pull watch: {}", e);
                }
            });
            s.spawn(|| {
                if let Err(e) = push_watch(ctx, path) {
                    eprintln!("push watch: {}", e);
                }
            });
            if let Err(e) = initial_sync(ctx, path, decrypt) {
                eprintln!("initial sync: {}", e);
            }
        });
    } else {
        initial_sync(ctx, path, decrypt)?;
    }

    Ok(())
}

fn initial_sync(ctx: &IdentityContext, path: &Path, decrypt: bool) -> io::Result<()> {
    let (entries, last_sync_request) = check(ctx, path)?;

    for entry in entries {
        if let Err(e) = sync_entry(ctx, &entry, decrypt) {
            eprintln!("sync failed for {}: {}", entry.relative_path, e);
        }
    }

    if let Some(l) = last_sync_request {
        let ark_dir = path.join(".ark");
        fs::create_dir_all(&ark_dir)?;
        fs::write(ark_dir.join("last_sync_request"), &l)?;
    }

    Ok(())
}

fn pull_watch(ctx: &IdentityContext, path: &Path, decrypt: bool) -> io::Result<()> {
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
        let is_dir = matches!(event.kind, Some(DirectoryEntryKind::Dir));

        match event.action {
            WatchAction::Created | WatchAction::Modified => {
                let entry = SyncEntry {
                    relative_path: relative_path.clone(),
                    modified_local_body: false,
                    modified_local_metadata: false,
                    modified_remote_body: !is_dir,
                    modified_remote_metadata: true,
                };
                if let Err(e) = sync_entry(ctx, &entry, decrypt) {
                    eprintln!("sync failed for {}: {}", relative_path, e);
                }
            }
            WatchAction::Deleted => {
                let local_path = ctx.root.join(&relative_path);
                if local_path.exists() && !is_dir {
                    if let Err(e) = fs::remove_file(&local_path) {
                        eprintln!("pull delete {}: {}", relative_path, e);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    })
}

fn push_watch(ctx: &IdentityContext, path: &Path) -> io::Result<()> {
    watch_local(path, |event| {
        match event.action {
            WatchAction::Created | WatchAction::Modified => {}
            _ => return false,
        }

        let absolute = path.join(&event.path);
        if !absolute.is_file() { return false; }

        match check_entry(ctx, &absolute) {
            Ok(Some(entry)) => {
                if let Err(e) = sync_entry(ctx, &entry, false) {
                    eprintln!("push failed for {}: {}", absolute.display(), e);
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("check {}: {}", absolute.display(), e),
        }

        false
    }, None)
}

fn check(ctx: &IdentityContext, path: &Path) -> io::Result<(Vec<SyncEntry>, Option<String>)> {
    let (log_map, last_sync_request) = fetch_log_map(ctx, path)?;

    let mut entries: HashMap<String, SyncEntry> = HashMap::new();
    check_dir(ctx, path, &mut entries)?;

    for (rel, log) in &log_map {
        if log.modified_by == ctx.identity.address { continue; }

        let is_dir = log.body_hash.is_none();
        let local_path = ctx.root.join(rel);
        let has_local_metadata = local_path.exists() && has_metadata_attributes(&local_path)?;

        if !is_dir && local_path.exists() && !has_local_metadata {
            eprintln!("skip pull for untracked local {}", local_path.display());
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
                modified_local_metadata: false,
                modified_remote_body: body_changed,
                modified_remote_metadata: metadata_changed,
            });
    }

    let list = entries.into_values()
        .filter(|e| e.modified_local_body || e.modified_local_metadata || e.modified_remote_body || e.modified_remote_metadata)
        .collect();
    Ok((list, last_sync_request))
}

fn check_dir(
    ctx: &IdentityContext,
    path: &Path,
    entries: &mut HashMap<String, SyncEntry>,
) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() { continue; }

        let path = entry.path();

        if path.is_dir() {
            check_dir(ctx, &path, entries)?;
        }
        if path.is_dir() || path.is_file() {
            match check_entry(ctx, &path) {
                Ok(Some(e)) => { entries.insert(e.relative_path.clone(), e); }
                Ok(None) => {}
                Err(e) => eprintln!("check {}: {}", path.display(), e),
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

    let modified_local_metadata = match (&local.sync_modified, has_metadata_attributes(path)?) {
        (Some(baseline), true) => &read_metadata_attributes(path)?.modified != baseline,
        _ => false,
    };

    Ok(Some(SyncEntry {
        relative_path: to_relative_path(ctx, path)?,
        modified_local_body,
        modified_local_metadata,
        modified_remote_body: false,
        modified_remote_metadata: false,
    }))
}

fn sync_entry(ctx: &IdentityContext, entry: &SyncEntry, decrypt: bool) -> io::Result<()> {
    let local_path = ctx.root.join(&entry.relative_path);
    let target = format!("/{}", entry.relative_path);

    if entry.modified_local_body && entry.modified_remote_body {
        eprintln!("pull: {}", entry.relative_path);
        let sidecar_path = sidecar_path_for(&local_path);
        get(ctx, &target, sidecar_path.to_str(), decrypt)?;

        remove_local_metadata_attributes(&sidecar_path)?;
        eprintln!("conflict: remote kept at {}", sidecar_path.display());
    } else if entry.modified_local_body {
        eprintln!("push: {}", entry.relative_path);
        put(ctx, &target, local_path.to_str(), None)?;
    } else if entry.modified_remote_body {
        eprintln!("pull: {}", entry.relative_path);
        get(ctx, &target, local_path.to_str(), decrypt)?;
    } else if entry.modified_local_metadata && entry.modified_remote_metadata {
        eprintln!("pull: {}", entry.relative_path);
        let sidecar_path = sidecar_path_for(&local_path);
        let (_, remote_metadata) = head(ctx, &target)?;

        if remote_metadata.body_hash.is_none() {
            fs::create_dir_all(&sidecar_path)?;
        } else {
            fs::copy(&local_path, &sidecar_path)?;
        }
        write_metadata_attributes(&sidecar_path, &remote_metadata)?;
        eprintln!("conflict: remote kept at {}", sidecar_path.display());
    } else if entry.modified_local_metadata {
        eprintln!("push: {}", entry.relative_path);
        put(ctx, &target, local_path.to_str(), None)?;
    } else if entry.modified_remote_metadata {
        eprintln!("pull: {}", entry.relative_path);
        let (_, metadata) = head(ctx, &target)?;

        if metadata.body_hash.is_none() {
            fs::create_dir_all(&local_path)?;
        }
        if !local_path.exists() {
            return Err(io_err(&format!("local path missing: {}", local_path.display())));
        }
        write_metadata_attributes(&local_path, &metadata)?;

        let mut local = read_local_metadata_attributes(&local_path).unwrap_or_default();
        local.sync_modified = Some(metadata.modified.clone());
        write_local_metadata_attributes(&local_path, &local)?;
    }

    Ok(())
}

fn fetch_log_map(ctx: &IdentityContext, path: &Path) -> io::Result<(HashMap<String, Metadata>, Option<String>)> {
    let last_sync_request = match fs::read_to_string(path.join(".ark").join("last_sync_request")) {
        Ok(s) => Some(s.trim().to_string()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };

    let rel_prefix = to_relative_path(ctx, path)?;

    let requests_path = "/.ark/requests/";
    let requests_url = resolve_client_url(ctx, requests_path)?;
    let (code, _, body) = request(Some(ctx), "GET", &requests_url, &[], &[])?;
    if code == 404 {
        return Ok((HashMap::new(), None));
    }
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    let mut entries: Vec<DirectoryEntry> = serde_json::from_slice(&body)
        .map_err(|e| io_err(&format!("dir listing: {}", e)))?;
    entries.retain(|entry|
        matches!(entry.kind, DirectoryEntryKind::File) && entry.name.ends_with(".http"));
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let (account_name, _, _) = parse_address(&ctx.identity.address)?;
    let account_prefix = format!("/ark/{}/", account_name);

    let mut map: HashMap<String, Metadata> = HashMap::new();
    let mut new_last_sync_request = last_sync_request.clone();

    for entry in entries {
        if let Some(cutoff) = &last_sync_request {
            if entry.name.as_str() <= cutoff.as_str() {
                continue;
            }
        }

        new_last_sync_request = Some(entry.name.clone());

        let entry_path = format!("{}{}", requests_path, entry.name);
        let mut entry_body: Vec<u8> = Vec::new();
        if get_stream(ctx, &entry_path, &mut entry_body, false).is_err() {
            continue;
        }

        let (relative_path, metadata) = match parse_put(&entry_body, &account_prefix) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => { eprintln!("bad log entry: {}", e); continue; }
        };

        if !under_prefix(&relative_path, &rel_prefix) { continue; }

        match map.get(&relative_path) {
            Some(existing) if metadata.modified < existing.modified => {}
            _ => { map.insert(relative_path, metadata); }
        }
    }

    Ok((map, new_last_sync_request))
}

fn parse_put(entry_bytes: &[u8], account_prefix: &str) -> io::Result<Option<(String, Metadata)>> {
    let entry = parse_request_entry(entry_bytes)?;

    if entry.method != "PUT" { return Ok(None); }
    if entry.status != 201 && entry.status != 204 { return Ok(None); }

    let Some(relative_path) = entry.target.strip_prefix(account_prefix) else { return Ok(None); };

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
    local_path.with_file_name(format!("{}.conflict-{}", file_name, now_iso_fs()))
}

#[cfg(test)]
mod tests {
    use std::env::{current_dir, set_current_dir};
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::client::{chmod, get::get, init, put::put};
    use crate::context::create_client_context;
    use crate::server::start_test_server;
    use crate::util::test::{in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};

    fn prime_plain(ctx: &IdentityContext, path: &Path, target: &str, body: &[u8]) {
        fs::write(path, body).unwrap();
        put(ctx, target, path.to_str(), Some("none")).unwrap();
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
        chmod(alice_ctx, shared.to_str().unwrap(), &[], &[writer_addr.to_string()], &[], &[], true, None).unwrap();
        put(alice_ctx, "shared/", Some(shared.to_str().unwrap()), None).unwrap();
    }

    #[test]
    fn sync_skips_untracked_files() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::write(temp_dir.join("bare.txt"), b"hi").unwrap();

            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

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

            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

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

            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

            assert_eq!(
                read_local_metadata_attributes(&local).unwrap().sync_body_hash.as_ref().unwrap().value,
                sha256(b"v2"),
                "sync_body_hash must track uploaded body after push"
            );

            let server_path = temp_dir.join("ark/gyan/f.txt");
            let before = fs::read(&server_path).unwrap();
            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();
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
            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();
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
            put(&bob_ctx, &target, Some(payload.to_str().unwrap()), Some("none")).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

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
            chmod(&alice_ctx, shared.to_str().unwrap(), &[bob_ctx.identity.address.clone()], &[], &[], &[], true, None).unwrap();
            put(&alice_ctx, "shared/", Some(shared.to_str().unwrap()), None).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let bob_local = bob_dir.join("payload.bin");
            fs::write(&bob_local, b"v1").unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            put(&bob_ctx, &target, Some(bob_local.to_str().unwrap()), Some("none")).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

            let pulled = alice_dir.join("shared/foo.txt");
            assert_eq!(fs::read(&pulled).unwrap(), b"v1");
            let members_before = read_metadata_attributes(&pulled).unwrap().members.len();
            let modified_before = read_metadata_attributes(&pulled).unwrap().modified;

            set_current_dir(&bob_dir).unwrap();
            chmod(&bob_ctx, bob_local.to_str().unwrap(), &[], &[], &["public".to_string()], &[], true, None).unwrap();
            put(&bob_ctx, &target, Some(bob_local.to_str().unwrap()), Some("none")).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

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
            put(&bob_ctx, &target, Some(local_dir.to_str().unwrap()), None).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

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
            put(&alice_ctx, "notes.txt", Some(local.to_str().unwrap()), Some("none")).unwrap();

            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

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
            put(&bob_ctx, &target, Some(payload.to_str().unwrap()), Some("none")).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();
            assert_eq!(fs::read(alice_dir.join("shared/foo.txt")).unwrap(), b"first");

            fs::remove_file(alice_dir.join("shared/foo.txt")).unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();
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
            put(&alice_ctx, "notes.txt", Some(local.to_str().unwrap()), Some("none")).unwrap();
            fs::remove_file(&local).unwrap();

            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

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
            put(&alice_ctx, "/shared/foo.txt", Some(local.to_str().unwrap()), Some("none")).unwrap();
            chmod(&alice_ctx, local.to_str().unwrap(), &[], &[bob_ctx.identity.address.clone()], &[], &[], true, None).unwrap();
            put(&alice_ctx, "/shared/foo.txt", Some(local.to_str().unwrap()), Some("none")).unwrap();

            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let bob_payload = bob_dir.join("payload.bin");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, Some(bob_payload.to_str().unwrap()), false).unwrap();
            fs::write(&bob_payload, b"bob-v2").unwrap();
            put(&bob_ctx, &target, Some(bob_payload.to_str().unwrap()), Some("none")).unwrap();

            set_current_dir(&alice_dir).unwrap();
            fs::write(&local, b"alice-v2-unpushed").unwrap();

            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

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
            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

            assert_eq!(fs::read(temp_dir.join("ark/gyan/f.txt")).unwrap(), b"v2");
            let entries: Vec<_> = fs::read_dir(temp_dir).unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            assert!(!entries.iter().any(|n| n.contains(".conflict-")), "no sidecar for pure local edit");
        });
    }

    #[test]
    fn sync_pushes_local_metadata_only_after_chmod() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local = temp_dir.join("f.txt");
            prime_plain(&ctx, &local, "f.txt", b"v1");

            let server_path = temp_dir.join("ark/gyan/f.txt");
            let body_before = fs::read(&server_path).unwrap();
            let modified_before = read_metadata_attributes(&server_path).unwrap().modified;

            chmod(&ctx, local.to_str().unwrap(), &[], &[], &["public".to_string()], &[], true, None).unwrap();

            sync(&ctx, &current_dir().unwrap(), false, false).unwrap();

            let body_after = fs::read(&server_path).unwrap();
            assert_eq!(body_after, body_before, "body should be unchanged");

            let server_meta = read_metadata_attributes(&server_path).unwrap();
            assert!(server_meta.members.iter().any(|m| m.address == "*"), "public member should propagate");
            assert_ne!(server_meta.modified, modified_before, "modified stamp should advance");

            let local_after = read_local_metadata_attributes(&local).unwrap();
            assert_eq!(local_after.sync_modified.as_deref(), Some(server_meta.modified.as_str()),
                "sync_modified should track pushed metadata stamp");
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
            put(&bob_ctx, &target, Some(payload.to_str().unwrap()), Some("none")).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

            assert_eq!(fs::read(&local).unwrap(), b"untracked local", "untracked local must not be clobbered");
        });
    }

    #[test]
    fn sync_writes_metadata_sidecar_when_both_sides_bump_metadata() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);
            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            let shared = alice_dir.join("shared");
            fs::create_dir(&shared).unwrap();
            chmod(&alice_ctx, shared.to_str().unwrap(), &[bob_ctx.identity.address.clone()], &[], &[], &[], true, None).unwrap();
            put(&alice_ctx, "shared/", Some(shared.to_str().unwrap()), None).unwrap();

            let alice_local = alice_dir.join("shared/foo.txt");
            fs::write(&alice_local, b"v1").unwrap();
            put(&alice_ctx, "/shared/foo.txt", Some(alice_local.to_str().unwrap()), Some("none")).unwrap();
            chmod(&alice_ctx, alice_local.to_str().unwrap(), &[bob_ctx.identity.address.clone()], &[], &[], &[], true, None).unwrap();
            put(&alice_ctx, "/shared/foo.txt", Some(alice_local.to_str().unwrap()), Some("none")).unwrap();

            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let bob_payload = bob_dir.join("payload.bin");
            let target = format!("alice@127.0.0.1:{}/shared/foo.txt", port);
            get(&bob_ctx, &target, Some(bob_payload.to_str().unwrap()), false).unwrap();

            chmod(&alice_ctx, alice_local.to_str().unwrap(), &[], &[], &["public".to_string()], &[], true, None).unwrap();

            chmod(&bob_ctx, bob_payload.to_str().unwrap(), &[], &["carol@host".to_string()], &[], &[], true, None).unwrap();
            put(&bob_ctx, &target, Some(bob_payload.to_str().unwrap()), Some("none")).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

            assert_eq!(fs::read(&alice_local).unwrap(), b"v1", "original body untouched");
            let local_meta = read_metadata_attributes(&alice_local).unwrap();
            assert!(local_meta.members.iter().any(|m| m.address == "*"), "local keeps its own chmod");

            let sidecar = fs::read_dir(alice_dir.join("shared")).unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .find(|n| n.starts_with("foo.txt.conflict-"))
                .expect("metadata sidecar present");
            let sidecar_path = alice_dir.join("shared").join(&sidecar);
            assert_eq!(fs::read(&sidecar_path).unwrap(), b"v1", "sidecar copies local body");
            let sidecar_meta = read_metadata_attributes(&sidecar_path).unwrap();
            assert!(sidecar_meta.members.iter().any(|m| m.address == "carol@host"), "sidecar carries remote members");
            assert!(read_local_metadata_attributes(&sidecar_path).unwrap().sync_body_hash.is_none(), "sidecar must not be sync-tracked");
        });
    }

    #[test]
    fn sync_writes_dir_metadata_sidecar_when_both_sides_bump_metadata() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = init_two_accounts(temp_dir, port);
            let alice_dir = temp_dir.join("alice_client");
            let bob_dir = temp_dir.join("bob_client");

            set_current_dir(&alice_dir).unwrap();
            let shared = alice_dir.join("shared");
            fs::create_dir(&shared).unwrap();
            chmod(&alice_ctx, shared.to_str().unwrap(), &[bob_ctx.identity.address.clone()], &[], &[], &[], true, None).unwrap();
            put(&alice_ctx, "shared/", Some(shared.to_str().unwrap()), None).unwrap();

            let alice_sub = alice_dir.join("shared/sub");
            fs::create_dir(&alice_sub).unwrap();
            chmod(&alice_ctx, alice_sub.to_str().unwrap(), &[bob_ctx.identity.address.clone()], &[], &[], &[], true, None).unwrap();
            put(&alice_ctx, "/shared/sub", Some(alice_sub.to_str().unwrap()), None).unwrap();

            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

            set_current_dir(&bob_dir).unwrap();
            let bob_sub = bob_dir.join("sub");
            fs::create_dir(&bob_sub).unwrap();
            let target = format!("alice@127.0.0.1:{}/shared/sub", port);
            head(&bob_ctx, &target).unwrap();
            let (_, remote_meta) = head(&bob_ctx, &target).unwrap();
            write_metadata_attributes(&bob_sub, &remote_meta).unwrap();

            chmod(&alice_ctx, alice_sub.to_str().unwrap(), &[], &[], &["public".to_string()], &[], true, None).unwrap();

            chmod(&bob_ctx, bob_sub.to_str().unwrap(), &[], &["carol@host".to_string()], &[], &[], true, None).unwrap();
            put(&bob_ctx, &target, Some(bob_sub.to_str().unwrap()), None).unwrap();

            set_current_dir(&alice_dir).unwrap();
            let alice_ctx = create_client_context().unwrap();
            sync(&alice_ctx, &current_dir().unwrap(), false, false).unwrap();

            let sidecar = fs::read_dir(alice_dir.join("shared")).unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .find(|n| n.starts_with("sub.conflict-"))
                .expect("dir metadata sidecar present");
            let sidecar_path = alice_dir.join("shared").join(&sidecar);
            assert!(sidecar_path.is_dir(), "sidecar must be a dir");
            let sidecar_meta = read_metadata_attributes(&sidecar_path).unwrap();
            assert!(sidecar_meta.members.iter().any(|m| m.address == "carol@host"), "sidecar carries remote members");
            assert!(sidecar_meta.body_hash.is_none(), "dir sidecar carries no body_hash");
        });
    }
}
