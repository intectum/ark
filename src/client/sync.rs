use std::fs;
use std::io;
use std::path::Path;
use std::thread;

use crate::client::get::get_io;
use crate::client::put::put_io;
use crate::metadata::read_local_metadata_attributes;
use crate::types::{DirectoryEntryKind, IdentityContext, WatchAction};
use crate::util::{io_err, resolve_client_url, sha256};
use crate::watch;

/// Push tracked local files under `ctx.root` to the server. Skips symlinks,
/// `.ark/` directories, and files whose current SHA-256 matches the stored
/// `sync_hash` (unchanged files) or that lack a `sync_hash` entirely
/// (untracked or encrypted-at-rest).
///
/// When `watch` is true, blocks after the initial push and spawns two watchers:
/// a local FS watcher that re-pushes on change, and a remote SSE watcher that
/// pulls remote creates/modifies/deletes. `decrypt` controls whether pulled
/// files are decrypted on write.
pub fn sync_io(ctx: &IdentityContext, watch: bool, decrypt: bool) -> io::Result<()> {
    // TODO: pull_dir
    push_dir(&ctx, &ctx.root)?;

    if watch {
        thread::scope(|s| {
            s.spawn(|| {
                if let Err(e) = pull_watch(ctx, decrypt) {
                    eprintln!("pull watch: {}", e);
                }
            });
            if let Err(e) = push_watch(ctx) {
                eprintln!("push watch: {}", e);
            }
        });
    }

    Ok(())
}

fn pull_watch(ctx: &IdentityContext, decrypt: bool) -> io::Result<()> {
    let url = resolve_client_url(ctx, "/")?;

    watch::watch_remote(ctx, &url, |event| {
        let rel_str = event.path.to_string_lossy();
        let rel = rel_str.trim_start_matches('/');
        if rel.is_empty() || rel == ".ark" || rel.starts_with(".ark/") {
            return Ok(());
        }
        if matches!(event.kind, Some(DirectoryEntryKind::Dir)) {
            return Ok(());
        }

        let local_path = ctx.root.join(rel);

        match event.action {
            WatchAction::Created | WatchAction::Modified => {
                if let Err(e) = pull_file(ctx, rel, &local_path, decrypt) {
                    eprintln!("pull file {}: {}", rel, e);
                }
            }
            WatchAction::Deleted => {
                if local_path.exists() {
                    if let Err(e) = fs::remove_file(&local_path) {
                        eprintln!("pull delete {}: {}", rel, e);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    })
}

fn push_watch(ctx: &IdentityContext) -> io::Result<()> {
    eprintln!("watching {}", ctx.root.display());

    watch::watch_local(&ctx.root, |event| {
        match event.action {
            WatchAction::Created | WatchAction::Modified => {}
            _ => return false,
        }

        if let Ok(rel) = event.path.strip_prefix(&ctx.root) {
            if rel.starts_with(".ark") { return false; }
        }

        if !event.path.is_file() { return false; }

        if let Err(e) = push_file(ctx, &event.path) {
            eprintln!("push failed for {}: {}", event.path.display(), e);
        }

        false
    }, None)
}

fn push_dir(ctx: &IdentityContext, dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            continue;
        }

        let path = entry.path();
        if path.file_name().map_or(false, |file_name| file_name == ".ark") {
            continue;
        }

        if path.is_dir() {
            push_dir(ctx, &path)?;
        } else if path.is_file() {
            if let Err(e) = push_file(ctx, &path) {
                eprintln!("push failed for {}: {}", path.display(), e);
            }
        }
    }

    Ok(())
}

fn pull_file(ctx: &IdentityContext, remote_rel: &str, local_path: &Path, decrypt: bool) -> io::Result<()> {
    let target = format!("/{}", remote_rel);

    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let local_str = local_path.to_str().ok_or_else(|| io_err("local path is not valid UTF-8"))?;
    get_io(ctx, &target, Some(local_str), decrypt)
}

fn push_file(ctx: &IdentityContext, local_path: &Path) -> io::Result<()> {
    let sync_hash = match read_local_metadata_attributes(local_path)?.sync_hash {
        Some(v) => v,
        None => return Ok(()),
    };

    let bytes = fs::read(local_path)?;
    if sync_hash == sha256(&bytes) {
        return Ok(());
    }

    let rel = local_path.strip_prefix(&ctx.root)
        .map_err(|_| io_err("path outside account root"))?;
    let target = format!("/{}", rel.to_string_lossy());

    eprintln!("push: {}", target);
    put_io(ctx, &target, local_path.to_str(), None)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::client::get::get_io;
    use crate::client::put::put_io;
    use crate::server::start_test_server;
    use crate::util::test::{in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};

    fn prime_plain(ctx: &IdentityContext, path: &Path, target: &str, body: &[u8]) {
        fs::write(path, body).unwrap();
        put_io(ctx, target, path.to_str(), Some("none")).unwrap();
    }

    #[test]
    fn sync_skips_untracked_files() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::write(temp_dir.join("bare.txt"), b"hi").unwrap();

            sync_io(&ctx, false, false).unwrap();

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
            sync_io(&ctx, false, false).unwrap();

            let server_body = fs::read(temp_dir.join("ark/gyan/a/b/c.txt")).unwrap();
            assert_eq!(server_body, b"deep v2");
        });
    }

    #[test]
    fn sync_skips_dot_ark_dir() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            sync_io(&ctx, false, false).unwrap();

            assert!(!temp_dir.join("ark/gyan/.ark/identity.key").exists());
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

            sync_io(&ctx, false, false).unwrap();

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
            sync_io(&ctx, false, false).unwrap();

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
            get_io(&ctx, "pulled.txt", Some(local.to_str().unwrap()), false).unwrap();

            sync_io(&ctx, false, false).unwrap();

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
            sync_io(&ctx, false, false).unwrap();

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
            std::os::unix::fs::symlink(&target, &link).unwrap();

            fs::write(&target, b"v2").unwrap();
            sync_io(&ctx, false, false).unwrap();

            assert_eq!(fs::read(temp_dir.join("ark/gyan/target.txt")).unwrap(), b"v2");
            assert!(!temp_dir.join("ark/gyan/link.txt").exists(), "symlink must not be uploaded");
        });
    }

    #[test]
    fn sync_skips_nested_dot_ark_dir() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let staging = temp_dir.join("staging.txt");
            prime_plain(&ctx, &staging, "staging.txt", b"v1");

            fs::create_dir_all(temp_dir.join("a/.ark")).unwrap();
            let hidden = temp_dir.join("a/.ark/hidden.txt");
            fs::rename(&staging, &hidden).unwrap();
            fs::write(&hidden, b"v2 modified").unwrap();
            assert!(read_local_metadata_attributes(&hidden).unwrap().sync_hash.is_some(), "hidden must carry sync_hash so a naive walk would push it");

            sync_io(&ctx, false, false).unwrap();

            assert!(!temp_dir.join("ark/gyan/a/.ark").exists(), "nested .ark dir must not be uploaded");
        });
    }

    #[test]
    fn sync_refreshes_sync_hash_after_push() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local = temp_dir.join("f.txt");
            prime_plain(&ctx, &local, "f.txt", b"v1");

            fs::write(&local, b"v2").unwrap();
            sync_io(&ctx, false, false).unwrap();

            assert_eq!(
                read_local_metadata_attributes(&local).unwrap().sync_hash.as_deref(),
                Some(sha256(b"v2").as_slice()),
                "sync_hash must track uploaded body after push"
            );

            let server_path = temp_dir.join("ark/gyan/f.txt");
            let before = fs::read(&server_path).unwrap();
            sync_io(&ctx, false, false).unwrap();
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
            get_io(&ctx, "secret", Some(local.to_str().unwrap()), false).unwrap();
            assert_eq!(xattr::get(&local, "user.ark_local.encrypted").unwrap().as_deref(), Some(b"true".as_slice()));
            assert!(read_local_metadata_attributes(&local).unwrap().sync_hash.is_none(), "encrypted-at-rest file should not carry sync_hash");

            let before = fs::read(&server_path).unwrap();
            sync_io(&ctx, false, false).unwrap();
            let after = fs::read(&server_path).unwrap();
            assert_eq!(before, after, "encrypted-at-rest file should be skipped by sync");
        });
    }
}
