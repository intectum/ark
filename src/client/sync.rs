use std::fs;
use std::io;
use std::path::Path;
use std::sync::mpsc::channel;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::client::put::cmd_put;
use crate::metadata::read_local_metadata_attributes;
use crate::types::IdentityContext;
use crate::util::{io_err, sha256};

pub fn cmd_sync(ctx: &IdentityContext, watch: bool) -> io::Result<()> {
    sync_dir(&ctx, &ctx.root)?;

    if watch {
        sync_watch(ctx)?;
    }

    Ok(())
}

fn sync_dir(ctx: &IdentityContext, dir: &Path) -> io::Result<()> {
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
            sync_dir(ctx, &path)?;
        } else if path.is_file() {
            if let Err(e) = sync_file(ctx, &path) {
                eprintln!("sync failed for {}: {}", path.display(), e);
            }
        }
    }

    Ok(())
}

fn sync_file(ctx: &IdentityContext, local_path: &Path) -> io::Result<()> {
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

    eprintln!("sync: {}", target);
    cmd_put(ctx, &target, local_path.to_str(), None)?;

    Ok(())
}

fn sync_watch(ctx: &IdentityContext) -> io::Result<()> {
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| { let _ = tx.send(res); },
        Config::default(),
    ).map_err(|e| io_err(&format!("watcher: {}", e)))?;

    watcher.watch(&ctx.root, RecursiveMode::Recursive)
        .map_err(|e| io_err(&format!("watch {}: {}", ctx.root.display(), e)))?;

    eprintln!("watching {}", ctx.root.display());

    for res in rx {
        let event = match res {
            Ok(e) => e,
            Err(e) => { eprintln!("watch error: {}", e); continue; }
        };

        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {}
            _ => continue,
        }

        for path in event.paths {
            match path.strip_prefix(&ctx.root) {
                Ok(rel) if rel.starts_with(".ark") => continue,
                _ => true,
            };

            if !path.is_file() { continue; }

            if let Err(e) = sync_file(ctx, &path) {
                eprintln!("sync failed for {}: {}", path.display(), e);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::client::get::cmd_get;
    use crate::client::put::cmd_put;
    use crate::server::start_test_server;
    use crate::util::test::{in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};

    fn prime_plain(ctx: &IdentityContext, path: &Path, target: &str, body: &[u8]) {
        fs::write(path, body).unwrap();
        cmd_put(ctx, target, path.to_str(), Some("none")).unwrap();
    }

    #[test]
    fn sync_skips_untracked_files() {
        in_test_dir("ark_sync_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::write(temp_dir.join("bare.txt"), b"hi").unwrap();

            cmd_sync(&ctx, false).unwrap();

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
            cmd_sync(&ctx, false).unwrap();

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

            cmd_sync(&ctx, false).unwrap();

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

            cmd_sync(&ctx, false).unwrap();

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
            cmd_sync(&ctx, false).unwrap();

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
            cmd_get(&ctx, "pulled.txt", Some(local.to_str().unwrap()), false).unwrap();

            cmd_sync(&ctx, false).unwrap();

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
            cmd_sync(&ctx, false).unwrap();

            let server_body = fs::read(temp_dir.join("ark/gyan/f.txt")).unwrap();
            assert_eq!(server_body, b"v2");
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
            cmd_get(&ctx, "secret", Some(local.to_str().unwrap()), false).unwrap();
            assert_eq!(xattr::get(&local, "user.ark_local.encrypted").unwrap().as_deref(), Some(b"true".as_slice()));
            assert!(read_local_metadata_attributes(&local).unwrap().sync_hash.is_none(), "encrypted-at-rest file should not carry sync_hash");

            let before = fs::read(&server_path).unwrap();
            cmd_sync(&ctx, false).unwrap();
            let after = fs::read(&server_path).unwrap();
            assert_eq!(before, after, "encrypted-at-rest file should be skipped by sync");
        });
    }
}
