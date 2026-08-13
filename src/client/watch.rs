use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use notify::event::{CreateKind, ModifyKind, RemoveKind};
use url::Url;

use crate::http::{connect, read_stream_events, write_request};
use crate::timestamp;
use crate::types::{DirEntry, DirEntryKind, EntryAction, EntryEvent, IdentityContext, StreamEvent};
use crate::util::create_authorization_header;

const REMOTE_READ_TIMEOUT: Duration = Duration::from_secs(45);
const REMOTE_RECONNECT_DELAY: Duration = Duration::from_secs(2);
const LOCAL_REWATCH_INTERVAL: Duration = Duration::from_secs(2);

/// Watch a local file or directory tree recursively and invoke `on_event` for
/// every create/modify/delete. Blocks. Either callback returning `true` stops
/// the watcher; `on_error` receives non-fatal watcher errors.
///
/// `path` need not exist yet: the watch is established once it appears, and
/// re-established if it is replaced. Changes made while `path` is unwatched
/// are missed, so consumers needing completeness must reconcile separately.
///
/// Events are advisory. On macOS, FSEvents may coalesce or reorder
/// Create/Modify pairs; consumers should re-read the file to get authoritative
/// state.
pub fn watch_local<F, G>(path: &Path, mut on_event: F, on_error: G) -> io::Result<()>
where
    F: FnMut(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| { let _ = tx.send(res); },
        Config::default(),
    ).map_err(|e| io::Error::other(format!("watcher: {}", e)))?;

    let mut watched_inode: Option<u64> = None;

    loop {
        // A watch follows the inode it was placed on, not the path, so it goes
        // deaf once that inode is gone (deleted, or replaced by a rename over
        // the top of it). Re-place it whenever the path resolves elsewhere.
        let inode = fs::metadata(path).ok().map(|m| m.ino());
        if inode != watched_inode {
            if watched_inode.is_some() {
                let _ = watcher.unwatch(path);
                watched_inode = None;
            }
            if inode.is_some() {
                match watcher.watch(path, RecursiveMode::Recursive) {
                    Ok(()) => watched_inode = inode,
                    Err(e) => {
                        if on_error(io::Error::other(format!("watch {}: {}", path.display(), e))) { return Ok(()); }
                    }
                }
            }
        }

        let event = match rx.recv_timeout(LOCAL_REWATCH_INTERVAL) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                if on_error(io::Error::other(format!("watch: {}", e))) { return Ok(()); }
                continue;
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        };

        for event_path in event.paths {
            let relative_path = event_path.strip_prefix(path).unwrap_or(&event_path);
            let watch_event = to_entry_event_local(&event.kind, relative_path);
            if let Some(e) = watch_event {
                if on_event(e) { return Ok(()); }
            }
        }
    }
}

/// Subscribe to server-sent events at `url` (any directory on the server) and
/// invoke `on_event` for each remote change under it. Blocks; auto-reconnects
/// on stream errors after a short delay. Either callback returning `true`
/// stops the watcher (skipping reconnect); `on_error` receives stream errors
/// prior to each reconnect and bad payload parse failures. `ctx` authenticates
/// the subscription.
pub fn watch_remote<F, G>(ctx: &IdentityContext, url: &Url, mut on_event: F, on_error: G) -> io::Result<()>
where
    F: FnMut(EntryEvent) -> bool,
    G: Fn(io::Error) -> bool,
{
    loop {
        let host = url.host_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL missing host"))?;
        let host_header = match url.port() {
            Some(p) => format!("{}:{}", host, p),
            None => host.to_string(),
        };

        let authorization = create_authorization_header(ctx, "GET", &host_header, url.path(), timestamp::now_ms(), &[])?;

        let headers: Vec<(&str, &str)> = vec![
            ("Authorization", authorization.as_str()),
            ("Accept", "text/event-stream"),
        ];

        let mut stream = connect(url, REMOTE_READ_TIMEOUT)?;
        write_request(&mut stream, url, "GET", &headers, &[])?;
        let result = read_stream_events(&mut stream, &mut |stream_event: &StreamEvent| {
            match to_entry_event_remote(stream_event, &on_error) {
                Some(entry_event) => on_event(entry_event),
                None => false,
            }
        });

        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                if on_error(e) { return Ok(()); }
                thread::sleep(REMOTE_RECONNECT_DELAY);
            }
        }
    }
}

fn to_entry_event_local(event_kind: &EventKind, path: &Path) -> Option<EntryEvent> {
    let (action, kind) = match event_kind {
        EventKind::Create(CreateKind::Folder) => (EntryAction::Created, Some(DirEntryKind::Dir)),
        EventKind::Create(CreateKind::File) => (EntryAction::Created, Some(DirEntryKind::File)),
        EventKind::Create(_) => (EntryAction::Created, None),
        EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Name(_)) => (EntryAction::Modified, None),
        EventKind::Modify(_) => return None,
        EventKind::Remove(RemoveKind::Folder) => (EntryAction::Deleted, Some(DirEntryKind::Dir)),
        EventKind::Remove(_) => (EntryAction::Deleted, Some(DirEntryKind::File)),
        _ => return None,
    };

    Some(EntryEvent { action, kind, path: path.to_path_buf(), conflict: false })
}

fn to_entry_event_remote<G: Fn(io::Error) -> bool>(event: &StreamEvent, on_error: &G) -> Option<EntryEvent> {
    let action = EntryAction::parse(&event.event)?;

    let entry: DirEntry = match serde_json::from_str(&event.data) {
        Ok(e) => e,
        Err(e) => {
            on_error(io::Error::new(io::ErrorKind::InvalidData, format!("bad SSE payload: {}", e)));
            return None;
        }
    };

    Some(EntryEvent {
        action,
        kind: Some(entry.kind),
        path: PathBuf::from(entry.name),
        conflict: false,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;

    use crate::testing::fs::in_test_dir;

    use super::*;

    /// Watch `dir` in the background, run `act`, and report whether an event
    /// for `expected` arrives before `LOCAL_REWATCH_INTERVAL * 2` elapses.
    fn watch_until(dir: &Path, expected: &'static str, act: impl FnOnce()) -> bool {
        let (tx, rx) = channel();
        let watch_dir = dir.to_path_buf();
        // Detached: on failure `watch_local` never returns, so joining it would
        // hang the test rather than fail it.
        thread::spawn(move || {
            let _ = watch_local(&watch_dir, |event| {
                let hit = event.path == Path::new(expected);
                if hit { let _ = tx.send(()); }
                hit
            }, |_| false);
        });

        act();

        rx.recv_timeout(LOCAL_REWATCH_INTERVAL * 2).is_ok()
    }

    #[test]
    fn watches_dir_created_after_start() {
        in_test_dir("ark_watch_test", |temp_dir| {
            let dir = temp_dir.join("later");

            let seen = watch_until(&dir, "a.txt", || {
                // Let the first watch attempt fail before the dir exists.
                thread::sleep(Duration::from_millis(200));
                fs::create_dir_all(&dir).unwrap();
                thread::sleep(LOCAL_REWATCH_INTERVAL + Duration::from_millis(500));
                fs::write(dir.join("a.txt"), b"hi").unwrap();
            });

            assert!(seen);
        });
    }

    #[test]
    fn rewatches_dir_replaced_after_start() {
        in_test_dir("ark_watch_test", |temp_dir| {
            let dir = temp_dir.join("replaced");
            fs::create_dir_all(&dir).unwrap();

            let seen = watch_until(&dir, "b.txt", || {
                thread::sleep(Duration::from_millis(200));
                fs::remove_dir_all(&dir).unwrap();
                fs::create_dir_all(&dir).unwrap();
                thread::sleep(LOCAL_REWATCH_INTERVAL + Duration::from_millis(500));
                fs::write(dir.join("b.txt"), b"hi").unwrap();
            });

            assert!(seen);
        });
    }
}
