use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

use notify::event::{CreateKind, ModifyKind, RemoveKind};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use url::Url;

use crate::http::{read_stream_events, write_request};
use crate::types::{DirEntry, DirEntryKind, IdentityContext, StreamEvent, WatchAction, WatchEvent};
use crate::util::{create_authorization_header, io_err, now};

const REMOTE_READ_TIMEOUT: Duration = Duration::from_secs(45);
const REMOTE_RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Watch a local directory tree recursively and invoke `on_event` for every
/// create/modify/delete. Blocks.
///
/// `on_event` returning `true` stops the watcher. When `keepalive` is `Some`,
/// synthesises a [`WatchAction::Keepalive`] event after each idle interval so
/// the callback can time out.
///
/// Events are advisory. On macOS, FSEvents may coalesce or reorder
/// Create/Modify pairs; consumers should re-read the file to get authoritative
/// state.
pub fn watch_local<F>(path: &Path, mut on_event: F, keepalive: Option<Duration>) -> io::Result<()>
where
    F: FnMut(WatchEvent) -> bool,
{
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| { let _ = tx.send(res); },
        Config::default(),
    ).map_err(|e| io_err(&format!("watcher: {}", e)))?;

    watcher.watch(path, RecursiveMode::Recursive)
        .map_err(|e| io_err(&format!("watch {}: {}", path.display(), e)))?;

    loop {
        let result = match keepalive {
            Some(t) => match rx.recv_timeout(t) {
                Ok(v) => v,
                Err(RecvTimeoutError::Timeout) => {
                    // TODO: move this out of here?
                    if on_event(WatchEvent { action: WatchAction::Keepalive, kind: None, path: PathBuf::new() }) {
                        return Ok(());
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            },
            None => match rx.recv() {
                Ok(v) => v,
                Err(_) => return Ok(()),
            },
        };

        let event = match result {
            Ok(e) => e,
            Err(e) => { eprintln!("watch error: {}", e); continue; }
        };

        for event_path in event.paths {
            let relative_path = event_path.strip_prefix(path).unwrap_or(&event_path);
            let watch_event = to_watch_event_local(&event.kind, relative_path);
            if let Some(e) = watch_event {
                if on_event(e) { return Ok(()); }
            }
        }
    }
}

/// Subscribe to server-sent events at `url` (any directory on the server) and
/// invoke `on_event` for each remote change under it. Blocks; auto-reconnects
/// on stream errors after a short delay. `ctx` authenticates the
/// subscription.
pub fn watch_remote<F>(ctx: &IdentityContext, url: &Url, mut on_event: F) -> io::Result<()>
where
    F: FnMut(WatchEvent) -> io::Result<()>,
{
    loop {
        let host = url.host_str().ok_or_else(|| io_err("URL missing host"))?;
        let port = url.port().unwrap_or(80);
        let host_header = format!("{}:{}", host, port);

        let authorization = create_authorization_header(ctx, "GET", &host_header, url.path(), now(), &[])?;

        let headers: Vec<(&str, &str)> = vec![
            ("Authorization", authorization.as_str()),
            ("Accept", "text/event-stream"),
        ];

        let mut stream = TcpStream::connect((host, port))?;
        stream.set_read_timeout(Some(REMOTE_READ_TIMEOUT))?;
        write_request(&mut stream, url, "GET", &headers, &[])?;

        let result = read_stream_events(&mut stream, &mut |stream_event: &StreamEvent| {
            match to_watch_event_remote(stream_event) {
                Some(watch_event) => on_event(watch_event),
                None => Ok(()),
            }
        });

        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("watch remote: {} (reconnecting)", e);
                thread::sleep(REMOTE_RECONNECT_DELAY);
            }
        }
    }
}

fn to_watch_event_local(event_kind: &EventKind, path: &Path) -> Option<WatchEvent> {
    let (action, kind) = match event_kind {
        EventKind::Create(CreateKind::Folder) => (WatchAction::Created, Some(DirEntryKind::Dir)),
        EventKind::Create(CreateKind::File) => (WatchAction::Created, Some(DirEntryKind::File)),
        EventKind::Create(_) => (WatchAction::Created, None),
        EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Name(_)) => (WatchAction::Modified, None),
        EventKind::Modify(_) => return None,
        EventKind::Remove(RemoveKind::Folder) => (WatchAction::Deleted, Some(DirEntryKind::Dir)),
        EventKind::Remove(_) => (WatchAction::Deleted, Some(DirEntryKind::File)),
        _ => return None,
    };

    Some(WatchEvent { action, kind, path: path.to_path_buf() })
}

fn to_watch_event_remote(event: &StreamEvent) -> Option<WatchEvent> {
    let action = WatchAction::parse(&event.event)?;

    let entry: DirEntry = match serde_json::from_str(&event.data) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("watch remote: bad SSE payload: {}", e);
            return None;
        }
    };

    Some(WatchEvent {
        action,
        kind: Some(entry.kind),
        path: PathBuf::from(entry.name),
    })
}
