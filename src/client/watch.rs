use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use notify::event::{CreateKind, ModifyKind, RemoveKind};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use url::Url;

use crate::http::{connect, read_stream_events, write_request};
use crate::timestamp;
use crate::types::{DirEntry, DirEntryKind, EntryAction, EntryEvent, IdentityContext, StreamEvent};
use crate::util::{create_authorization_header, io_err};

const REMOTE_READ_TIMEOUT: Duration = Duration::from_secs(45);
const REMOTE_RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Watch a local directory tree recursively and invoke `on_event` for every
/// create/modify/delete. Blocks. Either callback returning `true` stops the
/// watcher; `on_error` receives non-fatal watcher errors.
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
    ).map_err(|e| io_err(&format!("watcher: {}", e)))?;

    watcher.watch(path, RecursiveMode::Recursive)
        .map_err(|e| io_err(&format!("watch {}: {}", path.display(), e)))?;

    loop {
        let event = match rx.recv() {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                if on_error(io_err(&format!("watch: {}", e))) { return Ok(()); }
                continue;
            }
            Err(_) => return Ok(()),
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
        let host = url.host_str().ok_or_else(|| io_err("URL missing host"))?;
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
            on_error(io_err(&format!("bad SSE payload: {}", e)));
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
