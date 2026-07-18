use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use notify::event::{CreateKind, ModifyKind, RemoveKind};

use crate::http::{write_stream_event, write_stream_keepalive, write_stream_start};
use crate::types::{DirectoryEntry, DirectoryEntryKind};
use crate::util::{io_err, now_milliseconds};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

pub fn serve_stream(fs_path: &Path, stream: &mut dyn Write) -> std::io::Result<()> {
    write_stream_start(stream)?;

    // notify: on macOS FSEvents coalesces batched events with coarser timestamps
    // and may reorder Create/Modify pairs. Consumers should treat (path, event)
    // as an advisory hint and re-HEAD the file to get authoritative metadata.
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| { let _ = tx.send(res); },
        Config::default(),
    ).map_err(|e| io_err(&format!("watcher: {}", e)))?;

    watcher.watch(fs_path, RecursiveMode::Recursive)
        .map_err(|e| io_err(&format!("watch {}: {}", fs_path.display(), e)))?;

    loop {
        match rx.recv_timeout(KEEPALIVE_INTERVAL) {
            Ok(Ok(event)) => {
                let (name, kind) = match &event.kind {
                    EventKind::Create(CreateKind::Folder) => ("created", Some(DirectoryEntryKind::Dir)),
                    EventKind::Create(CreateKind::File) => ("created", Some(DirectoryEntryKind::File)),
                    EventKind::Create(_) => ("created", None),
                    EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Name(_)) => ("modified", None),
                    EventKind::Modify(_) => continue,
                    EventKind::Remove(RemoveKind::Folder) => ("deleted", Some(DirectoryEntryKind::Dir)),
                    EventKind::Remove(_) => ("deleted", Some(DirectoryEntryKind::File)),
                    _ => continue,
                };

                for path in &event.paths {
                    if write_event(stream, fs_path, path, name, kind.as_ref()).is_err() {
                        return Ok(());
                    }
                }
            }
            Ok(Err(_)) => continue,
            Err(RecvTimeoutError::Timeout) => {
                if write_stream_keepalive(stream).is_err() { return Ok(()); }
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

fn write_event(stream: &mut dyn Write, root: &Path, path: &Path, name: &str, kind: Option<&DirectoryEntryKind>) -> std::io::Result<()> {
    let kind = match kind {
        Some(k) => k.clone(),
        None => std::fs::metadata(path)
            .map(|m| if m.is_dir() { DirectoryEntryKind::Dir } else { DirectoryEntryKind::File })
            .unwrap_or(DirectoryEntryKind::File),
    };

    let entry = DirectoryEntry {
        kind,
        name: path.strip_prefix(root).unwrap_or(path).to_string_lossy().into_owned(),
    };

    let json = serde_json::to_string(&entry).map_err(|e| io_err(&e.to_string()))?;
    write_stream_event(stream, &now_milliseconds().to_string(), name, &json)
}
