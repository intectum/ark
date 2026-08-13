use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

use crate::client::watch_local;
use crate::http::{write_stream_event, write_stream_keepalive, write_stream_start};
use crate::timestamp;
use crate::types::{DirEntry, DirEntryKind, EntryEvent};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

pub fn serve_stream(fs_path: &Path, stream: &mut dyn Write, verbose: bool) -> io::Result<()> {
    write_stream_start(stream)?;

    let (tx, rx) = channel::<EntryEvent>();
    let watch_path = fs_path.to_path_buf();
    thread::spawn(move || {
        let _ = watch_local(&watch_path, |event| tx.send(event).is_err(), |e| {
            if verbose { eprintln!("stream watch: {}", e); }
            false
        });
    });

    loop {
        match rx.recv_timeout(KEEPALIVE_INTERVAL) {
            Ok(event) => {
                if write_event(stream, fs_path, &event.path, event.action.as_str(), event.kind.as_ref()).is_err() {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if write_stream_keepalive(stream).is_err() { break; }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    Ok(())
}

fn write_event(stream: &mut dyn Write, root: &Path, path: &Path, name: &str, kind: Option<&DirEntryKind>) -> io::Result<()> {
    let kind = match kind {
        Some(k) => k.clone(),
        None => fs::metadata(path)
            .map(|m| if m.is_dir() { DirEntryKind::Dir } else { DirEntryKind::File })
            .unwrap_or(DirEntryKind::File),
    };

    let entry = DirEntry {
        kind,
        name: path.strip_prefix(root).unwrap_or(path).to_string_lossy().into_owned(),
    };

    let json = serde_json::to_string(&entry).map_err(|e| io::Error::other(e.to_string()))?;
    write_stream_event(stream, &timestamp::now_ms().to_string(), name, &json)
}
