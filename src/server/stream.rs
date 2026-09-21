use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

use crate::client::watch_local;
use crate::http::{write_stream_event, write_stream_keepalive, write_stream_start};
use crate::storage::{is_dir, join_path, to_account_path, to_fs_path};
use crate::timestamp;
use crate::types::{Context, DirEntry, DirEntryKind, EntryEvent};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

pub fn serve_stream(ctx: &Context, path: &str, stream: &mut dyn Write, verbose: bool) -> io::Result<()> {
    let account_root = to_account_path(ctx, path)?;
    let watch_path = to_fs_path(ctx, path)?;

    write_stream_start(stream)?;

    let (tx, rx) = channel::<EntryEvent>();
    thread::spawn(move || {
        let _ = watch_local(&watch_path, |event| tx.send(event).is_err(), |e| {
            if verbose { eprintln!("stream watch: {}", e); }
            false
        });
    });

    loop {
        match rx.recv_timeout(KEEPALIVE_INTERVAL) {
            Ok(event) => {
                if write_event(ctx, stream, &account_root, &event.path, event.action.as_str(), event.kind.as_ref()).is_err() {
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

fn write_event(ctx: &Context, stream: &mut dyn Write, account_root: &str, path: &Path, name: &str, kind: Option<&DirEntryKind>) -> io::Result<()> {
    let relative_path = path.to_string_lossy().into_owned();

    let kind = match kind {
        Some(k) => k.clone(),
        None => match is_dir(ctx, &join_path(account_root, &relative_path)) {
            true => DirEntryKind::Dir,
            false => DirEntryKind::File,
        }
    };

    let entry = DirEntry {
        kind,
        name: relative_path,
    };

    let json = serde_json::to_string(&entry).map_err(|e| io::Error::other(e.to_string()))?;
    write_stream_event(stream, &timestamp::now_ms().to_string(), name, &json)
}
