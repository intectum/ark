use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use crate::http::{write_stream_event, write_stream_keepalive, write_stream_start};
use crate::types::{DirectoryEntry, DirectoryEntryKind, WatchAction};
use crate::client::watch_local;
use crate::util::{io_err, now};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

pub fn serve_stream(fs_path: &Path, stream: &mut dyn Write) -> io::Result<()> {
    write_stream_start(stream)?;

    watch_local(fs_path, |event| {
        let name = match event.action {
            WatchAction::Keepalive => return write_stream_keepalive(stream).is_err(),
            a => a.as_str(),
        };

        write_event(stream, fs_path, &event.path, name, event.kind.as_ref()).is_err()
    }, Some(KEEPALIVE_INTERVAL))
}

fn write_event(stream: &mut dyn Write, root: &Path, path: &Path, name: &str, kind: Option<&DirectoryEntryKind>) -> io::Result<()> {
    let kind = match kind {
        Some(k) => k.clone(),
        None => fs::metadata(path)
            .map(|m| if m.is_dir() { DirectoryEntryKind::Dir } else { DirectoryEntryKind::File })
            .unwrap_or(DirectoryEntryKind::File),
    };

    let entry = DirectoryEntry {
        kind,
        name: path.strip_prefix(root).unwrap_or(path).to_string_lossy().into_owned(),
    };

    let json = serde_json::to_string(&entry).map_err(|e| io_err(&e.to_string()))?;
    write_stream_event(stream, &now().to_string(), name, &json)
}
