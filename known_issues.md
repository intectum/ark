# Known issues

Where the reference implementation falls short of [the spec](spec.md), or of
what it will want to do eventually. Spec sections that describe behaviour
nothing implements yet are listed under
[not yet implemented](spec.md#13-not-yet-implemented) instead; this file is
about code that is there but incomplete.

## A watch of the account root is told about the reserved namespace

`serve_stream` (`src/server/stream.rs`) watches the directory it was asked for
and reports every write beneath it, so a sync of the account root hears about
`/.ark/` as well. One put from a peer reports several events, among them the
log entry that recorded it and the version the server kept. `pull_watch` now
drops these, so no client acts on them, but every watcher is still sent them.
Skipping every path under `/.ark/` in the stream itself would close it.

## Paths last written before every write was versioned lack their current version

Every write is now kept as a version as it lands, so what a path holds is its
newest version. A path last written before that holds an entry that is in no
history, and stays so until its next write. A delete then drops it for good.
Nothing migrates these.

## A version of a directory cannot be fetched under a file, nor the reverse

A path deleted and written again keeps one history, which can hold a file's
versions and a directory's. `validate_version` refuses a version whose kind is
not the kind of the copy held, so those are listed but cannot be fetched by a
client holding the other kind.

## Nothing prunes a client's version store

A client keeps every version it uploads or downloads, as copies, under
`/.ark/versions/`. Nothing drops them, so the store grows with the account's
whole history of changes the client has seen. A server keeps its history by
design; a client's is a cache, and could drop anything the server also has.

## A purge leaves other devices' version stores

`ark versions --purge` drops the server's history of a path and the store of
the device that ran it. Every other device of the account keeps the copies
in its own store, so the history is recoverable from any of them until each
drops it.

## A copy written before clients kept versions has no base in the store

A metadata-only put, and a merge base, read the version a copy's metadata names
from the client's own store. A copy last written before clients kept versions
has none there, so it is fetched from the server on demand — which needs the
server, and that version to still be readable there.

## Two concurrent creates of one identity can mix their files

`init` and `create_client_identity` refuse a path whose identity or key is
already there, but check before writing rather than as they write. Two creates
racing on one path both pass the check, and each file then holds whichever
write landed last, so the identity and its key may come from different
creates.

## Nothing prunes the request log

Spec §10 leaves retention to "clients or admins", and neither has a way to do
it. Every pass lists the log's `PUT_2` entries in full (`fetch_log_map`), so
that listing grows with the account's whole history.

## Changes made while a watch stream is down are missed

`watch_local` says it outright, and the same holds for the SSE stream a client
subscribes to: changes made while the path is unwatched are not reported, and
nothing reconciles on reconnect. They are picked up by the next pass, which may
be the next time `sync` is called.

## A server's event stream can go quietly deaf

`serve_stream` (`src/server/stream.rs`) reports a watcher error and keeps the
connection open, so a subscriber holds a stream that will never tell it anything
again. Ending the stream instead would have subscribers reconnect, as they do
for every other kind of break.
