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
log entry that recorded it. `pull_watch` pulls these like any other change, so
a watching client takes copies of log entries it should not hold at all.
Skipping every path under `/.ark/` would close it.

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
