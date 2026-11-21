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
log entry that recorded it and the version the server stored. `pull_watch` now
drops these, so no client acts on them, but every watcher is still sent them.
Skipping every path under `/.ark/` in the stream itself would close it.

## A version of a directory cannot be fetched under a file, nor the reverse

A path deleted and written again keeps one history, which can hold a file's
versions and a directory's. `get_version` refuses a version whose kind is not
the kind of the copy held, so those are listed but cannot be fetched by a
client holding the other kind.

## Nothing prunes a client's version store

A client stores every version it uploads or downloads, as copies, under
`/.ark/versions/`. Nothing drops them, so the store grows with the account's
whole history of changes the client has seen. A server stores its history by
design; a client's is a cache, and could drop anything the server also has.

## A purge leaves other devices' version stores

`ark versions --purge` purges the server's history of a path and the store of
the device that ran it. Every other device of the account keeps the copies
in its own store, so the history is recoverable from any of them until each
drops it.

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

## Who wrote a change is only as trusted as the author's identity document

Clients check every change they take in against who was allowed to make it,
but the author's key comes from `resolve_identity`, which fetches the
identity document from the author's host and trusts it on first sight. A host
serving a forged identity for one of its accounts can sign as that account.
Pinning identities, and accepting a new key only under the old one's
signature, would close it.

## A removed member can still sign a new file under an old date

On a client, a first version answers to the directory above it as the
directory's history held it at the file's `author_date`, which the author sets.
A server checks it against the directory it holds now, so refuses one from
someone removed since, but a client cannot tell: someone removed from the
directory can sign a new file dated before the removal, and a server that skips
its checks can serve it. A first version naming the directory version it was
written under would close this.

## A missed relay leaves a server refusing the path

A server takes only a write made on the version it holds. Where a relayed
write never reached it — its server was down, say — it holds no version the
next one was made on, and refuses that and every one after, until the path is
shared again. Fetching the missing versions from the sender would close it,
but the receiving server signs as itself, which is no member of the sender's
path, so it needs a rule letting one server read another's history of a path
both hold.

## Taking in a history costs a request per version

A client taking in a path's history, as on its first download of it, lists
that history once per version it lacks, one after another back along the
chain. A path with a long history, or a tree of many, makes that many
requests. Every listing already carries each version's signed metadata, so
taking the chain in from one would take one.

## A download in address form is checked against the account's own directories

`get` of `bob@host/a/b` writes to the account's own `/a/b`. It is checked with
`bob@host` as the account, whose tree it is, but against the account's own
copy of `/a/b`, its own version store, and its own copies of the directories
above, though the history belongs to another account's tree. Keeping another
account's paths, and their history, under their own address would close it.
