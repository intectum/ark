# Building on Ark

A guide for app developers. Wire-level details live in the [spec](spec.md); the library surface is documented in the [README](README.md) and Rustdoc. This document covers the *patterns* — how Ark's primitives (files, directories, membership) compose into real app features.

If you're new to Ark, read the [README](README.md) first, then come back here.

## Table of Contents

1. [Mental model](#1-mental-model)
2. [Namespacing your app](#2-namespacing-your-app)
3. [Directory-as-container](#3-directory-as-container)
4. [Chronological items in a directory](#4-chronological-items-in-a-directory)
5. [Membership on a shared directory](#5-membership-on-a-shared-directory)
6. [Syncing a subtree](#6-syncing-a-subtree)
7. [Accepting share proposals](#7-accepting-share-proposals)
8. [Resolving identities](#8-resolving-identities)
9. [Reading files a peer sent you](#9-reading-files-a-peer-sent-you)
10. [Conflicts](#10-conflicts)
11. [Common mistakes](#11-common-mistakes)

---

## 1. Mental model

Ark gives you one primitive — a **signed, member-listed file on disk** — and four things fall out of it:

| App concern | Ark equivalent |
|---|---|
| A record / row | A file. |
| A collection / table | A directory. |
| A user / actor | An address (`name@host`). |
| An ACL | The file's member list. |
| A cross-user feature (chat, share, collab) | Add a member. |
| A push notification | A file appearing in a directory the user watches. |
| A background job | A bot user with its own address, watching a shared directory. |

An app is a **path layout convention** plus code that reads and writes files at those paths. There is no schema layer, no API server, no session store. Whatever you can express as *a file at a path with a member list* is a feature.

Keep this reflex: **when you'd reach for an endpoint, reach for a path instead.**

---

## 2. Namespacing your app

App files live under `apps/<app>/` in each user's account root. This is convention, not enforcement — Ark won't stop you writing elsewhere — but staying in your namespace is what lets multiple apps coexist on the same account without stepping on each other.

```rust
use ark::context::create_client_context;

let ctx = create_client_context()?;   // walks up from cwd to find .ark/
let app_root = ctx.root.join("apps/notes");
std::fs::create_dir_all(&app_root)?;
```

`create_client_context` locates the account root by walking up from the current directory looking for `.ark/`. Cache the returned `IdentityContext` and pass it to every client call — it carries the identity keypair and account root.

**Pick your subtree once, then always work relative to it.** Everything below assumes you have `ctx` and an `app_root` under `apps/<app>/`.

---

## 3. Directory-as-container

The recurring pattern: a **directory** models a container (a conversation, a shared album, a project, a channel), its **members** are the participants, and **files inside** are the container's items (messages, photos, notes, events).

Two levels of membership fall naturally out of this:

- **Container membership** — writers on the directory can add items. Owners can change membership.
- **Item membership** — the sender is owner, everyone else is reader. Ark wraps the item's file key per member.

Only **directories without metadata** inherit — an auto-created intermediate dir on a nested PUT path picks up member checks from its nearest metadata-bearing ancestor. Files always carry their own metadata (author, body hash, member list), so there's no file-level inheritance. Set every item's members explicitly at PUT time.

```rust
use ark::client::put;
use ark::permissions::writers;

// Create the container. Members are writers on the dir — they can add items.
let dir_rel = "apps/notes/team-brainstorm";
let local_dir = ctx.root.join(dir_rel);
std::fs::create_dir_all(&local_dir)?;

put(&ctx, &format!("/{}", dir_rel), Some(local_dir.to_str().unwrap()),
    &writers(["bob@host", "carol@host"]), None, /*metadata_only=*/ false)?;
```

Because path mirroring is guaranteed by the protocol, `apps/notes/team-brainstorm/` lives at that same relative path on every member's server. No rehoming, no per-server IDs — the path *is* the identifier.

---

## 4. Chronological items in a directory

Ark preserves no server-side ordering across files. If your app needs chronological order (messages, log entries, events), bake the timestamp into the filename.

```rust
use ark::timestamp::{format_fs_safe, now};

let file_name = format!("msg_{}.md", format_fs_safe(now()));
// e.g. "msg_2026-07-29T14-22-03.418Z.md"
```

`format_fs_safe` produces a filesystem-safe ISO-8601 stamp. Because ISO stamps sort lexically, `std::fs::read_dir` + `sort_by(name)` yields chronological order without any extra index.

Prefix the file with a short type discriminator (`msg_`, `event_`, `photo_`) so multiple item kinds can share a directory without collision, and so `starts_with` gives you a cheap filter when listing. Use `_` as the field separator — timestamps already contain `-`, so hyphens make names harder to split and scan.

---

## 5. Membership on a shared directory

Two dedicated wrappers cover the common membership ops without re-uploading bodies:

- `put_content(ctx, path)` — upload the body at `path` with default permissions.
- `put_permissions(ctx, path, &permissions)` — metadata-only PUT that adds or drops members.

Compose them with the `ark::permissions` helpers (`owner`, `writer`, `reader`, `drop`, `assign`, `without`).

```rust
use ark::client::put_permissions;
use ark::permissions::{drop, owner, reader, writer};

// Add a new writer to the container.
put_permissions(&ctx, "/apps/notes/team-brainstorm", &writer("dave@host"))?;

// Drop a member.
put_permissions(&ctx, "/apps/notes/team-brainstorm", &drop("carol@host"))?;

// Promote to owner.
put_permissions(&ctx, "/apps/notes/team-brainstorm", &owner("bob@host"))?;
```

Each `put_permissions` on a directory is one PUT. If you have per-item permission (message files, per-photo ACLs), the same membership change may need to fan out across the children — that's app-side today. Batch it under one user action so latency is one visible cost, not N.

**When creating a new item, derive its member list from the container's members**, not from your own state:

```rust
use ark::metadata::read_metadata_attributes;
use ark::permissions::{assign, without};
use ark::types::Permission;

let meta = read_metadata_attributes(&local_dir)?;
let others = without(&meta.members, &ctx.identity.address);
let item_perms = assign(&others, Permission::Reader);   // self stays owner via put
```

This keeps the source of truth in one place: the container's metadata. If members join or leave, the next item you send picks up the new list automatically.

---

## 6. Syncing a subtree

`sync` walks a subtree and reconciles local and remote state. Point it at your app root, not the account root — you don't need to touch other apps' files.

```rust
use ark::client::sync;

// One-shot pass.
sync(&ctx, &ctx.root.join("apps/notes"),
     /*watch=*/ false, /*decrypt=*/ true,
     |ev| { println!("{} {}", ev.action.as_str(), ev.path.display()); false },
     |err| { eprintln!("sync: {}", err); false })?;
```

For a live app, run `sync(..., watch=true, ...)` on a background thread. It blocks and streams reconciled `EntryEvent`s for the lifetime of the call. Each callback returns `bool` — return `true` to stop the stream, `false` to keep going. Both callbacks must be `Fn + Send + Sync`; wrap a `Sender` in `Arc<Mutex<_>>` if you want to fan events into a channel.

```rust
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

let (tx, rx) = mpsc::channel();
let ctx = Arc::new(ctx);
{
    let ctx = ctx.clone();
    let event_tx = Arc::new(Mutex::new(tx.clone()));
    let error_tx = event_tx.clone();
    thread::spawn(move || {
        let path = ctx.root.join("apps/notes");
        let _ = sync(&ctx, &path, true, true,
            move |ev| { let _ = event_tx.lock().unwrap().send(Ok(ev)); false },
            move |e|  { let _ = error_tx.lock().unwrap().send(Err(e));  false });
    });
}
```

**Coalesce bursts.** A watch stream can fire many events for one user action (a directory PUT surfaces the dir and its children). Set a `dirty` flag on receipt and do the reload once per redraw tick rather than once per event.

**One thread, not two — for file/dir events.** `sync(watch=true)` handles both push (local → remote) and pull (remote → local) internally. You don't need a separate watcher.

**Proposals are the exception.** Share proposals — unauthorized PUTs recorded in the request log — are *not* on the watch stream today. See [§7](#7-accepting-share-proposals).

---

## 7. Accepting share proposals

When someone adds you as a member of a file or directory, their server relays the PUT to yours. Your server rejects it (you weren't a member yet) and records the attempt in `/.ark/requests/`. That record is a **proposal**: pending consent to receive the file.

```rust
use ark::client::{accept_proposal, list_proposals, reject_proposal};

for p in list_proposals(&ctx)? {
    // p.target is the relative path the sender tried to write to.
    // p.metadata.modified_by is the sender's address.
    if p.target.starts_with("apps/notes/") {
        accept_proposal(&ctx, &p.id, /*force=*/ false)?;
        // On accept: your client fetches, verifies, and PUTs the file locally.
    }
}
```

`list_proposals` returns proposals for every path. Filter by prefix to keep your app looking only at its own subtree.

### Group by directory

When someone shares a directory with N pre-existing files, you get N proposals — one per file. Group them by their target directory before showing the user, so they see "Bob shared *team-brainstorm*" rather than N separate line items.

```rust
use std::collections::BTreeMap;

let marker = "/apps/notes/";
let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
for p in list_proposals(&ctx)? {
    let Some(i) = p.target.find(marker) else { continue };
    let after = &p.target[i + marker.len()..];
    let dir = after.split('/').next().unwrap_or("").to_string();
    if !dir.is_empty() {
        by_dir.entry(dir).or_default().push(p.id);
    }
}
```

Accept all proposal IDs in the group in one user action.

### Discovering new proposals

Because proposals aren't on the sync watch stream, poll `list_proposals` on an interval (30s is usually fine for interactive apps) *and* re-poll immediately after any accept/reject so the UI reflects the new state without waiting for the tick. A small `mpsc::channel` trigger works well: the poller loops on `recv_timeout(interval)` and re-runs whenever a message arrives or the timer expires.

---

## 8. Resolving identities

To share an encrypted file with a new member, your client needs their **public key** so it can wrap the file key for them. Ark fetches this on demand from the member's server (via their address) the first time you write to a shared file, and caches it locally under `.ark/`.

You rarely call the identity API directly — `put`/`put_permissions` do it for you. What matters is that **the fetch is a hidden network dependency on the member's server**. If Carol's server is unreachable when you `put_permissions` her onto a file, the whole PUT fails.

Mitigations, from cheapest to most involved:

1. **Fetch identities at "add contact" time**, not at first shared PUT. Call `resolve_identity` (from `ark::identity`) when the user first pastes a peer's address into your app. That warms the cache and surfaces a bad address immediately.
2. **Retry on transient failures.** Split the user action into add-and-share, so an outage during share doesn't block adding.
3. **Batch shares.** If you're adding one peer to many files, put the identity fetch on the critical path once, then loop.

---

## 9. Reading files a peer sent you

Once `sync` has pulled a shared file (either from a first-pass reconcile or a watch event), it's on disk. If you passed `decrypt=true` to `sync`, the bytes are plaintext; with `decrypt=false`, they're ciphertext and you'd need `decrypt` / `get_content` to unwrap.

For app code that reads shared files repeatedly, sync with `decrypt=true` once and treat the local mirror as your source of truth:

```rust
use ark::metadata::{has_metadata_attributes, read_metadata_attributes};

for entry in std::fs::read_dir(&local_dir)? {
    let entry = entry?;
    let path = entry.path();
    if !has_metadata_attributes(&path)? { continue; }
    let meta = read_metadata_attributes(&path)?;
    let body = std::fs::read(&path)?;
    // meta.modified_by = author, meta.modified = timestamp, meta.members = ACL
}
```

`has_metadata_attributes` is your filter: local files with no ark xattrs are untracked (drafts, editor swap files, sidecars) and should be skipped.

For one-off reads without touching the filesystem, `get_stream(ctx, path, &mut buf, /*decrypt=*/ true)` returns the metadata plus writes the body into `buf`.

---

## 10. Conflicts

When `sync` sees divergence — the local and remote body both changed since last sync — it does not merge and it does not lose data. It leaves the local copy untouched and writes the remote copy alongside as `<name>.conflict-<iso>`, carrying both the remote body and its metadata. The sidecar is not itself sync-tracked.

Detecting a conflict from an app is a filename check:

```rust
for entry in std::fs::read_dir(&local_dir)? {
    let name = entry?.file_name().to_string_lossy().into_owned();
    if let Some(dot) = name.rfind(".conflict-") {
        let original = &name[..dot];
        // Surface both copies to the user; delete the sidecar once resolved.
    }
}
```

Structure your data model so conflicts are *unlikely*, not impossible: append-only items (messages, log entries) each go in their own file with a unique timestamped name, so two authors never write to the same file. Mutable state (a shared document, a title) needs merge or a designated writer.

---

## 11. Common mistakes

**Writing outside `apps/<app>/`.** Works today, breaks tomorrow when a second app collides on `notes.md`. Namespace early.

**Assuming server-side ordering.** Ark surfaces `read_dir` order, which is unspecified. Sort in your app, and use timestamped filenames so the sort is chronological for free.

**Forgetting the "self" member.** When you `put` a file, you're implicitly its owner. You do not need to add yourself to a member list; you'll appear via the PUT. Adding yourself explicitly is harmless but adds noise.

**Re-fetching data you already synced.** After `sync`, the file is on disk. Don't `get` again for a read — hit the filesystem.

**Polling on the watch thread.** `sync(watch=true)` blocks. Anything else you need to do on a schedule (proposal polling, cache refresh) goes on its own thread with its own `mpsc` channel back to the UI.

**Treating a valid signature as valid content.** Ark's signature proves *who* wrote the bytes. Whether the bytes are well-formed is your app's job — validate schema, bound sizes, sanitize before rendering.

**Building an app-level "add member" flow that fails silently on unreachable peers.** The failure surfaces from `put_permissions` as an `io::Error` from the identity fetch. Surface it to the user with the peer's address in the message, so they know which contact to re-try.

---

## See also

- [README](README.md) — install, CLI, library quickstart.
- [Spec](spec.md) — wire protocol, authentication, encryption, federation.
- Rustdoc on the `ark::client`, `ark::metadata`, and `ark::identity` modules — the authoritative per-function reference.
