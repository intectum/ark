# Ark

**A distributed backend where every user hosts their own data.**

Ark gives your app four things from one primitive:

- **Storage** — files at HTTP paths, encrypted end-to-end by default.
- **Auth** — a keypair per user replaces passwords, tokens, and OAuth flows.
- **Sharing** — add another user as a member, they can read or write.
- **Federation** — servers push files to each other. No central service.

Think Firebase or Supabase, but each user runs (or picks) their own server, and no host ever sees plaintext.

See [`spec.md`](spec.md) for the wire protocol.

## Table of Contents

1. [Why](#why)
2. [Install](#install)
3. [Quick start](#quick-start)
4. [CLI](#cli)
5. [Rust library](#rust-library)
6. [Capabilities](#capabilities)
7. [Roadmap](#roadmap)

---

## Why

Most app backends couple three concerns you'd rather separate: **who the user is**, **where their data lives**, and **who runs the service**. Ark decouples them:

- Identity is a keypair, not a row in your users table.
- Data is a file on a server, not a record you rent from a vendor.
- Servers are commodity — anyone can run one, they interop over HTTP.

Consequences:

- **Users own their data.** A user's server is theirs to move, back up, or replace. Migrating between hosts keeps the identity keypair and every file.
- **No vendor lock-in for apps.** Any Ark-speaking app can read a user's files (with permission). Switching apps doesn't mean re-uploading.
- **No mass-breach target.** Servers store ciphertext they cannot read; there is no central identity provider.
- **Cross-user features come for free.** Messaging, sharing, collaboration — all reduce to "add a member to a file."
- **First contact is explicit.** Unauthorised writes never silently land on your server. They are rejected and recorded in a per-account request log as share proposals; you accept or reject on your terms.

---

## Install

Requires Rust 1.75+ and a filesystem with extended-attribute support (ext4, xfs, btrfs, apfs). Linux, macOS, and FreeBSD are supported. Windows / NTFS are not — no xattr backend yet.

```sh
cargo build --release
# Binary at target/release/ark
```

As a library:

```toml
[dependencies]
ark = { path = "path/to/ark" }
```

---

## Quick start

```sh
# Terminal 1 — run a server (serves the current directory)
mkdir server && cd server
ark server 8080

# Terminal 2 — create an account on that server
mkdir alice && cd alice
ark init alice@localhost:8080

# Upload and download an encrypted file
echo 'hello' > note.txt
ark track note.txt              # register the file with ark
ark put -i note.txt note.txt    # encrypt + upload
ark get note.txt -o out.txt -d  # download + decrypt

# Share with another user
ark chmod -r bob@localhost:8080 note.txt
ark put -i note.txt note.txt    # re-upload; server relays a copy to bob

# On bob's side — review and accept the share
ark proposals list              # shows pending share offers
ark proposals accept 1          # pulls the file, materialises it on bob's server
ark proposals reject 1          # discard instead

# Sync a whole tree
ark sync -w                     # push + watch (bidirectional)
```

---

## CLI

Every command takes `-h` for details. Paths accept three forms:

- Relative: `notes.txt`
- Absolute (within account): `/notes.txt`
- Cross-account: `bob@example.com/notes.txt`

| Command | What it does |
|---|---|
| `ark server [PORT]` | Run a server. Serves the current directory. |
| `ark init <ADDR>` | Create or download an account identity. `--password` gates remote key recovery. |
| `ark get <PATH>` | Download a file. `--decrypt` unwraps it, `-o FILE` writes to disk. |
| `ark put <PATH>` | Upload a file. `-i FILE` for input, `--encryption-algorithm none` for plaintext. Trailing `/` creates a directory. |
| `ark head <PATH>` | Fetch response headers only. |
| `ark delete <PATH>` | Delete a file or directory (recursive). |
| `ark chmod <FILE>` | Change members: `-o` owner, `-w` writer, `-r` reader, `-d` drop. Use `public` for anyone. Follow with `put` to sync. |
| `ark sync` | Push local changes to the server. `-w` also watches and pulls. |
| `ark track <PATH>` | Mark an existing local file as an ark file. |
| `ark proposals list` | Show pending share proposals — unauthorised PUTs from other accounts, recorded in `.ark/requests/`. |
| `ark proposals accept <ID>` | Fetch, verify, and PUT the shared file/dir. `-f` bypasses metadata-change checks. |
| `ark proposals reject <ID>` | Delete the log entry. |
| `ark encrypt` / `ark decrypt` | Local file crypto. `--in-place` rewrites the file. |

---

## Rust library

Every CLI command has a corresponding library function. Two shapes:

- **Plain** — `get`, `put`, `head`, `encrypt`, `decrypt`, `list_proposals`, `accept_proposal`, `reject_proposal`. Take/return values, read/write streams.
- **`_io`** — `get_io`, `put_io`, `head_io`, `encrypt_io`, `decrypt_io`, `chmod_io`, `sync_io`, `track_io`, `list_proposals_io`, `accept_proposal_io`, `reject_proposal_io`. CLI shape: optional file paths, stdio fallbacks, side effects on disk.

### Client

```rust
use ark::context::create_client_context;
use ark::client::{init, get_io, put_io, delete, chmod_io, sync_io};
use ark::watch::{watch_local, watch_remote};

init("alice@example.com:8080", None)?;   // create or recover the account

let ctx = create_client_context()?;      // walks up from cwd to find .ark/

put_io(&ctx, "notes.txt", Some("local.txt"), None)?;
get_io(&ctx, "notes.txt", Some("out.txt"), /*decrypt=*/ true)?;

chmod_io(&ctx, "local.txt",
    &[],
    &["bob@example.com".into()],         // writers
    &[],
    &[])?;

delete(&ctx, "old.txt")?;

sync_io(&ctx, /*watch=*/ true, /*decrypt=*/ true)?;  // blocks

// Local filesystem: create/modify/delete under a directory.
watch_local(&ctx.root, |event| {
    println!("{:?} {}", event.action.as_str(), event.path.display());
    false  // return true to stop
}, None)?;

// Remote SSE stream — events for any directory on the server.
let url = ark::util::resolve_client_url(&ctx, "/")?;
watch_remote(&ctx, &url, |event| {
    println!("remote: {}", event.path.display());
    Ok(())
})?;
```

Streaming form when you don't want to touch the filesystem:

```rust
use ark::client::get;

let mut buf = Vec::new();
let (metadata, _) = get(&ctx, "notes.txt", &mut buf, true)?;
```

### Server

```rust
use ark::server::start_server;

start_server(8080, "example.com:8080");  // blocks
```

`start_server` uses `cwd` as its root and bootstraps its own identity on first run.

---

## Capabilities

| | |
|---|---|
| Identities | Ed25519. Password-derived sub-identities (Argon2id). |
| File encryption | AES-256-GCM by default. HPKE key wrap per member. |
| Public files | Supported for plaintext only (any browser can fetch). |
| Directories | First-class. Recursive delete. Permissions inherit. |
| Sharing | Owner / writer / reader per file. Add or drop members with `chmod`. |
| Federation | On write, the server relays to co-members' servers at the same path. |
| Sync | One-shot push, or watch mode (push + pull via SSE). |
| Transport | Plain HTTP. Put a reverse proxy in front for TLS. |
| Auth scheme | `ArkIdentity` signed requests. No tokens, no sessions. |

---

## Roadmap

Planned, not yet built. See `spec.md` for details.

- Passkey identities (WebAuthn PRF).
- Groups — invite many users at once, one member entry.
- Invitations — token-based onboarding as a pre-accepted proposal shortcut.
- Key rotation with contact notification.
- Ratcheted sequences (Signal-style forward secrecy) for messaging.
- Legacy email interop.
