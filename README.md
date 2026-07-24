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
3. [CLI quickstart](#cli-quickstart)
4. [Rust library quickstart](#rust-library-quickstart)
7. [Capabilities](#capabilities)
8. [Roadmap](#roadmap)

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
- **First contact is explicit.** Unauthorized writes never silently land on your server. They are rejected and recorded in a per-account request log as share proposals; you accept or reject on your terms.

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

## CLI quickstart

```sh
# Terminal 1 — run a server (serves the current directory)
mkdir server && cd server
ark server 8080
```

```sh
# Terminal 2 — create an account on that server
mkdir alice && cd alice
ark init alice@localhost:8080

# Convention: apps namespace their files under apps/<app>/. Work from there.
mkdir -p apps/notes && cd apps/notes

# Upload and download an encrypted file
echo 'hello' > note.txt
ark track note.txt              # register the file with ark
ark put -i note.txt note.txt    # encrypt + upload
ark get note.txt -o out.txt -d  # download + decrypt

# Share with another user
ark chmod -r bob@localhost:8080 note.txt
ark put -i note.txt note.txt    # re-upload; server relays a copy to bob

# On bob's side — review and accept the share
ark proposals list              # shows pending share proposals
ark proposals accept 1          # pulls the file, materializes it on bob's server
ark proposals reject 1          # discard instead

# Sync the cwd
ark sync -w                     # pull + push + watch (bidirectional)
```

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
| `ark chmod <FILE>` | Change members: `-o` owner, `-w` writer, `-r` reader, `-d` drop. Use `public` for the `*` wildcard. Follow with `put` to sync. |
| `ark sync` | Push local changes to the server. `-w` also watches and pulls. |
| `ark track <PATH>` | Mark an existing local file as an ark file. |
| `ark proposals list` | Show pending share proposals — unauthorized PUTs from other accounts, recorded in `.ark/requests/`. |
| `ark proposals accept <ID>` | Fetch, verify, and PUT the shared file/dir. `-f` bypasses metadata-change checks. |
| `ark proposals reject <ID>` | Delete the log entry. |
| `ark encrypt` / `ark decrypt` | Local file crypto. `--in-place` rewrites the file. |

---

## Rust library quickstart

```rust
// Terminal 1 — run a server (serves the current directory)
// cwd = ./server
use ark::server::start_server;

start_server(8080, "localhost:8080");                           // blocks
```

```rust
// Terminal 2 — create an account on that server
// cwd = ./alice
use ark::context::create_client_context;
use ark::client::{init_io, track_io, put_io, get, get_io, chmod_io, sync_io,
    list_proposals_io, accept_proposal, reject_proposal, watch_local, watch_remote};

init_io("alice@localhost:8080", None)?;

// Convention: apps namespace their files under apps/<app>/. Work from there.
std::fs::create_dir_all("apps/notes")?;
std::env::set_current_dir("apps/notes")?;

let ctx = create_client_context()?;                             // walks up from cwd to find .ark/

// Upload and download an encrypted file
std::fs::write("note.txt", b"hello")?;
track_io(&ctx, "note.txt", None)?;                              // register the file with ark
put_io(&ctx, "note.txt", Some("note.txt"), None)?;              // encrypt + upload
get_io(&ctx, "note.txt", Some("out.txt"), /*decrypt=*/ true)?;  // download + decrypt

// Share with another user
chmod_io(&ctx, "note.txt", &[], &[], &["bob@localhost:8080".into()], &[])?;
put_io(&ctx, "note.txt", Some("note.txt"), None)?;              // re-upload; server relays a copy to bob

// On bob's side — review and accept the share
list_proposals_io(&ctx)?;                                       // shows pending share proposals
accept_proposal(&ctx, "1", /*force=*/ false)?;                  // pulls the file, materializes it on bob's server
reject_proposal(&ctx, "1")?;                                    // discard instead

// Sync the cwd
sync_io(&ctx, /*watch=*/ true, /*decrypt=*/ true)?;             // pull + push + watch (bidirectional), blocks

// Watch for local changes
let cwd = std::env::current_dir()?;
watch_local(&cwd, |event| {
    println!("{:?} {}", event.action.as_str(), event.path.display());
    false  // return true to stop
}, None)?;

// Watch for remote changes
let url = ark::util::resolve_client_url(&ctx, ".")?;
watch_remote(&ctx, &url, |event| {
    println!("remote: {}", event.path.display());
    Ok(())
})?;

// Streaming form when you don't want to touch the filesystem
let mut buf = Vec::new();
let (metadata, _) = get(&ctx, "note.txt", &mut buf, true)?;
```

Every CLI command has a corresponding library function. Two shapes:

- **Plain** — `get`, `put`, `head`, `delete`, `encrypt`, `decrypt`, `init`, `list_proposals`, `accept_proposal`, `reject_proposal`. Take/return values, read/write streams.
- **`_io`** — `get_io`, `put_io`, `head_io`, `encrypt_io`, `decrypt_io`, `chmod_io`, `sync_io`, `track_io`, `init_io`, `list_proposals_io`. CLI shape: optional file paths, stdio fallbacks.

---

## Capabilities

| | |
|---|---|
| Identities | Public/private key pairs. Publicly addressable, ED25519 by default. Optional password. |
| Encryption | AES-256-GCM with HPKE key wrap per member by default. |
| Sharing | `owner` / `writer` / `reader` per file. Add or drop members with `chmod`. |
| Directories | First-class. Recursive delete. Permissions inherit. |
| Public files | Supported for plaintext only (any browser can fetch). |
| Federation | On write, the server relays to co-members' servers. |
| Sync | One-shot or watch mode (push + pull). |
| Transport | Server binds plain HTTP. Client URLs default to `https://` (put a reverse proxy in front for TLS); prefix an address with `http://` to override for dev. |
| Authentication | `ArkIdentity` signed requests. No tokens, no sessions. |

---

## Roadmap

Planned, not yet built. See `spec.md` for details.

- Passkey identities (WebAuthn PRF).
- Groups — invite many users at once, one member entry.
- Invitations — token-based onboarding as a pre-accepted proposal shortcut.
- Key rotation with contact notification.
- Ratcheted sequences (Signal-style forward secrecy) for messaging.
