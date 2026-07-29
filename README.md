# Ark

**A distributed backend where every user hosts their own data.**

Ark gives your app four things from one primitive:

- **Storage** — files at HTTP paths, encrypted end-to-end by default.
- **Auth** — a keypair per user replaces passwords, tokens, and OAuth flows.
- **Sharing** — add another user as a member, they can read or write.
- **Federation** — servers push files to each other. No central service.

Think Firebase or Supabase, but each user runs (or picks) their own server, and no host ever sees plaintext.

See the [guide](guide.md) for app-building patterns, or the [spec](spec.md) for the wire protocol.

## Table of Contents

1. [Why](#why)
2. [Install](#install)
3. [CLI quickstart](#cli-quickstart)
4. [Rust library quickstart](#rust-library-quickstart)
5. [Capabilities](#capabilities)
6. [FAQ](#faq)
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
ark put -i note.txt note.txt    # encrypt + upload
ark get note.txt -o out.txt -d  # download + decrypt

# Share with another user
ark put -r bob@localhost:8080 -m -i note.txt note.txt  # metadata-only put

# On bob's side — review and accept the share
ark proposals list              # shows pending share proposals
ark proposals accept 1          # pulls the file, materializes it on bob's server
ark proposals reject 1          # discard instead

# Sync the cwd
ark sync -w                     # reconcile local and remote; watch continuously
```

Every command takes `-h` for details. Paths accept three forms:

- Relative: `notes.txt`
- Absolute (within account): `/notes.txt`
- Cross-account: `bob@example.com/notes.txt`

| Command | What it does |
|---|---|
| `ark server [PORT]` | Run a server. Serves the current directory. |
| `ark init <ADDR>` | Create or download an account identity. `--password` gates remote key recovery. `--local-only` skips the server. |
| `ark get <PATH>` | Download a file. `--decrypt` unwraps it, `-o FILE` writes to disk. |
| `ark put <PATH>` | Upload a file, or create a directory when the input is a directory. `-i FILE` for input, `-o`/`-w`/`-r`/`-d` add or drop members (use `public` for the `*` wildcard), `--encryption-algorithm none` for plaintext, `-m` sends metadata only (server keeps the body). |
| `ark head <PATH>` | Fetch response headers only. |
| `ark list <PATH>` | List entries of a directory. |
| `ark delete <PATH>` | Delete a file or directory (recursive). |
| `ark sync` | Reconcile local and remote state in one pass. `-w` watches continuously. Prints one line per reconciled entry. |
| `ark watch local <PATH>` / `ark watch remote <PATH>` | Print events for local FS changes or the server's SSE stream at PATH. |
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

start_server(8080, "localhost:8080");           // blocks
```

```rust
// Terminal 2 — create an account on that server
// cwd = ./alice
use ark::context::create_client_context;
use ark::client::{init, put_content, put_permissions, get_content, get_stream, sync, list_proposals,
    accept_proposal, reject_proposal, watch_local, watch_remote};
use ark::metadata::reader;

init(&std::env::current_dir()?, "alice@localhost:8080", None, /*local_only=*/ false)?;

// Convention: apps namespace their files under apps/<app>/. Work from there.
std::fs::create_dir_all("apps/notes")?;
std::env::set_current_dir("apps/notes")?;

let ctx = create_client_context()?;             // walks up from cwd to find .ark/

// Upload and download an encrypted file
std::fs::write("note.txt", b"hello")?;
put_content(&ctx, "note.txt")?;                 // encrypt + upload
get_content(&ctx, "note.txt")?;                 // download + decrypt

// Share with another user
put_permissions(&ctx, "note.txt", &reader("bob@localhost:8080"))?;

// On bob's side — review and accept the share
let proposals = list_proposals(&ctx)?;          // pending share proposals
accept_proposal(&ctx, "1", /*force=*/ false)?;  // pulls the file, materializes it on bob's server
reject_proposal(&ctx, "1")?;                    // discard instead

// Sync the cwd
sync(&ctx, &std::env::current_dir()?, /*watch=*/ true, /*decrypt=*/ true,
    |event| { println!("{} {}", event.action.as_str(), event.path.display()); false },
    |error| { eprintln!("sync: {}", error); false }
)?;                                             // reconcile local and remote; watch continuously

// Watch for local changes
let cwd = std::env::current_dir()?;
watch_local(&cwd,
    |event| { println!("{} {}", event.action.as_str(), event.path.display()); false },
    |error| { eprintln!("watch: {}", error); false }
)?;

// Watch for remote changes
let url = ark::util::resolve_client_url(&ctx, ".")?;
watch_remote(&ctx, &url,
    |event| { println!("{} {}", event.action.as_str(), event.path.display()); false },
    |error| { eprintln!("watch: {}", error); false }
)?;

// Streaming form when you don't want to touch the filesystem
let mut buf = Vec::new();
let (metadata, _) = get_stream(&ctx, "note.txt", &mut buf, true)?;
```

Every CLI command has a corresponding library function. Most take file paths and use stdin/stdout when absent. For `encrypt`, `decrypt`, `get`, and `put`, a `_stream` variant (`encrypt_stream`, `decrypt_stream`, `get_stream`, `put_stream`) exposes the same operation over `Read`/`Write` streams and returns values instead of touching the filesystem.

`put` also has two focused wrappers: `put_content(ctx, path)` uploads the body at `path` with default permissions, and `put_permissions(ctx, path, &permissions)` sends a metadata-only PUT to add or drop members without re-uploading the body. Both delegate to `put`, which remains the full form (`input`, `permissions`, `encryption_algorithm`, `metadata_only`). Build a `Permissions` explicitly, or use the `ark::metadata::{owner, writer, reader, drop}` helpers for the common single-member cases.

`get` has a matching wrapper: `get_content(ctx, path)` downloads the body at `path` and writes it under the account root, decrypting when encrypted. `get` remains the full form (`output`, `decrypt`).

---

## Capabilities

| | |
|---|---|
| Identities | Public/private key pairs. Publicly addressable, ED25519 by default. Optional password. |
| Encryption | AES-256-GCM with HPKE key wrap per member by default. |
| Sharing | `owner` / `writer` / `reader` per file. Add or drop members with `put`. |
| Directories | First-class. Recursive delete. Permissions inherit. |
| Public files | Supported for plaintext only (any browser can fetch). |
| Federation | On write, the server relays to co-members' servers. |
| Sync | One-shot or watch mode; reconciles divergence with a conflict sidecar. |
| Transport | Server binds plain HTTP. Client URLs default to `https://` (put a reverse proxy in front for TLS); prefix an address with `http://` to override for dev. |
| Authentication | `ArkIdentity` signed requests. No tokens, no sessions. |

---

## FAQ

**Can I build a real app without server-side code?**

More than you'd think. Clients hold every file shared with them plus the keys to decrypt it, so most "backend" work — filtering, aggregating, joining, rendering — happens locally against files the client already has. Writes are signed by the client and federated to co-members automatically. Reach for a server-side component only when you need something clients genuinely can't do: authoritative ordering between mutually distrusting users, secrets no client should hold, or heavy compute over data one client shouldn't pull in full.

**What if I really do need server-side logic?**

Ark servers only store files — no functions, no queries, no compute. Instead, run your logic as a **bot user**: a long-running process with its own Ark identity that users share the relevant files with. It reacts to changes (via watch), does the work, and writes results back as files the users already have permission to read. Same auth, same sharing, same federation as any other user — no special server-side runtime to learn.

**Can I trust the files?**

Two separate questions.

*Provenance* — yes. Every file is signed by its author's identity keypair, and clients verify the signature on read. A server that tampers with ciphertext, swaps files, or forges an author will fail verification. Encrypted files are also unreadable to the server — it stores ciphertext plus per-member wrapped keys.

*Content* — no, not automatically. A valid signature only proves *who* wrote the bytes, not that the bytes are well-formed or benign. A buggy client, a malicious member with write access, or a compromised key can all produce properly signed garbage. Treat file contents the same way you'd treat any untrusted input: validate schema, bound sizes, sanitize before rendering. Ark gives you authenticity; correctness is your app's job.

**What happens if my server goes down?**

While it's down, readers can't fetch files that only live on your server. Anything you've shared already exists on co-members' servers too — federation pushed them a copy at write time — so those files stay reachable via their hosts. There is no central service to fail; other users' servers keep working. Files are just directories on disk, so back them up like any other data.

**What if a user loses their key?**

Depends on whether they set a password at `ark init`. With a password, the encrypted private key lives on the server and can be re-downloaded and unlocked on a new device. Without one, the key exists only on the original machine — lose it and encrypted files become unrecoverable, and the identity itself can't be reused. Treat it like an SSH key: back it up, or set a password.

**Can non-Ark clients read the files?**

Only public plaintext files (any HTTP client can `GET` them). Encrypted files require an Ark client with the right identity key to unwrap the per-member key.

**Does Ark work on Windows?**

Not yet. Ark stores metadata in filesystem extended attributes; NTFS support isn't wired up. Linux, macOS, and FreeBSD on ext4/xfs/btrfs/apfs work today.

**How does Ark compare to Solid / IPFS / Nostr?**

- **Solid** — closest in spirit: user-owned personal data pods addressed by URL. Ark differs by encrypting end-to-end by default and pushing writes between servers automatically (federation).
- **IPFS** — content-addressed and public by default; great for immutable, shareable blobs. Ark is location-addressed (`user@host/path`), mutable, and private by default, with per-file ACLs.
- **Nostr** — relay-based event stream for messaging. Ark is file-oriented with directories, permissions, and encrypted content; messaging is one thing you can build on top, not the primitive.

**Is Ark production-ready?**

No — treat it as early / experimental. Core storage, auth, sharing, and federation work, but several items in the [Roadmap](#roadmap) (passkeys, groups, key rotation, ratcheted messaging) are unbuilt, and the wire protocol may still change. Fine for prototypes, self-hosting, and small trusted groups; not yet for high-stakes production.

---

## Roadmap

Planned, not yet built. See `spec.md` for details.

- Passkey identities (WebAuthn PRF).
- Groups — invite many users at once, one member entry.
- Invitations — token-based onboarding as a pre-accepted proposal shortcut.
- Key rotation with contact notification.
- Ratcheted sequences (Signal-style forward secrecy) for messaging.
