# Ark Protocol Specification

> **Status:** Draft v0.6
> **Date:** 2026-07-24

## Table of Contents

1. [Overview](#1-overview)
2. [Concepts](#2-concepts)
3. [Client ⇄ Server contract](#3-client--server-contract)
4. [Endpoints](#4-endpoints)
5. [Authentication (`ArkIdentity`)](#5-authentication-arkidentity)
6. [Authorization](#6-authorization)
7. [Metadata](#7-metadata)
8. [Encryption](#8-encryption)
9. [Federation & relay](#9-federation--relay)
10. [Request log](#10-request-log)
11. [Recovery](#11-recovery)
12. [Threat model](#12-threat-model)
13. [Not yet implemented](#13-not-yet-implemented)
- [Appendix A — Types](#appendix-a--types)
- [Appendix B — Algorithms](#appendix-b--algorithms)

---

## 1. Overview

Ark is a federated protocol for storing and sharing files. It gives an application four capabilities from one primitive:

- **Storage** — files at HTTP paths, encrypted end-to-end by default.
- **Auth** — one keypair per user; requests are signed, no passwords or tokens on the wire.
- **Sharing** — add another account as a member of a file or directory; they can read, write, or own it.
- **Federation** — a server writes to another user's server directly. No central service.

An Ark **server** is an authenticated file server rooted at `/ark/<account>/…`. An Ark **client** signs requests with an account's private key, encrypts bodies before uploading, and unwraps them after downloading. Every file carries signed metadata that binds a body hash, an author, and a member list. Access decisions are made from that member list — no separate ACL system.

### Design principles

- **Cryptographic identity, not reputation.** An account is a keypair. There is no IP or domain reputation model.
- **Encrypted by default.** Bodies are encrypted with a per-file symmetric key, wrapped for each member's public key. Servers store ciphertext they cannot read. Unencrypted files are allowed for public content; integrity is still signed.
- **Files on disk.** Storage is the filesystem. No database is required. A file's body is its bytes; its metadata is stored in extended attributes.
- **One primitive.** Everything is a file or directory. Membership decides what is a message, a note, a photo, a website.
- **Simple to self-host.** A single binary, a single account root, a domain with an A record.
- **Federated, not peer-to-peer.** Servers give offline availability and stable addressing. Delivery is server-to-server HTTPS.
- **Spam-resistant by construction.** A write is only accepted from a member of the target path. Everything else is rejected and recorded.
- **App-agnostic.** The protocol defines files, membership, and transport. Path layout is an application concern.

---

## 2. Concepts

**Account.** An addressable entity on a server. Backed by an identity keypair. Rooted on disk at `/ark/<account>/`. Has a self-signed identity document at `/ark/<account>/.ark/identity.json`.

**Address.** `<account>@<host>[:<port>][/<path>]`. `host` is the server's hostname or IP; port defaults to 443. Path defaults to `/.ark/identity.json` (the primary identity). A path other than the default addresses a **sub-identity** — a distinct keypair whose identity file lives under the same account root (for example a password identity at `/.ark/passwords/primary.json`).

**Identity.** A JSON document at some path under `/ark/<account>/.ark/` that pairs an address with a public key and a self-signature (Appendix A.1). The primary identity is at `identity.json`; alternative identities (password, passkey, group) live under `passwords/`, `passkeys/`, `groups/`. Servers do not validate identity content beyond the self-signature.

**Group.** Any identity whose JSON document carries a `members` field. The field lists the addresses of the group's members. A group's own address may appear in a `Member` entry on a file or directory; authorization then treats any listed group member as if they held the group's permission. Convention is to keep groups under `/.ark/groups/`, but the authoritative rule is field presence, not path.

**File.** Raw body bytes on disk, plus a signed metadata record (§7). The metadata carries the file's `id`, timestamps, author, member list, encryption algorithm, body hash, and signature. Bodies of encrypted files are `nonce ‖ ciphertext+tag`; bodies of unencrypted files are raw.

**Directory.** A filesystem directory that may carry metadata of its own. Directory metadata omits `body_hash` and `encryption_algorithm`. A directory's members apply to files under it that do not carry their own metadata.

**Version.** What a path held before a write replaced it — the body bytes and the signed record its author published, kept unchanged. A server keeps a version every time a path is written over, keeps all of them for as long as the path exists, and serves them under that path (§4.3).

**Member.** An entry in a metadata's member list. Consists of an address, a permission, and — for encrypted files — the per-file key wrapped for that member's public key. Special address `*` denotes a public member.

**Permission.** `owner` > `writer` > `reader`. `owner` can modify the member list; `writer` can modify body/metadata but not membership; `reader` can read only. Highest permission a requestor is granted by any of its member matches wins.

**Path mirroring.** A shared file lives at the same relative path on every co-member's server. `apps/notes/team/foo.md` on Alice's server is `apps/notes/team/foo.md` on Bob's. There is no rehoming layer.

---

## 3. Client ⇄ Server contract

| Concern | Client | Server |
|---|---|---|
| **Identity keypair** | Owns the private key. Signs requests. Wraps and unwraps file keys. | Never sees the plaintext private key. Holds an **encrypted** copy of it (as `/.ark/identity.key`) only when password recovery is enabled (§11.2). |
| **Metadata** | Constructs, signs, and sends `X-Ark-Meta-*` headers on PUT. Verifies signatures on GET. | Persists metadata as `user.ark.*` xattrs. Verifies the request signature and metadata signature. Does not construct metadata (except its own `ark@` account entries — §10). |
| **Encryption** | Generates a fresh file key per encrypted PUT. Wraps it to each member's public key. Encrypts and decrypts bodies. | Stores ciphertext. Never sees a plaintext body. Never sees a file key. |
| **Authorization** | Chooses the member list on new files/dirs. | Enforces the member list on every request. Rejects unauthorized writes and records them (§10). |
| **Federation** | Sends **one** PUT to the account's own server with `?relay=full`. | Fans that PUT out to every co-member on every other host, at the identical path. |
| **Public read** | Marks a file public by adding member `*` at `reader`. | Allows unauthenticated GET/HEAD on paths with a `*` member. Still rejects PUT/DELETE without a signed request. |
| **Account creation** | PUTs the new identity to `/.ark/identity.json` on a server. | Creates the account when that path is unclaimed. Rejects claims to existing accounts. |
| **Request log** | Owned by the account. Client reads and prunes it. | The server's `ark@<host>` account writes an entry per non-log request (§10). |

---

## 4. Endpoints

### 4.1 URL shape

`https://<host>/ark/<account>/<path>`

- `<account>` matches the local part of the address; lowercase alphanumeric plus `.`, `-`, `_`; 1–64 chars; not pure dots.
- `<path>` is the file or directory path within the account. `..` segments are rejected.
- A trailing `/` is a hint that the request targets a directory; it is not authoritative. On PUT, dir-vs-file is decided by the presence of `body_hash` in the request metadata (§7). On GET, it is decided by what exists on disk at the resolved path.
- Requests directly to `/ark`, `/ark/`, `/ark/<account>` (no subpath), or to any path outside `/ark/` are rejected.
- Symlinks anywhere in the resolved path are rejected with 403.

### 4.2 Common conventions

**Signed request.** Every non-public request carries an `Authorization: ArkIdentity …` header (§5). A `Host` header is required and must match the server's own host.

**Metadata.** File and directory metadata rides as `X-Ark-Meta-*` request/response headers. Kebab-case field names; base64url for binary values. Members are numbered — `X-Ark-Meta-Member-0-Address`, `X-Ark-Meta-Member-0-Permission`, `X-Ark-Meta-Member-0-Key-Algorithm`, `X-Ark-Meta-Member-0-Key-Value`. Unknown `X-Ark-Meta-*` headers are ignored. Servers MUST verify the metadata signature on every PUT before storing, rejecting with `403` on failure; the signature is checked against the public key of the identity named in `modified_by`, and for files `body_hash` MUST also be recomputed from the request body and compared. Clients SHOULD perform the same checks on every GET before trusting the data, and where the download replaces a copy they already hold, SHOULD also apply the conflict rules of §9 to it — same `id`, `modified` no older — so a server cannot roll a client back or substitute an unrelated file at a path.

**Content-Type on GET.** Not fixed by the protocol. The server picks a value; `application/octet-stream` is a safe default. Directory listings are `application/json`.

**Content-Length.** Required on every request and response.

**Errors.** All non-2xx responses have `Content-Type: text/plain` and a short human message as the body.

### 4.3 `GET`

**File.** Response body is the file's bytes exactly as stored (ciphertext for encrypted files, raw bytes for unencrypted). Response headers include the full `X-Ark-Meta-*` set. Membership is enforced (§6); a `*` member allows unauthenticated GET.

**Directory (default).** Response body is `[DirectoryEntry]` (Appendix A.5) as JSON — `{type, name}` per entry, `type` in `dir | file | symlink`. If the directory itself has metadata, its `X-Ark-Meta-*` are also returned. No recursion.

**Directory (`?prefix=`).** Lists only the entries whose name starts with the given string. A filter on the name alone, so what it can narrow is whatever the names encode — the request log (§10) leads its names with the method and status for this.

**Optional query param: `versions`.** The response body is `[VersionEntry]` (Appendix A.10) as JSON — the history of the path, newest first, or an empty array where it has none. The path's own metadata is not returned.

**Optional query param: `version=<id>`.** The response is that version's body, with the `X-Ark-Meta-*` set its author signed. `404` where the id names no version the server kept. A version is served under the **current** metadata of the path in the URL, never under the member list its own record carries (§6).

Note for clients: a `?version=` response is deliberately older than the copy the client holds, so of the comparison in §4.2 only the age half is waived. It must still be the same file — the same `id`, and a file where the copy is a file — or a server could answer with a validly signed record of some other file. Every other GET applies §4.2 in full.

**Directory (SSE upgrade).** If the request carries `Accept: text/event-stream`, the response is a `text/event-stream` connection that stays open. Each event describes a filesystem change under the target directory. Payload:

```
id: <unix-ms>
event: created | modified | deleted
data: <DirectoryEntry JSON>
```

A `: keepalive` comment is emitted every 15 seconds. The stream ends when the client disconnects.

### 4.4 `HEAD`

Same as `GET` on the same path, without a body. `Content-Length` reports the body size the equivalent GET would return. Not valid with `Accept: text/event-stream` (use GET).

### 4.5 `PUT`

Creates or updates a file or directory. **Dir vs file is determined by whether the request metadata contains `body_hash`** — files must carry a `body_hash`, directories must not. The URL's trailing `/` is a hint only.

**Required request headers.** Full `X-Ark-Meta-*` set. `Authorization` (unless the target is a fresh `/.ark/identity.json` — see below).

**Request body.** For files: the body bytes as stored (ciphertext for encrypted, raw for unencrypted). For directories: empty.

**Optional query param: `relay`.** Instructs the receiving server to fan out this PUT after storing locally (§9).
| Value | Effect |
|---|---|
| `full` | Fan out to every unique remote host in the metadata member list, once per host. Same-host members are also written in-process. |
| `internal` | Same-host members only. No outbound requests. Used to break relay loops. |
| absent | No relay. Server stores locally only. |

**Optional query param: `metadata`.** Metadata-only PUT. The request body is ignored and the file body on disk is left unchanged; only the `X-Ark-Meta-*` xattrs are rewritten. The new metadata's `body_hash` MUST equal the existing file's `body_hash`; otherwise `400`. The target file MUST already exist; otherwise `409`. Query params combine (e.g. `?relay=full&metadata`) — relay carries the flag forward.

**Superseding, not destroying.** A PUT over an existing path keeps what that path held as a version of it (§4.3). A server MUST keep every version until the path is deleted (§4.6); it does not drop old versions on its own.

**Parent directories.** Missing intermediate directories on the path are created automatically. They are created without metadata, so they inherit member checks from the nearest metadata-bearing ancestor (§7.3).

**Response codes.** `201 Created` (new path), `204 No Content` (existing path updated), `400` (missing/bad metadata, body-vs-dir mismatch, or metadata-only body_hash mismatch), `401` (bad signature), `403` (not authorized, or member change without owner), `409` (id mismatch on overwrite, older `modified` than existing, or metadata-only PUT on nonexistent file).

**Bootstrap: `PUT /ark/<account>/.ark/identity.json`.** If no identity exists at that path, the request is unauthenticated and the body is the new account's `Identity` JSON. The request metadata must still be signed by the new account's key. This is how an account is created.

### 4.6 `DELETE`

Removes a file, or recursively removes a directory and its contents, **along with the versions (§4.3) of the path and of everything beneath it**. Deletion leaves nothing to recover: a server that kept history past a delete would keep serving what a removed member still appears in. Membership is enforced. Returns `204 No Content` on success, `404` if the path does not exist, `403` for insufficient permission or a symlinked target.

### 4.7 Response codes

| Code | Meaning |
|---|---|
| 200 | GET/HEAD success. |
| 201 | PUT created a new path. |
| 204 | PUT overwrote an existing path, or DELETE succeeded. |
| 400 | Malformed request (bad metadata, dir-with-body, unparseable path). |
| 401 | Missing / invalid `Authorization` (also: bad `Host`, stale timestamp, bad signature). |
| 403 | Not a member with sufficient permission, member change without `owner`, symlink target, path outside `/ark/`. |
| 404 | Target does not exist, or names no version the server kept. |
| 405 | Method not allowed at this path (e.g. PUT on `/ark/<account>`). |
| 409 | id conflict, or `modified` older than existing. |
| 500 | Server-side error (I/O, corrupt metadata). |

### 4.8 Reserved `/ark/<account>/.ark/` namespace

Everything under `/.ark/` is protocol-defined. Applications must not write arbitrary paths here.

| Path | Content | Notes |
|---|---|---|
| `identity.json` | `Identity` (A.1) | Public. Self-signed. PUT unauthenticated only when creating the account. |
| `identity.key` | Encrypted account private key, as a normal Ark file | Owner + recovery members with `reader`. Body is the base64url identity seed, encrypted under a per-file key like any other file (§8). |
| `identities/<address>.json` | Cached peer `Identity` | **Client-local.** Not required or served by the server; documented so implementations agree on where clients keep their TOFU cache. `<address>` is percent-encoded per the rule below. A reader MUST check that the entry it finds answers for the address asked for, and ignore it otherwise. |
| `versions/<path>/<id>` | What a path held before a write replaced it | **Server-local.** One directory per path, holding an ordinary ark entry per version — body bytes and the record its author signed. Reached through `?version=` / `?versions` on the path itself (§4.3), never as a path of its own. `<path>` is percent-encoded per the rule below. |
| `versions/<path>/.previous` | The metadata a directory carried before a rewrite | **Server-local.** Empty file carrying the previous record in its own attributes, set aside so an interrupted rewrite can be put back. See §7.2. Not a version: an id never begins with `.`, and a listing skips it. |
| `passwords/<name>.json` | `Identity` with `algorithm: argon2id-ed25519` | Publicly readable. GET/HEAD unauthenticated. See §11. |
| `passkeys/<name>.json` | `Identity` with `algorithm: webauthn-prf-ed25519` | Publicly readable. **Status: not yet implemented.** |
| `groups/<name>.json` | `Identity` with a `members` field | Publicly readable. Path is convention; any identity with `members` is a group (§2). |
| `groups/<name>.key` | Group Ed25519 seed as an encrypted Ark file, members-only | Body is the base64url seed; wrapped per member like `identity.key` (§11.2). |
| `invitations/<token>.json` | `Invitation` (A.9) | **Status: not yet implemented.** |
| `invitations/<token>.html` | Human landing page | **Status: not yet implemented.** |
| `requests/<method>_<status>_<ts>_<seq>.http` | Request log entry | See §10. Owner reads; `ark@<host>` writes. |
| `blocked/<address>.json` | Per-sender blocklist entry | **Status: not yet implemented.** |

Requests to `/ark/<account>/.ark/requests/` and its entries are **not** themselves logged.

**Where an implementation's own files go.** Beyond the account's content, an implementation writes files of its own. Two placements, and which one applies is not a free choice:

- **Beside the entry**, as a sibling. For a file that has to land by a rename, since a rename across filesystems fails and only a sibling is guaranteed to share one — a temporary copy on the way to replacing an entry (§7.2), named so it is skipped by directory listings. And for a file the user is meant to find next to what it refers to, such as a conflict copy from a sync.
- **Under `/.ark/<kind>/`**, flat, for everything else — including state about a single path that outlives the operation that wrote it, such as the metadata a rewrite sets aside. A directory of its own can be swept in one pass, and a path with no parent inside the account (the account root) still has somewhere to live.

An entry in a flat directory keyed by something that is itself a path or an address percent-encodes `/` and `%` in that key, leaving the rest readable. Both characters must be encoded: without `%`, two distinct keys could encode to one name, and the entry for one would be served under the other. Folding separators into an ordinary character (`/` to `_`, say) is not sufficient for the same reason.

---

## 5. Authentication (`ArkIdentity`)

Every non-public request carries:

```
Authorization: ArkIdentity address="<address>", timestamp="<unix-ms>", signature="<base64url>"
```

- `address` — the requestor's identity address. May be the primary account identity or any sub-identity path (e.g. `alice@example.com/.ark/passwords/primary.json`).
- `timestamp` — unix time in **milliseconds**. Requests outside a ±5 minute window (300 000 ms) are rejected `401`.
- `signature` — signature over the request bytes below, using the requestor's identity private key, base64url-encoded (no padding).

Parameter syntax follows RFC 7235; order is not significant.

**Signed bytes.** Concatenation, no spaces, delimiter is LF (`0x0A`):

```
method || 0x0A || host || 0x0A || path || 0x0A || timestamp || 0x0A || body
```

- `method` — the ASCII request method (`GET`, `PUT`, `HEAD`, `DELETE`).
- `host` — the `Host` request header, lower-cased ASCII.
- `path` — the URL path, no query, percent-decoded.
- `timestamp` — the decimal ASCII form of the `timestamp` param (unix ms).
- `body` — the raw request body bytes, verbatim. Empty for GET/HEAD/DELETE.

Binding `host` prevents replay against a different server. Binding `path` prevents redirection. Binding `body` prevents tampering — the body is signed in full rather than by hash because PUT bodies must be buffered by the server anyway (Content-Length is required), so streaming-signing offers no gain here.

**Verification.** The server resolves the identity document at `address`, verifies the signature, and passes the resolved identity to authorization (§6). If resolution fails (identity file missing, self-signature invalid), the request is rejected `401`.

**Sub-identity semantics.** Only the **primary** identity (address exactly `<name>@<host>`, at `/.ark/identity.json`) receives the implicit `owner` grant on its own account root. A sub-identity (password, passkey, other) is authenticated but is only granted the permissions it appears with in the target's member list.

---

## 6. Authorization

The server derives an **effective member list** for the target:

- File exists and has metadata → its own member list.
- File does not exist (PUT to a new path) → walk up ancestor directories until one carries metadata; use its member list. Stops at the account root.
- Directory exists and has metadata → its own member list.
- Directory exists without metadata → walk up as above.

A `?version=` or `?versions` request (§4.3) names the live path, so this is the live path's list — the same one a plain GET is answered under. A version's own record carries the member list it was written with, which may include the wrapped file key of a member since removed, and a server MUST NOT derive the effective list from it. Deriving it from the version would leave every removed member a way back into the history they were removed from.

**Permission decision.**

1. If the request is unauthenticated and the effective list contains `*`, GET/HEAD succeed with `reader`; PUT/DELETE return `401`.
2. Otherwise authenticate (§5), then compute the highest permission across:
   - a direct match on `requestor_identity.address`,
   - a match on the metadata's `modified_by` (for PUT — proving the request was signed on behalf of a member author),
   - a group match — for any member entry whose identity carries a `members` list, treat the requestor (or `modified_by`) as matching if their address is in that list; the entry's permission is granted,
   - the `*` public member (read-only shortcut).
3. If none match, `403`.

**Group resolution.** When a member entry's identity is itself a group, the server resolves that identity and checks the requestor against its `members` list. Groups whose members list other groups are rejected — nested groups are **Status: not yet implemented** (§13).

**Method vs permission.**

| Permission | GET / HEAD | PUT (body / metadata) | PUT (member change) | DELETE |
|---|---|---|---|---|
| `reader` | ✓ | ✗ (403) | ✗ (403) | ✗ (403) |
| `writer` | ✓ | ✓ | ✗ (403) | ✓ |
| `owner` | ✓ | ✓ | ✓ | ✓ |

**Auto-owner on own account.** A request signed by the account's own primary identity is granted `owner` on anything under `/ark/<account>/`. Sub-identities do not receive this.

**Member-change check.** On a PUT that would overwrite an existing file or directory, the server compares the incoming member list to the existing one. If they differ, the requestor must hold `owner`; otherwise `403`.

---

## 7. Metadata

Every Ark file and directory has a `Metadata` record (Appendix A.2). Fields:

| Field | Required for file | Required for dir | Description |
|---|---|---|---|
| `id` | ✓ | ✓ | UUID, plain hyphenated lowercase form; other UUID spellings are rejected `400`. Immutable after creation. |
| `created` | ✓ | ✓ | RFC 3339 timestamp, millisecond precision, `Z`-terminated (e.g. `2026-07-24T10:00:00.000Z`). |
| `modified` | ✓ | ✓ | RFC 3339, same format as `created`. Used for last-write-wins on relay. |
| `modified_by` | ✓ | ✓ | Address of the identity that signed this metadata. |
| `parent_version` | optional | optional | The id of the version (§4.3) this write was made against. Omitted on a first write, and where the writer does not track it. Two writes carrying the same `parent_version` forked from one state. A server records it and does not act on it: conflict resolution stays last-write-wins (§9), and the field is there so a fork can be seen at all. Acting on it — refusing a write whose parent is not current — is **Status: not yet implemented**. |
| `encryption_algorithm` | optional (omit for unencrypted; default per Appendix B.2) | must be omitted | See §8. |
| `members` | ✓ (at least one `owner`) | ✓ (at least one `owner`) | Member list. |
| `body_hash` | ✓ (hash algorithm per Appendix B) | must be omitted | Hash of `body_bytes_as_stored` under the named hash algorithm. |
| `signature` | ✓ | ✓ | Signature by `modified_by`'s identity key over the JCS-canonical serialization of the other fields, with `signature.algorithm` and `signature.value` cleared before signing. |

### 7.1 On the wire

Transmitted as `X-Ark-Meta-*` HTTP headers, one field per header. Kebab-case. Members numbered from 0. Example:

```
X-Ark-Meta-Id: 5f3f...
X-Ark-Meta-Created: 2026-07-24T10:00:00.000Z
X-Ark-Meta-Modified: 2026-07-24T10:00:00.000Z
X-Ark-Meta-Modified-By: alice@example.com
X-Ark-Meta-Parent-Version: 2026-07-24T09-12-33.418Z_p7Qk2-Xd
X-Ark-Meta-Encryption-Algorithm: aes-256-gcm
X-Ark-Meta-Body-Hash-Algorithm: sha-256
X-Ark-Meta-Body-Hash-Value: <b64u>
X-Ark-Meta-Signature-Algorithm: ed25519
X-Ark-Meta-Signature-Value: <b64u>
X-Ark-Meta-Member-0-Address: alice@example.com
X-Ark-Meta-Member-0-Permission: owner
X-Ark-Meta-Member-0-Key-Algorithm: hpke-x25519-hkdf-sha256-aes256gcm
X-Ark-Meta-Member-0-Key-Value: <b64u>
```

Members must be contiguous from index 0. Sparse indexes are rejected `400`.

### 7.2 At rest

Each field is stored as its own extended attribute on the body file, under the `user.ark.` namespace. Names use snake_case: `user.ark.id`, `user.ark.modified_by`, `user.ark.member_0_address`, `user.ark.signature_value`, etc. Binary values are base64url. Ark requires a filesystem with xattr support (ext4, xfs, btrfs, apfs).

Updates should be atomic: write body + xattrs to a temp file, then rename over the target. A metadata-only update (§4.5) must do the same — the fields are separate attributes and cannot be replaced as a set where they sit — so it copies the body rather than editing in place. This is what keeps a body and its `body_hash` in step: a reader sees both of the old or both of the new, never one of each.

Directory metadata (§7.3) cannot be written that way. A rename only succeeds onto an empty directory, and a directory being updated holds the entries beneath it, so its attributes are replaced where they stand. Two things make that safe:

- **A lock.** A writer holds an exclusive advisory lock on the directory for the whole replacement, and a reader holds a shared one. Concurrent readers therefore never observe a partial set. The lock is released by the host if the process holding it stops, so it cannot be left stranded. It is advisory and local to one host: an account root MUST live on a local filesystem, and MUST NOT be shared between hosts over a network filesystem.
- **The previous metadata, set aside.** Before touching a directory's attributes, the writer creates an empty file at `/.ark/versions/<percent-encoded account path>/.previous` carrying what the directory carries in that file's own `user.ark.*` attributes — metadata at rest in the same shape as anywhere else, landed by a rename so what is set aside is never caught part-way itself. A file carrying no attributes records that the directory carried no metadata. The writer removes it only once the new record is whole, so its presence marks a replacement as still under way.

  A reader that holds a lock on the directory knows no writer holds the exclusive one, so previous metadata it can see is what a stopped writer left behind. It takes the exclusive lock, puts back what that file carries — the previous record, or no metadata at all where it carries none — removes it, and reads again.

  A directory's metadata and any local metadata beside it are replaced under the one lock and set aside together, so a reader never sees a new record next to the local state that belonged to the record before it, and neither is lost on its own.

  This is what makes the detection complete. An interrupted replacement is not always visible in the attributes: a write that stopped after four of six members leaves a record that is contiguous from index 0, carries an owner and a signature, and parses as a whole record with the wrong member list. Only the metadata set aside distinguishes it. An update interrupted part-way is therefore put back to the state before it, rather than serving a short member list or leaving the directory to inherit from its nearest metadata-bearing ancestor.

The `.previous` entry sits beside the path's versions (§4.8) so that everything kept about one path lives in one place, and a `DELETE` that drops the history (§4.6) drops it too. It is not account content and not a version.

An implementation MAY also sweep `/.ark/versions/*/.previous` at startup to put these back eagerly, rather than waiting for each directory to be read.

The rename is atomic against concurrent readers but says nothing about durability. Ark does not require an implementation to flush before renaming; a host that loses power may lose recent writes, which converge again through relay (§9).

### 7.3 Directories

A directory may or may not carry metadata. A directory without metadata inherits member checks from its nearest metadata-bearing ancestor. A directory PUT with a body is rejected `400`. Directory metadata rejected if `encryption_algorithm` is set.

Inheritance applies only where a directory genuinely carries no metadata. Metadata that is present but cannot be read as a whole record is rejected `500` — never treated as absent, and never inherited past. The same holds for every directory on the walk up: a server MUST NOT step over an unreadable ancestor to a further one, which would grant the access the unreadable record was there to withhold.

---

## 8. Encryption

Every encrypted file uses two layers:

- A **symmetric file key** encrypts the body under the file's AEAD (`encryption_algorithm`).
- The file key is **wrapped** for each member under the wrap algorithm (`member.key.algorithm`) against the member's public key. Each member entry in the metadata carries its own wrapped copy.

A fresh random file key is generated on every PUT of an encrypted file. Adding a member does not re-encrypt the body; removing a member does (§8.4).

### 8.1 Modes

| `encryption_algorithm` | Body layout | Member `key` field |
|---|---|---|
| present (AEAD id per Appendix B) | `nonce ‖ ciphertext ‖ tag` — sizes per the named AEAD | Present, wrapped file key |
| absent | raw plaintext | Absent |

When `encryption_algorithm` is absent, the body is stored verbatim. Integrity is provided by the metadata signature over `body_hash` — there is no AEAD tag.

### 8.2 Key wrap suite

The wrapped file key uses HPKE with X25519-HKDF-SHA256 as the KEM, HKDF-SHA256 as the KDF, and AES-256-GCM as the AEAD (RFC 9180, KEM `0x0020`, KDF `0x0001`, AEAD `0x0002`). The suite id emitted in `member.key.algorithm` is:

```
hpke-x25519-hkdf-sha256-aes256gcm
```

**KEM key material.** The recipient's public key is derived from their Ed25519 identity key by decompressing the Ed25519 point and mapping it to Montgomery form (X25519). The recipient's private key is derived by hashing the Ed25519 seed with SHA-512 and clamping the first 32 bytes (RFC 7748 clamp). This is a well-known Ed25519↔X25519 mapping.

**HPKE `info`.** ASCII bytes `ark-hpke-v1`. `aad` is empty. Base-mode single-shot seal/open.

**Wrapped format on disk / in headers.**

```
<32-byte encapsulated key> ‖ <ciphertext of the file key + AEAD tag>
```

### 8.3 Encrypted PUT (client)

1. Generate a random file key of the size the AEAD requires.
2. AEAD-encrypt the plaintext under `file_key` → body bytes.
3. For each member, wrap the file key against the member's public key → `member.key`.
4. Compute `body_hash` = hash of `body_bytes_as_stored` under the file's hash algorithm.
5. Sign metadata; PUT.

### 8.4 Removing a member

Every PUT of an encrypted file body already generates a fresh file key (§8), so a removed member loses access to future edits as a natural consequence of the next write — no extra step is required for regular member removals. The removed member retains any local copy they downloaded, but the server never re-issues them the current file key.

Removing a **group** member is different: the group's public key does not change, so a fresh file key wrapped for the group's public key would still be unwrappable by the removed member (who kept the group's private key locally). Preventing that requires rotating the group's Ed25519 keypair, re-publishing `groups/<name>.json`, and re-publishing `groups/<name>.key` wrapped only for the remaining members. **Status: not yet implemented** (§13).

The server cannot verify that a client rotated the file key. On a member-list change it MAY require the incoming `body_hash` to differ from the previous — a minimum "you re-encrypted something" backstop — but a client that reuses the file key with a new nonce would pass that check. Rotation is a client responsibility.

### 8.5 Public `*` member

The `*` public member never receives a wrapped key. Public files must therefore be unencrypted — encryption with a `*` member is a misconfiguration; the file would not be readable by the public. Clients should refuse to encrypt to `*`.

---

## 9. Federation & relay

Ark makes federation a server responsibility. A client publishes once; the server distributes.

**Client responsibility.** For any shared file or directory, the client sends **one** PUT — to its own account's server, at the shared path, with `?relay=full`.

**Server responsibility.** On a PUT that carries `?relay=full`, after storing locally the server iterates the metadata's members and, for each member whose address is on a **different host**, sends the same PUT to `/ark/<member-account>/<same-path>` on that host — once per unique host. The outbound PUT carries `?relay=internal` so the receiving server does not fan out further. Members on the **same host** are handled in-process, once, and skip the origin account itself. Members whose address is not parseable, `*`, or `groups:…` are skipped. A `?metadata` flag on the incoming PUT is carried through to every relayed request.

**Cross-server signing.** Outbound requests are signed by the relaying server's own `ark@<host>` account (see §10). The receiving server verifies that signature against `ark@<host>`'s identity document and then applies its normal member checks against the target account.

**Conflict resolution.** Last-write-wins by `modified` timestamp. A PUT whose `modified` is older than the existing file returns `409`. A PUT whose `id` differs from the existing `id` returns `409`.

**Failure.** Relay is fire-and-forget in v0. If the destination is unreachable, the write is dropped. Delivery retries, backoff, and bounces are **Status: not yet implemented**.

**Unauthorized destination.** If the recipient server rejects with `403` (the sender is not a member of the target path), that response is recorded in the recipient's request log (§10). The recipient owner's client is free to build a "share proposal" UX on top of that log — the flow is not part of the protocol.

---

## 10. Request log

Every server keeps a per-account append-only log of received requests. It is the record the account owner uses to see what happened to their account.

**Location.** `/ark/<account>/.ark/requests/<method>_<status>_<timestamp>_<seq>.http`.

- `<method>` — the request method, e.g. `PUT`.
- `<status>` — the response status, e.g. `204`. With the method it leads the name so a reader after one kind of entry can ask for it by `prefix` (§4.3) rather than reading the whole log.
- `<timestamp>` — RFC 3339 (millisecond precision, `Z`-terminated) with `:` replaced by `-` for filesystem safety, e.g. `2026-07-24T10-00-00.000Z`.
- `<seq>` — zero-padded 3-digit sequence counter, disambiguating concurrent requests within the same instant.

**Entry format.** The raw HTTP request line and headers, a blank line, then the raw HTTP response line and headers. **Bodies are excluded.** Entries are capped at 16 KiB; longer requests are truncated. Example:

```
PUT /ark/bob/apps/notes/team/foo.md HTTP/1.1
Host: bob.example
Authorization: ArkIdentity address="alice@x.example", timestamp="1721476800000", signature="..."
X-Ark-Meta-Id: 3f2a...
X-Ark-Meta-Modified-By: alice@x.example
X-Ark-Meta-Member-0-Address: alice@x.example
X-Ark-Meta-Member-0-Permission: owner
X-Ark-Meta-Member-1-Address: bob@bob.example
X-Ark-Meta-Member-1-Permission: writer
X-Ark-Meta-Body-Hash-Algorithm: sha-256
X-Ark-Meta-Body-Hash-Value: ...
X-Ark-Meta-Signature-Algorithm: ed25519
X-Ark-Meta-Signature-Value: ...
Content-Length: 2048

HTTP/1.1 403 Forbidden
Content-Length: 9
```

**Who writes.** The server's `ark@<host>` account signs each entry. The account under whose namespace the log lives is the entry's `owner`; `ark@<host>` is `writer`. That means the account owner (or a client acting for them) can read, list, and delete entries; the `ark` account can append.

**When entries are written.** Every request handled by the server, **except** requests targeting `/.ark/requests/` themselves. This includes 2xx, 4xx, and 5xx responses. Entries are always signed by `ark@<host>`, giving the owner tamper-evident evidence of what any sender attempted.

**Prerequisites.** For log writes to happen at all, `/ark/<account>/.ark/requests/` must exist and its metadata must grant `ark@<host>` at least `writer`. This is set up at account creation.

**Retention.** Not specified. Clients or admins prune.

**Share proposals note.** A client can watch the log for `403` PUT entries where the current account is a member of the incoming metadata's member list, and offer the user an "accept / reject" UI (accept = pull the file from the sender's server, PUT it locally; reject = delete the log entry). This is a client convention over the log, not a protocol feature — the server has no notion of a proposal.

**`ark@<host>` account.** Created automatically when the server starts on a fresh directory. Its identity document lives at `/ark/ark/.ark/identity.json` and its private key at `/ark/ark/.ark/identity.key`. It is used to sign log entries and outbound relay requests. It should not be used by human users.

---

## 11. Recovery

An account's identity keypair is the only way in. If lost with no recovery configured, the account is gone.

### 11.1 Seed phrase

The client generates a BIP-39 mnemonic covering the account's identity seed and displays it to the user at account creation. Storage is the user's responsibility. Re-entering the mnemonic on any device re-derives the same keypair and grants full account access. The server never sees the mnemonic or the private key.

**Status: seed phrase generation not yet implemented in the reference client.** The current client writes the raw seed to `.ark/identity.key` and expects the user to back that file up.

### 11.2 Password identity

The client creates a **password identity** — a sub-identity whose keypair is derived from a user-supplied password via Argon2id + HKDF-SHA256, and adds it as a `reader` member of `/.ark/identity.key`. The password identity file is published at `/.ark/passwords/<name>.json` and is publicly readable.

**Layout.** `Identity.public_key.value` = `verifier(32) ‖ salt(16) ‖ ed25519_public(32)`.

- `verifier = SHA-256( HKDF-SHA256(Argon2id(pw, salt), info: "ark-auth-v1", L=32) )`
- `ed25519_seed = HKDF-SHA256(Argon2id(pw, salt), info: "ark-ed25519-v1", L=32)`

`Identity.public_key.algorithm = "argon2id-ed25519"`. The identity file is self-signed by the derived Ed25519 key.

**Recovery.** A second device with the password and address:

1. GETs `/.ark/passwords/<name>.json` (unauthenticated — public).
2. Re-derives the Argon2id output; verifies against the `verifier`; if it matches, derives the Ed25519 seed.
3. Signs `ArkIdentity` requests as the password identity to GET `/.ark/identity.key`.
4. Uses its `reader` member entry to unwrap the file key; decrypts the body; obtains the account's Ed25519 seed; writes it locally.

**Trust cost.** A server holding a password identity file can brute-force the password offline (the verifier is public). Weak passwords are catastrophic. Passkey-derived identities avoid this — **Status: not yet implemented.**

### 11.3 Key rotation and transition

**Status: not yet implemented.** `Identity` already reserves a `key_transition` field (A.7) that publishes both old and new public keys and cross-signatures so peers can pin the new key. Wire behavior is not specified in this version.

---

## 12. Threat model

### 12.1 What is protected

| Property | Guarantee |
|---|---|
| Data confidentiality | Only members holding the identity private key can unwrap the file key. Servers see only ciphertext. |
| Author authenticity | Every file/directory is signed by `modified_by`'s identity key. Forging requires that private key. |
| Body integrity | Encrypted files: AEAD tag catches ciphertext tampering. Unencrypted files: metadata signature over `body_hash`. |
| Request integrity | The `ArkIdentity` signature covers method, host, path, timestamp, body. Redirection, tampering, cross-server replay all invalidate the signature. |
| Spam resistance | Non-member writes are rejected with `403`. Log-spam bound requires per-sender rate limits and a blocklist — **Status: not yet implemented.** |

### 12.2 What is not protected

- **Metadata visibility.** Paths, sizes, modification timestamps, member addresses are readable by the server and by any co-member's server.
- **Forward secrecy.** If an identity key is compromised, all past and future files it can unwrap are exposed. Ratcheted sequences are **Status: not yet implemented.**
- **Password brute force.** A compromised server holding a `passwords/<name>.json` file can attack a weak password offline.
- **Removed member's stored copy.** Re-keying stops access to future writes, not to any local copy they downloaded. Versions (§4.3) widen this from the copy they held to every version written while they were a member: their server kept those too, and the file key wrapped for them is in each one's record. The access rule of §6 keeps them off *this* server's history; it says nothing about their own.
- **A file's history cannot be shared.** Each version's file key is wrapped for the members as they stood at that write, so a member added later cannot read anything written before they joined. Only re-encrypting each version to the new member would change that, and only a client that can already read them all could do it.
- **First-contact identity trust.** Fetching `identity.json` for the first time trusts TLS + the server. Clients should pin the public key on first use and warn on unexpected changes. Key-transparency style discovery is out of scope.

### 12.3 Server compromise (single-key model)

- The compromised server sees all metadata and ciphertext but no plaintext.
- It cannot forge signatures for existing files (no identity key).
- It can serve a **different** `identity.json` to a new peer, so first-contact peers who don't verify out of band could be MITM'd. Pinned peers are safe.
- It can replay an **older** signed version of a file, or a signed file from another path, in place of the current one. A client holding its own copy catches both (§4.2); one fetching a path for the first time has nothing to compare against. `?version=` (§4.3) asks for an older version on purpose, so only the second of those still applies to it: a client MUST refuse a record whose `id` differs from its own copy's, and MUST recompute the version id from the record it was served and refuse anything that is not the version it asked for. The id travels in the query, which the request signature does not cover (§5).
- If a password identity is configured, the server also holds `identity.key` encrypted under the password identity — see §12.2.

---

## 13. Not yet implemented

### A note on the `parent_version` field and existing data

`parent_version` (§7) is a field of the signed record, so it changes the bytes the signature covers. A reader that does not know the field cannot reconstruct them: §4.2 has it ignore the `X-Ark-Meta-Parent-Version` header, and it then computes a different canonical serialization and rejects a perfectly valid file. The failure reports itself as a bad signature rather than as a version skew.

Adding it is therefore a break in both directions — old readers reject new files, and readers that know it reject files signed before it existed only if those files are re-served unchanged, which they are. There is no migration: an account written by an earlier version must be re-signed or rewritten. This is called out because "optional field" does not mean "compatible" for anything inside the signature, and it applies equally to whatever is added to `Metadata` next.

### Not yet shipped

The following spec sections describe intended behavior that the reference implementation does not yet ship. They remain in the spec so the wire format and semantics are settled before code lands.

- Password recovery UX and seed-phrase display (§11.1) — the low-level password identity flow (§11.2) is implemented.
- Passkey identities (§4.8 `passkeys/`).
- Nested groups — a group whose `members` list references another group (§2, §6, A.1).
- Group member removal with forward secrecy — removing a member requires rotating the group keypair; the reference implementation does not yet perform this rotation (§8.4).
- Invitations (§4.8 `invitations/`, Appendix A.9).
- Blocklists (§4.8 `blocked/`).
- Per-sender rate limits (§12.1).
- Key rotation with `key_transition` (§11.3, Appendix A.7).
- Aliases and account migration between servers.
- Relay retries, exponential backoff, and bounces (§9).
- Bounded version retention (§2, §4.5). Every version is kept until its path is deleted (§4.6), so the store grows without bound: a path written `n` times holds `n` bodies. A retention rule is expected to replace this. Until it is specified, a server keeps everything.
- Acting on `parent_version` (§7) — a server records what a write was made against but does not refuse a write whose parent is not the version it holds. Conflict resolution stays last-write-wins on `modified` (§9), which compares clocks across hosts that need not agree. The field ships first so the record exists; the rule over it is unsettled, because refusing out-of-order arrivals costs availability that fire-and-forget relay cannot currently repay.
- `allow_remote_registration` server config toggle for §4.5 bootstrap.
- Ratcheted sequences (forward secrecy) and prekey bundles.

---

## Appendix A — Types

Types below define the JSON shapes that ride in bodies and the field set that rides in `X-Ark-Meta-*` headers. All binary values are base64url (no padding).

### A.1 Identity

```json
{
  "public_key": Key,
  "address": "alice@example.com",
  "members": ["bob@example.com", "carol@example.com"],
  "signature": Signature
}
```

| Field | Required | Notes |
|---|---|---|
| `public_key` | ✓ | The identity's public key. Must be a signing algorithm (Appendix B). |
| `address` | ✓ | Full address (may include a sub-identity path). |
| `members` | optional | Addresses of the identity's members. When present, this identity is a group (§2, §6). Entries must be non-group identities — nested groups are **Status: not yet implemented**. |
| `signature` | ✓ | Self-signature over the JCS-canonical serialization with `signature.algorithm` and `signature.value` cleared. |
| `key_transition` | optional | See A.7. **Status: not yet implemented.** |

### A.2 Metadata

```json
{
  "id": "<uuid>",
  "created": "2026-07-24T10:00:00.000Z",
  "modified": "2026-07-24T10:00:00.000Z",
  "modified_by": "alice@example.com",
  "parent_version": "2026-07-24T09-12-33.418Z_p7Qk2-Xd",
  "encryption_algorithm": "aes-256-gcm",
  "members": [Member],
  "body_hash": Hash,
  "signature": Signature
}
```

Field rules per §7. Signature computed over the JCS-canonical serialization with `signature.algorithm` and `signature.value` cleared. Files have `body_hash`; directories do not. Directories must omit `encryption_algorithm`.

### A.3 Member

```json
{
  "address": "alice@example.com",
  "permission": "owner",
  "key": Key
}
```

| Field | Required | Notes |
|---|---|---|
| `address` | ✓ | Full address (may be a group's address), or `*`. |
| `permission` | ✓ | `owner` / `writer` / `reader`. |
| `key` | when encrypted | The file key wrapped for this member under the wrap algorithm (§8.2). Omitted for `*`, for group members without a group key, and for unencrypted files. |

### A.4 Key

```json
{ "algorithm": "ed25519", "value": "<b64u>" }
```

Algorithm ids are registered in Appendix B.1.

### A.5 DirectoryEntry

```json
{ "type": "file", "name": "todo.md" }
```

`type` ∈ `dir | file | symlink`. Symlink entries are listed for inspection; the server rejects requests that actually traverse a symlink with `403`.

### A.6 Signature / Hash

```json
{ "algorithm": "ed25519", "value": "<b64u>" }
{ "algorithm": "sha-256", "value": "<b64u>" }
```

### A.7 KeyTransition — **Status: not yet implemented**

```json
{
  "old_key": "<b64u>",
  "new_key": "<b64u>",
  "old_signs_new": "<b64u>",
  "new_signs_old": "<b64u>",
  "reason": "scheduled_rotation",
  "timestamp": "2026-07-24T10:00:00.000Z"
}
```

Cross-signatures prove both keys authorized the transition. Verification and lifetime rules TBD.

### A.8 Group

A group is an [`Identity`](#a1-identity) whose `members` field is set. The identity's `public_key` is the group's Ed25519 key used to wrap file keys when the group is a member of an encrypted file; the group's Ed25519 seed lives in the companion members-only `.key` file (§4.8), wrapped for each member like `identity.key` (§11.2). Groups have no dedicated JSON shape beyond that.

### A.9 Invitation — **Status: not yet implemented**

```json
{
  "expires": "2026-08-01T00:00:00.000Z"
}
```

A share proposal pre-accepted by the inviter. Redemption creates the target directory with the redeemer added as a member.

### A.10 VersionEntry

```json
{
  "id": "2026-07-24T09-12-33.418Z_p7Qk2-Xd",
  "modified": "2026-07-24T09:12:33.418Z",
  "modified_by": "alice@example.com",
  "body_hash": Hash,
  "size": 2048
}
```

One entry of the history returned by `GET <path>?versions` (§4.3), newest first.

| Field | Required | Notes |
|---|---|---|
| `id` | ✓ | Names the version, and is what `?version=` and `parent_version` (§7) take. Derived from the record itself: the `modified` timestamp with `:` replaced by `-`, an underscore, then the first 8 base64url characters of `signature.value`. Every host holding a version names it the same, so two histories that drifted apart through a dropped relay (§9) can still be compared. |
| `modified` | ✓ | The version's `Metadata.modified`. **Derived, not independent:** it is the same timestamp `id` opens with, sent in its ordinary form so a client need not take an id apart to learn when a version was written. A client that does parse it out of `id` must split on the *first* `_`, since base64url includes `_` and the signature characters may contain one. |
| `modified_by` | ✓ | The version's `Metadata.modified_by`. |
| `body_hash` | for a file | The version's `Metadata.body_hash`. Absent for a directory. Two entries sharing one `body_hash` differ only in their record — a `?metadata` PUT (§4.5) that moved the member list and left the body alone — which is what lets a client tell those apart in a listing without fetching either. |
| `size` | ✓ | Bytes the version's body holds as stored. `0` for a directory. |

`id` and `modified` carry the same timestamp, so an implementation that changes the id grammar must keep them in step.

---

## Appendix B — Algorithms

Every implementation MUST support the algorithms below; a message that uses only these is guaranteed to interoperate. Other algorithms may appear on the wire, but interop is not guaranteed.

| ID | Role | Notes |
|---|---|---|
| `ed25519` | signature | 32-byte private, 32-byte public, 64-byte signature. |
| `aes-256-gcm` | encryption | 96-bit nonce, 128-bit tag. Body = `nonce ‖ ciphertext ‖ tag`. |
| `hpke-x25519-hkdf-sha256-aes256gcm` | wrap | HPKE base mode (RFC 9180), KEM `0x0020`, KDF `0x0001`, AEAD `0x0002`. `info = "ark-hpke-v1"`, empty aad. Wire form = `encapped_key(32) ‖ ciphertext ‖ tag`. Recipient key derived from the Ed25519 identity key — public: point decompress → Montgomery form; private: SHA-512(seed) → RFC 7748 clamp of first 32 bytes. |
| `sha-256` | hash | 32-byte output. |
| `argon2id-ed25519` | identity derivation | Derives an Ed25519 keypair from a password. Argon2id (default params) + HKDF-SHA256. Two HKDF branches: `ark-auth-v1` for the verifier, `ark-ed25519-v1` for the derived Ed25519 seed. `public_key.value` = `verifier(32) ‖ salt(16) ‖ ed25519_public(32)`. |
| — | canonicalization | JCS (RFC 8785). Applied to a signed structure with its `signature.algorithm` and `signature.value` cleared before signing. |
