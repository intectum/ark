# Ark Protocol Specification

> **Status:** Draft v0.5
> **Date:** 2026-04-26

## Table of Contents

1. [Overview](#1-overview)
2. [System 1: Identity](#2-system-1-identity--who-are-you)
3. [System 2: Files](#3-system-2-files--the-core-primitive)
4. [System 3: Encryption](#4-system-3-encryption--nobody-else-can-read-this)
5. [System 4: Authentication](#5-system-4-authentication--this-really-came-from-alice)
6. [System 5: Spam Resistance](#6-system-5-spam-resistance--sending-costs-effort)
7. [System 6: Transport](#7-system-6-transport--how-data-moves)
8. [File Format](#8-file-format)
9. [Threat Model](#9-threat-model)
10. [Extensions](#10-extensions)

---

## 1. Overview

Ark is a federated, encrypted protocol for personal data. It replaces email, cloud storage, and note-taking with a single system built on cryptographic identity and end-to-end encryption. It has six core systems:

| System | Purpose |
|---|---|
| **Identity** | Who are you? Keypair mapped to a human-readable address. |
| **Files** | The core data primitive. Everything — messages, documents, notes — is an encrypted file on disk. |
| **Encryption** | Nobody else can read your data. Symmetric file keys wrapped with public-key encryption. |
| **Authentication** | Proof that data really came from the claimed author. |
| **Spam Resistance** | Cross-server delivery costs computational effort. No reputation systems needed. |
| **Transport** | How files move between servers. Plain HTTPS, trivially self-hostable. |

### Design principles

- **Cryptographic identity, not reputation-based.** Your identity is a keypair, not an IP address or domain reputation score. This eliminates the entire class of deliverability problems that plague self-hosted email.
- **Encrypted by default.** All file content is end-to-end encrypted. Servers store ciphertext they cannot read.
- **Files on disk.** Storage is the filesystem. No database for user data. Files are accessed by path over HTTPS. Any tool that can read files can interact with Ark data.
- **One primitive.** Everything is a file with an unencrypted header and an encrypted body. Different membership patterns produce different behaviors, not different concepts.
- **Simple to self-host.** A single binary, a single config file, a domain with an A record. That's it.
- **Federated, not peer-to-peer.** Servers provide reliable offline storage and key hosting. Pure P2P systems (Bitmessage, Briar) struggle with reliability and adoption.
- **Spam-resistant by construction.** Proof of work + unforgeable identity + contact allowlists make bulk spam economically infeasible without complex filtering infrastructure.
- **Simple key model.** One keypair per identity, like a crypto wallet. Lose the key, lose the identity. Have the key, have all your data. No complex session state to manage.
- **Flexible trust model.** Users choose where their private key lives — on their device (maximum security) or on their server (maximum convenience). Self-hosters get both.
- **App-agnostic.** The protocol defines files, membership, and transport. How files are organized into directories is up to applications. A mail app, a notes app, and a file manager all operate on the same files — just arranged differently.

### How a message flows (end to end)

A message is a file with two members — sender (owner) and recipient (read). Here is how it flows:

```
Bob's Client                Bob's Server              Alice's Server             Alice's Client
    |                           |                          |                          |
    |  1. Fetch Alice's         |                          |                          |
    |     identity doc -------->|------- HTTPS GET ------->|                          |
    |  2. Receive public key    |<------ JSON response ----|                          |
    |                           |                          |                          |
    |  3. Generate file key,    |                          |                          |
    |     encrypt content,      |                          |                          |
    |     wrap key for self     |                          |                          |
    |     and Alice             |                          |                          |
    |                           |                          |                          |
    |  4. Compute proof of work |                          |                          |
    |     (Argon2id, ~0.5s)     |                          |                          |
    |                           |                          |                          |
    |  5. Sign envelope         |                          |                          |
    |                           |                          |                          |
    |  6. Store file on ------->|                          |                          |
    |     home server           |                          |                          |
    |                           |  7. Relay via HTTPS POST |                          |
    |                           |------- envelope -------->|                          |
    |                           |                          |  8. Verify signature      |
    |                           |                          |  9. Verify PoW            |
    |                           |                          |  10. Store in .ark/inbox/ |
    |                           |                          |                          |
    |                           |                          |  11. Alice fetches ------>|
    |                           |                          |  12. Decrypt with         |
    |                           |                          |      private key          |
    |                           |                          |                          |
    |                           |                          |  13. Mail app moves file  |
    |                           |                          |      to mail/inbox/       |
```

### Example use cases

The protocol defines no directory structure — apps do. Here are examples of how different apps might organize files:

**Mail app:**
```
/ark/alice/mail/inbox/abc123          ← received message (moved from .ark/inbox/)
/ark/alice/mail/sent/def456           ← sent message
/ark/alice/mail/drafts/ghi789         ← draft
/ark/alice/mail/archive/2026/jkl012   ← archived message
```

**Notes app:**
```
/ark/alice/notes/personal/todo.md     ← personal note
/ark/alice/notes/work/meeting-notes   ← work note (could be shared with coworkers)
```

**File storage:**
```
/ark/alice/files/photos/vacation.jpg  ← personal photo
/ark/alice/files/documents/tax-2025   ← tax document
/ark/alice/files/shared/project-plan  ← shared with collaborators
```

**Calendar app:**
```
/ark/alice/calendar/2026-04-28-standup  ← calendar event
/ark/alice/calendar/2026-05-01-birthday ← recurring event
```

All of these are the same thing underneath: encrypted files with members. The path and organization are conventions between the app and the user.

---

## 2. System 1: Identity — "Who are you?"

### 2.1 Concept

Every user has a cryptographic keypair — like a crypto wallet. The public key *is* your identity. It's mapped to a human-readable address like `alice@example.com`, where `example.com` is the server that hosts Alice's account.

### 2.2 Address format

Addresses use the familiar `user@domain` format:

```
alice@example.com
bob@mail.myserver.org
```

- `user` — the local part, unique within the server. Lowercase alphanumeric, dots, hyphens, underscores. Max 64 characters.
- `domain` — the server's hostname. Must resolve to an IP address via DNS A/AAAA record.

This format is deliberately identical to email. Users already understand it, and it requires no new mental model.

### 2.3 Keypair generation

Each user has a single **identity keypair**. This keypair is used for both signing (Ed25519) and encryption (converted to X25519 for Diffie-Hellman operations — this is a standard, well-defined mathematical conversion).

There are two modes of key generation, chosen at account creation:

**Mode A: Client-generated key (maximum security)**

1. Alice's client generates a **seed phrase**: 24 random words using the BIP-39 wordlist (2048 words, 256 bits of entropy).
   ```
   witch collapse practice feed shame open despair creek road again ice least
   glimpse tree mango mandate concert problem grief attack mosquito task final jeans
   ```
2. The seed phrase is run through HKDF-SHA256 to derive a 32-byte master secret.
3. The master secret derives an **Ed25519 identity keypair**:
   - Private key (32 bytes) — stays on Alice's device, never transmitted to the server.
   - Public key (32 bytes) — sent to the server during registration.
4. Alice writes down the seed phrase and stores it securely offline.
5. The server **never has the private key**. If Alice loses her seed phrase and all devices, the key is gone.

**Mode B: Server-generated key (maximum convenience)**

1. The server generates the Ed25519 identity keypair.
2. The server stores the private key (encrypted at rest).
3. The server provides the private key to Alice's client when she logs in (over TLS + an additional authentication step, e.g., password or registration token).
4. This means the server *can* decrypt Alice's data. Alice trusts her server.
5. Alice can export her seed phrase at any time and switch to Mode A.

**Why offer both modes?**

Most people will choose Mode B — it's how email works today (your email provider can read your email). It means:
- No seed phrase to lose.
- Seamless multi-device (server provides the key to each device).
- If you forget your password, the server admin can reset it (for self-hosters, you *are* the admin).

Security-conscious users choose Mode A — the server is purely a relay and storage node that cannot read data.

**Self-hosters get the best of both worlds:** They control the server, so Mode B gives them convenience without trusting a third party. The private key is on infrastructure they own.

**Why Ed25519?**
- Fast signing and verification (important for per-file signatures).
- Small keys (32 bytes) and signatures (64 bytes).
- Deterministic — same input always produces the same signature (no nonce-reuse vulnerabilities).
- Well-audited, widely implemented, no known weaknesses.
- Easily converted to X25519 for encryption operations.

### 2.4 Identity document

Alice's public identity is published as a JSON document on her server:

```
GET https://example.com/ark/alice/.ark/identity
```

Response:

```json
{
  "version": 1,
  "address": "alice@example.com",
  "identity_key": "base64url-encoded-ed25519-public-key",
  "encryption_key": "base64url-encoded-x25519-public-key",
  "devices": [
    {
      "device_id": 1,
      "device_key": "base64url-encoded-ed25519-public-key",
      "label": "Alice's Laptop",
      "registered": "2026-03-15T00:00:00Z"
    },
    {
      "device_id": 2,
      "device_key": "base64url-encoded-ed25519-public-key",
      "label": "Alice's Phone",
      "registered": "2026-04-01T00:00:00Z"
    }
  ],
  "updated": "2026-04-11T12:00:00Z",
  "signature": "base64url-encoded-ed25519-signature-over-everything-above"
}
```

**Field details:**

| Field | Purpose |
|---|---|
| `version` | Protocol version. Currently `1`. |
| `address` | The user's full address. |
| `identity_key` | Ed25519 public key. The root of trust for this user. Used for signing. |
| `encryption_key` | X25519 public key (derived from the identity key). Used for encryption. Published explicitly so senders don't need to perform the Ed25519→X25519 conversion themselves. |
| `devices[]` | List of authorized devices. |
| `devices[].device_id` | Numeric ID, unique per user. |
| `devices[].device_key` | Per-device Ed25519 signing key, authorized by the identity key. |
| `devices[].label` | Human-readable device name. |
| `signature` | Ed25519 signature over the entire document (excluding this field). Proves the identity key holder authored this. |

**The self-signature is the key security property** (for Mode A users). The server hosts this document but cannot tamper with it — any modification invalidates the signature. This means:
- A compromised server cannot swap in a different public key to intercept data.
- A MITM attacker who compromises the TLS connection cannot forge the identity document.
- The document is self-authenticating: anyone can verify it using only the public key it contains.

Note: For Mode B users (server holds the private key), the server *could* sign a different identity document. The user is already trusting the server with their private key, so this doesn't change the trust model.

### 2.5 Key discovery

When Bob wants to contact Alice for the first time:

1. Bob's client extracts the domain from `alice@example.com`.
2. Bob's client makes an HTTPS GET to `https://example.com/ark/alice/.ark/identity`.
3. Bob's client verifies the `signature` field against the `identity_key` in the document.
4. **Trust On First Use (TOFU):** Bob's client stores Alice's `identity_key` locally. This is the first time Bob has seen this key, so he trusts it (like SSH's "The authenticity of host 'example.com' can't be established... Are you sure you want to continue?").
5. On subsequent fetches, Bob's client compares the `identity_key` against the stored value. If it has changed without a proper key transition (see 2.8), the client raises an alert.

**Optional: Out-of-band verification.**
Alice and Bob can verify each other's keys by comparing a **safety number** — a fingerprint derived from both their identity keys. This can be done by:
- Comparing a numeric code displayed in both clients.
- Scanning a QR code in person.
- Reading the number aloud over a phone call.

Once verified, the client marks the contact as "verified." Any key change after verification triggers a prominent warning.

### 2.6 Multi-device support

Alice uses a laptop and a phone. Multi-device works differently depending on the key mode:

**Mode B (server-managed key):**
- Simple. Each device authenticates with the server (password, token, etc.) and receives the private key.
- All devices can decrypt all files (they all have the same identity private key).
- Each device also has its own **device signing key** (Ed25519) for authenticating requests and signing outgoing data.

**Mode A (client-managed key):**
- Alice sets up her first device with the seed phrase.
- To add a second device, Alice enters the seed phrase on the new device (or transfers the private key via QR code / secure channel).
- Each device also generates its own **device signing key**.
- The identity key signs each device key (proving "I, Alice, authorize this device").

**Device signing keys** are useful in both modes:
- They identify which device authored an operation.
- A device can be individually revoked without changing the identity key.
- Request authentication is per-device (the server knows which device is making each request).

**Device removal:**
- Alice signs a revocation statement with her identity key, removing the device from her identity document.
- Other users' clients see the device is gone on the next identity document fetch.

### 2.7 Key rotation

**Identity key:**
- Rarely changed. Only needed if the key is compromised or the user wants to start fresh.
- See section 2.8 for the transition process.

**Device signing keys:**
- Can be rotated independently. The new device key is signed by the identity key and published in the identity document.

### 2.8 Identity key transition

If Alice needs to change her identity key:

1. Alice generates a new identity keypair (from a new seed phrase, or derived from the same seed with an incremented index).
2. Alice creates a **key transition document**:
   ```json
   {
     "type": "key_transition",
     "old_key": "base64url-old-identity-public-key",
     "new_key": "base64url-new-identity-public-key",
     "old_signs_new": "base64url-signature-of-new-key-by-old-key",
     "new_signs_old": "base64url-signature-of-old-key-by-new-key",
     "reason": "scheduled_rotation",
     "timestamp": "2026-04-11T12:00:00Z"
   }
   ```
3. This document is included in Alice's identity document alongside the new key for a transition period (default: 30 days).
4. Contacts' clients see the transition:
   - If the transition is properly cross-signed (old key endorsed new, new key endorsed old), it's accepted automatically (or with a mild notification).
   - If only one direction is signed (e.g., old key is lost), clients warn the user and require manual acceptance.
5. After the transition period, the old key and transition document are removed.

When an identity key changes, Alice must re-wrap her file keys. Each file has a symmetric file key encrypted to her identity key (Section 4). Alice decrypts each file key with the old identity key and re-encrypts it with the new one. For shared files, other members' entries are unaffected — they hold the file key wrapped to their own identity keys.

### 2.9 Account recovery

**Mode B (server-managed key):**
- The server holds the private key. Recovery is a standard password reset / admin intervention.
- Files are stored on the server and remain accessible.
- This is the simplest recovery story — works like email.

**Mode A (client-managed key):**
- Alice enters her 24-word seed phrase on a new device.
- The client derives the identity keypair from the seed.
- The client registers the new device with Alice's server (the server recognizes the identity public key).
- Files stored on the server (encrypted) can be decrypted because Alice has the same private key, which unwraps the file keys.

**What is lost if the seed phrase is lost (Mode A):**
- The identity key is gone. Alice must create a new account with a new keypair.
- All files encrypted to the old key are unrecoverable.
- Contacts will see a new key and need to re-verify.

**No DNS complexity:**
- The server just needs a domain name pointing to it (A/AAAA record). That's it.
- No MX records, no SPF, no DKIM, no DMARC. Identity is cryptographic, not DNS-based.

### 2.10 Server migration

Alice can move from one server to another while keeping the same identity keypair.

**When the old server is still online:**

1. Alice creates an account on the new server with her existing identity key (Mode A: enters seed phrase; Mode B: transfers the private key).
2. Alice copies her files from the old server to the new server. No re-encryption needed — all file keys are encrypted to the same identity key regardless of which server stores them.
3. Alice copies her contacts file to the new server.
4. On the old server, Alice's identity document is replaced with an alias redirect:
   ```json
   {
     "type": "alias",
     "redirect": "alice@new-server.com"
   }
   ```
5. Anyone who contacts `alice@old-server.com` is seamlessly redirected to the new address. Contacts who have Alice's key pinned via TOFU won't be alarmed — it's the same key, just a new address.
6. After a transition period, Alice can delete her account on the old server.

**When the old server is gone:**

If Alice's old server goes offline (provider shut down, lost access), the alias redirect can't be set up. Contacts who send to the old address will get a DNS failure or 404. This is the same as losing an email provider — Alice needs to tell her contacts the new address out-of-band. When they look up her identity document on the new server, they'll see the same identity key they had pinned, confirming it's really her.

**What migrates:**
- Identity keypair (same key on both servers).
- All files (copy from old server to new — encrypted, no re-encryption needed).
- Contacts file.
- Alias redirect on old server (if still online).

**What doesn't migrate automatically:**
- Other people's allowlists. Contacts who had Alice allowlisted on the old address may need to re-allowlist the new address. However, since allowlists are keyed by identity public key (not address), a smart server implementation can recognize that the same key is now at a new address and preserve the allowlist entry.
- Shared file co-membership. Other members of shared files have Alice's old server address in the member list. Alice notifies co-members (via a `MEMBER_MOVED` envelope) so they update the address. Since membership is verified by identity key, the transition is seamless once addresses are updated.

### 2.11 Aliases

A single identity (one keypair) can have **multiple addresses** that all resolve to the same account. One address is the **primary** and has a full identity document. All others are **aliases** that redirect to the primary.

**Alias identity document:**

```
GET https://example.com/ark/old-alice/.ark/identity
```

```json
{
  "version": 1,
  "type": "alias",
  "redirect": "alice@example.com"
}
```

When someone encounters an alias document, they follow the `redirect` to fetch the real identity document and deliver to the primary address. The alias is transparent — addressing to either the alias or the primary reaches the same account.

**Use cases:**
- **Name changes.** Alice changes her username from `old-alice` to `alice`. The old address becomes an alias. Existing contacts are seamlessly redirected.
- **Vanity aliases.** Alice has `alice@example.com` as primary but also wants `a@example.com`.
- **Generated aliases.** Machine-generated aliases for special purposes like legacy email interop (see Section 10.2).

**Cross-server aliases** are not supported in v1. An alias must be on the same server as the primary address. Cross-server migration is handled by key transitions (Section 2.8).

---

## 3. System 2: Files ��� "The core primitive"

### 3.1 Concept

Everything in Ark is a **file** — encrypted data stored on the server's filesystem, accessed by path over HTTPS. Each file has an unencrypted **header** (metadata, ownership, wrapped keys) and an encrypted **body** (the actual content). The URL is the path:

```
GET  https://example.com/ark/alice/notes/todo     → full file (header + body)
HEAD https://example.com/ark/alice/notes/todo     → header only
GET  https://example.com/ark/alice/notes/         → directory listing
```

Messages, notes, documents, photos — all the same thing underneath. Different apps organize them into different directories, but the protocol doesn't care. It just stores and serves encrypted files.

### 3.2 File structure

Every Ark file consists of two parts:

1. **Header (unencrypted)** — metadata the server needs to index, serve, and enforce access control. Includes member list, timestamps, signature, and wrapped file keys.
2. **Body (encrypted)** — the actual content, encrypted with the symmetric file key. Opaque to the server.

See Section 8 for the full binary format.

### 3.3 Path conventions

The protocol defines one path convention:

- **`/ark/<user>/.ark/inbox/`** — the landing zone for all cross-server deliveries. Remote servers POST files here. This is the only directory that accepts writes from other servers.

Everything else is up to applications. The protocol reserves the `.ark/` directory under each scope for system use:

| Path | Purpose |
|---|---|
| `/ark/.ark/identity` | Server identity document |
| `/ark/.ark/policy` | Server spam policy |
| `/ark/.ark/accounts` | Account creation endpoint (POST) |
| `/ark/<user>/.ark/identity` | User identity document |
| `/ark/<user>/.ark/inbox/` | Cross-server delivery landing zone |
| `/ark/<user>/.ark/policy` | User spam policy overrides |
| `/ark/<user>/.ark/contacts` | Contacts allowlist |
| `/ark/<user>/.ark/stream` | Real-time event stream (WebSocket/SSE) |

All other paths under `/ark/<user>/` are free for apps and users to organize however they want.

### 3.4 Membership

Each file has one or more members, listed in the header. Every member holds the file's symmetric key, encrypted to their identity key. This means any member can decrypt the content.

**Member permissions:**

| Permission | Can decrypt | Can modify | Can change members |
|---|---|---|---|
| `owner` | Yes | Yes | Yes |
| `write` | Yes | Yes | No |
| `read` | Yes | No | No |

Permission enforcement is server-side. When a file is updated via PUT, the server:

1. Verifies the request signer is in the file's current member list.
2. If the **body** changed, requires `write` or `owner` permission. Rejects `read` members with `403`.
3. If the **member list** changed (members added, removed, or permissions modified), requires `owner` permission. Rejects `write` and `read` members with `403`.

This is not cryptographically enforced — any member has the file key and *could* craft a modified file locally, but other members' servers won't accept it during sync because they check the modifier's permission level against the current member list.

Each member entry includes the **path** where that member's copy of the file lives on their server. This allows co-members to fetch updates from each other:

```
Member {
  address: "alice@example.com"
  path: "/ark/alice/docs/project-plan"
  identity_key: ...
  permission: "owner"
  wrapped_key: ...
}
```

**Single member (default):** Notes, personal files. One member entry (self, owner).

**Two members (messaging):** Sender creates file with two members — self (owner) and recipient (read). A copy is delivered to the recipient's `.ark/inbox/` via an envelope (Section 7). The recipient's app can move it to any path.

**Multiple members (collaboration):** Shared documents. All members at `write` or `owner` permission can read and modify. See Section 3.7 for sync.

### 3.5 Directory listings

A GET request to a directory path returns a listing of entries with their headers. The server knows whether a path is a file or a directory — no trailing slash needed:

```
GET https://example.com/ark/alice/notes
Authorization: ArkUser <device_id>:<signature>
```

Response (JSON):

```json
{
  "entries": [
    {
      "name": "todo",
      "size": 4096,
      "modified": "2026-04-11T12:00:00Z",
      "modified_by": "alice@example.com"
    },
    {
      "name": "meeting-notes",
      "size": 2048,
      "modified": "2026-04-10T09:00:00Z",
      "modified_by": "alice@example.com"
    },
    {
      "name": "work",
      "type": "directory"
    }
  ]
}
```

Entries include header metadata (from the unencrypted header) but not the encrypted body. Subdirectories are listed with `"type": "directory"`.

### 3.6 Directory membership

A directory can have its own member list, stored at `.ark/members` within the directory:

```
/ark/alice/projects/.ark/members
```

```json
{
  "members": [
    {
      "address": "alice@example.com",
      "identity_key": "...",
      "permission": "owner"
    },
    {
      "address": "bob@other.com",
      "identity_key": "...",
      "permission": "write"
    }
  ],
  "signature": "..."
}
```

When a file is created in a directory with a members file, the client wraps the file key for each directory member. The server enforces this — it rejects any PUT where the file's member list does not include all directory members at their directory-level permission or higher.

**Inheritance rules:**

- Directory members cascade to all subdirectories and files below.
- A subdirectory's `.ark/members` can **add** new members or **elevate** permissions (e.g., `read` → `write`), but cannot reduce or remove members inherited from a parent directory.
- The server resolves the effective member list by walking up from the file's directory to the user root, accumulating members. The highest permission for each identity key wins.
- Only members with `owner` permission on a directory can modify that directory's `.ark/members` file.

**Example:**

```
/ark/alice/projects/.ark/members          → alice (owner), bob (read)
/ark/alice/projects/secret/.ark/members   → carol (write), bob (write)
```

Effective members for files in `/ark/alice/projects/secret/`:
- alice: `owner` (inherited from parent)
- bob: `write` (elevated from parent's `read` by subdirectory)
- carol: `write` (added by subdirectory)

**No directory members (default):** If no `.ark/members` file exists in a directory or any parent, files have only the members specified in their own headers. This is the normal case for personal files.

### 3.7 Multi-member sync

When a file has multiple members with `write` or `owner` permission, edits need to propagate.

**Last-write-wins.** The `modified` timestamp is the tiebreaker. No merge, no conflict resolution in v1. When Alice updates a shared file:

1. Alice edits the content, re-encrypts with the file key, bumps `modified`, signs with her device key.
2. Alice's client writes the updated file to her server.
3. Alice's server sends an `OBJECT_UPDATED` notification to each co-member's server (lightweight envelope, no PoW — see Section 7.3).
4. Co-members' servers (or clients) fetch the updated file from Alice's server using the path in her member entry.
5. If a co-member also made an edit concurrently, the higher `modified` timestamp wins. The losing edit is discarded (or preserved in the history chain if versioning is enabled).

**Fetching from another member's server:**

```
GET https://example.com/ark/alice/docs/project-plan
Authorization: ArkUser <device_id>:<signature>
```

The server verifies the requester is in the file's member list (by checking identity key against the header) before serving the file.

### 3.8 Adding and removing members

**Adding a member:**

1. An existing member (with `owner` permission) decrypts the file key.
2. Encrypts the file key to the new member's identity key (fetched via key discovery, Section 2.5).
3. Adds a new `Member` entry to the file header.
4. Signs the updated file and syncs to other members.

**Removing a member:**

1. An existing member (with `owner` permission) removes the `Member` entry.
2. Remaining members generate a **new file key** (the removed member knew the old one).
3. Re-encrypt the body with the new key.
4. Re-wrap the new key for each remaining member.
5. The removed member still has their old copy (can't prevent this — they had the key). But new edits use the new key they don't have.

### 3.9 Versioning

Versioning is optional, per-file. When enabled, the file always represents the **current version**. History is stored in a separate **history file**, referenced from the main file's header.

**How it works:**

1. File header has `versioned = true` and `history_path` pointing to the history file (e.g., `notes/todo.history`).
2. When the file is updated, the current body is prepended to the history file (newest first).
3. The file body is replaced with the new content.
4. The history file is itself an Ark file — same format, same encryption (using the same file key as the parent), same ownership.

**History file contents (decrypted):**

A list of previous versions in reverse chronological order:

```
[
  { modified, modified_by, body (previous version) },
  { modified, modified_by, body (version before that) },
  ...
]
```

See Section 8.3 for the wire format.

**Storage:** History counts toward `max_account_size`. Members can configure max history depth per-file. Pruning removes the oldest entries.

**When versioning is off (default):** No history file. Updates overwrite. Simpler, lighter.

**When versioning is on:** Full edit history. Clients that don't care about history never need to fetch the history file — the main file always has the current version.

---

## 4. System 3: Encryption — "Nobody else can read this"

### 4.1 Concept

Every file's body is encrypted with a **symmetric file key** (AES-256-GCM). The file key is then wrapped (encrypted) to each member's identity key using ECIES. This two-layer approach means:

- Content is encrypted once, regardless of how members there are.
- Adding a member only requires wrapping the existing file key — no re-encryption of content.
- Removing a member requires generating a new file key and re-encrypting content (since the removed member knew the old key).

### 4.2 File key generation

When a file is created:

1. The client generates a random 256-bit **file key**.
2. The client encrypts the file body with the file key:
   ```
   nonce = random 12 bytes
   ciphertext, tag = AES-256-GCM(file_key, nonce, payload)
   ```
3. For each member, the client wraps the file key using **ECIES**:
   ```
   ephemeral_key = random X25519 keypair
   shared_secret = X25519(ephemeral_private, owner_encryption_key)
   wrapping_key = HKDF-SHA256(
     ikm: shared_secret,
     salt: ephemeral_public || owner_encryption_key,
     info: "file-key-wrap",
     length: 32
   )
   wrapped_file_key = AES-256-GCM(wrapping_key, random_nonce, file_key)
   ```
4. Each member entry in the header stores the `ephemeral_public`, `nonce`, and `wrapped_file_key`.

### 4.3 Decryption

When Alice decrypts a file:

1. Alice finds her member entry in the header (matched by identity key).
2. Alice computes the shared secret using her private key and the ephemeral public key in her member entry:
   ```
   shared_secret = X25519(alice_private, ephemeral_public)
   ```
3. Alice derives the wrapping key via HKDF (same parameters as encryption).
4. Alice decrypts the wrapped file key.
5. Alice decrypts the file body with the file key.

### 4.4 Why a symmetric file key?

Direct ECIES encryption (as in v0.3) encrypts content directly to each recipient's public key. This works for one-to-one messages but breaks down for shared files:

- **N members would require N copies of the ciphertext** (each encrypted to a different key). A 100MB file shared with 5 people would require 500MB of storage.
- **Adding a member requires re-encrypting the entire content.** With a symmetric file key, adding a member only wraps the 32-byte key — instant, regardless of content size.

The symmetric key approach encrypts content once and wraps the small key per-member. Standard construction, used by Signal (group messages), PGP (session keys), and every major encrypted storage system.

### 4.5 Multi-device decryption

Since there's a single identity keypair per user, multi-device is straightforward:

- **Mode B (server-managed key):** All devices get the private key from the server. Any device can unwrap any file key.
- **Mode A (client-managed key):** All devices derive the same private key from the seed phrase. Same result.

File keys are wrapped to the **identity key**, not per-device. One wrap per member, regardless of how many devices that member has.

### 4.6 Encryption algorithms

| Operation | Algorithm | Parameters |
|---|---|---|
| Identity keys (signing) | Ed25519 | — |
| Encryption key exchange | X25519 | — |
| Key derivation | HKDF-SHA256 | ��� |
| File key wrapping | AES-256-GCM | 96-bit nonce, 128-bit tag |
| File body encryption | AES-256-GCM | 96-bit nonce, 128-bit tag |
| Alternative body encryption | ChaCha20-Poly1305 | 96-bit nonce, 128-bit tag |
| Proof of work | Argon2id | configurable |

Clients MUST support AES-256-GCM. ChaCha20-Poly1305 is recommended as an alternative (faster on devices without AES hardware acceleration). The algorithm used is indicated in the file header.

### 4.7 Why not PGP?

PGP/GPG uses a similar model (session keys wrapped with public keys) but has well-known usability problems:
- Key management is manual and error-prone (keyrings, keyservers, web of trust).
- The PGP message format is complex and has accumulated decades of legacy.
- No standard for key discovery (keyservers are unreliable and have privacy issues).

This protocol uses the same fundamental cryptographic approach but with:
- Automatic key discovery via the identity document.
- A simple, modern binary file format.
- Built-in server infrastructure for key hosting and file storage.

---

## 5. System 4: Authentication — "This really came from Alice"

### 5.1 Concept

Every file modification is digitally signed by the author's device key. When files are delivered cross-server, the envelope is signed so the receiving server can verify authenticity without decrypting the content. Identity forgery is mathematically impossible without the sender's private key.

### 5.2 File signature

When Alice creates or modifies a file:

1. Alice computes an Ed25519 signature over the file's header fields:
   ```
   signature = Ed25519_Sign(
     device_private_key,
     modified || modified_by || members_hash || body_hash
   )
   ```
   Where `members_hash` is the SHA-256 of the serialized member entries and `body_hash` is the SHA-256 of the encrypted body.
2. The signature and `modifier_device_id` are included in the header.
3. Any server or client can verify by fetching the modifier's identity document and checking the device key.

### 5.3 Envelope signature

When files are delivered cross-server via an envelope:

1. The sender constructs the envelope (see Section 8.4 for full format).
2. The sender computes an Ed25519 signature over the serialized envelope contents (excluding the signature field itself):
   ```
   signature = Ed25519_Sign(
     device_private_key,
     version || sender || recipient || timestamp || message_id ||
     envelope_type || proof_of_work
   )
   ```
3. The signature is included in the envelope's `envelope_signature` field.

**Verification by the receiving server:**

1. Alice's server receives the envelope.
2. It extracts the sender address (`bob@sender.example.com`).
3. It fetches (or uses a cached copy of) Bob's identity document from `sender.example.com`.
4. It finds the device matching `sender_device_id` in Bob's identity document.
5. It verifies the `envelope_signature` against the device's public key.
6. If verification fails: the delivery is rejected with a `403 Invalid Signature` response.

**Cache policy for identity documents:**
- Servers cache fetched identity documents for a configurable period (default: 1 hour).
- If a signature fails to verify, the server re-fetches the identity document (the device key may have been added recently) and retries verification once.

### 5.4 Server-level authentication

Servers also authenticate themselves:

1. Each server has its own Ed25519 keypair, published at:
   ```
   GET https://example.com/ark/.ark/identity
   ```
   ```json
   {
     "domain": "example.com",
     "server_key": "base64url-encoded-ed25519-public-key",
     "updated": "2026-04-11T00:00:00Z",
     "signature": "base64url-self-signature"
   }
   ```
2. When server A sends an envelope to server B, it includes an `Authorization` header:
   ```
   Authorization: ArkServer sender.example.com <signature-over-request-body>
   ```
3. Server B verifies this against server A's published server key.

This is defense-in-depth. Even without it, the per-file signature from the author's device key provides authentication. Server-level auth adds:
- Protection against rogue servers forwarding envelopes they didn't originate.
- Rate limiting and abuse tracking at the server level.

### 5.5 Non-repudiation

The Ed25519 signature provides **non-repudiation**: Alice can prove to a third party that Bob authored a specific file. This is a deliberate design choice — you *want* proof of who sent what (contracts, agreements, records).

---

## 6. System 5: Spam Resistance — "Sending costs effort"

Spam resistance applies to **cross-server delivery** — when an envelope is sent from one server to another. Local operations (creating files on your own server, editing your own data) never require proof of work.

### 6.1 Concept

Email spam is possible because sending is free and identity is forgeable. This protocol eliminates both: identity is cryptographically unforgeable, and every cross-server envelope requires proof of computational work.

### 6.2 Layer 1: Proof of Work

Every cross-server envelope includes a proof-of-work stamp computed using **Argon2id**.

**Why Argon2id?**
- It's **memory-hard**: requires a configurable amount of RAM per computation.
- Spammers use GPUs and ASICs, which have massive parallel compute but limited per-core memory. Memory-hardness neutralizes this advantage — each parallel computation needs its own chunk of RAM.
- It's the winner of the Password Hashing Competition and is well-understood.
- Simple hashcash (SHA-256) is vulnerable to GPU/ASIC acceleration. An attacker with a GPU farm could compute PoW stamps orders of magnitude faster than legitimate users.

**How the puzzle works:**

1. The sender constructs the envelope data (excluding the PoW fields).
2. The sender serializes it into a byte string: `challenge = sender || recipient || timestamp || message_id`.
3. The sender picks a random starting nonce (16 bytes).
4. The sender repeatedly computes:
   ```
   result = Argon2id(
     password: challenge || nonce,
     salt: recipient_domain,
     time_cost: 1,
     memory_cost: 65536,    // 64 MB
     parallelism: 1,
     output_length: 32
   )
   ```
   incrementing the nonce each time, until the first `difficulty` bits of `result` are zero.
5. The winning nonce and difficulty are included in the envelope.

**Verification** (by the receiving server):
1. Reconstruct the challenge from the envelope fields.
2. Run Argon2id once with the provided nonce.
3. Check that the first `difficulty` bits are zero.
4. Check that the timestamp in the PoW is recent (within 1 hour).
5. Total verification time: < 1 second (single computation vs. sender's many attempts).

**Default difficulty:**
- At the default difficulty (20 leading zero bits), a sender computes ~1 million Argon2id evaluations on average. With 64MB memory per evaluation, this takes approximately **0.5–2 seconds** on a modern machine.
- This is imperceptible for a human sending a message. For a spammer sending 1 million messages, it would take ~12–24 CPU-days.

### 6.3 Variable difficulty

Each server publishes its spam policy:

```
GET https://example.com/ark/.ark/policy
```

```json
{
  "pow": {
    "algorithm": "argon2id",
    "default_difficulty": 20,
    "first_contact_difficulty": 22,
    "known_contact_difficulty": 0,
    "registration_difficulty": 22,
    "account_creation_difficulty": 24,
    "memory_cost": 65536,
    "time_cost": 1
  }
}
```

| Scenario | Difficulty | Approximate time |
|---|---|---|
| Known contact (in allowlist) | 0 (none) | Instant |
| Default (unknown sender) | 20 bits | ~0.5–2 seconds |
| First contact (no prior exchange) | 22 bits | ~2–8 seconds |
| Registration (subscribing to a sender) | 22 bits | ~2–8 seconds |
| Under load / attack | 24+ bits | ~10–30+ seconds |

Servers can dynamically increase difficulty when under load.

### 6.4 Size-scaled difficulty

PoW difficulty increases with envelope size. This prevents storage-filling attacks where an attacker sends many large files to exhaust a recipient's storage.

The effective difficulty is:

```
effective_difficulty = base_difficulty + min(floor(log2(envelope_size_kb)), size_difficulty_cap)
```

Where `base_difficulty` is the applicable difficulty from Section 6.3 and `size_difficulty_cap` limits how much the size penalty can add (default: 4 bits).

| Envelope size | Extra bits | Total (base 20) | Approx. time |
|---|---|---|---|
| 1 KB (short text) | 0 | 20 | ~1 second |
| 100 KB (long message) | 2 | 22 | ~4 seconds |
| 1 MB (small attachment) | 4 (capped) | 24 | ~15 seconds |
| 25 MB (large attachment) | 4 (capped) | 24 | ~15 seconds |

The cap prevents legitimate large attachments from being impractical to send. The server publishes its cap in the policy:

```json
{
  "pow": {
    "size_difficulty_cap": 4
  }
}
```

Combined with `max_account_size` (server config, default 1GB) and `max_file_size` (server config, default 25MB for deliveries), this creates layered storage protection:
- `max_file_size` rejects oversized deliveries outright.
- Size-scaled PoW makes large deliveries more expensive to send in bulk.
- `max_account_size` is the hard ceiling — once full, the server returns `507 Insufficient Storage`.

### 6.5 Layer 2: Registration

Some users — newsletters, services, notification systems — need to send to many recipients without paying per-delivery PoW. The **registration** mechanism solves this: the *recipient* initiates contact by sending a lightweight registration envelope to the sender, paying PoW once. After registration, the sender can deliver to that recipient at `known_contact_difficulty` (typically 0).

**How it works:**

1. Alice wants to receive updates from `newsletter@example.com`.
2. Alice's client fetches the identity document for `newsletter@example.com` and checks that `accept_registrations` is `true` (see Section 6.5.2).
3. Alice's client sends a `REGISTER` envelope to `newsletter@example.com`:
   - The envelope has `type: REGISTER` and no file payload.
   - Alice computes PoW at the `registration_difficulty` published by `newsletter@example.com`'s server.
   - The envelope is signed by Alice's device key (proving Alice authorized this registration).
4. The newsletter's server verifies the PoW and signature, then adds Alice's identity key to the newsletter's contacts allowlist.
5. The newsletter can now deliver to Alice at `known_contact_difficulty` (typically 0).

**Unregistration:**

Alice can send an `UNREGISTER` envelope (same format, `type: UNREGISTER`, no PoW required — only the signature is needed to prove identity). The sender's server removes Alice from the allowlist.

Alice's client also removes the sender from her own allowlist, so future deliveries from the sender revert to default PoW requirements on her server.

**Why the recipient pays PoW (not the sender):**

- Legitimate bulk senders would be crushed by per-delivery PoW at scale. A newsletter with 100,000 subscribers sending weekly would need ~100,000 PoW computations per send — impractical.
- The subscriber pays once (~2–8 seconds). The sender benefits permanently (or until unregistration).
- Spam is impossible: no one registers to receive spam.
- Unlike traditional email subscription bombing, an attacker cannot register *someone else* — the registration envelope is signed by the registrant's identity key.

**Registration difficulty:**

The receiving server publishes `registration_difficulty` in its policy (see Section 6.3). Default: same as `first_contact_difficulty` (22 bits).

#### 6.5.1 Per-user PoW overrides

Individual users can override the server's default PoW settings via a separate policy file at `/ark/<user>/.ark/policy`. This allows a newsletter account on a shared server to accept registrations while personal accounts on the same server do not.

```
GET https://example.com/ark/newsletter/.ark/policy
```

```json
{
  "accept_registrations": true,
  "default_difficulty": 20,
  "first_contact_difficulty": 24,
  "known_contact_difficulty": 0,
  "registration_difficulty": 20,
  "signature": "..."
}
```

**Rules:**

- Per-user policy is optional. If absent, the server's policy applies.
- Per-user difficulty values can only be **equal to or higher** than the server's defaults — a user cannot lower PoW requirements below what the server enforces.
- `accept_registrations` defaults to `false`. Only users who explicitly enable it will accept registration envelopes.
- The policy file is signed by the user's identity key, so it cannot be tampered with by the server (Mode A users).

**Resolution order** (when an envelope arrives for a user):

1. Check user's policy file at `/ark/<user>/.ark/policy`.
2. Fall back to server-wide policy from `/ark/.ark/policy`.
3. Apply size-scaled difficulty on top (Section 6.4).

**Use cases:**

| User type | `accept_registrations` | `first_contact_difficulty` | Notes |
|---|---|---|---|
| Personal account | `false` (default) | Server default (22) | Normal behavior. |
| Newsletter / service | `true` | Higher (24+) | Accepts registrations, discourages cold contact. |
| Public figure | `false` | Higher (26+) | No registrations, very high bar for cold contact. |
| Private account | `false` | Higher (28+) | Effectively unreachable unless allowlisted. |

#### 6.5.2 Sender discovery of registration support

Before sending a registration envelope, the client fetches the recipient's policy file at `/ark/<user>/.ark/policy` and checks for `"accept_registrations": true`. If the file is absent or the field is `false`, the client should not send a registration envelope — the recipient's server will reject it with `403 Forbidden`.

### 6.6 Layer 3: Contacts allowlist

Once Alice replies to Bob, Bob's identity key is added to Alice's contacts allowlist on her server. Future deliveries from Bob require zero (or minimal) proof of work.

This is automatic and transparent:
- Alice replies to Bob → Bob is allowlisted.
- Alice registers with Bob (Section 6.5) → mutual allowlisting.
- Alice adds Bob manually → Bob is allowlisted.
- Alice removes Bob → Bob is de-listed, reverts to default PoW requirement.

The allowlist is stored in `/ark/alice/.ark/contacts` and is keyed by the sender's **identity public key**, not their address. This means:
- Bob can change servers and remain allowlisted as long as he keeps the same identity key.
- Someone who registers bob@attacker.com with a different key is NOT allowlisted.

### 6.7 Layer 4: Account creation PoW

Account creation also requires proof of work. This prevents mass creation of throwaway accounts to circumvent per-sender PoW.

```
POST https://example.com/ark/.ark/accounts
Content-Type: application/json

{
  "address": "alice",
  "identity_key": "base64url-encoded-ed25519-public-key",
  "encryption_key": "base64url-encoded-x25519-public-key",
  "proof_of_work": {
    "algorithm": "argon2id",
    "nonce": "base64url-encoded-nonce",
    "difficulty": 24,
    "memory_cost": 65536,
    "time_cost": 1,
    "timestamp": 1712838400
  }
}
```

The PoW challenge for account creation is: `challenge = "account-creation" || address || identity_key || timestamp`.

Servers can disable remote account creation entirely:

```toml
allow_remote_registration = false  # Only admin can create accounts (default: true)
```

When disabled, the endpoint returns `403 Forbidden`. Local account creation (via the admin CLI) always works regardless of this setting.

### 6.8 Layer 5: Social trust signals (optional)

**Introduction field:**
- The envelope can include an optional plaintext `introduction` field (max 280 characters) visible to the receiving server (but not E2E encrypted).
- Use case: "Hi, I'm Bob from Acme Corp, we met at the conference."

**Cross-signing vouches:**
- Alice can sign a statement: "I vouch for `bob@example.com` (identity key: `...`)".
- Bob can attach this vouch to his envelopes to Alice's contacts.
- Carol's server, upon seeing a vouch from Alice (whom Carol trusts), reduces PoW requirements for Bob.

### 6.9 Why this eliminates IP reputation

| Email problem | How Ark solves it |
|---|---|
| Unknown IP → spam folder | Identity is cryptographic, not IP-based. A brand-new server delivers just as well as an established one. |
| IP blocklists | No blocklists needed. PoW + signatures prevent abuse. |
| Shared IP risk (cloud hosting) | IP doesn't matter. Your cryptographic identity is unique. |
| SPF/DKIM/DMARC complexity | None of these exist. Authentication is per-file signatures. |

---

## 7. System 6: Transport — "How data moves"

### 7.1 Concept

All communication happens over **HTTPS**. No custom protocols, no special ports. A server is a single binary with a single config file.

Transport has three modes:
1. **Local access** — client reads/writes files on its own server by path.
2. **Cross-server delivery** — sending files to other users' `.ark/inbox/` via envelopes.
3. **Cross-server sync** — keeping shared files in sync between co-members' servers.

### 7.2 Local file access

Alice's client communicates with her home server over HTTPS.

**Authentication:** Every request is signed with the device's Ed25519 key:
```
Authorization: ArkUser <device_id>:<signature-over-method-path-timestamp-body>
X-Ark-Timestamp: 1712838400
```
The server verifies the signature against the device key registered in Alice's identity document. Requests with timestamps older than 5 minutes are rejected (replay protection).

**File operations:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/ark/alice/path/to/file` | Fetch file (header + encrypted body) |
| `HEAD` | `/ark/alice/path/to/file` | Fetch header/metadata only |
| `PUT` | `/ark/alice/path/to/file` | Create or update a file |
| `DELETE` | `/ark/alice/path/to/file` | Delete a file |
| `GET` | `/ark/alice/path/to/dir` | List directory contents |

**GET response:**

The raw Ark file — binary header followed by encrypted body. The `Content-Type` is `application/x-ark`.

**HEAD response:**

HTTP headers include file metadata extracted from the Ark header:

```
X-Ark-Modified: 1712838400
X-Ark-Modified-By: alice@example.com
X-Ark-Members: 2
X-Ark-Versioned: true
Content-Length: 4096
```

Clients that need the full header (member entries, wrapped keys) use GET and read only the header portion.

**Special endpoints:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/ark/alice/.ark/contacts` | List contacts (allowlisted identity keys) |
| `PUT` | `/ark/alice/.ark/contacts` | Update contacts |
| `GET` | `/ark/alice/.ark/stream` | Real-time event stream (WebSocket/SSE) |

### 7.3 Cross-server delivery

When Bob sends a message (file) to Alice:

**Step 1: Store locally.** Bob's client creates the file on Bob's server via PUT.

**Step 2: Deliver via envelope.** Bob's server wraps the file in an envelope and delivers it to Alice's `.ark/inbox/`:

```
POST https://example.com/ark/alice/.ark/inbox/
Content-Type: application/x-ark-envelope
Authorization: ArkServer sender.example.com <server-signature>

<binary envelope>
```

The envelope contains the Ark file plus Alice's member entry (her wrapped file key), the PoW stamp, and the sender's signature. Alice's server extracts the file and writes it to `.ark/inbox/` with a generated filename (the envelope's `message_id`).

The file header includes an `app` hint (e.g., `"mail"`, `"calendar"`) so client-side apps know which files to claim from `.ark/inbox/`.

**Response codes:**

| Code | Meaning |
|---|---|
| `202 Accepted` | File accepted, written to `.ark/inbox/`. |
| `400 Bad Request` | Malformed envelope. |
| `403 Forbidden` | Signature verification failed. |
| `404 Not Found` | Recipient does not exist on this server. |
| `422 Unprocessable` | PoW verification failed or difficulty too low. |
| `429 Too Many Requests` | Rate limited. Includes `Retry-After` header. |
| `507 Insufficient Storage` | Recipient's storage is full. |

**Delivery retries:**
- If delivery fails (server down, network error), the sending server retries with exponential backoff (1 min, 5 min, 30 min, 2 hours, 8 hours) for up to 72 hours, then returns a bounce notification to the sender.

### 7.4 Cross-server sync (shared files)

When a shared file is updated, co-members' servers are notified.

**Update notification:**

```
POST https://example.com/ark/alice/.ark/inbox/
Content-Type: application/x-ark-envelope
Authorization: ArkServer sender.example.com <server-signature>

<binary envelope with type OBJECT_UPDATED>
```

The notification envelope contains:
- `path` — the updated file's path on the modifier's server.
- `modified` — new timestamp.
- `modified_by` — who made the change.
- Signature from the modifier (proves membership).

**No PoW required** for sync notifications between co-members. The co-membership relationship is already established — the receiving server verifies the modifier is in the file's member list.

**Fetching the updated file:**

After receiving a notification, the co-member's server (or client) fetches the updated file:

```
GET https://bob-server.com/ark/bob/docs/project-plan
Authorization: ArkUser <device_id>:<signature>
```

The serving server verifies the requester's identity key is in the file's member list before responding.

**Member moved notification:**

When a member migrates to a new server (Section 2.10), they send a `MEMBER_MOVED` envelope to co-members' `.ark/inbox/` directories:

```
Envelope type: MEMBER_MOVED
Payload: { old_address, new_address, identity_key, signature }
```

Co-members' clients update the member address and path in shared files. Identity key stays the same, so trust is preserved.

### 7.5 Real-time events

```
GET https://example.com/ark/alice/.ark/stream
Authorization: ArkUser <device_id>:<signature>
```

WebSocket or SSE stream. Events:

```json
{"event": "created", "path": "/ark/alice/.ark/inbox/abc123", "from": "bob@example.com"}
{"event": "modified", "path": "/ark/alice/notes/todo", "modified_by": "alice@example.com"}
{"event": "deleted", "path": "/ark/alice/mail/trash/old-msg"}
{"event": "sync", "path": "/ark/alice/.ark/inbox/def456", "type": "OBJECT_UPDATED"}
```

### 7.6 Server architecture

A server is a **single statically-linked binary** containing:

```
┌──────────────────────────────────────────────┐
│              ark-server                      │
├──────────────────────────────────────────────┤
│  HTTPS Server                                │
│  ├── File access (GET/HEAD/PUT/DELETE)       │
│  ├── Envelope delivery (POST .ark/inbox/)    │
│  └── WebSocket/SSE (.ark/stream)             │
├──────────────────────────────────────────────┤
│  Filesystem Storage                          │
│  ├── /ark/<user>/ (encrypted files)          │
│  ├── /ark/<user>/.ark/inbox/ (incoming)      │
│  └── /ark/<user>/.ark/contacts (allowlist)   │
├──────────────────────────────────────────────┤
│  Outbound Relay                              │
│  ├── Queue for outgoing envelopes            │
│  ├── Retry logic (exponential backoff)       │
│  └── Remote identity document cache          │
├──────────────────────────────────────────────┤
│  Sync Engine                                 │
│  ├── Notify co-members on file update         │
│  ├── Fetch updates from co-members            │
│  └── Conflict resolution (last-write)        │
├──────────────────────────────────────────────┤
│  TLS (ACME / Let's Encrypt)                  │
│  └── Auto-provision and renewal              │
├──────────────────────────────────────────────┤
│  Admin CLI                                   │
│  ├── user add/remove/list                    │
│  ├── stats / diagnostics                     │
│  └── config reload                           │
└──────────────────────────────────────────────┘
```

**Configuration:**

```toml
# ark.toml — the entire configuration file

domain = "example.com"
storage = "./data"

# Optional overrides (all have sensible defaults)
# listen = "0.0.0.0:443"
# acme_email = "admin@example.com"
# max_account_size = "1GB"
# max_file_size = "100MB"
# max_delivery_size = "25MB"
```

**Setup process:**
1. Install the binary (single file, no dependencies).
2. Point a domain to the server's IP (A/AAAA record).
3. Create the config file (2 lines minimum).
4. Start the server. It auto-provisions a TLS certificate via Let's Encrypt.
5. Add users locally: `ark-server user add alice` (bypasses PoW for local admin).
6. Or users self-register via the accounts endpoint (requires account creation PoW).
7. Alice's client registers her public key (Mode A) or the server generates one for her (Mode B).

**Storage:**
- Filesystem. Files are stored on disk exactly as they are — the server is essentially an authenticated file server. No database required for user data.
- The server may use a lightweight index (e.g., SQLite) for caching directory listings and metadata queries, but the files themselves are the source of truth.
- Contacts allowlists are stored as JSON files at `/ark/<user>/.ark/contacts`.

### 7.7 Deployment: co-hosting with a website

The protocol only uses paths under `/ark/`. It coexists with a website on the same domain.

**Reverse proxy setup (recommended):**

```nginx
# nginx example
server {
    listen 443 ssl;
    server_name example.com;

    # Ark server
    location /ark/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;  # WebSocket support
        proxy_set_header Connection "upgrade";
    }

    # Your website (everything else)
    location / {
        root /var/www/example.com;
        # or proxy_pass to your web app
    }
}
```

The Ark server runs on a local port (e.g., 8080) without TLS — the reverse proxy handles TLS termination:

```toml
domain = "example.com"
storage = "./data"
listen = "127.0.0.1:8080"
tls = false  # reverse proxy handles TLS
```

### 7.8 Self-hosting comparison

| Concern | Email | Ark |
|---|---|---|
| DNS records | A, MX, PTR, SPF, DKIM, DMARC | A (or AAAA) only |
| TLS certificates | Manual or separate ACME setup | Built-in ACME or use reverse proxy |
| IP reputation | Critical. New IPs go to spam for months. | Not a concept. |
| Spam filtering | SpamAssassin, Bayesian filters, blocklists | Built-in: PoW + signatures |
| Deliverability | Gmail/Outlook may silently drop your mail | Guaranteed — cryptographic identity |
| Software | Postfix + Dovecot + OpenDKIM + Rspamd + ... | Single binary |
| Config files | Dozens across multiple services | One file |
| Ports | 25 (SMTP), 465 (SMTPS), 587 (submission), 993 (IMAPS) | 443 (HTTPS) only |
| Maintenance | Monitor blacklists, rotate DKIM, manage certs, update filter rules | Auto TLS renewal |
| Time to working setup | Hours to days (plus months for reputation) | Minutes |
| Co-hosting with website | Separate IP or complex port routing | Shares port 443, just one `/ark/` location block |

---

## 8. File Format

### 8.1 Binary layout

An Ark file is a binary file with two sections:

```
┌──────────────────────────────────┐
│  Magic bytes: "ARK\x01" (4)      │
│  Header length: uint32 BE (4)    │
├──────────────────────────────────┤
│  Header (protobuf, unencrypted)  │
│  └── variable length             │
├──────────────────────────────────┤
│  Body (encrypted)                │
│  ├── nonce (12 bytes)            │
│  └── ciphertext + tag (rest)     │
└──────────────────────────────────┘
```

The first 8 bytes are fixed: 4-byte magic (`ARK\x01`, where `\x01` is the format version) and 4-byte big-endian header length. The header follows immediately, then the encrypted body fills the rest of the file.

### 8.2 Header

The header is serialized using Protocol Buffers.

```protobuf
syntax = "proto3";

message Header {
  // Timestamps
  uint64 created = 1;                   // Unix milliseconds
  uint64 modified = 2;                  // Unix milliseconds

  // Membership
  repeated Member members = 3;

  // Encryption
  string algorithm = 4;                 // "aes-256-gcm" or "chacha20-poly1305"

  // Versioning (optional)
  bool versioned = 5;
  string history_path = 6;             // Path to history file (if versioned)

  // Author of last modification
  string modified_by = 7;              // "alice@example.com"
  uint32 modifier_device_id = 8;
  bytes signature = 9;                 // Ed25519 signature over fields 1-8 + body hash

  // App hint (for .ark/inbox/ routing by client apps)
  string app = 10;                     // e.g., "mail", "calendar", "notes" — optional
}

message Member {
  string address = 1;                   // "alice@example.com"
  string path = 2;                     // "/ark/alice/notes/todo" — where this member's copy lives
  bytes identity_key = 3;              // Member's Ed25519 public key (for verification)
  string permission = 4;               // "owner", "write", or "read"

  // File key wrapped for this member (ECIES)
  bytes ephemeral_key = 5;            // X25519 ephemeral public key (32 bytes)
  bytes key_nonce = 6;                // AES-256-GCM nonce for key wrapping (12 bytes)
  bytes wrapped_file_key = 7;         // File key encrypted to this member (32 bytes + 16 byte tag)
}
```

### 8.3 History file

The history file uses the same Ark file format (magic + header + encrypted body). Its decrypted body contains a list of previous versions:

```protobuf
message HistoryPayload {
  repeated HistoryEntry entries = 1;   // Newest first (reverse chronological)
}

message HistoryEntry {
  uint64 modified = 1;                // When this version was current
  string modified_by = 2;             // Who created this version
  bytes body = 3;                     // Previous file body (decrypted content of previous version)
}
```

The history file is encrypted with the same file key as the parent file. Same membership, same access control.

### 8.4 Envelope

The envelope is the transport wrapper for cross-server delivery. It wraps a file (or a notification) for delivery to another server's `.ark/inbox/`.

```protobuf
enum EnvelopeType {
  DELIVER = 0;                         // Deliver a file to a recipient
  REGISTER = 1;                        // Registration request (Section 6.5)
  UNREGISTER = 2;                      // Unregistration request (Section 6.5)
  OBJECT_UPDATED = 3;                  // Notify co-member of file update
  MEMBER_MOVED = 4;                     // Notify co-members of address change
}

message Envelope {
  uint32 version = 1;                  // Protocol version (1)

  // Routing
  string sender = 2;                   // "bob@sender.example.com"
  string recipient = 3;               // "alice@example.com"
  uint64 timestamp = 4;               // Unix milliseconds
  bytes message_id = 5;               // 16 bytes, random UUID

  // Sender device
  uint32 sender_device_id = 6;

  // Envelope type
  EnvelopeType type = 7;              // Default: DELIVER

  // Spam resistance (required for DELIVER, REGISTER; absent for others)
  ProofOfWork proof_of_work = 8;

  // Optional plaintext introduction (for first-contact filtering)
  string introduction = 9;            // Max 280 chars, optional

  // Sender authentication (Ed25519 signature over fields 1-9)
  bytes envelope_signature = 10;      // 64 bytes

  // Payload — depends on envelope type:
  // DELIVER: raw Ark file bytes (header + encrypted body)
  // OBJECT_UPDATED: FileUpdateNotification
  // MEMBER_MOVED: MemberMovedNotification
  // REGISTER/UNREGISTER: empty
  bytes payload = 11;
}

message ProofOfWork {
  string algorithm = 1;               // "argon2id"
  bytes nonce = 2;                    // 16 bytes
  uint32 difficulty = 3;              // Number of leading zero bits required
  uint32 memory_cost = 4;            // Argon2 memory parameter (KB)
  uint32 time_cost = 5;              // Argon2 time parameter
  uint64 timestamp = 6;              // When PoW was computed (must be recent)
}

message FileUpdateNotification {
  string path = 1;                    // Path on the modifier's server
  uint64 modified = 2;
  string modified_by = 3;
  bytes signature = 4;               // Modifier's signature (proves membership)
}

message MemberMovedNotification {
  string old_address = 1;
  string new_address = 2;
  bytes identity_key = 3;
  bytes signature = 4;               // Signed by the identity key
}
```

### 8.5 Identity and policy documents

Identity documents, server identity, policy files, and contacts are JSON (human-readable, easy to debug with curl). See Section 2.4, Section 5.4, and Section 6.5.1 for schemas.

### 8.6 Serialization rules

- **File headers, envelopes:** Protocol Buffers (binary). Compact, efficient, schema-evolvable.
- **Identity documents, policy, server identity, contacts:** JSON. Human-readable.
- **Signatures:** computed over the canonical protobuf serialization (deterministic encoding) plus the SHA-256 hash of the encrypted body.
- **All binary values in JSON:** base64url encoding (RFC 4648, no padding).

---

## 9. Threat Model

### 9.1 What is protected

| Property | Guarantee |
|---|---|
| **Data confidentiality** | Only holders of the file key can read file content. Servers see only ciphertext (Mode A). |
| **Author authentication** | Files and envelopes are signed by the author's device key. Forgery requires the private key. |
| **Integrity** | Any modification to a file invalidates the signature. Any modification to the ciphertext invalidates the AEAD tag. |
| **Spam resistance** | Bulk cross-server delivery requires proportional computational resources (PoW). |
| **Data persistence** | All files can be decrypted with the single identity key (which unwraps file keys). No session state to lose. |

### 9.2 What is NOT protected

| Risk | Details |
|---|---|
| **Metadata** | File paths, sizes, timestamps, member addresses, and cross-server delivery patterns are visible to the server and network observers. Path names may reveal content intent (e.g., `/notes/tax-2025`). |
| **Forward secrecy** | If the identity private key is compromised, all file keys can be unwrapped, and all past and future data can be decrypted. This is a deliberate tradeoff for simplicity and recoverability. See Section 10.1 for the forward secrecy extension. |
| **Mode B server trust** | If the server holds the private key (Mode B), the server can read all data. Self-hosters mitigate this by controlling the server. |
| **Removed member's existing copy** | When a member is removed from a shared file, they retain any copy they already downloaded. Re-keying prevents access to future edits, not past content. |
| **Path metadata** | File paths are unencrypted (the server needs them for routing). Path names like `/mail/inbox/` or `/notes/secret-project` are visible to the server. For maximum privacy, use opaque paths. |

### 9.3 Compromise scenarios

**Scenario: Alice's server is compromised (Mode A — client-managed key)**
- Attacker can see metadata (paths, sizes, timestamps, who Alice shares with).
- Attacker **cannot** read file content (doesn't have Alice's private key to unwrap file keys).
- Attacker **cannot** forge files from Alice (doesn't have her signing key).
- Attacker could serve a fake identity document with a different public key. Mitigations: (1) existing contacts have Alice's key pinned via TOFU, (2) verified contacts will see a safety number change warning.

**Scenario: Alice's server is compromised (Mode B — server-managed key)**
- Attacker gets Alice's private key from the server.
- Attacker **can** read all files (past and future, until the key is rotated).
- Attacker **can** forge files from Alice.
- This is the tradeoff of Mode B. Mitigation: use Mode A for high-security needs.

**Scenario: Alice's identity key is compromised (either mode)**
- Worst case. Attacker can impersonate Alice and decrypt all data.
- Mitigation: Alice performs a key transition (Section 2.8). After transition, new files use the new key and are safe.

**Scenario: Shared file key is compromised**
- Only the specific file is affected, not Alice's other data.
- Mitigation: re-key the file (generate new file key, re-encrypt body, re-wrap for all members).

**Scenario: Server-to-server traffic is intercepted (TLS broken)**
- Attacker sees encrypted envelopes in transit. They can see metadata (routing info is plaintext).
- Attacker **cannot** read file content (E2E encrypted independent of TLS).
- Attacker **cannot** forge envelopes (signatures are verified).
- TLS is defense-in-depth for metadata, not the primary security layer.

### 9.4 Trust assumptions

| Assumption | Consequence if violated |
|---|---|
| Ed25519 is secure | All identity and authentication breaks. |
| X25519 is secure | All encryption key exchange breaks. |
| AES-256-GCM / ChaCha20-Poly1305 is secure | Data confidentiality breaks. |
| Argon2id is memory-hard | PoW can be computed cheaply by attackers with specialized hardware. |
| User's seed phrase / private key is stored securely | Attacker can decrypt all data and impersonate user. |
| TOFU on first contact is not intercepted | MITM on first key fetch allows interception until detected. |

---

## 10. Extensions

These are planned features not included in the core v1 protocol. They can be layered on top without breaking compatibility.

### 10.1 Forward Secrecy (optional mode)

A future version could add an optional **forward secrecy mode** for message conversations between two users who both opt in. This would use the Signal protocol's Double Ratchet:

- Each message would use a unique ephemeral key, and old keys would be destroyed.
- Compromising the identity key would not expose past messages.
- The tradeoff: messages encrypted with destroyed keys become unrecoverable.

This would be negotiated per-conversation and coexist with the default file key mode.

### 10.2 Legacy Email Interop

An optional system for communicating with legacy email users. There are two methods, which can be used independently or together.

#### Method 1: Notification Link (outbound to email users)

When a protocol user sends a message to a legacy email address, the server creates a temporary account for the recipient and sends them a notification email with a link to read the message.

**How it works:**

1. Bob sends a message to `carol@gmail.com` from the protocol.
2. Bob's server computes a deterministic alias from the email address:
   ```
   alias = "x-" + base32_lowercase(sha256("carol@gmail.com")[:10])
   → "x-a7f3k2m9p4q8r2"
   ```
3. Bob's server checks whether this alias already exists on the **gateway server**.
4. If not, it requests account creation on the gateway (with account creation PoW):
   - The gateway creates a Mode B account (server-generated keypair).
   - The gateway publishes a legacy email identity document for the alias.
5. Bob's server encrypts the message to the new account's public key and delivers it.
6. The gateway sends a notification email to `carol@gmail.com`:
   ```
   Subject: Bob sent you a message
   
   Read it here: https://gateway.example.com/read/a8Kx7mP2...
   ```
7. Carol clicks the link. A web client loads. She reads the message and can reply.

**Legacy email identity document:**

```
GET https://gateway.example.com/ark/x-a7f3k2m9p4q8r2/.ark/identity
```

```json
{
  "version": 1,
  "type": "legacy_email",
  "address": "x-a7f3k2m9p4q8r2@gateway.example.com",
  "legacy_email": "carol@gmail.com",
  "identity_key": "base64url-encoded-ed25519-public-key",
  "encryption_key": "base64url-encoded-x25519-public-key",
  "notify": true,
  "updated": "2026-04-14T12:00:00Z",
  "signature": "base64url-encoded-signature"
}
```

**Claiming the identity:**

When Carol decides she wants a real address:
1. Carol chooses a username (e.g., `carol`).
2. The gateway creates a new identity document at `carol@gateway.example.com` (same keypair).
3. The hash alias redirects to the new address.
4. Carol can migrate to her own server later using a key transition (Section 2.8).

**The gateway server:**

The gateway is an Ark server that specializes in hosting accounts for legacy email recipients and sending notification emails via a transactional email API (SendGrid, Postmark, etc.).

```toml
domain = "example.com"
storage = "./data"
legacy_gateway = "gateway.ark.io"
```

#### Method 2: Email Bridge (inbound from email users)

For protocol users who want to receive legacy email, a bridge service can forward incoming emails.

1. Alice configures a forwarding rule in her email provider to a webhook handled by the bridge.
2. The bridge receives the email, wraps the content in an Ark file, and delivers it to Alice's `.ark/inbox/` via a standard envelope.
3. The file is marked as "received via email (unencrypted)" in Alice's client.

**Security note:** Bridged messages are not encrypted in transit. The bridge sees plaintext during processing. These files should be clearly distinguished from native Ark files in the client UI.

### 10.3 Metadata Privacy

A future version could add onion routing or mixnet support to hide metadata (sender/recipient/timing) from servers and network observers. The protocol's layered design (file vs. envelope) makes this possible without changing the core file format.

### 10.4 Collaborative Editing (CRDTs)

V1 uses last-write-wins for shared files. A future extension could support real-time collaborative editing via CRDTs (Conflict-free Replicated Data Types):

- File body would be an encrypted operation log instead of a snapshot.
- Each edit appends an encrypted CRDT operation (e.g., Yjs or Automerge format).
- Clients replay operations to reconstruct current state.
- This would be opt-in per file and coexist with the default snapshot model.

---

## Appendix A: Cryptographic Algorithms Summary

| Purpose | Algorithm | Key Size | Output Size |
|---|---|---|---|
| Identity / signing | Ed25519 | 256-bit | 512-bit signature |
| Encryption key exchange | X25519 | 256-bit | 256-bit shared secret |
| Key derivation | HKDF-SHA256 | variable | variable |
| File key wrapping | AES-256-GCM | 256-bit | ciphertext + 128-bit tag |
| File body encryption | AES-256-GCM | 256-bit | ciphertext + 128-bit tag |
| Alt. body encryption | ChaCha20-Poly1305 | 256-bit | ciphertext + 128-bit tag |
| Proof of work | Argon2id | variable | 256-bit |
| Seed phrase | BIP-39 | 256-bit entropy | 24 words |

## Appendix B: URL Structure Summary

All Ark paths are under `https://<domain>/ark/`.

**Server-level (no auth required):**

| Path | Method | Purpose |
|---|---|---|
| `/ark/.ark/identity` | GET | Server identity document |
| `/ark/.ark/policy` | GET | Server spam policy |
| `/ark/.ark/accounts` | POST | Create account (requires PoW) |

**User-level (public, no auth):**

| Path | Method | Purpose |
|---|---|---|
| `/ark/<user>/.ark/identity` | GET | User identity document |
| `/ark/<user>/.ark/policy` | GET | User spam policy (optional) |

**User-level (authenticated — member):**

| Path | Method | Purpose |
|---|---|---|
| `/ark/<user>/<path>` | GET | Fetch file (header + body) |
| `/ark/<user>/<path>` | HEAD | Fetch header/metadata only |
| `/ark/<user>/<path>` | PUT | Create or update file |
| `/ark/<user>/<path>` | DELETE | Delete file |
| `/ark/<user>/<dir>` | GET | List directory |
| `/ark/<user>/.ark/contacts` | GET/PUT | Manage contacts allowlist |
| `/ark/<user>/.ark/stream` | GET | Real-time event stream |

**Cross-server delivery (server auth):**

| Path | Method | Purpose |
|---|---|---|
| `/ark/<user>/.ark/inbox/` | POST | Deliver envelope (file, notification, registration) |
