# Ark Protocol Specification

> **Status:** Draft v0.4
> **Date:** 2026-04-26

## Table of Contents

1. [Overview](#1-overview)
2. [System 1: Identity](#2-system-1-identity--who-are-you)
3. [System 2: Objects](#3-system-2-objects--the-core-primitive)
4. [System 3: Encryption](#4-system-3-encryption--nobody-else-can-read-this)
5. [System 4: Authentication](#5-system-4-authentication--this-really-came-from-alice)
6. [System 5: Spam Resistance](#6-system-5-spam-resistance--sending-costs-effort)
7. [System 6: Transport](#7-system-6-transport--how-data-moves)
8. [Wire Formats](#8-wire-formats)
9. [Threat Model](#9-threat-model)
10. [Extensions](#10-extensions)

---

## 1. Overview

Ark is a federated, encrypted protocol for personal data. It replaces email, cloud storage, and note-taking with a single system built on cryptographic identity and end-to-end encryption. It has six core systems:

| System | Purpose |
|---|---|
| **Identity** | Who are you? Keypair mapped to a human-readable address. |
| **Objects** | The core data primitive. Everything — messages, files, notes, folders — is an object. |
| **Encryption** | Nobody else can read your data. Symmetric object keys wrapped with public-key encryption. |
| **Authentication** | Proof that data really came from the claimed author. |
| **Spam Resistance** | Cross-server delivery costs computational effort. No reputation systems needed. |
| **Transport** | How objects move between servers. Plain HTTPS, trivially self-hostable. |

### Design principles

- **Cryptographic identity, not reputation-based.** Your identity is a keypair, not an IP address or domain reputation score. This eliminates the entire class of deliverability problems that plague self-hosted email.
- **Encrypted by default.** All object content is end-to-end encrypted. Servers store ciphertext they cannot read.
- **One primitive.** Everything is an object — messages, notes, files, folders. Different ownership patterns produce different behaviors, not different concepts.
- **Simple to self-host.** A single binary, a single config file, a domain with an A record. That's it.
- **Federated, not peer-to-peer.** Servers provide reliable offline storage and key hosting. Pure P2P systems (Bitmessage, Briar) struggle with reliability and adoption.
- **Spam-resistant by construction.** Proof of work + unforgeable identity + contact allowlists make bulk spam economically infeasible without complex filtering infrastructure.
- **Simple key model.** One keypair per identity, like a crypto wallet. Lose the key, lose the identity. Have the key, have all your data. No complex session state to manage.
- **Flexible trust model.** Users choose where their private key lives — on their device (maximum security) or on their server (maximum convenience). Self-hosters get both.

### How a message flows (end to end)

A message is an object with two owners — sender (full) and recipient (read-only). Here is how it flows:

```
Bob's Client                Bob's Server              Alice's Server             Alice's Client
    |                           |                          |                          |
    |  1. Fetch Alice's         |                          |                          |
    |     identity doc -------->|------- HTTPS GET ------->|                          |
    |  2. Receive public key    |<------ JSON response ----|                          |
    |                           |                          |                          |
    |  3. Generate object key,  |                          |                          |
    |     encrypt content,      |                          |                          |
    |     wrap key for self     |                          |                          |
    |     and Alice             |                          |                          |
    |                           |                          |                          |
    |  4. Compute proof of work |                          |                          |
    |     (Argon2id, ~0.5s)     |                          |                          |
    |                           |                          |                          |
    |  5. Sign envelope         |                          |                          |
    |                           |                          |                          |
    |  6. Store object on ----->|                          |                          |
    |     home server           |                          |                          |
    |                           |  7. Relay via HTTPS POST |                          |
    |                           |------- envelope -------->|                          |
    |                           |                          |  8. Verify signature      |
    |                           |                          |  9. Verify PoW            |
    |                           |                          |  10. Store object         |
    |                           |                          |                          |
    |                           |                          |  11. Alice fetches ------>|
    |                           |                          |  12. Decrypt with         |
    |                           |                          |      private key          |
```

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
- Fast signing and verification (important for per-object signatures).
- Small keys (32 bytes) and signatures (64 bytes).
- Deterministic — same input always produces the same signature (no nonce-reuse vulnerabilities).
- Well-audited, widely implemented, no known weaknesses.
- Easily converted to X25519 for encryption operations.

### 2.4 Identity document

Alice's public identity is published as a JSON document at a well-known URL on her server:

```
GET https://example.com/.well-known/ark/identity/alice
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
| `policy` | Optional per-user policy overrides (Section 6.5.1). Includes `accept_registrations`, PoW difficulty overrides. |
| `signature` | Ed25519 signature over the entire document (excluding this field). Proves the identity key holder authored this. |

**The self-signature is the key security property** (for Mode A users). The server hosts this document but cannot tamper with it — any modification invalidates the signature. This means:
- A compromised server cannot swap in a different public key to intercept data.
- A MITM attacker who compromises the TLS connection cannot forge the identity document.
- The document is self-authenticating: anyone can verify it using only the public key it contains.

Note: For Mode B users (server holds the private key), the server *could* sign a different identity document. The user is already trusting the server with their private key, so this doesn't change the trust model.

### 2.5 Key discovery

When Bob wants to contact Alice for the first time:

1. Bob's client extracts the domain from `alice@example.com`.
2. Bob's client makes an HTTPS GET to `https://example.com/.well-known/ark/identity/alice`.
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
- All devices can decrypt all objects (they all have the same identity private key).
- Each device also has its own **device signing key** (Ed25519) for authenticating API requests and signing outgoing data.

**Mode A (client-managed key):**
- Alice sets up her first device with the seed phrase.
- To add a second device, Alice enters the seed phrase on the new device (or transfers the private key via QR code / secure channel).
- Each device also generates its own **device signing key**.
- The identity key signs each device key (proving "I, Alice, authorize this device").

**Device signing keys** are useful in both modes:
- They identify which device authored an operation.
- A device can be individually revoked without changing the identity key.
- API request authentication is per-device (the server knows which device is making each request).

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

When an identity key changes, Alice must re-wrap her object keys. Each object has a symmetric object key encrypted to her identity key (Section 4). Alice decrypts each object key with the old identity key and re-encrypts it with the new one. For shared objects, other owners' grants are unaffected — they hold the object key wrapped to their own identity keys.

### 2.9 Account recovery

**Mode B (server-managed key):**
- The server holds the private key. Recovery is a standard password reset / admin intervention.
- Objects are stored on the server and remain accessible.
- This is the simplest recovery story — works like email.

**Mode A (client-managed key):**
- Alice enters her 24-word seed phrase on a new device.
- The client derives the identity keypair from the seed.
- The client registers the new device with Alice's server (the server recognizes the identity public key).
- Objects stored on the server (encrypted) can be decrypted because Alice has the same private key, which unwraps the object keys.

**What is lost if the seed phrase is lost (Mode A):**
- The identity key is gone. Alice must create a new account with a new keypair.
- All objects encrypted to the old key are unrecoverable.
- Contacts will see a new key and need to re-verify.

**No DNS complexity:**
- The server just needs a domain name pointing to it (A/AAAA record). That's it.
- No MX records, no SPF, no DKIM, no DMARC. Identity is cryptographic, not DNS-based.

### 2.10 Server migration

Alice can move from one server to another while keeping the same identity keypair.

**When the old server is still online:**

1. Alice creates an account on the new server with her existing identity key (Mode A: enters seed phrase; Mode B: transfers the private key).
2. Alice exports her objects from the old server and imports them to the new server. No re-encryption is needed — all object keys are encrypted to the same identity key regardless of which server stores them.
3. Alice exports her contacts allowlist (list of trusted public keys) and imports it to the new server.
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
- Objects (download from old, upload to new — encrypted to same key).
- Contacts allowlist (export/import list of trusted public keys).
- Alias redirect on old server (if still online).

**What doesn't migrate automatically:**
- Other people's allowlists. Contacts who had Alice allowlisted on the old address may need to re-allowlist the new address. However, since allowlists are keyed by identity public key (not address), a smart server implementation can recognize that the same key is now at a new address and preserve the allowlist entry.
- Shared object co-ownership. Other owners of shared objects have Alice's old server address in the owner list. Alice notifies co-owners (via an `OWNER_MOVED` envelope) so they update the address. Since ownership is verified by identity key, the transition is seamless once addresses are updated.

### 2.11 Aliases

A single identity (one keypair) can have **multiple addresses** that all resolve to the same account. One address is the **primary** and has a full identity document. All others are **aliases** that redirect to the primary.

**Alias identity document:**

```
GET https://example.com/.well-known/ark/identity/old-alice
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
- **Name changes.** Alice changes her username from `old-alice` to `alice`. The old address becomes an alias that redirects to the new one. Existing contacts who have the old address cached will be seamlessly redirected.
- **Vanity aliases.** Alice has `alice@example.com` as primary but also wants `a@example.com` as a short alias.
- **Generated aliases.** The server can create machine-generated aliases (e.g., hash-based) for special purposes like legacy email interop (see Section 10.2).

**Cross-server aliases** are not supported in v1. An alias must be on the same server as the primary address. Cross-server migration is handled by key transitions (Section 2.8) — the user creates a new account on the new server with the same identity key.

---

## 3. System 2: Objects — "The core primitive"

### 3.1 Concept

Everything in Ark is an **object** — an encrypted piece of data stored on a server, with one or more **owners** who can decrypt it. Messages, notes, files, and folders are all objects. The difference is in the ownership pattern, not the data model.

| What the user sees | What it is |
|---|---|
| Note to self | Object, one owner (self, full permission) |
| File in personal storage | Object, one owner (self, full permission) |
| Sent message | Object, two owners (self=full, recipient=read) |
| Received message | Copy of sender's object, stored on recipient's server |
| Shared document | Object, multiple owners (all full permission) |
| Shared file (view-only) | Object, multiple owners (owner=full, others=read) |
| Folder | Object whose children reference it via `parent_id` |

### 3.2 Object structure

An object consists of:

- **Metadata** — object ID, type, timestamps, parent reference. Stored in plaintext on the server (needed for indexing and sync).
- **Owner list** — who can access this object, with what permission. Each owner entry contains the symmetric object key encrypted to that owner's identity key.
- **Ciphertext** — the actual content, encrypted with the symmetric object key.
- **Signature** — proof of who last modified the object.

See Section 8.1 for the full wire format.

### 3.3 Object types

The `object_type` field is a string that tells clients how to present the object. The protocol does not enforce type-specific behavior — types are a client concern. Common types:

| Type | Typical usage |
|---|---|
| `message` | A message sent to another user |
| `note` | A personal note |
| `file` | A stored file (document, image, etc.) |
| `folder` | A container for organizing other objects |

Clients can define additional types. Unknown types are treated as opaque encrypted blobs.

### 3.4 Ownership

Each object has one or more owners. Every owner holds the object's symmetric key, encrypted to their identity key. This means any owner can decrypt the content.

**Owner permissions:**

| Permission | Can decrypt | Can modify | Can add/remove owners |
|---|---|---|---|
| `full` | Yes | Yes | Yes |
| `read` | Yes | No | No |

Permission enforcement is server-side — other owners' servers reject updates from `read` owners. It is not cryptographically enforced (a `read` owner has the object key and *could* create a modified copy locally, but other owners' servers won't accept it).

**Single owner (default):** Notes, personal files. One owner entry (self, full). Object key encrypted only to your identity key.

**Two owners (messaging):** Sender creates object with two owners — self (full) and recipient (read). Content is encrypted once with the object key. The object key is wrapped separately for each owner. Sender stores the object on their server; a copy is delivered to the recipient's server via an envelope (Section 7).

**Multiple owners (collaboration):** Shared documents, team folders. All owners at `full` permission can read and modify. See Section 3.7 for sync.

### 3.5 Hierarchy

Objects can reference a parent via `parent_id`, forming a tree. Root objects have no parent.

- A folder is an object of type `folder` whose content may include display metadata (name, color, sort order).
- Child objects point to the folder's `object_id` as their `parent_id`.
- Clients render hierarchy however they want — tree view, flat list, breadcrumbs.

Hierarchy is per-owner. When Alice shares an object with Bob, Bob can place it in any folder in his own hierarchy by setting `parent_id` on his local copy.

### 3.6 Large objects (blob storage)

**Small objects (< 1 MB):** Content stored directly in the object's ciphertext field.

**Large objects (>= 1 MB):**
1. The content is encrypted with the object key (same symmetric encryption as any object).
2. The encrypted blob is stored on the owner's server at a unique URL.
3. The object's ciphertext contains metadata only:
   - The URL of the encrypted blob.
   - The SHA-256 hash of the encrypted blob (for integrity verification).
   - Filename, content type, and size.
4. Clients fetch the blob, verify the hash, and decrypt with the object key.

**Blob cleanup:** Encrypted blobs are deleted when the object is deleted, or after a configurable retention period for objects received from others (default: 30 days).

### 3.7 Multi-owner sync

When an object has multiple owners with `full` permission, edits need to propagate.

**Last-write-wins.** The `modified` timestamp is the tiebreaker. No merge, no conflict resolution in v1. When Alice updates a shared object:

1. Alice edits the content, re-encrypts with the object key, bumps `modified`, signs with her device key.
2. Alice's server stores the updated object.
3. Alice's server sends an `OBJECT_UPDATED` notification to each co-owner's server (lightweight envelope, no PoW — see Section 7.3).
4. Co-owners' servers (or clients) fetch the updated object from Alice's server.
5. If a co-owner also made an edit concurrently, the higher `modified` timestamp wins. The losing edit is discarded (or preserved in the history chain if versioning is enabled).

**Fetching from another owner's server:**

```
GET https://alice-server.com/.well-known/ark/objects/{object_id}
Authorization: ArkUser <device_id>:<signature>
```

The server verifies the requester is in the object's owner list (by checking identity key) before serving the object.

**Polling fallback:** If a notification is missed (server was down), clients can poll. `GET /api/v1/objects/{id}/modified` returns just the timestamp and modifier — lightweight check.

### 3.8 Adding and removing owners

**Adding an owner:**

1. An existing owner (with `full` permission) decrypts the object key.
2. Encrypts the object key to the new owner's identity key (fetched via key discovery, Section 2.5).
3. Adds a new `Owner` entry to the object.
4. Signs the updated object and syncs to other owners.

**Removing an owner:**

1. An existing owner (with `full` permission) removes the `Owner` entry.
2. Remaining owners generate a **new object key** (the removed owner knew the old one).
3. Re-encrypt the content with the new key.
4. Re-wrap the new key for each remaining owner.
5. The removed owner still has their old copy (can't prevent this — they had the key). But new edits use the new key they don't have.

### 3.9 Versioning

Versioning is optional, per-object. When enabled, the object always represents the **current version**. History is stored in a separate **history chain** object, referenced by the main object.

**How it works:**

1. Object has `versioned = true` and `history_id` pointing to a history chain object.
2. When the object is updated, the current content is prepended to the history chain (newest first).
3. The object body is replaced with the new content.
4. The history chain is itself an object — same encryption, same storage, same sync.

**History chain structure:**

The history chain is an object whose decrypted content is a list of `HistoryEntry` records in reverse chronological order:

```
[
  { modified, modified_by, nonce, ciphertext (previous version, encrypted with object key) },
  { modified, modified_by, nonce, ciphertext (version before that) },
  ...
]
```

See Section 8.3 for the wire format.

**Storage:** History counts toward `max_account_size`. Owners can configure max history depth per-object. Pruning removes the oldest entries.

**When versioning is off (default):** No history chain. Updates overwrite. Simpler, lighter. Good for messages, most files.

**When versioning is on:** Full edit history. Good for notes, collaborative documents, important files. Clients that don't care about history never need to fetch the history chain — the main object always has the current version.

---

## 4. System 3: Encryption — "Nobody else can read this"

### 4.1 Concept

Every object is encrypted with a **symmetric object key** (AES-256-GCM). The object key is then wrapped (encrypted) to each owner's identity key using ECIES. This two-layer approach means:

- Content is encrypted once, regardless of how many owners there are.
- Adding an owner only requires wrapping the existing object key — no re-encryption of content.
- Removing an owner requires generating a new object key and re-encrypting content (since the removed owner knew the old key).

### 4.2 Object key generation

When an object is created:

1. The client generates a random 256-bit **object key**.
2. The client encrypts the object content with the object key:
   ```
   nonce = random 12 bytes
   ciphertext, tag = AES-256-GCM(object_key, nonce, payload)
   ```
3. For each owner, the client wraps the object key using **ECIES**:
   ```
   ephemeral_key = random X25519 keypair
   shared_secret = X25519(ephemeral_private, owner_encryption_key)
   wrapping_key = HKDF-SHA256(
     ikm: shared_secret,
     salt: ephemeral_public || owner_encryption_key,
     info: "object-key-wrap",
     length: 32
   )
   wrapped_object_key = AES-256-GCM(wrapping_key, random_nonce, object_key)
   ```
4. Each owner entry stores the `ephemeral_public`, `nonce`, and `wrapped_object_key`.

### 4.3 Decryption

When Alice decrypts an object:

1. Alice finds her owner entry (matched by identity key).
2. Alice computes the shared secret using her private key and the ephemeral public key in her owner entry:
   ```
   shared_secret = X25519(alice_private, ephemeral_public)
   ```
3. Alice derives the wrapping key via HKDF (same parameters as encryption).
4. Alice decrypts the wrapped object key.
5. Alice decrypts the object content with the object key.

### 4.4 Why a symmetric object key?

Direct ECIES encryption (as in v0.3) encrypts content directly to each recipient's public key. This works for one-to-one messages but breaks down for shared objects:

- **N owners would require N copies of the ciphertext** (each encrypted to a different key). A 100MB file shared with 5 people would require 500MB of storage.
- **Adding an owner requires re-encrypting the entire content.** With a symmetric object key, adding an owner only wraps the 32-byte key — instant, regardless of content size.

The symmetric key approach encrypts content once and wraps the small key per-owner. Standard construction, used by Signal (group messages), PGP (session keys), and every major encrypted storage system.

### 4.5 Multi-device decryption

Since there's a single identity keypair per user, multi-device is straightforward:

- **Mode B (server-managed key):** All devices get the private key from the server. Any device can unwrap any object key.
- **Mode A (client-managed key):** All devices derive the same private key from the seed phrase. Same result.

Object keys are wrapped to the **identity key**, not per-device. One wrap per owner, regardless of how many devices that owner has.

### 4.6 Encryption algorithms

| Operation | Algorithm | Parameters |
|---|---|---|
| Identity keys (signing) | Ed25519 | — |
| Encryption key exchange | X25519 | — |
| Key derivation | HKDF-SHA256 | — |
| Object key wrapping | AES-256-GCM | 96-bit nonce, 128-bit tag |
| Object content encryption | AES-256-GCM | 96-bit nonce, 128-bit tag |
| Alternative content encryption | ChaCha20-Poly1305 | 96-bit nonce, 128-bit tag |
| Proof of work | Argon2id | configurable |

Clients MUST support AES-256-GCM. ChaCha20-Poly1305 is recommended as an alternative (faster on devices without AES hardware acceleration). The algorithm used is indicated in the object metadata.

### 4.7 Why not PGP?

PGP/GPG uses a similar model (session keys wrapped with public keys) but has well-known usability problems:
- Key management is manual and error-prone (keyrings, keyservers, web of trust).
- The PGP message format is complex and has accumulated decades of legacy.
- No standard for key discovery (keyservers are unreliable and have privacy issues).

This protocol uses the same fundamental cryptographic approach but with:
- Automatic key discovery via the identity document.
- A simple, modern wire format (Protocol Buffers).
- Built-in server infrastructure for key hosting and object storage.

---

## 5. System 4: Authentication — "This really came from Alice"

### 5.1 Concept

Every object modification is digitally signed by the author's device key. When objects are delivered cross-server, the envelope is signed so the receiving server can verify authenticity without decrypting the content. Identity forgery is mathematically impossible without the sender's private key.

### 5.2 Object signature

When Alice creates or modifies an object:

1. Alice computes an Ed25519 signature over the object's plaintext metadata and ciphertext:
   ```
   signature = Ed25519_Sign(
     device_private_key,
     object_id || version || modified || modified_by ||
     parent_id || owners_hash || ciphertext_hash
   )
   ```
2. The signature and `modifier_device_id` are included in the object.
3. Any server or client can verify by fetching Alice's identity document and checking the device key.

### 5.3 Envelope signature

When objects are delivered cross-server via an envelope:

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
6. If verification fails: the message is rejected with a `403 Invalid Signature` response.

**Cache policy for identity documents:**
- Servers cache fetched identity documents for a configurable period (default: 1 hour).
- If a signature fails to verify, the server re-fetches the identity document (the device key may have been added recently) and retries verification once.

### 5.4 Server-level authentication

Servers also authenticate themselves:

1. Each server has its own Ed25519 keypair, published at:
   ```
   GET https://example.com/.well-known/ark/server-identity
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

This is defense-in-depth. Even without it, the per-object signature from the author's device key provides authentication. Server-level auth adds:
- Protection against rogue servers forwarding envelopes they didn't originate.
- Rate limiting and abuse tracking at the server level.

### 5.5 Non-repudiation

The Ed25519 signature provides **non-repudiation**: Alice can prove to a third party that Bob authored a specific object. This is a deliberate design choice — you *want* proof of who sent what (contracts, agreements, records).

---

## 6. System 5: Spam Resistance — "Sending costs effort"

Spam resistance applies to **cross-server delivery** — when an envelope is sent from one server to another. Local operations (creating objects on your own server, editing your own data) never require proof of work.

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
GET https://example.com/.well-known/ark/policy
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

PoW difficulty increases with envelope size. This prevents storage-filling attacks where an attacker sends many large objects to exhaust a recipient's storage.

The effective difficulty is:

```
effective_difficulty = base_difficulty + min(floor(log2(envelope_size_kb)), size_difficulty_cap)
```

Where `base_difficulty` is the applicable difficulty from Section 6.3 (default, first-contact, or known-contact) and `size_difficulty_cap` limits how much the size penalty can add (default: 4 bits).

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

Combined with `max_account_size` (server config, default 1GB) and `max_envelope_size` (server config, default 25MB), this creates layered storage protection:
- `max_envelope_size` rejects oversized envelopes outright.
- Size-scaled PoW makes large deliveries more expensive to send in bulk.
- `max_account_size` is the hard ceiling — once full, the server returns `507 Insufficient Storage`.

### 6.5 Layer 2: Registration

Some users — newsletters, services, notification systems — need to send to many recipients without paying per-envelope PoW. The **registration** mechanism solves this: the *recipient* initiates contact by sending a lightweight registration envelope to the sender, paying PoW once. After registration, the sender can deliver to that recipient at `known_contact_difficulty` (typically 0).

**How it works:**

1. Alice wants to receive updates from `newsletter@example.com`.
2. Alice's client fetches the identity document for `newsletter@example.com` and checks that `accept_registrations` is `true` (see Section 6.5.2).
3. Alice's client sends a `REGISTER` envelope to `newsletter@example.com`:
   - The envelope has `type: REGISTER` and no object payload.
   - Alice computes PoW at the `registration_difficulty` published by `newsletter@example.com`'s server.
   - The envelope is signed by Alice's device key (proving Alice authorized this registration).
4. The newsletter's server verifies the PoW and signature, then adds Alice's identity key to the newsletter's contacts allowlist.
5. The newsletter can now deliver to Alice at `known_contact_difficulty` (typically 0).

**Unregistration:**

Alice can send an `UNREGISTER` envelope (same format, `type: UNREGISTER`, no PoW required — only the signature is needed to prove identity). The sender's server removes Alice from the allowlist.

Alice's client also removes the sender from her own allowlist, so future deliveries from the sender revert to default PoW requirements on her server.

**Why the recipient pays PoW (not the sender):**

- Legitimate bulk senders would be crushed by per-envelope PoW at scale. A newsletter with 100,000 subscribers sending weekly would need ~100,000 PoW computations per send — impractical.
- The subscriber pays once (~2–8 seconds). The sender benefits permanently (or until unregistration).
- Spam is impossible: no one registers to receive spam.
- Unlike traditional email subscription bombing, an attacker cannot register *someone else* — the registration envelope is signed by the registrant's identity key.

**Registration difficulty:**

The receiving server publishes `registration_difficulty` in its policy (see Section 6.3). Default: same as `first_contact_difficulty` (22 bits). Servers that accept registrations can set this independently.

#### 6.5.1 Per-user PoW overrides

Individual users can override the server's default PoW settings in their identity document. This allows a newsletter account on a shared server to accept registrations while personal accounts on the same server do not.

The identity document includes an optional `policy` field:

```json
{
  "version": 1,
  "address": "newsletter@example.com",
  "identity_key": "...",
  "encryption_key": "...",
  "policy": {
    "accept_registrations": true,
    "default_difficulty": 20,
    "first_contact_difficulty": 24,
    "known_contact_difficulty": 0,
    "registration_difficulty": 20
  },
  "devices": [ ... ],
  "updated": "2026-04-14T12:00:00Z",
  "signature": "..."
}
```

**Rules:**

- Per-user `policy` is optional. If absent, the server's policy applies.
- Per-user difficulty values can only be **equal to or higher** than the server's defaults — a user cannot lower PoW requirements below what the server enforces. The server validates this constraint when the identity document is updated.
- `accept_registrations` defaults to `false`. Only users who explicitly enable it will accept registration envelopes.
- The `policy` field is included in the self-signature, so it cannot be tampered with by the server (Mode A users).

**Resolution order** (when an envelope arrives for a user):

1. Check user's identity document for `policy` overrides.
2. Fall back to server-wide policy from `/.well-known/ark/policy`.
3. Apply size-scaled difficulty on top (Section 6.4).

**Use cases:**

| User type | `accept_registrations` | `first_contact_difficulty` | Notes |
|---|---|---|---|
| Personal account | `false` (default) | Server default (22) | Normal behavior. |
| Newsletter / service | `true` | Higher (24+) | Accepts registrations, discourages cold contact. |
| Public figure | `false` | Higher (26+) | No registrations, very high bar for cold contact. |
| Private account | `false` | Higher (28+) | Effectively unreachable unless allowlisted. |

#### 6.5.2 Sender discovery of registration support

Before sending a registration envelope, the client checks the recipient's identity document for `"accept_registrations": true`. If the field is absent or `false`, the client should not send a registration envelope — the recipient's server will reject it with `403 Forbidden`.

This means registration support is discoverable: a client can display "Subscribe" or "Register" UI when viewing a user whose identity document advertises registration support.

### 6.6 Layer 3: Contacts allowlist

Once Alice replies to Bob, Bob's identity key is added to Alice's **cryptographic contact list** on her server. Future deliveries from Bob require zero (or minimal) proof of work.

This is automatic and transparent:
- Alice replies to Bob → Bob is allowlisted.
- Alice registers with Bob (Section 6.5) → mutual allowlisting.
- Alice adds Bob manually (e.g., "add contact") → Bob is allowlisted.
- Alice removes Bob → Bob is de-listed, reverts to default PoW requirement.

The allowlist is stored server-side (it needs to be checked before accepting incoming envelopes) and is keyed by the sender's **identity public key**, not their address. This means:
- Bob can change servers (bob@old.com → bob@new.com) and remain allowlisted as long as he keeps the same identity key.
- Someone who registers bob@attacker.com with a different key is NOT allowlisted.

### 6.7 Layer 4: Account creation PoW

Account creation also requires proof of work. This prevents mass creation of throwaway accounts to circumvent per-sender PoW.

When a new account is created (either by a local user or by a remote server requesting a legacy email account — see Section 10.2), the request must include a PoW stamp at the `account_creation_difficulty` level published in the server's policy.

The account creation PoW is typically higher than the envelope PoW (default: 24 bits vs. 20 bits for envelopes), since accounts are created rarely but deliveries happen frequently.

```
POST https://example.com/.well-known/ark/accounts
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

This approach eliminates the need for API keys, registration tokens (for remote account creation), or rate limiting infrastructure. Any server can create an account on any other server by doing the work. No coordination, no pre-registration, no credentials — just computation.

Servers can disable remote account creation entirely:

```toml
allow_remote_registration = false  # Only admin can create accounts (default: true)
```

When disabled, the `POST /.well-known/ark/accounts` endpoint returns `403 Forbidden`. This is appropriate for personal servers or organization-only servers where the admin controls who gets an account.

Note: Local account creation (via the admin CLI) always works regardless of this setting, since the admin already controls the server.

### 6.8 Layer 5: Social trust signals (optional)

**Introduction field:**
- The envelope can include an optional plaintext `introduction` field (max 280 characters) visible to the receiving server (but not E2E encrypted).
- Servers can filter or flag deliveries based on this field.
- Use case: "Hi, I'm Bob from Acme Corp, we met at the conference."

**Cross-signing vouches:**
- Alice can sign a statement: "I vouch for `bob@example.com` (identity key: `...`)".
- Bob can attach this vouch to his envelopes to Alice's contacts.
- Carol's server, upon seeing a vouch from Alice (whom Carol trusts), reduces PoW requirements for Bob.
- This creates a lightweight web-of-trust for spam resistance without requiring a centralized reputation system.

### 6.9 Why this eliminates IP reputation

Email deliverability depends on IP reputation — a new server's emails go to spam for months until it "warms up." This protocol has **no concept of IP reputation:**

| Email problem | How this protocol solves it |
|---|---|
| Unknown IP → spam folder | Identity is cryptographic, not IP-based. A brand-new server with a fresh IP delivers just as well as an established one. |
| IP blocklists | No blocklists needed. PoW + signatures prevent abuse. |
| Shared IP risk (cloud hosting) | IP doesn't matter. Your cryptographic identity is unique. |
| SPF/DKIM/DMARC complexity | None of these exist. Authentication is per-object signatures. |

---

## 7. System 6: Transport — "How data moves"

### 7.1 Concept

All communication happens over **HTTPS**. No custom protocols, no special ports, no complex infrastructure. A server is a single binary with a single config file.

Transport serves two purposes:
1. **Cross-server delivery** — sending objects to other users via envelopes.
2. **Cross-server sync** — keeping shared objects in sync between co-owners' servers.

### 7.2 Cross-server delivery

When Bob sends a message (object) to Alice:

**Step 1: Store locally.** Bob's client creates the object on Bob's server (Bob is an owner with `full` permission).

**Step 2: Deliver via envelope.** Bob's server wraps the object in an envelope and delivers it to Alice's server:

```
POST https://example.com/.well-known/ark/inbox/alice
Content-Type: application/x-ark-envelope
Authorization: ArkServer sender.example.com <server-signature>
Content-Length: 4096

<binary envelope>
```

The envelope contains the object data plus Alice's owner entry (her wrapped object key), the PoW stamp, and the sender's signature. Alice's server extracts the object and stores it. Alice now has a local copy she can decrypt.

**Response codes:**

| Code | Meaning |
|---|---|
| `202 Accepted` | Envelope accepted, object stored. |
| `400 Bad Request` | Malformed envelope. |
| `403 Forbidden` | Signature verification failed. |
| `404 Not Found` | Recipient does not exist on this server. |
| `422 Unprocessable` | PoW verification failed or difficulty too low. |
| `429 Too Many Requests` | Rate limited. Includes `Retry-After` header. |
| `507 Insufficient Storage` | Recipient's storage is full. |

**Delivery retries:**
- If delivery fails (server down, network error), the sending server retries with exponential backoff (1 min, 5 min, 30 min, 2 hours, 8 hours) for up to 72 hours, then returns a bounce notification to the sender.

### 7.3 Cross-server sync (shared objects)

When a shared object is updated, co-owners' servers are notified.

**Update notification:**

```
POST https://example.com/.well-known/ark/notify/alice
Content-Type: application/x-ark-envelope
Authorization: ArkServer sender.example.com <server-signature>

<binary envelope with type OBJECT_UPDATED>
```

The notification envelope contains:
- `object_id` — which object changed.
- `modified` — new timestamp.
- `modified_by` — who made the change.
- Signature from the modifier (proving they're an owner).

**No PoW required** for sync notifications between co-owners. The co-ownership relationship is already established — the receiving server verifies the modifier is in the object's owner list.

**Fetching the updated object:**

After receiving a notification, the co-owner's server (or client) fetches the updated object:

```
GET https://bob-server.com/.well-known/ark/objects/{object_id}
Authorization: ArkUser <device_id>:<signature>
```

The serving server verifies the requester's identity key is in the object's owner list before responding.

**Owner moved notification:**

When an owner migrates to a new server (Section 2.10), they send an `OWNER_MOVED` envelope to co-owners:

```
Envelope type: OWNER_MOVED
Payload: { old_address, new_address, identity_key, signature }
```

Co-owners' servers update the owner address in shared objects. Identity key stays the same, so trust is preserved.

### 7.4 Federation endpoints

```
GET https://example.com/.well-known/ark/identity/<user>
Accept: application/json

→ 200 OK
Content-Type: application/json
Cache-Control: max-age=3600

{ ... identity document ... }
```

```
GET https://example.com/.well-known/ark/server-identity
Accept: application/json

→ 200 OK
{ ... server identity document ... }
```

```
GET https://example.com/.well-known/ark/policy
Accept: application/json

→ 200 OK
{ ... policy document ... }
```

```
GET https://example.com/.well-known/ark/objects/<object_id>
Authorization: ArkUser <device_id>:<signature>

→ 200 OK
Content-Type: application/x-ark-object

<binary object>
```

### 7.5 Client-to-server API

Alice's client communicates with her home server over HTTPS.

**Authentication:** Every request is signed with the device's Ed25519 key:
```
Authorization: ArkUser <device_id>:<signature-over-method-path-timestamp-body>
X-Ark-Timestamp: 1712838400
```
The server verifies the signature against the device key registered in Alice's identity document. Requests with timestamps older than 5 minutes are rejected (replay protection).

**Endpoints:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/objects` | List objects. Query params: `type`, `parent_id`, `owner` (self/others/all), `since` (timestamp), `limit` (default 50). |
| `GET` | `/api/v1/objects/{id}` | Fetch a single object by ID. |
| `POST` | `/api/v1/objects` | Create an object. |
| `PUT` | `/api/v1/objects/{id}` | Update an object (new version). |
| `DELETE` | `/api/v1/objects/{id}` | Delete an object from server storage. |
| `GET` | `/api/v1/objects/{id}/modified` | Lightweight check — returns only `modified` timestamp and `modified_by`. |
| `POST` | `/api/v1/objects/{id}/owners` | Add an owner to an object. |
| `DELETE` | `/api/v1/objects/{id}/owners/{key}` | Remove an owner from an object. |
| `POST` | `/api/v1/send` | Submit an envelope for cross-server delivery. Body is a binary envelope. |
| `GET` | `/api/v1/contacts` | List contacts (allowlisted identity keys). |
| `POST` | `/api/v1/contacts` | Add a contact. |
| `DELETE` | `/api/v1/contacts/{id}` | Remove a contact. |
| `GET` | `/api/v1/stream` | WebSocket or SSE stream for real-time push notifications. |

**Object list response:**

```json
{
  "objects": [
    {
      "id": "uuid",
      "object_type": "message",
      "created": "2026-04-11T12:00:00Z",
      "modified": "2026-04-11T12:00:00Z",
      "modified_by": "bob@example.com",
      "parent_id": null,
      "size": 4096
    }
  ],
  "has_more": false
}
```

Object content (ciphertext, owner entries) is returned only on individual fetch (`GET /api/v1/objects/{id}`). The list endpoint returns metadata only for efficiency.

**Real-time stream events:**

```json
{"event": "object_created", "object_id": "...", "object_type": "message", "from": "bob@example.com"}
{"event": "object_updated", "object_id": "...", "modified": 1712838400, "modified_by": "bob@example.com"}
{"event": "object_deleted", "object_id": "..."}
{"event": "owner_added", "object_id": "...", "new_owner": "carol@example.com"}
{"event": "owner_removed", "object_id": "...", "removed_owner": "carol@example.com"}
```

### 7.6 Server architecture

A server is a **single statically-linked binary** containing:

```
┌─────────────────────────────────────────┐
│              ark-server                │
├─────────────────────────────────────────┤
│  HTTPS Server                           │
│  ├── Well-known endpoints (federation)  │
│  ├── Client API (/api/v1/*)             │
│  └── WebSocket/SSE (push notifications) │
├─────────────────────────────────────────┤
│  Object Store (SQLite)                  │
│  ├── Objects (per-user, encrypted)      │
│  ├── Blob store (large encrypted data)  │
│  └── Contact lists                      │
├─────────────────────────────────────────┤
│  Outbound Relay                         │
│  ├── Queue for outgoing envelopes       │
│  ├── Retry logic (exponential backoff)  │
│  └── Remote identity document cache     │
├─────────────────────────────────────────┤
│  Sync Engine                            │
│  ├── Notify co-owners on object update  │
│  ├── Fetch updates from co-owners       │
│  └── Conflict resolution (last-write)   │
├─────────────────────────────────────────┤
│  TLS (ACME / Let's Encrypt)             │
│  └── Auto-provision and renewal         │
├─────────────────────────────────────────┤
│  Admin CLI                              │
│  ├── user add/remove/list               │
│  ├── stats / diagnostics                │
│  └── config reload                      │
└─────────────────────────────────────────┘
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
# max_envelope_size = "25MB"
# max_object_size = "100MB"
# blob_retention = "30d"
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
- SQLite by default (embedded, zero-configuration, handles thousands of users easily).
- Optional PostgreSQL support for large deployments.
- Blob storage (large encrypted objects) as files on disk, organized by hash.

### 7.7 Deployment: co-hosting with a website

The protocol only uses paths under `/.well-known/ark/` and `/api/v1/`. It coexists with a website on the same domain.

**Reverse proxy setup (recommended):**

```nginx
# nginx example
server {
    listen 443 ssl;
    server_name example.com;

    # Protocol server
    location /.well-known/ark/ {
        proxy_pass http://127.0.0.1:8080;
    }
    location /api/v1/ {
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

The protocol server runs on a local port (e.g., 8080) without TLS — the reverse proxy handles TLS termination. In this setup, disable the protocol server's built-in ACME:

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
| Co-hosting with website | Separate IP or complex port routing | Shares port 443 behind reverse proxy |

---

## 8. Wire Formats

### 8.1 Object

Objects are serialized using Protocol Buffers (compact binary encoding with schema evolution support).

```protobuf
syntax = "proto3";

message Object {
  bytes object_id = 1;                   // 16 bytes, random UUID
  string object_type = 2;               // "message", "note", "file", "folder", etc.
  bytes parent_id = 3;                  // Optional, for hierarchy
  uint64 created = 4;                   // Unix milliseconds
  uint64 modified = 5;                  // Unix milliseconds

  // Ownership
  repeated Owner owners = 6;

  // Encrypted content
  bytes nonce = 7;                      // AES-256-GCM nonce (12 bytes)
  string algorithm = 8;                 // "aes-256-gcm" or "chacha20-poly1305"
  bytes ciphertext = 9;                 // Content encrypted with object key

  // Versioning (optional)
  bool versioned = 10;
  bytes history_id = 11;               // object_id of the history chain (if versioned)

  // Author of last modification
  string modified_by = 12;             // "alice@example.com"
  uint32 modifier_device_id = 13;
  bytes signature = 14;                // Ed25519 signature over fields 1-12
}

message Owner {
  string address = 1;                   // "alice@example.com"
  bytes identity_key = 2;              // Owner's Ed25519 public key (for verification)
  string permission = 3;               // "full" or "read"

  // Object key wrapped for this owner (ECIES)
  bytes ephemeral_key = 4;            // X25519 ephemeral public key (32 bytes)
  bytes key_nonce = 5;                // AES-256-GCM nonce for key wrapping (12 bytes)
  bytes wrapped_object_key = 6;       // Object key encrypted to this owner (32 bytes + 16 byte tag)
}
```

### 8.2 Object payload

The payload is serialized with Protocol Buffers, then encrypted with the object key. The receiving client decrypts and deserializes.

```protobuf
message ObjectPayload {
  string content_type = 1;             // MIME type: "text/markdown", "text/plain", etc.
  bytes body = 2;                      // The content

  repeated Attachment attachments = 3;

  map<string, string> metadata = 4;    // Arbitrary key-value pairs (title, tags, etc.)

  uint32 flags = 5;                    // Bitfield: 0x01 = read receipt requested
}

message Attachment {
  string filename = 1;
  string content_type = 2;             // MIME type
  uint64 size = 3;                     // Size in bytes

  // Inline (small attachments, < 1 MB)
  bytes data = 4;

  // External (large attachments, stored as blobs)
  string url = 5;                      // URL of encrypted blob
  bytes sha256 = 6;                    // Hash of the encrypted blob
}
```

### 8.3 History chain

The history chain is stored as an object (same encryption, same ownership). Its decrypted payload is a list of history entries.

```protobuf
message HistoryChainPayload {
  repeated HistoryEntry entries = 1;   // Newest first (reverse chronological)
}

message HistoryEntry {
  uint64 modified = 1;                // When this version was current
  string modified_by = 2;             // Who created this version
  bytes nonce = 3;                    // AES-256-GCM nonce
  bytes ciphertext = 4;              // Previous ObjectPayload, encrypted with same object key
}
```

### 8.4 Envelope

The envelope is the transport wrapper for cross-server delivery. It wraps an object (or a notification) for delivery to another server.

```protobuf
enum EnvelopeType {
  DELIVER = 0;                         // Deliver an object to a recipient
  REGISTER = 1;                        // Registration request (Section 6.5)
  UNREGISTER = 2;                      // Unregistration request (Section 6.5)
  OBJECT_UPDATED = 3;                  // Notify co-owner of object update
  OWNER_MOVED = 4;                     // Notify co-owners of address change
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
  // DELIVER: the full Object being delivered
  // OBJECT_UPDATED: ObjectUpdateNotification
  // OWNER_MOVED: OwnerMovedNotification
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

message ObjectUpdateNotification {
  bytes object_id = 1;
  uint64 modified = 2;
  string modified_by = 3;
  bytes signature = 4;               // Modifier's signature (proves ownership)
}

message OwnerMovedNotification {
  string old_address = 1;
  string new_address = 2;
  bytes identity_key = 3;
  bytes signature = 4;               // Signed by the identity key
}
```

### 8.5 Identity document

Identity documents are JSON (human-readable, served over HTTP). See Section 2.4 for the full schema.

### 8.6 Serialization rules

- **Objects, envelopes, payloads:** Protocol Buffers (binary). Compact, efficient, schema-evolvable.
- **Identity documents, policy, server identity:** JSON. Human-readable, easy to debug with curl.
- **Signatures:** computed over the canonical protobuf serialization (deterministic encoding).
- **All binary values in JSON:** base64url encoding (RFC 4648, no padding).

---

## 9. Threat Model

### 9.1 What is protected

| Property | Guarantee |
|---|---|
| **Data confidentiality** | Only holders of the object key can read object content. Servers see only ciphertext (Mode A). |
| **Author authentication** | Objects and envelopes are signed by the author's device key. Forgery requires the private key. |
| **Integrity** | Any modification to an object invalidates the signature. Any modification to the ciphertext invalidates the AEAD tag. |
| **Spam resistance** | Bulk cross-server delivery requires proportional computational resources (PoW). |
| **Data persistence** | All objects can be decrypted with the single identity key (which unwraps object keys). No session state to lose. No data becomes unrecoverable due to key rotation. |

### 9.2 What is NOT protected

| Risk | Details |
|---|---|
| **Metadata** | Object type, size, timestamps, owner addresses, and cross-server delivery patterns are visible to servers and network observers. Same as email for messages; same as any cloud provider for stored data. |
| **Forward secrecy** | If the identity private key is compromised, all object keys can be unwrapped, and all past and future data can be decrypted. This is a deliberate tradeoff for simplicity and recoverability. See Section 10.1 for the forward secrecy extension. |
| **Mode B server trust** | If the server holds the private key (Mode B), the server can read all data. The user is trusting the server, like they trust Gmail or Google Drive today. Self-hosters mitigate this by controlling the server. |
| **Removed owner's existing copy** | When an owner is removed from a shared object, they retain any copy they already downloaded. The re-keying prevents access to future edits, not past content. |

### 9.3 Compromise scenarios

**Scenario: Alice's server is compromised (Mode A — client-managed key)**
- Attacker can see metadata (object types, sizes, timestamps, who Alice shares with).
- Attacker **cannot** read object content (doesn't have Alice's private key to unwrap object keys).
- Attacker **cannot** forge objects from Alice (doesn't have her signing key).
- Attacker could serve a fake identity document with a different public key. Mitigations: (1) existing contacts have Alice's key pinned via TOFU, (2) verified contacts will see a safety number change warning.

**Scenario: Alice's server is compromised (Mode B — server-managed key)**
- Attacker gets Alice's private key from the server.
- Attacker **can** read all objects (past and future, until the key is rotated).
- Attacker **can** forge objects from Alice.
- This is the tradeoff of Mode B. Mitigation: use Mode A for high-security needs.

**Scenario: Alice's identity key is compromised (either mode)**
- Worst case. Attacker can impersonate Alice and decrypt all data.
- No forward secrecy — all objects encrypted to this key are compromised.
- Mitigation: Alice performs a key transition (Section 2.8). After transition, new objects use the new key and are safe.

**Scenario: Shared object key is compromised**
- Only the specific object is affected, not Alice's other data.
- Mitigation: re-key the object (generate new object key, re-encrypt content, re-wrap for all owners).

**Scenario: Server-to-server traffic is intercepted (TLS broken)**
- Attacker sees encrypted envelopes in transit. They can see metadata (routing info in the envelope is plaintext).
- Attacker **cannot** read object content (E2E encrypted independent of TLS).
- Attacker **cannot** forge envelopes (envelope signatures are verified).
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
- The tradeoff: messages encrypted with destroyed keys become unrecoverable. Users who want data persistence would stay on the default mode.

This would be negotiated per-conversation (both parties must support and enable it) and would coexist with the default object key mode.

### 10.2 Legacy Email Interop

An optional system for communicating with legacy email users. There are two methods, which can be used independently or together.

#### Method 1: Notification Link (outbound to email users)

When a protocol user sends a message to a legacy email address, instead of trying to deliver it as email, the server creates a temporary account for the recipient and sends them a notification email with a link to read the message.

**How it works:**

1. Bob sends a message to `carol@gmail.com` from the protocol.
2. Bob's server computes a deterministic alias from the email address:
   ```
   alias = "x-" + base32_lowercase(sha256("carol@gmail.com")[:10])
   → "x-a7f3k2m9p4q8r2"
   ```
3. Bob's server checks whether this alias already exists on the **gateway server** (see below).
4. If not, it requests account creation on the gateway (with account creation PoW):
   - The gateway creates a Mode B account (server-generated keypair).
   - The gateway publishes a legacy email identity document for the alias.
5. Bob's server encrypts the message to the new account's public key and delivers it.
6. The gateway sends a notification email to `carol@gmail.com`:
   ```
   Subject: Bob sent you a message
   
   Read it here: https://gateway.example.com/read/a8Kx7mP2...
   ```
   The URL contains a secret token (128-bit, base64url) that acts as Carol's credential.
7. Carol clicks the link. A web client loads. She reads the message and can reply.

**Legacy email identity document:**

```
GET https://gateway.example.com/.well-known/ark/identity/x-a7f3k2m9p4q8r2
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

The `type: legacy_email` and `notify: true` fields tell the server to send notification emails when objects are delivered to this account.

**Authentication for the web client:**

The link token is the credential by default — clicking the link logs Carol in. This is a deliberate convenience-over-security choice (the security is no worse than email itself — if someone can read Carol's email, they could already read anything sent to her).

Optionally, Carol can upgrade security:
- Add a passkey (WebAuthn) so she can access the account without needing a new link each time.
- Add a password for simpler devices.
- After upgrading, the `notify` flag can be changed to send notifications without tokens, since Carol can log in independently.

**Claiming the identity:**

When Carol decides she wants a real address:
1. Carol chooses a username (e.g., `carol`).
2. The gateway creates a new identity document at `carol@gateway.example.com` (same keypair).
3. The hash alias document is updated to a redirect:
   ```json
   {
     "version": 1,
     "type": "alias",
     "redirect": "carol@gateway.example.com"
   }
   ```
4. Anyone who previously sent to the hash address is seamlessly redirected to Carol's real address.
5. Carol can also migrate to her own server later using a key transition (Section 2.8).

**The gateway server:**

The gateway is a Ark server that specializes in hosting accounts for legacy email recipients and sending notification emails. It uses a transactional email API (SendGrid, Postmark, etc.) to send notifications — it does not run an SMTP server or manage email deliverability directly.

The reference implementation includes a config option for which gateway to use:

```toml
domain = "example.com"
storage = "./data"

# Where to create accounts for legacy email recipients.
# Defaults to the public gateway run by the protocol maintainers.
# Self-hosters can point this to their own server.
legacy_gateway = "gateway.ark.io"
```

- The default (`gateway.ark.io`) is a public gateway run by the protocol maintainers. It handles notification emails and hosts temporary accounts so that individual server operators don't need to set up email sending.
- Self-hosters can override this to use their own server as the gateway (requires configuring a transactional email provider for sending notifications).
- Any server can act as a gateway — it just needs the notification email capability.
- The gateway requires account creation PoW (Section 6.7), preventing abuse without API keys or registration.

**The gateway is also a natural onboarding point.** Carol, who received a message on the gateway, is already using the protocol via the web client. She might claim a real address, install a native client, or eventually migrate to her own server. The gateway acts as both infrastructure and front door for new users.

**What the gateway does NOT do:**
- Run an SMTP server for inbound email.
- Manage MX records, SPF, DKIM, or DMARC.
- Maintain IP reputation (the transactional email provider handles deliverability for the notification emails).

#### Method 2: Email Bridge (inbound from email users)

For protocol users who want to **receive** legacy email in their protocol inbox, a bridge service can forward incoming emails. This is a separate component from the notification link system.

**How it works:**
1. Alice configures a forwarding rule in her email provider: "forward all mail to `https://bridge.example.com/inbound/alice`" (webhook) or to a catch-all address handled by the bridge.
2. The bridge receives the forwarded email, parses it, wraps the content in a Ark object, and delivers it to Alice via a standard envelope.
3. The object is marked as "received via email (unencrypted)" in Alice's client.

**The bridge is much simpler than a full email system** because it only receives forwarded mail — it doesn't need MX records, spam filtering, or deliverability management. The user's existing email provider handles all of that.

**Outbound replies** to email senders can use the email provider's API (Gmail API, SMTP relay, etc.) or route through the notification link system described above.

**Security note:** Bridged inbound messages are not encrypted in transit (standard email has no encryption). The bridge sees plaintext during processing. These objects should be clearly distinguished from native protocol objects in the client UI.

### 10.3 Metadata Privacy

A future version could add onion routing or mixnet support to hide metadata (sender/recipient/timing) from servers and network observers. This is out of scope for v1 but the protocol's layered design (object vs. envelope) makes it possible to add without changing the core data format.

### 10.4 Collaborative Editing (CRDTs)

V1 uses last-write-wins for shared objects. A future extension could support real-time collaborative editing via CRDTs (Conflict-free Replicated Data Types):

- Object content would be an encrypted operation log instead of a snapshot.
- Each edit appends an encrypted CRDT operation (e.g., Yjs or Automerge format).
- Clients replay operations to reconstruct current state.
- Operations are encrypted with the shared object key, so any owner can read them.
- This would be opt-in per object (`collaborative: true`) and coexist with the default snapshot model.

---

## Appendix A: Cryptographic Algorithms Summary

| Purpose | Algorithm | Key Size | Output Size |
|---|---|---|---|
| Identity / signing | Ed25519 | 256-bit | 512-bit signature |
| Encryption key exchange | X25519 | 256-bit | 256-bit shared secret |
| Key derivation | HKDF-SHA256 | variable | variable |
| Object key wrapping | AES-256-GCM | 256-bit | ciphertext + 128-bit tag |
| Object content encryption | AES-256-GCM | 256-bit | ciphertext + 128-bit tag |
| Alt. content encryption | ChaCha20-Poly1305 | 256-bit | ciphertext + 128-bit tag |
| Proof of work | Argon2id | variable | 256-bit |
| Seed phrase | BIP-39 | 256-bit entropy | 24 words |

## Appendix B: Well-Known Endpoints Summary

All federation endpoints are under `https://<domain>/.well-known/ark/`.

| Path | Method | Purpose |
|---|---|---|
| `identity/<user>` | GET | Fetch user's identity document (or alias redirect) |
| `server-identity` | GET | Fetch server's identity document |
| `policy` | GET | Fetch spam policy (PoW difficulty) |
| `inbox/<user>` | POST | Deliver an envelope to a user |
| `notify/<user>` | POST | Send a sync notification to a user |
| `objects/<object_id>` | GET | Fetch a shared object (requires owner auth) |
| `accounts` | POST | Create a new account (requires PoW) |

Client API endpoints are under `https://<domain>/api/v1/`.

| Path | Method | Purpose |
|---|---|---|
| `objects` | GET | List objects |
| `objects/{id}` | GET | Fetch a single object |
| `objects` | POST | Create an object |
| `objects/{id}` | PUT | Update an object |
| `objects/{id}` | DELETE | Delete an object |
| `objects/{id}/modified` | GET | Lightweight modification check |
| `objects/{id}/owners` | POST | Add an owner |
| `objects/{id}/owners/{key}` | DELETE | Remove an owner |
| `send` | POST | Submit an envelope for cross-server delivery |
| `contacts` | GET | List contacts |
| `contacts` | POST | Add a contact |
| `contacts/{id}` | DELETE | Remove a contact |
| `stream` | GET | Real-time push (WebSocket/SSE) |
