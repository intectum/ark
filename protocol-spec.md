# Ark Protocol Specification

> **Status:** Draft v0.5
> **Date:** 2026-04-26

## Table of Contents

1. [Overview](#1-overview)
2. [System 1: Identity](#2-system-1-identity--who-are-you)
3. [System 2: Files](#3-system-2-files--the-core-primitive)
4. [System 3: Encryption](#4-system-3-encryption--nobody-else-can-read-this)
5. [System 4: Authentication](#5-system-4-authentication--this-really-came-from-alice)
6. [System 5: Delivery Control](#6-system-5-delivery-control--who-can-reach-you)
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
| **Delivery Control** | Only contacts can reach your inbox by default. No reputation systems needed. |
| **Transport** | How files move between servers. Plain HTTPS, trivially self-hostable. |

### Design principles

- **Cryptographic identity, not reputation-based.** Your identity is a keypair, not an IP address or domain reputation score. This eliminates the entire class of deliverability problems that plague self-hosted email.
- **Encrypted by default.** File content is end-to-end encrypted unless explicitly opted out. Servers store ciphertext they cannot read. Unencrypted files are supported for public content — the header still provides authentication and integrity via signatures.
- **Files on disk.** Storage is the filesystem. No database for user data. Files are accessed by path over HTTPS. Any tool that can read files can interact with Ark data.
- **One primitive.** Everything is a file with an unencrypted header and an encrypted body. Different membership patterns produce different behaviors, not different concepts.
- **Simple to self-host.** A single binary, a single config file, a domain with an A record. That's it.
- **Federated, not peer-to-peer.** Servers provide reliable offline storage and key hosting. Pure P2P systems (Bitmessage, Briar) struggle with reliability and adoption.
- **Spam-resistant by construction.** Only contacts can deliver to your inbox by default. Unforgeable identity means no one can impersonate a contact.
- **Simple key model.** One keypair per identity, like a crypto wallet. Lose the key, lose the identity. Have the key, have all your data.
- **Flexible trust model.** Users choose where their private key lives — on their device (maximum security) or on their server (maximum convenience). Self-hosters get both.
- **App-agnostic.** The protocol defines files, membership, and transport. How files are organized into directories is up to applications. A mail app, a notes app, and a file manager all operate on the same files — just arranged differently.


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
  "identity_key": {
    "algorithm": "ed25519",
    "public_key": "base64url-encoded"
  },
  "updated": "2026-04-11T12:00:00Z",
  "signature": {
    "algorithm": "ed25519",
    "signature": "base64url-encoded-over-everything-above"
  }
}
```

**Field details:**

| Field | Purpose |
|---|---|
| `version` | Protocol version. Currently `1`. |
| `address` | The user's full address. |
| `identity_key` | The root of trust for this user. Used for signing and encryption (via key conversion). Contains `algorithm` and `public_key`. |
| `signature` | Signature over the entire document (excluding this field). Proves the identity key holder authored this. Contains `algorithm` and `signature`. |

**The self-signature is the key security property** (for Mode A users). The server hosts this document but cannot tamper with it — any modification invalidates the signature. This means:
- A compromised server cannot swap in a different public key to intercept data.
- A MITM attacker who compromises the TLS connection cannot forge the identity document.
- The document is self-authenticating: anyone can verify it using only the public key it contains.

Note: For Mode B users (server holds the private key), the server *could* sign a different identity document. The user is already trusting the server with their private key, so this doesn't change the trust model.

### 2.5 Key discovery

When Bob wants to contact Alice for the first time:

1. Bob's client extracts the domain from `alice@example.com`.
2. Bob's client makes an HTTPS GET to `https://example.com/ark/alice/.ark/identity.json`.
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
- All devices can decrypt all files and sign operations (they all have the same identity keypair).

**Mode A (client-managed key):**
- Alice sets up her first device with the seed phrase.
- To add a second device, Alice enters the seed phrase on the new device (or transfers the private key via QR code / secure channel).
- All devices derive the same identity keypair.

### 2.7 Identity key transition

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

### 2.8 Account recovery

**Mode B (server-managed key):**
- The server holds the private key. Recovery is a standard password reset / admin intervention.
- Files are stored on the server and remain accessible.
- This is the simplest recovery story — works like email.

**Mode A (client-managed key):**
- Alice enters her 24-word seed phrase on a new device.
- The client derives the identity keypair from the seed.
- The client authenticates with Alice's server using the identity key.
- Files stored on the server (encrypted) can be decrypted because Alice has the same private key, which unwraps the file keys.

**What is lost if the seed phrase is lost (Mode A):**
- The identity key is gone. Alice must create a new account with a new keypair.
- All files encrypted to the old key are unrecoverable.
- Contacts will see a new key and need to re-verify.

**No DNS complexity:**
- The server just needs a domain name pointing to it (A/AAAA record). That's it.
- No MX records, no SPF, no DKIM, no DMARC. Identity is cryptographic, not DNS-based.

### 2.9 Server migration

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

### 2.10 Aliases

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
- **Generated aliases.** Machine-generated aliases for special purposes.

**Cross-server aliases** are not supported in v1. An alias must be on the same server as the primary address. Cross-server migration is handled by key transitions (Section 2.7).

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
| `/ark/.ark/accounts` | Account creation endpoint (POST) |
| `/ark/<user>/.ark/identity` | HTML contact card / `.json` for identity document |
| `/ark/<user>/.ark/inbox/` | Cross-server delivery landing zone |
| `/ark/<user>/.ark/files/<file_id>` | File lookup by ID (sync recovery) |
| `/ark/<user>/.ark/contacts.json` | Contacts allowlist |
| `/ark/<user>/.ark/contact-invites/` | Contact invite tokens (HTML) / POST to create |
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

```
Member {
  address: "alice@example.com"
  identity_key_algorithm: "ed25519"
  identity_key: ...
  permission: "owner"
  ephemeral_key_algorithm: "x25519"
  ephemeral_key: ...
  wrapped_file_key: ...
}
```

**Single member (default):** Notes, personal files. One member entry (self, owner).

**Two members (messaging):** Sender creates file with two members — self (owner) and recipient (read). A copy is delivered to the recipient's `.ark/inbox/` via an envelope (Section 7). The recipient's app can move it to any path.

**Multiple members (collaboration):** Shared documents. All members at `write` or `owner` permission can read and modify. See Section 3.6 for sync.


### 3.5 Directory listings

A GET request to a directory path returns a listing of entries with their headers. The server knows whether a path is a file or a directory — no trailing slash needed:

```
GET https://example.com/ark/alice/notes
Authorization: ArkUser <signature>
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


### 3.6 Multi-member sync

When a file has multiple members with `write` or `owner` permission, edits need to propagate.

**Last-write-wins.** The `modified` timestamp is the tiebreaker. No merge, no conflict resolution in v1. When Alice updates a shared file:

1. Alice edits the content, re-encrypts with the file key, bumps `modified`, signs with her identity key.
2. Alice's client writes the updated file to her server.
3. Alice's server delivers the updated file to each co-member's `.ark/inbox/` via an envelope (co-membership is already established).
4. The receiving server matches the file by `file_id` in the header. If a local file with that `file_id` already exists, it compares `modified` timestamps and keeps the newer version (updating the local copy in place).
5. If a co-member also made an edit concurrently, the higher `modified` timestamp wins. The losing edit is discarded.

**No fetch step required.** Unlike a notification-based approach, the full file is pushed directly. This eliminates the need for co-members to know each other's file paths and removes any path resolution or polling mechanism.

### 3.7 Adding and removing members

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

---

## 4. System 3: Encryption — "Nobody else can read this"

### 4.1 Concept

Every file's body is encrypted with a **symmetric file key** (AES-256-GCM). The file key is then wrapped (encrypted) to each member's identity key using ECIES. This two-layer approach means:

- Content is encrypted once, regardless of how members there are.
- Adding a member only requires wrapping the existing file key — no re-encryption of content.
- Removing a member requires generating a new file key and re-encrypting content (since the removed member knew the old key).

### 4.2 Encryption modes

The file header's `algorithm` field specifies whether and how the body is encrypted:

| Algorithm | Body | Wrapped keys | Use case |
|---|---|---|---|
| `aes-256-gcm` (default) | Encrypted | Yes — ECIES-wrapped per member | Private files, messages, shared documents |
| `chacha20-poly1305` | Encrypted | Yes — ECIES-wrapped per member | Same, for devices without AES hardware acceleration |
| `none` | Unencrypted (raw bytes) | No — `wrapped_file_key` fields are empty | Public content, websites, published documents |

When `algorithm = "none"`:
- The body is stored as raw bytes (no nonce, no AEAD tag).
- Member entries have empty `ephemeral_key`, `key_nonce`, and `wrapped_file_key` fields.
- The file signature still covers the body hash, providing integrity and authenticity (Section 5.2). This is the **only** integrity guarantee for unencrypted files — there is no AEAD tag to catch tampering.

### 4.3 File key generation

When a file is created in static mode:

1. The client generates a random 256-bit **file key**.
2. The client encrypts the file body with the file key:
   ```
   nonce = random 12 bytes
   ciphertext, tag = AES-256-GCM(file_key, nonce, payload)
   ```
3. For each member, the client wraps the file key using **ECIES**:
   ```
   ephemeral_key = random X25519 keypair
   owner_x25519_key = convert(owner_identity_key, target: "x25519")
   shared_secret = X25519(ephemeral_private, owner_x25519_key)
   wrapping_key = HKDF-SHA256(
     ikm: shared_secret,
     salt: ephemeral_public || owner_x25519_key,
     info: "file-key-wrap",
     length: 32
   )
   wrapped_file_key = AES-256-GCM(wrapping_key, random_nonce, file_key)
   ```
4. Each member entry in the header stores the `ephemeral_public`, `nonce`, and `wrapped_file_key`.

### 4.4 Decryption

When Alice decrypts a file:

1. Alice finds her member entry in the header (matched by identity key).
2. Alice computes the shared secret using her private key and the ephemeral public key in her member entry:
   ```
   shared_secret = X25519(alice_private, ephemeral_public)
   ```
3. Alice derives the wrapping key via HKDF (same parameters as encryption).
4. Alice decrypts the wrapped file key.
5. Alice decrypts the file body with the file key.

### 4.5 Why a symmetric file key?

Direct ECIES encryption (as in v0.3) encrypts content directly to each recipient's public key. This works for one-to-one messages but breaks down for shared files:

- **N members would require N copies of the ciphertext** (each encrypted to a different key). A 100MB file shared with 5 people would require 500MB of storage.
- **Adding a member requires re-encrypting the entire content.** With a symmetric file key, adding a member only wraps the 32-byte key — instant, regardless of content size.

The symmetric key approach encrypts content once and wraps the small key per-member. Standard construction, used by Signal (group messages), PGP (session keys), and every major encrypted storage system.

### 4.6 Multi-device decryption

Since there's a single identity keypair per user, multi-device is straightforward:

- **Mode B (server-managed key):** All devices get the private key from the server. Any device can unwrap any file key.
- **Mode A (client-managed key):** All devices derive the same private key from the seed phrase. Same result.

File keys are wrapped to the **identity key**, not per-device. One wrap per member, regardless of how many devices that member has.

### 4.7 Encryption algorithms

| Operation | Algorithm | Parameters |
|---|---|---|
| Identity keys (signing) | Ed25519 | — |
| Encryption key exchange | X25519 | — |
| Key derivation | HKDF-SHA256 | ��� |
| File key wrapping | AES-256-GCM | 96-bit nonce, 128-bit tag |
| File body encryption | AES-256-GCM | 96-bit nonce, 128-bit tag |
| Alternative body encryption | ChaCha20-Poly1305 | 96-bit nonce, 128-bit tag |
| Unencrypted body | None | Raw bytes, no nonce or tag |

Clients MUST support AES-256-GCM and `none` (unencrypted). ChaCha20-Poly1305 is recommended as an alternative (faster on devices without AES hardware acceleration). The algorithm used is indicated in the file header.

### 4.8 Why not PGP?

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

Every file modification is digitally signed by the author's identity key. When files are delivered cross-server, the envelope is signed so the receiving server can verify authenticity without decrypting the content. Identity forgery is mathematically impossible without the private key.

### 5.2 File signature

When Alice creates or modifies a file:

1. Alice computes an Ed25519 signature over the file's header fields:
   ```
   signature = Ed25519_Sign(
     identity_private_key,
     modified || modified_by || members_hash || body_hash
   )
   ```
   Where `members_hash` is the SHA-256 of the serialized member entries and `body_hash` is the SHA-256 of the encrypted body.
2. The signature is included in the header.
3. Any server or client can verify by fetching the modifier's identity document and checking the identity key.

### 5.3 Envelope signature

When files are delivered cross-server via an envelope:

1. The sender constructs the envelope (see Section 8.4 for full format).
2. The sender computes an Ed25519 signature over the serialized envelope contents (excluding the signature field itself):
   ```
   signature = Ed25519_Sign(
     identity_private_key,
     version || sender || recipient || timestamp || message_id ||
     envelope_type
   )
   ```
3. The signature is included in the envelope's `envelope_signature` field.

**Verification by the receiving server:**

1. Alice's server receives the envelope.
2. It extracts the sender address (`bob@sender.example.com`).
3. It fetches (or uses a cached copy of) Bob's identity document from `sender.example.com`.
4. It verifies the `envelope_signature` against Bob's identity key.
5. If verification fails: the delivery is rejected with a `403 Invalid Signature` response.

**Cache policy for identity documents:**
- Servers cache fetched identity documents for a configurable period (default: 1 hour).
- If a signature fails to verify, the server re-fetches the identity document (the key may have changed via transition) and retries verification once.

### 5.4 Non-repudiation

The Ed25519 signature provides **non-repudiation**: Alice can prove to a third party that Bob authored a specific file. This is a deliberate design choice — you *want* proof of who sent what (contracts, agreements, records).

---

## 6. System 5: Delivery Control — "Who can reach you"

### 6.1 Concept

Email spam is possible because anyone can send to anyone. This protocol inverts that: by default, only your contacts can deliver to your inbox. Accounts that want to receive from anyone (e.g., `info@business.com`) opt into a public inbox.

Identity is cryptographically unforgeable, so the contacts allowlist is a reliable delivery gate — no one can impersonate a contact.

### 6.2 Public vs. private inboxes

The identity document includes a `public` flag:

```json
{
  "version": 1,
  "address": "alice@example.com",
  "identity_key": { "algorithm": "ed25519", "public_key": "..." },
  "public": false,
  "updated": "...",
  "signature": { "algorithm": "ed25519", "signature": "..." }
}
```

| `public` | Behavior |
|---|---|
| `false` (default) | Only senders in the contacts allowlist can deliver to `.ark/inbox/`. Unknown senders are rejected with `403`. |
| `true` | Any sender can deliver. The server may apply its own rate limiting or abuse prevention (not specified by the protocol). |

### 6.3 Contacts allowlist

The allowlist is stored at `/ark/<user>/.ark/contacts.json` and is keyed by **identity public key**, not address. This means:
- Bob can change servers and remain allowlisted as long as he keeps the same identity key.
- Someone who registers `bob@attacker.com` with a different key is NOT allowlisted.

**How contacts are added:**
- Alice adds Bob manually (out-of-band exchange of addresses).
- Alice replies to Bob → Bob is automatically allowlisted.
- Bob redeems a contact invite created by Alice (see Section 6.4).
- Alice removes Bob → future deliveries from Bob are rejected.

**Delivery flow:**

When an envelope arrives for a user with `public: false`:
1. The server verifies the `envelope_signature` against the sender's identity key.
2. The server checks if the sender's identity key is in the recipient's contacts allowlist.
3. If not in contacts → reject with `403 Forbidden`.
4. If in contacts → accept delivery.

For users with `public: true`, step 2–3 are skipped.

### 6.4 Contact invites

Contact invites allow adding someone to your contacts via a shareable link or QR code.

**Creating an invite:**

```
POST /ark/alice/.ark/contact-invites
Authorization: ArkUser <signature>
Content-Type: application/json

{
  "max_uses": 1,
  "expires": "2026-05-10T00:00:00Z"
}
```

Response:

```json
{
  "token": "base64url-encoded-random-token"
}
```

Both `max_uses` and `expires` are optional. If omitted, the invite is single-use with no expiry.

**Redeeming an invite:**

```
POST /ark/alice/.ark/contact-invites/<token>
Content-Type: application/json

{
  "identity_key": {
    "algorithm": "ed25519",
    "public_key": "base64url-encoded"
  },
  "address": "bob@other-server.com"
}
```

The server validates the token (not expired, uses remaining), then adds Bob's identity key to Alice's contacts allowlist. Returns `200 OK` on success, `404` if token is invalid/expired.

**Sharing invites:**

Invites are shared as regular HTTPS URLs: `https://example.com/ark/alice/.ark/contact-invites/<token>`

- **QR code**: Encode the URL. Recipient scans, their client POSTs to redeem.
- **Web fallback**: A GET to the invite URL (without `.json`) serves an HTML page with a confirm button for users without a native client.

### 6.5 Account creation

```
POST https://example.com/ark/.ark/accounts
Content-Type: application/json

{
  "address": "alice",
  "identity_key": {
    "algorithm": "ed25519",
    "public_key": "base64url-encoded"
  }
}
```

Servers can disable remote account creation:

```toml
allow_remote_registration = false  # Only admin can create accounts (default: true)
```

When disabled, the endpoint returns `403 Forbidden`. Local account creation (via the admin CLI) always works regardless of this setting.

### 6.6 Why this eliminates IP reputation

| Email problem | How Ark solves it |
|---|---|
| Unknown IP → spam folder | Identity is cryptographic, not IP-based. |
| IP blocklists | Not needed. Contacts allowlist prevents unwanted delivery. |
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

**Authentication:** Every request is signed with the identity key:
```
Authorization: ArkUser <signature-over-method-path-timestamp-body>
X-Ark-Timestamp: 1712838400
```
The server verifies the signature against the identity key in Alice's identity document. Requests with timestamps older than 5 minutes are rejected (replay protection).

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
Content-Length: 4096
```

Clients that need the full header (member entries, wrapped keys) use GET and read only the header portion.

**Special endpoints:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/ark/alice/.ark/identity.json` | Identity document (JSON) |
| `GET` | `/ark/alice/.ark/identity` | Contact card (HTML) |
| `GET` | `/ark/alice/.ark/contacts.json` | List contacts (allowlisted identity keys) |
| `PUT` | `/ark/alice/.ark/contacts.json` | Update contacts |
| `POST` | `/ark/alice/.ark/contact-invites` | Create contact invite |
| `POST` | `/ark/alice/.ark/contact-invites/<token>` | Redeem contact invite |
| `GET` | `/ark/alice/.ark/contact-invites/<token>` | Invite page (HTML) |
| `GET/HEAD` | `/ark/alice/.ark/files/<file_id>` | Fetch/check shared file by ID (sync recovery) |
| `GET` | `/ark/alice/.ark/stream` | Real-time event stream (WebSocket/SSE) |

### 7.3 Cross-server delivery

When Bob sends a message (file) to Alice:

**Step 1: Store locally.** Bob's client creates the file on Bob's server via PUT.

**Step 2: Deliver via envelope.** Bob's server wraps the file in an envelope and delivers it to Alice's `.ark/inbox/`:

```
POST https://example.com/ark/alice/.ark/inbox/
Content-Type: application/x-ark-envelope

<binary envelope>
```

The envelope is self-authenticating — it contains the sender's signature. No HTTP-level authentication is required. The receiving server verifies the `envelope_signature` against the sender's identity key, then checks the contacts allowlist (Section 6.3). The file is written to `.ark/inbox/` with a generated filename (the envelope's `message_id`).

Client-side apps inspect incoming files in `.ark/inbox/` and claim them based on content or directory conventions.

**Response codes:**

| Code | Meaning |
|---|---|
| `202 Accepted` | File accepted, written to `.ark/inbox/`. |
| `400 Bad Request` | Malformed envelope. |
| `403 Forbidden` | Signature verification failed. |
| `404 Not Found` | Recipient does not exist on this server. |
| `429 Too Many Requests` | Rate limited. Includes `Retry-After` header. |
| `507 Insufficient Storage` | Recipient's storage is full. |

**Delivery retries:**
- If delivery fails (server down, network error), the sending server retries with exponential backoff (1 min, 5 min, 30 min, 2 hours, 8 hours) for up to 72 hours, then returns a bounce notification to the sender.

### 7.4 Cross-server sync (shared files)

When a shared file is updated, the updated file is pushed to co-members using the same delivery mechanism as new files:

```
POST https://example.com/ark/alice/.ark/inbox/
Content-Type: application/x-ark-envelope

<binary envelope with type SYNC>
```

The envelope payload is the full updated Ark file (header + encrypted body). The receiving server:

1. Extracts the `file_id` from the header.
2. Checks if a local file with that `file_id` exists.
3. If yes: compares `modified` timestamps. If the incoming file is newer, updates the local copy in place (at whatever path the local file currently lives). If older, discards.
4. If no: writes to `.ark/inbox/` as a new file (shouldn't normally happen for SYNC envelopes — indicates the receiver deleted their copy).

Sync envelopes bypass the contacts allowlist check — the receiving server verifies the sender is in the file's member list instead.

**No path knowledge required.** The sender doesn't need to know where the receiver stores their copy. The receiver's server resolves `file_id` → local path internally.

**Member moved notification:**

When a member migrates to a new server (Section 2.9), they send a `MEMBER_MOVED` envelope to co-members' `.ark/inbox/` directories:

```
Envelope type: MEMBER_MOVED
Payload: { old_address, new_address, identity_key, signature }
```

Co-members' clients update the member address in shared files. Identity key stays the same, so trust is preserved.

**Sync recovery (pull fallback):**

If a server misses SYNC pushes (e.g., downtime exceeding the retry window), members can pull the latest version of a shared file directly from a co-member's server:

```
GET https://example.com/ark/alice/.ark/files/<file_id>
Authorization: ArkUser <signature>
```

The server resolves `file_id` to the local path, verifies the requester's identity key is in the file's member list, and returns the full file (header + body). Returns `404` if the file_id is unknown or `403` if the requester is not a member.

**Recovery flow:** On startup (or periodically), a client can check each shared file by sending a HEAD request to co-members' `.ark/files/<file_id>` endpoint. If the remote `modified` timestamp is newer than the local copy, the client fetches the full file via GET.

### 7.5 Real-time events

```
GET https://example.com/ark/alice/.ark/stream
Authorization: ArkUser <signature>
```

WebSocket or SSE stream. Events:

```json
{"event": "created", "path": "/ark/alice/.ark/inbox/abc123", "from": "bob@example.com"}
{"event": "modified", "path": "/ark/alice/notes/todo", "modified_by": "alice@example.com"}
{"event": "deleted", "path": "/ark/alice/mail/trash/old-msg"}
{"event": "sync", "path": "/ark/alice/docs/project-plan", "file_id": "def456"}
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
│  └── /ark/<user>/.ark/contacts.json (allowlist)│
├──────────────────────────────────────────────┤
│  Outbound Relay                              │
│  ├── Queue for outgoing envelopes            │
│  ├── Retry logic (exponential backoff)       │
│  └── Remote identity document cache          │
├──────────────────────────────────────────────┤
│  Sync Engine                                 │
│  ├── Push updates to co-members               │
│  ├── Receive updates (match by file_id)       │
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
5. Add users locally: `ark-server user add alice`.
6. Or users self-register via the accounts endpoint.
7. Alice's client registers her public key (Mode A) or the server generates one for her (Mode B).

**Storage:**
- Filesystem. Files are stored on disk exactly as they are — the server is essentially an authenticated file server. No database required for user data.
- The server maintains a lightweight index (e.g., SQLite) mapping `file_id` → local path (required for sync) and caching directory listings and metadata queries. The files themselves are the source of truth.
- Contacts allowlists are stored as JSON files at `/ark/<user>/.ark/contacts.json`.

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
| Spam filtering | SpamAssassin, Bayesian filters, blocklists | Built-in: contacts allowlist |
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
│  Body                            │
│  ├── If encrypted:               │
│  │   ├── nonce (12 bytes)        │
│  │   └── ciphertext + tag (rest) │
│  └── If algorithm = "none":      │
│      └── raw bytes (rest)        │
└──────────────────────────────────┘
```

The first 8 bytes are fixed: 4-byte magic (`ARK\x01`, where `\x01` is the format version) and 4-byte big-endian header length. The header follows immediately, then the encrypted body fills the rest of the file.

### 8.2 Header

The header is serialized using Protocol Buffers.

```protobuf
syntax = "proto3";

message Header {
  // File identity
  bytes file_id = 1;                    // 16 bytes, random UUID, immutable after creation

  // Timestamps
  uint64 created = 2;                   // Unix milliseconds
  uint64 modified = 3;                  // Unix milliseconds

  // Membership
  repeated Member members = 4;

  // Encryption
  string algorithm = 5;                 // "aes-256-gcm", "chacha20-poly1305", or "none"

  // Author of last modification
  string modified_by = 6;              // "alice@example.com"
  string signature_algorithm = 7;      // "ed25519"
  bytes signature = 8;                 // Signature over fields 1-6 + body hash

  // Key conversion (for ECIES wrapping)
  string encryption_algorithm = 9;     // "x25519" — target algorithm for deriving encryption key from identity key
}

message Member {
  string address = 1;                   // "alice@example.com"
  string identity_key_algorithm = 2;   // "ed25519"
  bytes identity_key = 3;              // Member's public key (for verification)
  string permission = 4;               // "owner", "write", or "read"

  // File key wrapped for this member (ECIES)
  string ephemeral_key_algorithm = 5;  // "x25519"
  bytes ephemeral_key = 6;            // Ephemeral public key (32 bytes)
  bytes key_nonce = 7;                // AES-256-GCM nonce for key wrapping (12 bytes)
  bytes wrapped_file_key = 8;         // File key encrypted to this member (32 bytes + 16 byte tag)
}
```

### 8.3 Envelope

The envelope is the transport wrapper for cross-server delivery. It wraps a file (or a notification) for delivery to another server's `.ark/inbox/`.

```protobuf
enum EnvelopeType {
  DELIVER = 0;                         // Deliver a file to a recipient
  SYNC = 1;                            // Push updated file to co-member
  MEMBER_MOVED = 2;                    // Notify co-members of address change
}

message Envelope {
  uint32 version = 1;                  // Protocol version (1)

  // Routing
  string sender = 2;                   // "bob@sender.example.com"
  string recipient = 3;               // "alice@example.com"
  uint64 timestamp = 4;               // Unix milliseconds
  bytes message_id = 5;               // 16 bytes, random UUID

  // Envelope type
  EnvelopeType type = 6;              // Default: DELIVER

  // Sender authentication (signature over fields 1-6)
  string signature_algorithm = 7;     // "ed25519"
  bytes envelope_signature = 8;       // 64 bytes

  // Payload — depends on envelope type:
  // DELIVER: raw Ark file bytes (header + encrypted body)
  // SYNC: raw Ark file bytes (header + encrypted body)
  // MEMBER_MOVED: MemberMovedNotification
  bytes payload = 9;
}

message MemberMovedNotification {
  string old_address = 1;
  string new_address = 2;
  string identity_key_algorithm = 3; // "ed25519"
  bytes identity_key = 4;
  string signature_algorithm = 5;    // "ed25519"
  bytes signature = 6;               // Signed by the identity key
}
```

### 8.4 Identity and contacts documents

Identity documents and contacts are JSON (human-readable, easy to debug with curl). See Section 2.4 for the identity document schema.

### 8.5 Serialization rules

- **File headers, envelopes:** Protocol Buffers (binary). Compact, efficient, schema-evolvable.
- **Identity documents, contacts:** JSON. Human-readable.
- **Signatures:** computed over the canonical protobuf serialization (deterministic encoding) plus the SHA-256 hash of the encrypted body.
- **All binary values in JSON:** base64url encoding (RFC 4648, no padding).

---

## 9. Threat Model

### 9.1 What is protected

| Property | Guarantee |
|---|---|
| **Data confidentiality** | Only holders of the file key can read file content. Servers see only ciphertext (Mode A). |
| **Author authentication** | Files and envelopes are signed by the author's identity key. Forgery requires the private key. |
| **Integrity** | Any modification to a file invalidates the signature. Any modification to the ciphertext invalidates the AEAD tag. |
| **Spam resistance** | Only contacts can deliver to private inboxes. Public inboxes are opt-in. |
| **Data persistence (static mode)** | All static-mode files can be decrypted with the single identity key (which unwraps file keys). No session state to lose. |

### 9.2 What is NOT protected

| Risk | Details |
|---|---|
| **Metadata** | File paths, sizes, timestamps, member addresses, and cross-server delivery patterns are visible to the server and network observers. Path names may reveal content intent (e.g., `/notes/tax-2025`). |
| **Forward secrecy** | If the identity private key is compromised, all file keys can be unwrapped, and all past and future data can be decrypted. This is a deliberate tradeoff for simplicity and recoverability. |
| **Mode B server trust** | If the server holds the private key (Mode B), the server can read all data. Self-hosters mitigate this by controlling the server. |
| **Removed member's existing copy** | When a member is removed from a shared file, they retain any copy they already downloaded. Re-keying prevents access to future edits, not past content. |
| **Path metadata** | File paths are unencrypted (the server needs them for routing). Path names like `/mail/inbox/` or `/notes/secret-project` are visible to the server. For maximum privacy, use opaque paths. |
| **Unencrypted files** | Files with `algorithm = "none"` have no confidentiality protection. The body is readable by the server, network observers (if TLS is broken), and anyone with read access. Integrity and authenticity are still provided by the file signature. |

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
- Mitigation: Alice performs a key transition (Section 2.7). After transition, new files use the new key and are safe.

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
| X25519 is secure | All encryption and key exchange breaks. |
| AES-256-GCM / ChaCha20-Poly1305 is secure | Data confidentiality breaks. |
| User's seed phrase / private key is stored securely | Attacker can decrypt all data and impersonate user. |
| TOFU on first contact is not intercepted | MITM on first key fetch allows interception until detected. |

---

## 10. Extensions

These are planned features not included in the core v1 protocol. They can be layered on top without breaking compatibility.

### 10.1 Forward Secrecy — Ratcheted Sequences

An optional **ratcheted key derivation mode** for file sequences between two parties. Uses the Double Ratchet algorithm (as used in Signal) to provide forward secrecy: compromising the identity key does not expose past messages, and compromising a single message key does not expose other messages.

This is opt-in. The default static mode (Section 4.2) remains unchanged. Both modes coexist — apps choose which to use based on the use case.

#### 10.1.1 Concept

A **ratcheted sequence** is an ordered collection of files between exactly two parties, where each file's key is derived from a ratchet chain rather than generated randomly and wrapped via ECIES. The sequence lives in a directory:

```
/ark/alice/mail/conversations/bob-abc123/
  .ark/members              ← exactly 2 members
  .ark/ratchet              ← ratchet session state (encrypted to self only, single device)
  0001                      ← file, key derived from ratchet
  0002                      ← file, key derived from ratchet
  ...
```

Each file in the sequence is still a standard Ark file (same binary format, same transport, same envelope delivery). The only difference is how the file key is derived — from the ratchet chain instead of random + ECIES.

#### 10.1.2 Prekey bundles

To establish a ratchet session without requiring both parties to be online simultaneously, the protocol uses **X3DH** (Extended Triple Diffie-Hellman) key agreement. This requires prekeys published in the identity document (Section 2.4):

| Field | Purpose |
|---|---|
| `prekeys.signed_prekey` | X25519 public key, rotated periodically (e.g., weekly). Signed by the identity key to prove authenticity. |
| `prekeys.signed_prekey_signature` | Ed25519 signature over the signed prekey. |
| `prekeys.one_time_prekeys` | List of single-use X25519 public keys. The server removes each key after it is fetched by a sender. Provides one-time forward secrecy for session initiation. |

Users who do not publish prekeys do not support ratcheted sequences. Senders fall back to static mode.

**Prekey replenishment:** Clients should monitor their one-time prekey count and upload new keys when the supply runs low. If no one-time prekeys are available, X3DH proceeds without one (reduced forward secrecy for the initial message only).

#### 10.1.3 Session establishment (X3DH)

When Alice initiates a ratcheted sequence with Bob:

1. Alice fetches Bob's identity document and extracts:
   - Bob's identity key (`IK_B`) — converted using the `encryption_algorithm` (e.g., `"x25519"`)
   - Bob's signed prekey (`SPK_B`)
   - One of Bob's one-time prekeys (`OPK_B`), if available
2. Alice verifies `signed_prekey_signature` against Bob's identity key.
3. Alice generates an ephemeral X25519 keypair (`EK_A`).
4. Alice computes four DH values:
   ```
   DH1 = X25519(IK_A_private, SPK_B)       # Alice's identity × Bob's signed prekey
   DH2 = X25519(EK_A_private, IK_B)        # Alice's ephemeral × Bob's identity
   DH3 = X25519(EK_A_private, SPK_B)       # Alice's ephemeral × Bob's signed prekey
   DH4 = X25519(EK_A_private, OPK_B)       # Alice's ephemeral × Bob's one-time prekey (if available)
   ```
5. Alice derives the initial root key:
   ```
   root_key = HKDF-SHA256(
     ikm: DH1 || DH2 || DH3 || DH4,
     salt: 0 (32 zero bytes),
     info: "ark-ratchet-init",
     length: 32
   )
   ```
6. Alice stores the ratchet state locally and sends the first file in the sequence with her ephemeral public key (`EK_A`) and the one-time prekey identifier in the file header, so Bob can compute the same root key.

#### 10.1.4 Double Ratchet operation

After session establishment, the Double Ratchet proceeds as follows:

**Symmetric ratchet (per-message):** Each file in a sending chain advances a chain key:

```
chain_key[n+1] = HMAC-SHA256(chain_key[n], 0x02)
message_key[n] = HMAC-SHA256(chain_key[n], 0x01)
```

The `message_key` is used as the file key for that file. It is used once and discarded.

**DH ratchet (per-turn):** When the sending direction changes (Alice sends, then Bob sends), a new DH ratchet step occurs:

1. The new sender generates a fresh X25519 ephemeral keypair.
2. The new sender computes a DH shared secret with the other party's latest ratchet key.
3. The root key advances:
   ```
   dh_output = X25519(new_private, other_ratchet_public)
   root_key[n+1], chain_key = HKDF-SHA256(
     ikm: dh_output,
     salt: root_key[n],
     info: "ark-ratchet-step",
     length: 64
   )
   ```
4. The sender's new ratchet public key is included in the file header's `ratchet_key` field.

**File header fields for ratcheted files:**

| Field | Purpose |
|---|---|
| `key_derivation` | `"ratchet"` |
| `sequence_id` | Identifies the ratchet session (random 16 bytes, set at session creation) |
| `message_index` | Monotonic counter — position in the ratchet chain |
| `ratchet_key` | Sender's current DH ratchet public key (X25519, 32 bytes) |

The `members` list still exists in the header but `wrapped_file_key` fields are empty — the file key is derived from the ratchet, not wrapped via ECIES.

#### 10.1.5 Ratchet state storage

Ratchet state is stored locally at `.ark/ratchets/<sequence_id>`, encrypted to self only. It contains:

- Current root key
- Sending and receiving chain keys
- Current DH ratchet keypair
- Other party's current DH ratchet public key
- Message counters
- Skipped message keys (for out-of-order delivery, capped and pruned)

**Single device only.** Ratchet state is not synced across devices. This is a deliberate choice — ratchet security depends on state never being duplicated. Users who opt into ratcheted sequences accept that those sequences are tied to one device.

**If ratchet state is lost** (device lost, storage failure), all messages in the sequence become unrecoverable. This is the fundamental tradeoff of forward secrecy. Users who need recoverability should use static mode.

#### 10.1.6 Out-of-order delivery

Files may arrive out of order (network delays, server queuing). The ratchet handles this:

1. The recipient checks the `message_index` against their current chain position.
2. If the index is ahead, the recipient advances the chain and stores skipped message keys (up to a configurable limit, default: 256).
3. If the index matches a stored skipped key, the recipient uses it and deletes it.
4. If the index is behind and the key was already deleted, the file is undecryptable.

#### 10.1.7 Group ratchet (future)

The Double Ratchet is fundamentally a 2-party protocol. Group forward secrecy (3+ members) can be layered on top using **sender keys**: each member maintains their own sending chain and distributes the sender key to the group via pairwise ratcheted channels. This is not specified in v1.

#### 10.1.8 Upgrade path

Nothing in the core protocol blocks adding ratcheted sequences later:

- Ratcheted files are standard Ark files — same format, same transport, same envelopes. The Header protobuf is extended with `key_derivation`, `sequence_id`, `message_index`, and `ratchet_key` fields.
- The identity document is extended with a `prekeys` object.
- Old clients that don't understand ratcheted files simply cannot decrypt them (they lack the ratchet state regardless).
- Proto3 silently ignores unknown fields, so old clients won't break on new headers.

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
4. If not, it requests account creation on the gateway:
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
  "identity_key": {
    "algorithm": "ed25519",
    "public_key": "base64url-encoded"
  },
  "notify": true,
  "updated": "2026-04-14T12:00:00Z",
  "signature": {
    "algorithm": "ed25519",
    "signature": "base64url-encoded"
  }
}
```

**Claiming the identity:**

When Carol decides she wants a real address:
1. Carol chooses a username (e.g., `carol`).
2. The gateway creates a new identity document at `carol@gateway.example.com` (same keypair).
3. The hash alias redirects to the new address.
4. Carol can migrate to her own server later using a key transition (Section 2.7).

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

### 10.3 Wildcard Members (Public Files)

A special member entry with `address = "*"` represents public access. The wildcard member has no `identity_key` and no `wrapped_file_key`. It is only valid on unencrypted files (`algorithm = "none"`).

| Wildcard permission | Meaning |
|---|---|
| `read` | Anyone can GET the file without authentication. |
| `write` | Any authenticated Ark user can read and modify the file. |
| `owner` | Any authenticated Ark user can read, modify, and change the file's members. |

The server skips authentication on GET requests when a `*` member with `read` (or higher) permission is present. For `write` and `owner`, the server still requires a valid `ArkUser` authorization header — "public write" means any authenticated Ark user, not unauthenticated HTTP requests.

**Use cases:**

- `*` (read): Public website, blog, published documents, open-source project files.
- `*` (write): Anonymous drop box, public wiki, open submission folder.
- `*` (owner): Fully open collaborative space (uncommon but not prohibited).

### 10.4 Directory Membership

A directory can have its own member list, stored at `.ark/members` within the directory:

```
/ark/alice/projects/.ark/members
```

```json
{
  "members": [
    {
      "address": "alice@example.com",
      "identity_key": { "algorithm": "ed25519", "public_key": "..." },
      "permission": "owner"
    },
    {
      "address": "bob@other.com",
      "identity_key": { "algorithm": "ed25519", "public_key": "..." },
      "permission": "write"
    }
  ],
  "signature": { "algorithm": "ed25519", "signature": "..." }
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

Wildcard members (Section 10.3) can also appear in directory membership files, cascading to all files and subdirectories below.

### 10.5 Metadata Privacy

A future version could add onion routing or mixnet support to hide metadata (sender/recipient/timing) from servers and network observers. The protocol's layered design (file vs. envelope) makes this possible without changing the core file format.

### 10.6 Collaborative Editing (CRDTs)

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
| No encryption | None | — | raw bytes |
| Seed phrase | BIP-39 | 256-bit entropy | 24 words |

## Appendix B: URL Structure Summary

All Ark paths are under `https://<domain>/ark/`.

**Server-level (no auth required):**

| Path | Method | Purpose |
|---|---|---|
| `/ark/.ark/accounts` | POST | Create account |

**User-level (public, no auth):**

| Path | Method | Purpose |
|---|---|---|
| `/ark/<user>/.ark/identity.json` | GET | Identity document (JSON) |
| `/ark/<user>/.ark/identity` | GET | Contact card (HTML) |
| `/ark/<user>/.ark/contact-invites/<token>` | GET/POST | View/redeem invite (HTML/JSON) |

**User-level (authenticated — member):**

| Path | Method | Purpose |
|---|---|---|
| `/ark/<user>/<path>` | GET | Fetch file (header + body) |
| `/ark/<user>/<path>` | HEAD | Fetch header/metadata only |
| `/ark/<user>/<path>` | PUT | Create or update file |
| `/ark/<user>/<path>` | DELETE | Delete file |
| `/ark/<user>/<dir>` | GET | List directory |
| `/ark/<user>/.ark/files/<file_id>` | GET/HEAD | Fetch/check shared file by ID (sync recovery) |
| `/ark/<user>/.ark/contacts.json` | GET/PUT | Manage contacts allowlist |
| `/ark/<user>/.ark/stream` | GET | Real-time event stream |

**Cross-server delivery (server auth):**

| Path | Method | Purpose |
|---|---|---|
| `/ark/<user>/.ark/inbox/` | POST | Deliver envelope (file, notification, registration) |

---

## Appendix C: Example Usage

### Message flow (end to end)

A message is a file with two members — sender (owner) and recipient (read):

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
    |  4. Sign envelope         |                          |                          |
    |                           |                          |                          |
    |  5. Store file on ------->|                          |                          |
    |     home server           |                          |                          |
    |                           |  6. Relay via HTTPS POST |                          |
    |                           |------- envelope -------->|                          |
    |                           |                          |  7. Verify signature      |
    |                           |                          |  8. Check contacts/public |
    |                           |                          |  9. Store in .ark/inbox/  |
    |                           |                          |                          |
    |                           |                          |  10. Alice fetches ------>|
    |                           |                          |  11. Decrypt with         |
    |                           |                          |      private key          |
    |                           |                          |                          |
    |                           |                          |  12. App moves file       |
    |                           |                          |      to desired path      |
```

### Example use cases

The protocol defines no directory structure — apps do. Examples of how different apps might organize files:

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
/ark/alice/notes/work/meeting-notes   ← work note (shared with coworkers)
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
