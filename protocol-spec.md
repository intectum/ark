# Ark Protocol Specification

> **Status:** Draft v0.5
> **Date:** 2026-04-26

## Table of Contents

1. [Overview](#1-overview)
2. [System 1: Identity](#2-system-1-identity)
3. [System 2: Files](#3-system-2-files--the-core-primitive)
4. [System 3: Encryption](#4-system-3-encryption--nobody-else-can-read-this)
5. [System 4: Authentication](#5-system-4-authentication--this-really-came-from-alice)
6. [System 5: Delivery Control](#6-system-5-delivery-control--who-can-reach-you)
7. [System 6: Transport](#7-system-6-transport--how-data-moves)
8. [File Format](#8-file-format)
9. [Threat Model](#9-threat-model)
10. [Extensions](#10-extensions)
- [Appendix A: Configuration](#appendix-a-configuration)
- [Appendix B: Endpoints](#appendix-b-endpoints)
- [Appendix C: Types](#appendix-c-types)
- [Appendix D: Cryptographic Algorithms](#appendix-d-cryptographic-algorithms)
- [Appendix E: Example Usage](#appendix-e-example-usage)

---

## 1. Overview

Ark is a federated, encrypted protocol for synchronizing personal and shared data. It is built on cryptographic identity and end-to-end encryption with six core systems:

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
- **Encrypted by default.** File content is end-to-end encrypted unless explicitly opted out. Servers store ciphertext they cannot read. Unencrypted files are supported for public content — the metadata still provides authentication and integrity via signatures.
- **Files on disk.** Storage is the filesystem. No database for user data. Files are accessed by path over HTTPS. Any tool that can read files can interact with Ark data.
- **One primitive.** Everything is a file: a body plus a small signed metadata record. Different membership patterns produce different behaviors, not different concepts.
- **Simple to self-host.** A single binary, a single config file, a domain with an A record. That's it.
- **Federated, not peer-to-peer.** Servers provide reliable offline storage and key hosting. Pure P2P systems (Bitmessage, Briar) struggle with reliability and adoption.
- **Spam-resistant by construction.** Only contacts can deliver to your inbox by default. Unforgeable identity means no one can impersonate a contact.
- **Simple key model.** One keypair per identity, like a crypto wallet. Lose the key, lose the identity. Have the key, have all your data.
- **Flexible trust model.** Users choose where their private key lives — on their device (maximum security) or on their server (maximum convenience). Self-hosters get both.
- **App-agnostic.** The protocol defines files, membership, and transport. How files are organized into directories is up to applications. A mail app, a notes app, and a file manager all operate on the same files — just arranged differently.

---

## 2. System 1: Identity

### 2.1 Concept

Every account has a cryptographic keypair — like a crypto wallet. The public key *is* the identity. It's mapped to a human-readable address like `alice@example.com`, where `example.com` is the server that hosts Alice's account.

### 2.2 Address format

Addresses use the familiar `user@domain` format:

```
alice@example.com
bob@ark.myserver.org
```

- `user` — the local part, unique within the server. Lowercase alphanumeric, dots, hyphens, underscores. Max 64 characters.
- `domain` — the server's hostname.

This format is deliberately identical to email. Users already understand it, and it requires no new mental model.

Addresses can also use IP addresses (`alice@127.0.0.1`) and include paths to specific files (`alice@example.com/.ark/groups/contacts.json` or `/.ark/groups/contacts.json`). Paths must point to an `Identity` or `Group` file.

### 2.3 Keypair generation

Each account has a single **identity keypair**. This keypair is used for both signing and encryption [TODO: ?] (converted to X25519 for Diffie-Hellman operations — this is a standard, well-defined mathematical conversion).

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

**Mode B: Server-hosted key (maximum convenience)**

1. Alice's client generates the Ed25519 identity keypair locally — the server never sees the private key.
2. The client stores it as an ordinary file at `/ark/<user>/.ark/identity.key` whose members are credential members — passwords and/or passkeys (Sections 2.11, 3.10) — so only a holder of one of those credentials can decrypt it, and the server gates access to it. The client creates this file exactly as it creates any other (encrypt body, wrap the file key to each member, sign, PUT); the server stores ciphertext it cannot read.
3. To log in on any device, Alice's client requests `identity.key` and decrypts it with her password or passkey, recovering the private key. The server verifies the credential before returning the file (Section 2.11), so the encrypted key is never freely downloadable. There is no seed phrase to manage, and multi-device works by entering the same credential on each device.
4. By default the server holds no credential of its own, so it **cannot** read the key. Alice may optionally add a **server recovery member** so an admin can reset her password — this re-enables the server to decrypt her data, the classic "your provider can read your mail" trade-off.
5. Alice can export her seed phrase at any time and switch to Mode A.

The only difference from Mode A is *where the key lives and how it is recovered*: in Mode B the encrypted key is hosted on the server and unlocked by a password/passkey; in Mode A nothing is hosted and the key is recovered from a seed phrase. In neither mode does the server see the private key (absent a server recovery member).

**Why offer both modes?**

Most people will choose Mode B — login with a password or passkey, like every web service. It means:
- No seed phrase to lose.
- Seamless multi-device (each device decrypts the same `identity.key`).
- Optionally, if Alice adds a server recovery member, a forgotten password can be reset by the admin (for self-hosters, you *are* the admin) — at the cost of letting the server read her data.

Security-conscious users choose Mode A — the encrypted key is never hosted on the server at all, so there is nothing for a compromised server to brute-force. Recovery is by seed phrase only.

**Self-hosters get the best of both worlds:** They control the server, so Mode B gives them convenience without trusting a third party. The private key — and any recovery member — is on infrastructure they own.

**Why Ed25519?**
- Fast signing and verification (important for per-file signatures).
- Small keys (32 bytes) and signatures (64 bytes).
- Deterministic — same input always produces the same signature (no nonce-reuse vulnerabilities).
- Well-audited, widely implemented, no known weaknesses.
- Easily converted to X25519 for encryption operations.

### 2.4 Identity document

Alice's public `Identity` is published as a JSON document on her server:

`https://example.com/ark/alice/.ark/identity.json`

See Section C.1 for format.

**The self-signature is the key security property** (for Mode A users). The server hosts this document but cannot tamper with it — any modification invalidates the signature. This means:
- A compromised server cannot swap in a different public key to intercept data.
- A MITM attacker who compromises the TLS connection cannot forge the identity document.
- The document is self-authenticating: anyone can verify it using only the public key it contains.

Note: A Mode B user with a server recovery member (Section 2.11) lets the server hold a credential to the private key, so the server *could* sign a different identity document — but the user already accepted that the server can read their data, so this doesn't change their trust model. A Mode B user without a server recovery member keeps the full self-signature guarantee, like Mode A.

### 2.5 Key discovery

When Bob wants to contact Alice for the first time:

1. Bob's client extracts the domain from `alice@example.com`.
2. Bob's client makes an HTTPS GET to `https://example.com/ark/alice/.ark/identity.json`.
3. Bob's client verifies the `signature` field against the `key` in the document.
4. **Trust On First Use (TOFU):** Bob's client stores Alice's `key` locally. This is the first time Bob has seen this key, so he trusts it (like SSH's "The authenticity of host 'example.com' can't be established... Are you sure you want to continue?").
5. On subsequent fetches, Bob's client compares the `key` against the stored value. If it has changed without a proper key transition (see 2.8), the client raises an alert.

### 2.6 Multi-device support

Alice uses a laptop and a phone. Multi-device works differently depending on the key mode:

**Mode B (server-hosted key):**
- Each device fetches `identity.key` and decrypts it with Alice's password or passkey (Section 2.11) to recover the private key.
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

**Mode B (server-hosted key):**
- With a remembered credential (password or passkey), Alice fetches and decrypts `identity.key` on a new device — files on the server remain accessible.
- With a **server recovery member**, a forgotten password can be reset by the admin — the simplest recovery story, like email. This is what lets the server decrypt the key.
- Without a server recovery member, losing **all** credentials means the identity key file can no longer be opened. Alice falls back to her exported seed phrase (Section 2.3, step 5); if she has none, the account is lost, as in Mode A.

**Mode A (client-managed key):**
- Alice enters her 24-word seed phrase on a new device.
- The client derives the identity keypair from the seed.
- The client authenticates with Alice's server using the identity key.
- Files stored on the server (encrypted) can be decrypted because Alice has the same private key, which unwraps the file keys.

**What is lost if the seed phrase is lost (Mode A):**
- The identity key is gone. Alice must create a new account with a new keypair.
- All files encrypted to the old key are unrecoverable.
- Contacts will see a new key and need to re-verify.

### 2.9 Server migration

Alice can move from one server to another while keeping the same identity keypair.

**When the old server is still online:**

1. Alice creates an account on the new server with her existing identity key (Mode A: enters seed phrase; Mode B: uploads her encrypted `identity.key` to the new server).
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
- Shared file co-membership. Other members of shared files have Alice's old server address in the member list. Alice notifies co-members by sending them her new identity document (Section 7.4) so they update the address. Since membership is verified by identity key, the transition is seamless once addresses are updated.

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

### 2.11 Identity key file (Mode B)

A Mode B account stores its identity private key in a file at `/ark/<user>/.ark/identity.key`. This is an **ordinary Ark file** (Section 8), not a special format: its **body** is the identity private key (encrypted with a file key, like any file), and its **members** are **credential members** — passwords and/or passkeys (Section 3.10) — with `read` permission, plus the identity itself as `owner`.

Because access is governed by the file's members, the server **verifies a credential before returning the body** (Section 3.10) — exactly as it would for any credential-gated file. The private key is never handed to an unauthenticated requester, and attempts are rate-limited. This gives Mode B its convenience — password/passkey login, seamless multi-device, no seed phrase — while keeping the server unable to decrypt (the credential's decryption key never reaches it, Section 3.10).

**Login flow:**

1. The client requests `identity.key`, presenting a password or passkey proof (Section 7.2). The server verifies it against a credential member and returns the file; a failed or unauthenticated request gets `403` — no ciphertext leaks.
2. The client derives its wrapping key from the credential, unwraps the file key from its member entry, and decrypts the body to recover the private key (Section 3.10).
3. The client derives the public key and verifies it equals the `key` in `identity.json`. This catches substitution of the file.
4. The client signs subsequent `ArkUser` requests (Section 7.2) with the private key. Possession of a credential *is* possession of the account.

**Adding / removing a credential.** Both are ordinary `owner`-level edits to the file, made with the recovered identity key:
- *Add:* unwrap the file key (via any credential, or the `owner` entry), then add a credential member that wraps it. The body is not re-encrypted.
- *Remove:* drop the member. This is **soft revocation only** — the holder may have cached the key, and the identity key is unchanged — so true revocation is an identity key transition (Section 2.7). Parallels Section 3.7.

The file is self-signed by the identity key like any file (Section 5.2), so a malicious server cannot tamper with the member list — e.g. it cannot strip a strong passkey member to force a weaker password path (a downgrade attack).

**Server recovery (optional).** Adding a credential member the server controls lets an admin reset access — and lets the server decrypt the private key (classic Mode B). Explicit per-account opt-in, not the default.

The key is generated by the client and uploaded encrypted, so the server never sees the private key (absent a server recovery member). The difference from Mode A is only that Mode A keeps nothing on the server and recovers from a seed phrase.

---

## 3. System 2: Files ��� "The core primitive"

### 3.1 Concept

Everything in Ark is a **file** — data stored on the server's filesystem, accessed by path over HTTPS. A file is its **body** (the content — ciphertext, or raw bytes for public files) plus a small signed **metadata** record (ownership, members, wrapped keys) kept alongside the body rather than inside it (Section 8). The URL is the path:

```
GET  https://example.com/ark/alice/notes/todo     → body + metadata
HEAD https://example.com/ark/alice/notes/todo     → metadata only
GET  https://example.com/ark/alice/notes/         → directory listing
```

Messages, notes, documents, photos — all the same thing underneath. Different apps organize them into different directories, but the protocol doesn't care. It just stores and serves files.

### 3.2 File structure

Every Ark file consists of two parts, stored separately:

1. **Metadata** — a small signed blob the server needs to index, serve, and enforce access control: member list, permissions, timestamps, algorithm, wrapped file keys, signature. Stored out-of-band (a `user.ark` xattr at rest, an `X-Ark-Metadata` header in transit), never inside the body.
2. **Body** — the content. Ciphertext for encrypted files (`nonce ‖ ciphertext + tag`), raw bytes for `algorithm = "none"`. Opaque to the server.

See Section 8 for the full format.

### 3.4 Membership

Each file has one or more members, listed in the metadata. Every member holds the file's symmetric key, wrapped to their key. This means any member can decrypt the content. Members are usually **identity members** (identified by an identity key); a file may also have **credential members** — passwords or passkeys the server verifies before serving (Section 3.10) — and a **wildcard member** for public access (Section 3.8).

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

**Two members (messaging):** Sender creates file with two members — self (owner) and recipient (read). A copy is delivered to the recipient's `.ark/inbox/` (Section 7). The recipient's app can move it to any path.

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

Entries include metadata (members, timestamps) but not the body. Subdirectories are listed with `"type": "directory"`.

### 3.6 Multi-member sync

When a file has multiple members with `write` or `owner` permission, edits need to propagate.

**Last-write-wins.** The `modified` timestamp is the tiebreaker. No merge, no conflict resolution in v1. When Alice updates a shared file:

1. Alice edits the content, re-encrypts with the file key, bumps `modified`, signs with her identity key.
2. Alice's client writes the updated file to her server.
3. Alice's server delivers the updated file to each co-member's `.ark/inbox/` (co-membership is already established).
4. The receiving server matches the file by `file_id` in the metadata. If a local file with that `file_id` already exists, it compares `modified` timestamps and keeps the newer version (updating the local copy in place).
5. If a co-member also made an edit concurrently, the higher `modified` timestamp wins. The losing edit is discarded.

**No fetch step required.** Unlike a notification-based approach, the full file is pushed directly. This eliminates the need for co-members to know each other's file paths and removes any path resolution or polling mechanism.

### 3.7 Adding and removing members

**Adding a member:**

1. An existing member (with `owner` permission) decrypts the file key.
2. Encrypts the file key to the new member's identity key (fetched via key discovery, Section 2.5).
3. Adds a new `Member` entry to the file's metadata.
4. Signs the updated file and syncs to other members.

**Removing a member:**

1. An existing member (with `owner` permission) removes the `Member` entry.
2. Remaining members generate a **new file key** (the removed member knew the old one).
3. Re-encrypt the body with the new key.
4. Re-wrap the new key for each remaining member.
5. The removed member still has their old copy (can't prevent this — they had the key). But new edits use the new key they don't have.

### 3.8 Wildcard members (public files)

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

### 3.9 Groups

A **group** is a reusable, named set of members. Instead of wrapping a file key to every member individually, a file is shared with the group once, and group members decrypt through the group's key.

A group is two files, **replicated to every member's account** and synced like any shared file (Section 7.4), so each member holds a copy at the same local path:

- **Group document** (`/ark/<user>/.ark/groups/<name>.json`) — like an identity document, but identifying a **member list** instead of a single address. Self-signed by an `owner` member. Holds the group's current **public key** and the members, each with a permission (`owner`, `write`, or `read`) within the group. See Section C.7.
- **Group key file** (`/ark/<user>/.ark/groups/<name>.key`) — the group's **private key**, wrapped to each member's identity key. Members-only read. Omitted for allowlist-only groups (no keypair).

**Addressing.** A group is addressed by the **local path** to its document, e.g. `/.ark/groups/team.json` (Section 2.2), used anywhere a user address is used — including the `address` field of a file `Member` entry. The path is local and contains no owner; because the group is replicated to every member at the same path, the address resolves for each member, and ownership can transfer without changing it.

**Sharing a file with a group.**

1. Take the group's current public key from the group document.
2. Wrap the file key to it via ECIES (Section 4.3).
3. Add a `Member` entry to the file: `address` = the group's local path, `key` = group public key, `permission` = the group's permission on this file.

**Decrypting a file shared with a group.**

1. Read your replicated copy of the group key file (`.key`) and unwrap the group private key with your own identity key.
2. Use it to unwrap the file key from the file's group member entry (Section 4.4).
3. Decrypt the body.

**Effective permission.** A user's permission on a file shared with a group is the **lower** of: the group's permission on the file, and the user's permission within the group (the group document). The server enforces writes by reading the (public) group document.

**Ownership transfer.** Ownership is just the `owner` permission in the group document. The current owner grants `owner` to another member (and optionally drops their own). Nothing about the address changes.

**Adding a member.** Add them to the group document and re-wrap the private key to them in the `.key` file. Both sync to members. Files already shared with the group are unaffected — instant.

**Removing a member.** The removed member knew the group private key, so the group is **re-keyed**: generate a new group keypair, re-wrap the new private key to the remaining members in the `.key` file, and re-wrap the file key of every file shared with the group to the new group public key. Cost scales with the number of files shared with the group.

**Default group for a directory (client hint).** A reserved marker file `<dir>/.ark/group` containing a group's local path:

```
/ark/alice/projects/.ark/group   →   /.ark/groups/team.json
```

When a client creates a file in that directory, it shares with that group by default. This is a **hint only** — the server does not enforce it, and files in the directory may use any membership.

### 3.10 Credential members (password / passkey)

Most members are **identity members**, identified by an identity key (the default). A **credential member** is instead identified by a secret — a **password** or a **passkey**. Two things make it useful:

- The file can be shared with someone who is **not an Ark identity** — a link plus a password, or a passkey — with no key discovery.
- The server can **verify the credential before returning the file**, so gated content is never handed to an unauthenticated requester (and attempts are rate-limited).

A credential member is set by `credential_type` in its member entry (Section 8.2): `"password"` or `"passkey"` (vs. `"identity"`). It is **read-only** in v1 (see *Writes*). Each carries two independent pieces:

**1. Gate material** — what the server checks to authorize a request:
- *Passkey:* the credential's WebAuthn public key. On access the server runs a challenge-response (`401` + challenge → client returns a signed assertion → server verifies, Section 7.2). Nothing here is offline-attackable — the authenticator private key never leaves the device.
- *Password:* a `verifier`. The client sends an `auth_secret` over TLS; the server compares it to the verifier and rate-limits. A *compromised* server holding the verifier can brute-force the password offline, so passwords are the weaker option — prefer passkeys.

**2. Wrapped file key** — the file key wrapped to a `wrap_key` derived from the same credential and stored in `wrapped_file_key` (with `key_nonce`; the `ephemeral_key` ECIES fields are empty — wrapping is direct AES-256-GCM under `wrap_key`, not ECIES):
- *Passkey:* `wrap_key = HKDF-SHA256(WebAuthn-PRF(prf_salt))`.
- *Password:* `wrap_key = HKDF-SHA256(Argon2id(password, salt), info: "wrap")`.

**The gate key and the wrap key are domain-separated.** For passwords, `auth_secret = HKDF-SHA256(Argon2id(password, salt), info: "auth")` while `wrap_key` uses `info: "wrap"` — so the server learns `auth_secret` but can never derive `wrap_key`. The server gates access **without being able to decrypt**; end-to-end encryption is preserved.

**Access flow (GET):**

1. The server sees the file has credential members and challenges accordingly (Section 7.2).
2. The client proves a credential. The server verifies it against a member with `read` (or higher) and returns the file; otherwise `403`.
3. The client derives `wrap_key`, unwraps the file key from that member entry, and decrypts the body.

**Metadata exposure.** A password member's `verifier` and `salt` are brute-force material, so for a file with password members the server MUST require the same authorization for `HEAD` and directory listings as for `GET` — it must not reveal those fields to an unauthenticated requester. Passkey gate material (a public key) is safe to expose.

**Writes.** Modifying a file requires an Ed25519 signature by an identity key (Section 5.2); a credential member has none. So credential members are **read-only** in v1 — a credential-shared file is still authored and modified by its identity `owner`/`write` members. (Credential-based authorship would need a signing extension; out of scope for v1.)

**Browser fallback.** As with invitations (Section 6.4), a server may serve an HTML page that prompts for the password (or invokes the passkey) and fetches the file, so recipients without a native client can open a credential-shared file.

The identity key file (Section 2.11) is the canonical use of credential members: its body is the identity private key, its members are the passwords/passkeys that can unlock it.

---

## 4. System 3: Encryption — "Nobody else can read this"

### 4.1 Concept

Every file's body is encrypted with a **symmetric file key** (AES-256-GCM). The file key is then wrapped (encrypted) to each member — to an identity key via ECIES, or to a credential-derived key for credential members (Section 3.10). This two-layer approach means:

- Content is encrypted once, regardless of how members there are.
- Adding a member only requires wrapping the existing file key — no re-encryption of content.
- Removing a member requires generating a new file key and re-encrypting content (since the removed member knew the old key).

### 4.2 Encryption modes

The file metadata's `algorithm` field specifies whether and how the body is encrypted:

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
4. Each member entry in the metadata stores the `ephemeral_public`, `nonce`, and `wrapped_file_key`.

### 4.4 Decryption

When Alice decrypts a file:

1. Alice finds her member entry in the metadata (matched by identity key).
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

- **Mode B (server-hosted key):** All devices decrypt the same `identity.key` with Alice's password or passkey (Section 2.11) to obtain the private key. Any device can unwrap any file key.
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

Clients MUST support AES-256-GCM and `none` (unencrypted). ChaCha20-Poly1305 is recommended as an alternative (faster on devices without AES hardware acceleration). The algorithm used is indicated in the file metadata.

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

Every file modification is digitally signed by the author's identity key, and identity and group documents are self-signed. When data is delivered cross-server, the receiving server verifies these signatures directly — there is no separate transport signature — so it authenticates the author without decrypting the content. Identity forgery is mathematically impossible without the private key.

### 5.2 File signature

When Alice creates or modifies a file:

1. Alice computes an Ed25519 signature over the canonical serialization of the metadata fields (`file_id`, timestamps, members, algorithm, `modified_by` — Section 8.2) plus the SHA-256 hash of the body:
   ```
   signature = Ed25519_Sign(
     identity_private_key,
     metadata_fields || SHA-256(body)
   )
   ```
2. The signature is stored in the metadata's `signature` field.
3. Any server or client can verify by fetching the modifier's identity document and checking the identity key.

### 5.3 Cross-server verification

Files are POSTed to a recipient's `.ark/inbox/` directly (Section 7.3) — there is no transport wrapper and no separate transport signature. The receiving server authenticates the payload by its own signature:

- **File:** verify the metadata signature (Section 5.2) against the identity key of `modified_by`. The verified `modified_by` is the sender, used for the contacts/membership gate (Section 7.3).
- **Identity document:** verify the document's self-signature against the key it contains.

If verification fails, the delivery is rejected with `403 Forbidden`.

**Cache policy for identity documents:**
- Servers cache fetched identity documents for a configurable period (default: 1 hour).
- If a signature fails to verify, the server re-fetches the identity document (the key may have changed via transition) and retries verification once.

### 5.4 Non-repudiation

The Ed25519 signature provides **non-repudiation**: Alice can prove to a third party that Bob authored a specific file. This is a deliberate design choice — you *want* proof of who sent what (contracts, agreements, records).

---

## 6. System 5: Delivery Control — "Who can reach you"

### 6.1 Concept

Spam is possible because anyone can send to anyone. This protocol inverts that: by default, only your contacts can deliver to your inbox. Accounts that want to receive from anyone (e.g., `info@business.com`) opt into a public inbox.

By default, the `/akr/<user>/.ark/inbox/` directory has the permission `group:contacts = "write"`. To opt into a public inbox, change the permission to `* = "write"`.

### 6.2 Public vs. private inboxes

The identity document includes a `public` flag:

```json
{
  "version": 1,
  "address": "alice@example.com",
  "key": { "algorithm": "ed25519", "public_key": "..." },
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

A user's contacts are a **group** (Section 3.9) — the built-in contacts group, whose document is at `/ark/<user>/.ark/contacts.json` (a `Group`, Section C.7). Its members are the user's contacts. Delivery control reduces to group membership: a sender may deliver iff its identity key is a member of the recipient's contacts group. Matching is by **identity key**, not address. This means:
- Bob can change servers and remain a contact as long as he keeps the same identity key.
- Someone who registers `bob@attacker.com` with a different key is NOT a contact.

The contacts group is an allowlist by default (no group keypair, so no `.key` file). If the user gives it a keypair, it doubles as a "share with all my contacts" group.

**How contacts are added:**
- Alice adds Bob manually (out-of-band exchange of addresses).
- Alice replies to Bob → Bob is automatically allowlisted.
- Bob redeems an invitation created by Alice (see Section 6.4).
- Alice removes Bob → future deliveries from Bob are rejected.

**Delivery flow:**

When a file arrives for a user with `public: false`:
1. The server verifies the file's signature and takes `modified_by` as the sender (Section 5.3).
2. The server checks if the sender's identity key is in the recipient's contacts allowlist.
3. If not in contacts → reject with `403 Forbidden`.
4. If in contacts → accept delivery.

For users with `public: true`, step 2–3 are skipped.

### 6.4 Invitations

Invitations allow adding someone to your contacts via a shareable link or QR code.

**Creating an invitation:**

The client generates a random token and PUTs an invitation file (Section C.5) at that token:

```
PUT /ark/alice/.ark/invitations/<token>.json
Authorization: ArkUser <signature>
Content-Type: application/json

{
  "max_uses": 1,
  "expires": "2026-05-10T00:00:00Z"
}
```

Both `max_uses` and `expires` are optional. If omitted, the invitation is single-use with no expiry.

**Redeeming an invitation:**

```
POST /ark/alice/.ark/invitations/<token>
Content-Type: application/json

<the redeemer's identity document — see Section C.1>
```

The body is the redeemer's identity document. The server validates the token (not expired, uses remaining), adds the redeemer's key to Alice's contacts allowlist, and returns Alice's identity document so the redeemer can add Alice in turn. Returns `404` if the token is invalid/expired.

**Sharing invitations:**

Invitations are shared as regular HTTPS URLs: `https://example.com/ark/alice/.ark/invitations/<token>`

- **QR code**: Encode the URL. Recipient scans, their client POSTs to redeem.
- **Web fallback**: A GET to `invitations/<token>.html` serves an HTML page with a confirm button for users without a native client.

### 6.5 Account creation

An account is created by PUTting an identity document to its address. No authentication is required when the file does not yet exist — the document is self-signed (Section C.1), so the server verifies the signature against the `key` it contains:

```
PUT https://example.com/ark/alice/.ark/identity.json
Content-Type: application/json

{
  "version": 1,
  "address": "alice@example.com",
  "public": false,
  "key": { "algorithm": "ed25519", "public_key": "base64url-encoded" },
  "updated": "2026-04-11T12:00:00Z",
  "signature": { "algorithm": "ed25519", "signature": "base64url-encoded" }
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
2. **Cross-server delivery** — POSTing files to other users' `.ark/inbox/`.
3. **Cross-server sync** — keeping shared files in sync between co-members' servers.

### 7.2 Local file access

Alice's client communicates with her home server over HTTPS.

**Authentication:** Every request is signed with the identity key:
```
Authorization: ArkUser <signature-over-method-path-timestamp-body>
X-Ark-Timestamp: 1712838400
```
The server verifies the signature against the identity key in Alice's identity document. Requests with timestamps older than 5 minutes are rejected (replay protection).

**Credential authentication.** Requests for files with credential members (Section 3.10) authorize with a credential instead of an identity signature:
- `Authorization: ArkPasskey <assertion>` — a WebAuthn assertion over a server challenge. The server issues the challenge with `401 Unauthorized` and `WWW-Authenticate: ArkPasskey challenge=<nonce>`; the client retries with the signed assertion.
- `Authorization: ArkPassword <auth_secret>` — the password-derived auth secret (Section 3.10), sent over TLS and rate-limited.

The server verifies the proof against the file's credential members before serving. For a file with password members, the server applies the same check to `HEAD` and directory listings (Section 3.10).

**File operations:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/ark/alice/path/to/file` | Fetch body + `X-Ark-Metadata` |
| `HEAD` | `/ark/alice/path/to/file` | Fetch `X-Ark-Metadata` only |
| `PUT` | `/ark/alice/path/to/file` | Create or update a file |
| `DELETE` | `/ark/alice/path/to/file` | Delete a file |
| `GET` | `/ark/alice/path/to/dir` | List directory contents |

**GET response:**

The raw body as the entity body (`Content-Type: application/x-ark`), with the metadata blob in the `X-Ark-Metadata` header (Section 8.3). The body is the file content itself — ciphertext for encrypted files, raw bytes for `algorithm = "none"` — so non-Ark clients can use it directly and ignore the header.

**HEAD response:**

`X-Ark-Metadata` (the full signed blob — member entries, wrapped keys, everything) plus `Content-Length`, with no body. The metadata blob is the authoritative source; servers may add convenience headers (e.g. `X-Ark-Modified`) but those are non-signed and derived.

**Special endpoints:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/ark/alice/.ark/identity.json` | Identity document (JSON) |
| `GET` | `/ark/alice/.ark/identity.key` | Identity private key, Mode B — credential-gated (Sections 2.11, 3.10) |
| `GET` | `/ark/alice/.ark/identity.html` | Contact card (HTML) |
| `GET` | `/ark/alice/.ark/contacts.json` | Contacts group document (members = contacts) |
| `PUT` | `/ark/alice/.ark/contacts.json` | Update contacts group |
| `PUT` | `/ark/alice/.ark/invitations/<token>.json` | Create invitation |
| `POST` | `/ark/alice/.ark/invitations/<token>` | Redeem invitation |
| `GET` | `/ark/alice/.ark/invitations/<token>.html` | Invitation page (HTML) |
| `GET/HEAD` | `/ark/alice/.ark/paths/<file_id>` | Resolve file ID to path (sync recovery) |
| `GET` | `/ark/alice/.ark/stream` | Real-time event stream (WebSocket/SSE) |

### 7.3 Cross-server delivery

When Bob sends a file to Alice — whether a brand-new file or an update to one she already has:

**Step 1: Store locally.** Bob's client creates or updates the file on Bob's server via PUT.

**Step 2: Deliver.** Bob's server POSTs the file directly to Alice's `.ark/inbox/` — the body as the entity body, the metadata in `X-Ark-Metadata`:

```
POST https://example.com/ark/alice/.ark/inbox/
Content-Type: application/x-ark
X-Ark-Metadata: <base64 metadata blob>

<raw body>
```

There is no transport wrapper — the metadata is self-authenticating, so no HTTP-level authentication is required. A request with no `X-Ark-Metadata` and a JSON body is an identity document (a move notification — Section 7.4); otherwise it is a file. For a file, the server verifies the metadata signature and takes `modified_by` as the sender (Section 5.3), then resolves it by `file_id` (the server indexes `file_id` → path, Section 7.6):

1. **`file_id` already exists in Alice's account** (an update) — the server checks the sender is a member of the **existing local** file (not the incoming one, which a spoofer could pad). If so, and the incoming `modified` is newer, the local copy is updated in place at its current path; if older, discarded. The contacts allowlist is **not** consulted.
2. **`file_id` is new** (a new delivery) — the server checks the contacts allowlist (Section 6.3). If the sender is a contact, the file is written to `.ark/inbox/` keyed by `file_id`; otherwise rejected.

In both cases the server also rejects the file unless the **receiving account is itself a member of it** (directly, or through a group it belongs to). A server only accepts files its owner actually belongs to — so a redirected or misaddressed file, even from a contact, is dropped rather than littering the inbox with an undecryptable blob.

Client-side apps inspect new files in `.ark/inbox/` and claim them based on content or directory conventions. Once a file is claimed (moved to a path), later updates resolve by `file_id` and land in place — no second inbox copy, no `message_id` needed.

**Response codes:**

| Code | Meaning |
|---|---|
| `202 Accepted` | Accepted — written to `.ark/inbox/`, or applied in place. |
| `400 Bad Request` | Malformed file or document. |
| `403 Forbidden` | Signature, contacts, or membership check failed (incl. receiving account not a member of the file). |
| `404 Not Found` | Recipient does not exist on this server. |
| `429 Too Many Requests` | Rate limited. Includes `Retry-After` header. |
| `507 Insufficient Storage` | Recipient's storage is full. |

**Delivery retries:**
- If delivery fails (server down, network error), the sending server retries with exponential backoff (1 min, 5 min, 30 min, 2 hours, 8 hours) for up to 72 hours, then returns a bounce notification to the sender. Retries are idempotent — re-delivering the same `file_id` + `modified` is a no-op (newest-wins).

### 7.4 Cross-server sync

Updating a shared file uses the same delivery path as a new file (Section 7.3): the updated file is pushed to each co-member's `.ark/inbox/`, and because its `file_id` already exists in their account, each server applies it in place (newest-`modified`-wins, sender checked against the existing local file's member list). There is no separate sync message type.

**No path knowledge required.** The sender doesn't need to know where the receiver stores their copy. The receiver's server resolves `file_id` → local path internally.

**Member moved notification:**

When a member migrates to a new server (Section 2.9), they announce it by POSTing their **new identity document** (Section C.1) to co-members' `.ark/inbox/` as a JSON body with no `X-Ark-Metadata` header — that absence is what distinguishes it from a file, so no marker is needed.

Each co-member verifies the document's signature and matches its `key` against the one they have pinned (TOFU). The key is unchanged, so it is the same member at a new address, and the client updates that member's address in shared files. Trust is preserved because the identity key never changed.

**Sync recovery (pull fallback):**

If a server misses pushed updates (e.g., downtime exceeding the retry window), members can pull the latest version of a shared file directly from a co-member's server. The requester doesn't know the co-member's local path, so it first resolves the `file_id`:

```
GET https://example.com/ark/alice/.ark/paths/<file_id>
Authorization: ArkUser <signature>
```

The server resolves `file_id` to the local path and returns it. Returns `404` if the file_id is unknown. The requester then HEADs or GETs the file at that path; membership is enforced on the file read itself.

**Recovery flow:** On startup (or periodically), a client resolves each shared file's path via `.ark/paths/<file_id>`, then HEADs the file. If the remote `modified` timestamp is newer than the local copy, the client fetches the full file via GET.

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
│  ├── Inbox delivery (POST .ark/inbox/)       │
│  └── WebSocket/SSE (.ark/stream)             │
├──────────────────────────────────────────────┤
│  Filesystem Storage                          │
│  ├── /ark/<user>/ (encrypted files)          │
│  ├── /ark/<user>/.ark/inbox/ (incoming)      │
│  └── /ark/<user>/.ark/contacts.json (allowlist)│
├──────────────────────────────────────────────┤
│  Outbound Relay                              │
│  ├── Queue for outgoing deliveries           │
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
6. Or users self-register by PUTting their identity document to `/ark/<user>/.ark/identity.json`.
7. Alice's client generates her keypair and registers her public key (`identity.json`); a Mode B client also uploads the encrypted `identity.key` (Section 2.11).

**Storage:**
- Filesystem (one that supports extended attributes). The body is stored on disk as the file's bytes; the signed metadata blob lives in the file's `user.ark` xattr (Section 8.3). The server is essentially an authenticated file server. No database required for user data.
- The server maintains a lightweight index (e.g., SQLite) mapping `file_id` → local path (required for sync) and caching directory listings and metadata queries. The files (body + xattr) are the source of truth.
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

### 8.1 File and metadata

An Ark file is split into two parts that live and travel separately:

- **Body** — the file content itself, stored as the file's bytes on disk:
  - `algorithm = "none"`: the raw file bytes (a public `.html` is stored and served verbatim).
  - encrypted (`aes-256-gcm` / `chacha20-poly1305`): `nonce (12 bytes) ‖ ciphertext + tag`.
- **Metadata** — a signed Protocol Buffers blob (Section 8.2) holding everything else: `file_id`, members + wrapped keys, permissions, timestamps, algorithm, signature. It is **not** part of the body; it is stored and carried out-of-band (Section 8.3).

Because the body is just the file content, a decrypted file (or a public unencrypted file) is a normal, directly usable file — no prefix to strip. The metadata accompanies it out-of-band.

### 8.2 Metadata

The metadata is a single Protocol Buffers blob. It is signed and stored/transmitted **verbatim** — never decomposed into separate attributes or headers (decomposition would reintroduce a canonicalization problem for the signature).

```protobuf
syntax = "proto3";

message Metadata {
  uint32 version = 1;                   // Format version (1)
  bytes file_id = 2;                    // 16 bytes, random UUID, immutable after creation

  uint64 created = 3;                   // Unix milliseconds
  uint64 modified = 4;                  // Unix milliseconds

  repeated Member members = 5;

  string algorithm = 6;                 // "aes-256-gcm", "chacha20-poly1305", or "none"
  string encryption_algorithm = 7;      // "x25519" — target for deriving the ECIES wrapping key

  string modified_by = 8;              // "alice@example.com"
  string signature_algorithm = 9;      // "ed25519"
  bytes signature = 10;                // Ed25519 over fields 1-9 + SHA-256(body)
}

message Member {
  string address = 1;                   // "alice@example.com" or a local group path (Section 3.9)
  string identity_key_algorithm = 2;   // "ed25519"
  bytes identity_key = 3;              // Member's (or group's) public key
  string permission = 4;               // "owner", "write", or "read"

  // File key wrapped for this member.
  // Identity members: ECIES (ephemeral_key set). Credential members: direct
  // AES-256-GCM under wrap_key (ephemeral_key empty), see Section 3.10.
  string ephemeral_key_algorithm = 5;  // "x25519" (identity members)
  bytes ephemeral_key = 6;            // Ephemeral public key (32 bytes); empty for credential members
  bytes key_nonce = 7;                // AES-256-GCM nonce for key wrapping (12 bytes)
  bytes wrapped_file_key = 8;         // File key wrapped to this member (32 bytes + 16 byte tag)

  // Credential members (Section 3.10). credential_type defaults to "identity".
  string credential_type = 9;          // "identity" (default), "password", or "passkey"
  // Password credential
  string kdf = 10;                     // "argon2id"
  string kdf_params = 11;              // e.g. "m=1048576,t=3,p=4"
  bytes kdf_salt = 12;                // Argon2id salt (shared by auth_secret and wrap_key derivation)
  bytes verifier = 13;                // server-checked gate value (e.g. SHA-256 of auth_secret)
  // Passkey credential
  bytes webauthn_credential_id = 14;  // selects the authenticator
  bytes webauthn_public_key = 15;     // gate: verifies WebAuthn assertions
  bytes prf_salt = 16;                // input to the WebAuthn PRF (derives wrap_key)
}
```

The signature covers fields 1–9 of the canonical (deterministic) protobuf serialization plus `SHA-256(body)`, so the metadata and body are cryptographically bound even though they are stored apart — a body cannot be swapped under a signed metadata blob.

### 8.3 Metadata storage and transport

**At rest.** The metadata blob is stored in a single extended attribute, `user.ark`, on the body file. Ark requires a filesystem that supports extended attributes; those without them are unsupported. Updates are atomic: write the new body to a temporary file in the same directory, set its `user.ark` xattr, `fsync`, then `rename` over the target. The rename swaps body and metadata together, so neither a concurrent reader nor a crash ever sees a body that disagrees with its metadata.

**In transit.** Over HTTP the metadata travels as one header, base64-encoded:

```
X-Ark-Metadata: <base64 of the metadata blob>
```

`GET` returns the body as the HTTP entity body plus `X-Ark-Metadata`; `HEAD` returns `X-Ark-Metadata` with no body; `PUT` and inbox `POST` send both. Because the entity body is always the raw file, there is no separate "raw" form — a non-Ark client (e.g. a browser fetching a public file) simply ignores the `X-Ark-Metadata` header.

**Size budget.** The blob must fit a single xattr value; the binding constraint is ext4's ~4 KB per-inode limit. A blob is ~120 B fixed plus ~150–200 B per member entry, so a file with a handful of members — or a single group member (Section 3.9) — sits far under it. Past ~25 direct members, use a group. The same budget keeps `X-Ark-Metadata` within proxies' HTTP header-size limits.

### 8.4 Identity and contacts documents

Identity documents and contacts are JSON (human-readable, easy to debug with curl). See Section 2.4 for the identity document schema.

### 8.5 Serialization rules

- **Metadata:** Protocol Buffers (binary), stored verbatim in the `user.ark` xattr and the `X-Ark-Metadata` header.
- **Identity documents, contacts:** JSON. Human-readable.
- **Signatures:** computed over the canonical protobuf serialization of metadata fields 1–9 (deterministic encoding) plus `SHA-256(body)`.
- **All binary values in JSON:** base64url encoding (RFC 4648, no padding).

---

## 9. Threat Model

### 9.1 What is protected

| Property | Guarantee |
|---|---|
| **Data confidentiality** | Only holders of the file key can read file content. Servers see only ciphertext (Mode A, and Mode B without a server recovery member). |
| **Author authentication** | Files, identity, and group documents are signed by the author's identity key. Forgery requires the private key. |
| **Integrity** | Any modification to a file invalidates the signature. Any modification to the ciphertext invalidates the AEAD tag. |
| **Spam resistance** | Only contacts can deliver to private inboxes. Public inboxes are opt-in. |
| **Data persistence (static mode)** | All static-mode files can be decrypted with the single identity key (which unwraps file keys). No session state to lose. |

### 9.2 What is NOT protected

| Risk | Details |
|---|---|
| **Metadata** | File paths, sizes, timestamps, member addresses, and cross-server delivery patterns are visible to the server and network observers. Path names may reveal content intent (e.g., `/notes/tax-2025`). |
| **Forward secrecy** | If the identity private key is compromised, all file keys can be unwrapped, and all past and future data can be decrypted. This is a deliberate tradeoff for simplicity and recoverability. |
| **Mode B server trust** | The key is client-generated and uploaded encrypted, so a Mode B server can read data only if it holds a credential — a **server recovery member** (Section 2.11). Without one it stores ciphertext it cannot read. Self-hosters mitigate either way by controlling the server. |
| **Password member brute force** | `identity.key` (and any password-gated file) is served only after the server verifies the credential, so it is not freely downloadable — online attempts are rate-limited. A *compromised* server holding the `verifier` can still brute-force a password member offline (Sections 2.11, 3.10). Passkey members are hardware-bound and resist even that. |
| **Removed member's existing copy** | When a member is removed from a shared file, they retain any copy they already downloaded. Re-keying prevents access to future edits, not past content. |
| **Path metadata** | File paths are unencrypted (the server needs them for routing). Path names like `/mail/inbox/` or `/notes/secret-project` are visible to the server. For maximum privacy, use opaque paths. |
| **Unencrypted files** | Files with `algorithm = "none"` have no confidentiality protection. The body is readable by the server, network observers (if TLS is broken), and anyone with read access. Integrity and authenticity are still provided by the file signature. |

### 9.3 Compromise scenarios

**Scenario: Alice's server is compromised (Mode A — client-managed key)**
- Attacker can see metadata (paths, sizes, timestamps, who Alice shares with).
- Attacker **cannot** read file content (doesn't have Alice's private key to unwrap file keys).
- Attacker **cannot** forge files from Alice (doesn't have her signing key).
- Attacker could serve a fake identity document with a different public key. Mitigations: (1) existing contacts have Alice's key pinned via TOFU, (2) verified contacts will see a safety number change warning.

**Scenario: Alice's server is compromised (Mode B — server-hosted key)**
- *With a server recovery member*: the attacker gets Alice's private key, **can** read all files (past and future, until the key is rotated), and **can** forge files from Alice. This is the tradeoff of opting into server recovery.
- *Without a server recovery member*: the attacker holds the `identity.key` file and its metadata (a password member's `verifier` and `salt`), so they can brute-force a password member offline; passkey members are not attackable this way. Until a password is cracked, the attacker **cannot** read files or forge as Alice.
- Mitigation: omit the server recovery member, use passkey members, and choose a strong passphrase — or use Mode A for high-security needs.

**Scenario: Alice's identity key is compromised (either mode)**
- Worst case. Attacker can impersonate Alice and decrypt all data.
- Mitigation: Alice performs a key transition (Section 2.7). After transition, new files use the new key and are safe.

**Scenario: Shared file key is compromised**
- Only the specific file is affected, not Alice's other data.
- Mitigation: re-key the file (generate new file key, re-encrypt body, re-wrap for all members).

**Scenario: Server-to-server traffic is intercepted (TLS broken)**
- Attacker sees files in transit. They can see metadata (the metadata blob is plaintext).
- Attacker **cannot** read file content (E2E encrypted independent of TLS).
- Attacker **cannot** forge files (signatures are verified).
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

Each file in the sequence is still a standard Ark file (same binary format, same transport, same inbox delivery). The only difference is how the file key is derived — from the ratchet chain instead of random + ECIES.

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
6. Alice stores the ratchet state locally and sends the first file in the sequence with her ephemeral public key (`EK_A`) and the one-time prekey identifier in the file metadata, so Bob can compute the same root key.

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
4. The sender's new ratchet public key is included in the file metadata's `ratchet_key` field.

**Metadata fields for ratcheted files:**

| Field | Purpose |
|---|---|
| `key_derivation` | `"ratchet"` |
| `sequence_id` | Identifies the ratchet session (random 16 bytes, set at session creation) |
| `message_index` | Monotonic counter — position in the ratchet chain |
| `ratchet_key` | Sender's current DH ratchet public key (X25519, 32 bytes) |

The `members` list still exists in the metadata but `wrapped_file_key` fields are empty — the file key is derived from the ratchet, not wrapped via ECIES.

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

- Ratcheted files are standard Ark files — same format, same transport, same inbox delivery. The Metadata protobuf is extended with `key_derivation`, `sequence_id`, `message_index`, and `ratchet_key` fields.
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
   - The gateway generates a keypair on the alias's behalf and holds it — the legacy recipient has no client of their own, so the gateway can display their messages. This is the legacy-interop trust trade-off (the gateway can read these messages).
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
  "key": {
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
2. The bridge receives the email, wraps the content in an Ark file, and delivers it to Alice's `.ark/inbox/` like any file.
3. The file is marked as "received via email (unencrypted)" in Alice's client.

**Security note:** Bridged messages are not encrypted in transit. The bridge sees plaintext during processing. These files should be clearly distinguished from native Ark files in the client UI.

### 10.3 Metadata Privacy

A future version could add onion routing or mixnet support to hide metadata (sender/recipient/timing) from servers and network observers. The protocol's separation of routing (the inbox path) from content makes this possible without changing the core file format.

### 10.4 Collaborative Editing (CRDTs)

V1 uses last-write-wins for shared files. A future extension could support real-time collaborative editing via CRDTs (Conflict-free Replicated Data Types):

- File body would be an encrypted operation log instead of a snapshot.
- Each edit appends an encrypted CRDT operation (e.g., Yjs or Automerge format).
- Clients replay operations to reconstruct current state.
- This would be opt-in per file and coexist with the default snapshot model.

---

## Appendix A: Configuration

### A.1 Server Configuration (`ark.toml`)

```toml
domain = "example.com"
listen = "0.0.0.0:443"
tls = true
acme_email = "admin@example.com"
max_account_size = "1GB"
max_file_size = "100MB"
max_delivery_size = "25MB"
allow_remote_registration = true
legacy_gateway = ""
```

| Field | Type | Required | Description |
|---|---|---|---|
| `domain` | string | Yes | Server's public hostname. |
| `listen` | string | No | Bind address and port. Default `0.0.0.0:443`. |
| `tls` | boolean | No | Enable built-in TLS. Disable if behind a reverse proxy. Default `true`. |
| `acme_email` | string | No | Email for Let's Encrypt certificate provisioning. |
| `max_account_size` | string | No | Maximum storage per account. Default `1GB`. |
| `max_file_size` | string | No | Maximum single file size. Default `100MB`. |
| `max_delivery_size` | string | No | Maximum size of a file delivered to an inbox. Default `25MB`. |
| `allow_remote_registration` | boolean | No | Allow account creation via PUT `/ark/<user>/.ark/identity.json`. Default `true`. |
| `legacy_gateway` | string | No | Gateway server address for legacy email interop (Section 10.2). Default empty. |

## Appendix B: Endpoints

All Ark endpoints are under `https://<domain>/ark/<user>/`.

Most endpoints are standard file resource requests:

| Endpoint | Body | Response | Purpose |
|---|---|---|---|
| `GET    /ark/<user>/<dir_path>` | - | `DirectoryEntry[]` | List directory entries |
| `HEAD   /ark/<user>/<file_path>` | - | - | Fetch metadata (`X-Ark-Metadata`) |
| `GET    /ark/<user>/<file_path>` | - | `File` | Fetch file |
| `PUT    /ark/<user>/<file_path>` | `File` | - | Create or update file |
| `DELETE /ark/<user>/<file_path>` | - | - | Delete file |

The `/ark/<user>/.ark/` directory is a special directory that is limited to specific Ark files. These files are of the format specified instead of the standard `File` format:

- `/ark/<user>/.ark/contacts.json`: `Group` (Section C.7) — the user's contacts group. Only its members can deliver files to `<user>`.
- `/ark/<user>/.ark/contacts.key`: contacts group private key, wrapped per member. Members-only. Present only if the contacts group has a keypair.
- `/ark/<user>/.ark/groups/<name>.json`: `Group` (Section C.7).
- `/ark/<user>/.ark/groups/<name>.key`: group private key, wrapped per member. Members-only.
- `/ark/<user>/.ark/identity.html`: Contact HTML page, auto-generated, HEAD/GET only, no authentication required. This should contain a link to add the user to your contacts.
- `/ark/<user>/.ark/identity.json`: `Identity`, no authentication required for PUT if creating new file. The creation of this file creates a new user.
- `/ark/<user>/.ark/identity.key`: `File` (Section 8, C.12) whose body is the Mode B identity private key, with credential members (Sections 2.11, 3.10). GET/HEAD require a valid credential proof (Section 7.2); PUT requires the identity (owner) key.
- `/ark/<user>/.ark/inbox/<file_id>`: `File` (or an `Identity` document for a move notification). New files are keyed by `file_id`; senders in `/ark/<user>/.ark/contacts.json` allowed for new files, existing-file members for updates (Section 7.3).
- `/ark/<user>/.ark/invitations/<token>.html`: Invitation HTML page, auto-generated, no authentication required. This should contain a link to redeem the invitation i.e. add yourself to their contacts (HEAD/GET only, no authentication required)
- `/ark/<user>/.ark/invitations/<token>.json`: `Invitation`
- `/ark/<user>/.ark/paths/<file_id>`: File path e.g. `/ark/<user>/my_dir/my_file.txt`, auto-generated, HEAD/GET only, users listed in `/ark/<user>/.ark/contacts.json` allowed.

The following are special requests that do not fit the standard file resource model:

| Endpoint | Body | Response | Purpose |
|---|---|---|---|
| `POST   /ark/<user>/.ark/invitations/<token>` | `Identity` | `Identity` | Redeem an invitation. The body is the identity of the redeemer, the response is the identity of `<user>`. |
| `GET    /ark/<user>/.ark/stream` | - | `Event` stream | Subscribe to a real-time event stream |

---

## Appendix C: Types

### C.1 Identity

```json
{
  "version": 1,
  "address": "alice@example.com",
  "public": false,
  "key": Key,
  "updated": "2026-04-11T12:00:00Z",
  "signature": Signature,
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | integer | Yes | Protocol version. Currently `1`. |
| `address` | string | Yes | Full `user@domain` address. |
| `public` | boolean | No | If `true`, inbox accepts delivery from anyone. Default `false`. |
| `key` | Key | Yes | The key that identifies the user. |
| `updated` | string | Yes | ISO 8601 timestamp of last update. |
| `signature` | Signature | Yes | A signature over all fields above by the identified user. |

**Optional extension fields (Section 10.1):**

| Field | Type | Description |
|---|---|---|
| `prekeys.signed_prekey` | string | Base64url X25519 public key for ratchet session establishment. |
| `prekeys.signed_prekey_signature` | string | Ed25519 signature over the signed prekey. |
| `prekeys.one_time_prekeys` | string[] | List of single-use base64url X25519 public keys. |

### C.2 Alias Identity Document

```json
{
  "version": 1,
  "type": "alias",
  "redirect": "alice@example.com"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | integer | Yes | Protocol version. |
| `type` | string | Yes | `"alias"`. |
| `redirect` | string | Yes | Primary address to redirect to. |

### C.3 Legacy Email Identity Document (Section 10.2)

```json
{
  "version": 1,
  "type": "legacy_email",
  "address": "x-a7f3k2m9p4q8r2@gateway.example.com",
  "legacy_email": "carol@gmail.com",
  "key": {
    "algorithm": "ed25519",
    "public_key": "<base64url>"
  },
  "notify": true,
  "updated": "2026-04-14T12:00:00Z",
  "signature": {
    "algorithm": "ed25519",
    "signature": "<base64url>"
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | `"legacy_email"`. |
| `legacy_email` | string | Yes | Original email address this account represents. |
| `notify` | boolean | Yes | Whether notification emails are sent on delivery. |

All other fields follow the standard identity document schema (C.1).

### C.4 Key Transition Document

```json
{
  "type": "key_transition",
  "old_key": "<base64url>",
  "new_key": "<base64url>",
  "old_signs_new": "<base64url>",
  "new_signs_old": "<base64url>",
  "reason": "scheduled_rotation",
  "timestamp": "2026-04-11T12:00:00Z"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | `"key_transition"`. |
| `old_key` | string | Yes | Base64url old identity public key. |
| `new_key` | string | Yes | Base64url new identity public key. |
| `old_signs_new` | string | Yes | Signature of new key by old key. |
| `new_signs_old` | string | Yes | Signature of old key by new key. |
| `reason` | string | No | Human-readable reason (e.g., `"scheduled_rotation"`, `"key_compromise"`). |
| `timestamp` | string | Yes | ISO 8601 timestamp. |

### C.5 Invitation

```json
{
  "max_uses": 1,
  "expires": "2026-05-10T00:00:00Z"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `max_uses` | integer | No | Maximum redemptions. Default: `1`. |
| `expires` | string | No | ISO 8601 expiry. Default: no expiry. |

### C.6 DirectoryEntry

```json
{
  "type": "file",
  "name": "todo",
  "size": 4096,
  "modified": "2026-04-11T12:00:00Z",
  "modified_by": "alice@example.com"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | `"directory"` for subdirectories, `"file"` for files. |
| `name` | string | Yes | Entry name. |
| `size` | integer | No | File size in bytes. Absent for directories. |
| `modified` | string | No | ISO 8601 last modification time. Absent for directories. |
| `modified_by` | string | No | Address of last modifier. Absent for directories. |

### C.7 Group (Section 3.9)

Like an identity document, but identifies a set of members instead of a single address. This is the public group document; the matching private key lives in the members-only `.key` file. Addressed by its local path (Section 2.2).

```json
{
  "version": 1,
  "members": Member[],
  "key": Key,
  "updated": "2026-04-11T12:00:00Z",
  "signature": Signature
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | integer | Yes | Protocol version. |
| `members` | array | Yes | Group members (`Member[]`), each with a permission within the group. |
| `key` | Key | No | Current group public key. Present when the group is used for sharing; absent for allowlist-only groups (e.g. a contacts group with no shared files). |
| `updated` | string | Yes | ISO 8601 timestamp of last update. |
| `signature` | Signature | Yes | An `owner` member's signature over all fields above. |

### C.8 Event

```json
{"event": "created", "path": "/ark/alice/.ark/inbox/abc123", "from": "bob@example.com"}
{"event": "modified", "path": "/ark/alice/notes/todo", "modified_by": "alice@example.com"}
{"event": "deleted", "path": "/ark/alice/mail/trash/old-msg"}
{"event": "sync", "path": "/ark/alice/docs/project-plan", "file_id": "def456"}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `event` | string | Yes | `"created"`, `"modified"`, `"deleted"`, or `"sync"`. |
| `path` | string | Yes | Path of affected file. |
| `from` | string | No | Sender address (for `created` events from delivery). |
| `modified_by` | string | No | Modifier address (for `modified` events). |
| `file_id` | string | No | File ID (for `sync` events). |

### C.9 Key

```json
{
  "algorithm": "ed25519",
  "public_key": "<base64url>"
},
```

| Field | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | Yes | Signing algorithm e.g. `"ed25519"`. |
| `public_key` | string | Yes | Base64url-encoded public key. |

### C.10 Signature

```json
{
  "algorithm": "ed25519",
  "signature": "<base64url>"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | Yes | Signing algorithm e.g. `"ed25519"`. |
| `signature` | string | Yes | Base64url-encoded signature. |

### C.11 Member

```json
{
  "address": "alice@example.com",
  "key": Key,
  "permission": "owner"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `address` | string | Yes | Member's full address. |
| `key` | object | Yes | Member's identity key. |
| `permission` | string | Yes | `"owner"`, `"write"`, or `"read"`. |

### C.12 Identity key file (`identity.key`, Section 2.11)

Not a distinct document type — an ordinary Ark **File** (Section 8) served at `/ark/<user>/.ark/identity.key`:

- **Body:** the identity private key, encrypted with the file key (like any file body).
- **Members:** one or more **credential members** (Section 3.10, `credential_type` `"password"` / `"passkey"`) with `read` permission — the credentials that can unlock the key — plus the identity itself as an `owner` identity member (used to add/remove credentials). An optional server-controlled credential member enables admin recovery (Section 2.11).
- **Metadata / signature:** standard file metadata (Section 8.2), self-signed by the identity key. The signature binds the member list, so a malicious server cannot strip a credential member to force a downgrade.

The server verifies a credential before returning the body (Section 3.10), so the encrypted key is never served to an unauthenticated requester. There is no bespoke schema: a credential member's fields (`kdf`, `kdf_salt`, `verifier`, `webauthn_public_key`, `prf_salt`, `wrapped_file_key`, …) live in the `Member` message (Section 8.2).

---

## Appendix D: Cryptographic Algorithms

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
| Password member KDF (Section 3.10) | Argon2id | — | 256-bit wrapping key |
| Passkey member secret (Section 3.10) | WebAuthn PRF (`hmac-secret`) | — | 256-bit |

---

## Appendix E: Example Usage

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
    |  4. Sign file             |                          |                          |
    |                           |                          |                          |
    |  5. Store file on ------->|                          |                          |
    |     home server           |                          |                          |
    |                           |  6. Relay via HTTPS POST |                          |
    |                           |--------- file ---------->|                          |
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
