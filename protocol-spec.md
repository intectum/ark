# Encrypted Mail Replacement — Protocol Specification

> **Status:** Draft v0.3
> **Date:** 2026-04-14

## Table of Contents

1. [Overview](#1-overview)
2. [System 1: Identity](#2-system-1-identity--who-are-you)
3. [System 2: Encryption](#3-system-2-encryption--nobody-else-can-read-this)
4. [System 3: Authentication](#4-system-3-authentication--this-really-came-from-bob)
5. [System 4: Spam Resistance](#5-system-4-spam-resistance--sending-costs-effort)
6. [System 5: Transport](#6-system-5-transport--how-messages-move)
7. [Wire Formats](#7-wire-formats)
8. [Threat Model](#8-threat-model)
9. [Extensions](#9-extensions)

---

## 1. Overview

This protocol is a federated, encrypted, spam-resistant messaging system designed as a replacement for email. It has five core systems:

| System | Purpose |
|---|---|
| **Identity** | Who are you? Keypair mapped to a human-readable address. |
| **Encryption** | Nobody else can read your messages. Simple public-key encryption. |
| **Authentication** | Proof the message really came from the claimed sender. |
| **Spam Resistance** | Sending costs computational effort. No reputation systems needed. |
| **Transport** | How messages move between servers. Plain HTTPS, trivially self-hostable. |

### Design principles

- **Cryptographic identity, not reputation-based.** Your identity is a keypair, not an IP address or domain reputation score. This eliminates the entire class of deliverability problems that plague self-hosted email.
- **Encrypted by default.** All message content is end-to-end encrypted. Servers relay ciphertext they cannot read.
- **Simple to self-host.** A single binary, a single config file, a domain with an A record. That's it.
- **Federated, not peer-to-peer.** Servers provide reliable offline delivery and key hosting. Pure P2P systems (Bitmessage, Briar) struggle with reliability and adoption.
- **Spam-resistant by construction.** Proof of work + unforgeable identity + contact allowlists make bulk spam economically infeasible without complex filtering infrastructure.
- **Simple key model.** One keypair per identity, like a crypto wallet. Lose the key, lose the identity. Have the key, have all your messages. No complex session state to manage.
- **Flexible trust model.** Users choose where their private key lives — on their device (maximum security) or on their server (maximum convenience). Self-hosters get both.

### How a message flows (end to end)

```
Bob's Client                Bob's Server              Alice's Server             Alice's Client
    |                           |                          |                          |
    |  1. Fetch Alice's         |                          |                          |
    |     identity doc -------->|------- HTTPS GET ------->|                          |
    |  2. Receive public key    |<------ JSON response ----|                          |
    |                           |                          |                          |
    |  3. Generate ephemeral    |                          |                          |
    |     key, compute shared   |                          |                          |
    |     secret, encrypt msg   |                          |                          |
    |                           |                          |                          |
    |  4. Compute proof of work |                          |                          |
    |     (Argon2id, ~0.5s)     |                          |                          |
    |                           |                          |                          |
    |  5. Sign envelope         |                          |                          |
    |                           |                          |                          |
    |  6. Send to home server ->|                          |                          |
    |                           |  7. Relay via HTTPS POST |                          |
    |                           |------- envelope -------->|                          |
    |                           |                          |  8. Verify signature      |
    |                           |                          |  9. Verify PoW            |
    |                           |                          |  10. Store in inbox       |
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
4. This means the server *can* decrypt Alice's messages. Alice trusts her server.
5. Alice can export her seed phrase at any time and switch to Mode A.

**Why offer both modes?**

Most people will choose Mode B — it's how email works today (your email provider can read your email). It means:
- No seed phrase to lose.
- Seamless multi-device (server provides the key to each device).
- If you forget your password, the server admin can reset it (for self-hosters, you *are* the admin).

Security-conscious users choose Mode A — the server is purely a relay and storage node that cannot read messages.

**Self-hosters get the best of both worlds:** They control the server, so Mode B gives them convenience without trusting a third party. The private key is on infrastructure they own.

**Why Ed25519?**
- Fast signing and verification (important for per-message signatures).
- Small keys (32 bytes) and signatures (64 bytes).
- Deterministic — same input always produces the same signature (no nonce-reuse vulnerabilities).
- Well-audited, widely implemented, no known weaknesses.
- Easily converted to X25519 for encryption operations.

### 2.4 Identity document

Alice's public identity is published as a JSON document at a well-known URL on her server:

```
GET https://example.com/.well-known/sigil/identity/alice
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
| `policy` | Optional per-user policy overrides (Section 5.5.1). Includes `accept_registrations`, PoW difficulty overrides. |
| `signature` | Ed25519 signature over the entire document (excluding this field). Proves the identity key holder authored this. |

**The self-signature is the key security property** (for Mode A users). The server hosts this document but cannot tamper with it — any modification invalidates the signature. This means:
- A compromised server cannot swap in a different public key to intercept messages.
- A MITM attacker who compromises the TLS connection cannot forge the identity document.
- The document is self-authenticating: anyone can verify it using only the public key it contains.

Note: For Mode B users (server holds the private key), the server *could* sign a different identity document. The user is already trusting the server with their private key, so this doesn't change the trust model.

### 2.5 Key discovery

When Bob wants to message Alice for the first time:

1. Bob's client extracts the domain from `alice@example.com`.
2. Bob's client makes an HTTPS GET to `https://example.com/.well-known/sigil/identity/alice`.
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
- All devices can decrypt all messages (they all have the same identity private key).
- Each device also has its own **device signing key** (Ed25519) for authenticating API requests and signing outgoing messages.

**Mode A (client-managed key):**
- Alice sets up her first device with the seed phrase.
- To add a second device, Alice enters the seed phrase on the new device (or transfers the private key via QR code / secure channel).
- Each device also generates its own **device signing key**.
- The identity key signs each device key (proving "I, Alice, authorize this device").

**Device signing keys** are useful in both modes:
- They identify which device sent a message.
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

### 2.9 Account recovery

**Mode B (server-managed key):**
- The server holds the private key. Recovery is a standard password reset / admin intervention.
- Messages are stored on the server and remain accessible.
- This is the simplest recovery story — works like email.

**Mode A (client-managed key):**
- Alice enters her 24-word seed phrase on a new device.
- The client derives the identity keypair from the seed.
- The client registers the new device with Alice's server (the server recognizes the identity public key).
- Messages stored on the server (encrypted) can be decrypted because Alice has the same private key.

**What is lost if the seed phrase is lost (Mode A):**
- The identity key is gone. Alice must create a new account with a new keypair.
- Messages encrypted to the old key are unrecoverable.
- Contacts will see a new key and need to re-verify.

**No DNS complexity:**
- The server just needs a domain name pointing to it (A/AAAA record). That's it.
- No MX records, no SPF, no DKIM, no DMARC. Identity is cryptographic, not DNS-based.

### 2.10 Server migration

Alice can move from one server to another while keeping the same identity keypair.

**When the old server is still online:**

1. Alice creates an account on the new server with her existing identity key (Mode A: enters seed phrase; Mode B: transfers the private key).
2. Alice exports her messages from the old server and imports them to the new server. No re-encryption is needed — all messages are encrypted to the same identity key regardless of which server stores them.
3. Alice exports her contacts allowlist (list of trusted public keys) and imports it to the new server.
4. On the old server, Alice's identity document is replaced with an alias redirect:
   ```json
   {
     "type": "alias",
     "redirect": "alice@new-server.com"
   }
   ```
5. Anyone who sends to `alice@old-server.com` is seamlessly redirected to the new address. Contacts who have Alice's key pinned via TOFU won't be alarmed — it's the same key, just a new address.
6. After a transition period, Alice can delete her account on the old server.

**When the old server is gone:**

If Alice's old server goes offline (provider shut down, lost access), the alias redirect can't be set up. Contacts who send to the old address will get a DNS failure or 404. This is the same as losing an email provider — Alice needs to tell her contacts the new address out-of-band. When they look up her identity document on the new server, they'll see the same identity key they had pinned, confirming it's really her.

**What migrates:**
- Identity keypair (same key on both servers).
- Messages (download from old, upload to new — encrypted to same key).
- Contacts allowlist (export/import list of trusted public keys).
- Alias redirect on old server (if still online).

**What doesn't migrate automatically:**
- Other people's allowlists. Contacts who had Alice allowlisted on the old address may need to re-allowlist the new address. However, since allowlists are keyed by identity public key (not address), a smart server implementation can recognize that the same key is now at a new address and preserve the allowlist entry.

### 2.11 Aliases

A single identity (one keypair) can have **multiple addresses** that all resolve to the same account. One address is the **primary** and has a full identity document. All others are **aliases** that redirect to the primary.

**Alias identity document:**

```
GET https://example.com/.well-known/sigil/identity/old-alice
```

```json
{
  "version": 1,
  "type": "alias",
  "redirect": "alice@example.com"
}
```

When a sender encounters an alias document, they follow the `redirect` to fetch the real identity document and deliver the message to the primary address. The alias is transparent to the sender — they can address messages to either the alias or the primary, and they arrive in the same inbox.

**Use cases:**
- **Name changes.** Alice changes her username from `old-alice` to `alice`. The old address becomes an alias that redirects to the new one. Existing contacts who have the old address cached will be seamlessly redirected.
- **Vanity aliases.** Alice has `alice@example.com` as primary but also wants `a@example.com` as a short alias.
- **Generated aliases.** The server can create machine-generated aliases (e.g., hash-based) for special purposes like legacy email interop (see Section 9.2).

**Cross-server aliases** are not supported in v1. An alias must be on the same server as the primary address. Cross-server migration is handled by key transitions (Section 2.8) — the user creates a new account on the new server with the same identity key.

---

## 3. System 2: Encryption — "Nobody else can read this"

### 3.1 Concept

Messages are end-to-end encrypted using **public-key encryption**. Every message is encrypted with the recipient's public key. Only the recipient's private key can decrypt it. The encryption model is simple and stateless — like encrypting a letter in an envelope that only the recipient can open.

### 3.2 How encryption works (ECIES)

The protocol uses **ECIES** (Elliptic Curve Integrated Encryption Scheme) — a standard construction that combines ephemeral key exchange with symmetric encryption.

**When Bob sends a message to Alice:**

```
Alice's published key          Bob generates
──────────────────            ──────────────
PK_A (X25519 public key)      ek (ephemeral X25519 keypair, used once)
```

1. **Bob generates an ephemeral keypair:** A fresh, random X25519 keypair (`ek_private`, `ek_public`). This keypair is used for this one message only.

2. **Bob computes a shared secret:**
   ```
   shared_secret = X25519(ek_private, PK_A)
   ```
   This is a Diffie-Hellman operation. Only Bob (who has `ek_private`) and Alice (who has her identity private key) can compute this value.

3. **Bob derives an encryption key:**
   ```
   message_key = HKDF-SHA256(
     ikm: shared_secret,
     salt: ek_public || PK_A,
     info: "message-encryption",
     length: 32
   )
   ```

4. **Bob encrypts the payload:**
   ```
   nonce = random 12 bytes
   ciphertext, tag = AES-256-GCM(message_key, nonce, payload)
   ```

5. **Bob includes in the envelope:**
   - `ek_public` (32 bytes) — the ephemeral public key.
   - `nonce` (12 bytes) — the AES-GCM nonce.
   - `ciphertext` — the encrypted payload.
   - The tag is appended to the ciphertext (standard AES-GCM behavior).

6. **Bob discards `ek_private`.** It's never stored or transmitted.

**When Alice decrypts:**

1. Alice extracts `ek_public` from the envelope.
2. Alice computes the same shared secret using her private key:
   ```
   shared_secret = X25519(alice_private, ek_public)
   ```
3. Alice derives the same `message_key` using HKDF.
4. Alice decrypts the ciphertext with AES-256-GCM.

**Why ephemeral keys?**

Even without forward secrecy, each message uses a *different* ephemeral key. This means:
- Each message has a unique encryption key (no key reuse).
- Bob doesn't need to maintain any session state with Alice.
- Messages are independent — encrypting message #2 doesn't depend on message #1.
- If Alice's private key is compromised, an attacker can decrypt all messages (this is the tradeoff for simplicity — see Section 9.1 for the forward secrecy extension).

### 3.3 Why not PGP?

PGP/GPG uses a similar model (public-key encryption) but has well-known usability problems:
- Key management is manual and error-prone (keyrings, keyservers, web of trust).
- The PGP message format is complex and has accumulated decades of legacy.
- No standard for key discovery (keyservers are unreliable and have privacy issues).

This protocol uses the same fundamental cryptographic approach but with:
- Automatic key discovery via the identity document.
- A simple, modern wire format (Protocol Buffers).
- Built-in server infrastructure for key hosting and message relay.

### 3.4 Multi-device decryption

Since there's a single identity keypair per user, multi-device is straightforward:

- **Mode B (server-managed key):** All devices get the private key from the server. Any device can decrypt any message. The sender only encrypts once — to Alice's identity public key.
- **Mode A (client-managed key):** All devices derive the same private key from the seed phrase. Same result — any device can decrypt any message.

The sender always encrypts to **one key** (Alice's identity `encryption_key`). No need to encrypt separately per device.

### 3.5 Encryption algorithms

| Operation | Algorithm | Parameters |
|---|---|---|
| Identity keys (signing) | Ed25519 | — |
| Encryption key exchange | X25519 | — |
| Key derivation | HKDF-SHA256 | — |
| Message encryption | AES-256-GCM | 96-bit nonce, 128-bit tag |
| Alternative message encryption | ChaCha20-Poly1305 | 96-bit nonce, 128-bit tag |

Clients MUST support AES-256-GCM. ChaCha20-Poly1305 is recommended as an alternative (faster on devices without AES hardware acceleration). The algorithm used is indicated in the envelope.

### 3.6 Attachments

**Small attachments (< 1 MB):**
- Included directly in the encrypted payload alongside the message body.

**Large attachments (>= 1 MB):**
1. The sender encrypts the attachment using ECIES with the recipient's public key — the same method used for message payloads (Section 3.2). No separate key management.
2. The encrypted blob is uploaded to the sender's server at a unique URL.
3. The message payload (itself encrypted) includes:
   - The URL of the encrypted blob.
   - The SHA-256 hash of the encrypted blob (for integrity verification).
   - Filename, content type, and size.
4. The recipient's client fetches the blob, verifies the hash, and decrypts with their private key.

The server hosts the encrypted blob but cannot decrypt it (ECIES, same as any message). The sender's client also encrypts a copy to the sender's own key for the sent folder (see Section 3.7).

**Blob cleanup:** Encrypted blobs are deleted after a configurable retention period (default: 30 days).

### 3.7 Sent messages (encrypt to self)

When Bob sends a message to Alice, Bob's client also encrypts a copy of the message (and any attachments) to **Bob's own public key** and stores it on Bob's server in a "sent" folder.

This means:
- Bob can read his sent messages from any of his devices.
- The sent folder is encrypted the same way as the inbox — the server sees only ciphertext (Mode A) or can decrypt if it holds the key (Mode B).
- Bob's sent messages survive device changes (they're on the server, encrypted to his identity key).
- No special protocol mechanism is needed — it's just another encrypted message stored on Bob's server.

The sent copy is a local operation (Bob's client → Bob's server). It does not go through the federation protocol and does not require PoW. Sent messages count toward the user's storage quota (`max_account_size`), which covers all per-user storage — inbox, sent folder, and attachment blobs. This protects public/shared servers from storage abuse without adding PoW overhead to local operations.

---

## 4. System 3: Authentication — "This really came from Bob"

### 4.1 Concept

Every message is digitally signed by the sender. The recipient's server can verify the signature without decrypting the message content. Identity forgery is mathematically impossible without the sender's private key.

### 4.2 Envelope signature

When Bob sends a message:

1. Bob constructs the message envelope (see Section 7.1 for full format).
2. Bob computes an Ed25519 signature over the serialized envelope contents (excluding the signature field itself):
   ```
   signature = Ed25519_Sign(
     device_private_key,
     version || sender || recipient || timestamp || message_id ||
     in_reply_to || ephemeral_key || proof_of_work
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

### 4.3 Server-level authentication

Servers also authenticate themselves:

1. Each server has its own Ed25519 keypair, published at:
   ```
   GET https://example.com/.well-known/sigil/server-identity
   ```
   ```json
   {
     "domain": "example.com",
     "server_key": "base64url-encoded-ed25519-public-key",
     "updated": "2026-04-11T00:00:00Z",
     "signature": "base64url-self-signature"
   }
   ```
2. When server A sends a message to server B, it includes an `Authorization` header:
   ```
   Authorization: SigilServer sender.example.com <signature-over-request-body>
   ```
3. Server B verifies this against server A's published server key.

This is defense-in-depth. Even without it, the per-message envelope signature from the sender's device key provides authentication. Server-level auth adds:
- Protection against rogue servers forwarding messages they didn't originate.
- Rate limiting and abuse tracking at the server level.

### 4.4 Non-repudiation

The Ed25519 envelope signature provides **non-repudiation**: Alice can prove to a third party that Bob signed a specific message. This is a deliberate design choice for an email replacement — you *want* proof of who sent what (contracts, agreements, records).

---

## 5. System 4: Spam Resistance — "Sending costs effort"

### 5.1 Concept

Email spam is possible because sending is free and identity is forgeable. This protocol eliminates both: identity is cryptographically unforgeable, and every message requires proof of computational work.

### 5.2 Layer 1: Proof of Work

Every message envelope includes a proof-of-work stamp computed using **Argon2id**.

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

### 5.3 Variable difficulty

Each server publishes its spam policy:

```
GET https://example.com/.well-known/sigil/policy
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

### 5.4 Size-scaled difficulty

PoW difficulty increases with message size. This prevents storage-filling attacks where an attacker sends many large messages to exhaust a recipient's inbox.

The effective difficulty is:

```
effective_difficulty = base_difficulty + min(floor(log2(message_size_kb)), size_difficulty_cap)
```

Where `base_difficulty` is the applicable difficulty from Section 5.3 (default, first-contact, or known-contact) and `size_difficulty_cap` limits how much the size penalty can add (default: 4 bits).

| Message size | Extra bits | Total (base 20) | Approx. time |
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

Combined with `max_account_size` (server config, default 1GB) and `max_message_size` (server config, default 25MB), this creates layered storage protection:
- `max_message_size` rejects oversized messages outright.
- Size-scaled PoW makes large messages more expensive to send in bulk.
- `max_account_size` is the hard ceiling — once full, the server returns `507 Insufficient Storage`.

### 5.5 Layer 2: Registration

Some users — newsletters, services, notification systems — need to send messages to many recipients without paying per-message PoW. The **registration** mechanism solves this: the *recipient* initiates contact by sending a lightweight registration message to the sender, paying PoW once. After registration, the sender can message that recipient at `known_contact_difficulty` (typically 0).

**How it works:**

1. Alice wants to receive messages from `newsletter@example.com`.
2. Alice's client fetches the identity document for `newsletter@example.com` and checks that `accept_registrations` is `true` (see Section 5.5.2).
3. Alice's client sends a `register` envelope to `newsletter@example.com`:
   - The envelope has `type: "register"` and no encrypted payload (no message content).
   - Alice computes PoW at the `registration_difficulty` published by `newsletter@example.com`'s server.
   - The envelope is signed by Alice's device key (proving Alice authorized this registration).
4. The newsletter's server verifies the PoW and signature, then adds Alice's identity key to the newsletter's contacts allowlist.
5. The newsletter can now send messages to Alice at `known_contact_difficulty` (typically 0).

**Unregistration:**

Alice can send an `unregister` envelope (same format, `type: "unregister"`, no PoW required — only the signature is needed to prove identity). The sender's server removes Alice from the allowlist.

Alice's client also removes the sender from her own allowlist, so future messages from the sender revert to default PoW requirements on her server.

**Why the recipient pays PoW (not the sender):**

- Legitimate bulk senders would be crushed by per-message PoW at scale. A newsletter with 100,000 subscribers sending weekly would need ~100,000 PoW computations per send — impractical.
- The subscriber pays once (~2–8 seconds). The sender benefits permanently (or until unregistration).
- Spam is impossible: no one registers to receive spam.
- Unlike traditional email subscription bombing, an attacker cannot register *someone else* — the registration message is signed by the registrant's identity key.

**Registration difficulty:**

The receiving server publishes `registration_difficulty` in its policy (see Section 5.3). Default: same as `first_contact_difficulty` (22 bits). Servers that accept registrations can set this independently.

#### 5.5.1 Per-user PoW overrides

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

**Resolution order** (when a message arrives for a user):

1. Check user's identity document for `policy` overrides.
2. Fall back to server-wide policy from `/.well-known/sigil/policy`.
3. Apply size-scaled difficulty on top (Section 5.4).

**Use cases:**

| User type | `accept_registrations` | `first_contact_difficulty` | Notes |
|---|---|---|---|
| Personal account | `false` (default) | Server default (22) | Normal behavior. |
| Newsletter / service | `true` | Higher (24+) | Accepts registrations, discourages cold messages. |
| Public figure | `false` | Higher (26+) | No registrations, very high bar for cold contact. |
| Private account | `false` | Higher (28+) | Effectively unreachable unless allowlisted. |

#### 5.5.2 Sender discovery of registration support

Before sending a registration message, the sender's client checks the recipient's identity document for `"accept_registrations": true`. If the field is absent or `false`, the client should not send a registration envelope — the recipient's server will reject it with `403 Forbidden`.

This means registration support is discoverable: a client can display "Subscribe" or "Register" UI when viewing a user whose identity document advertises registration support.

### 5.6 Layer 3: Contacts allowlist

Once Alice replies to Bob, Bob's identity key is added to Alice's **cryptographic contact list** on her server. Future messages from Bob require zero (or minimal) proof of work.

This is automatic and transparent:
- Alice replies to Bob → Bob is allowlisted.
- Alice registers with Bob (Section 5.5) → mutual allowlisting.
- Alice adds Bob manually (e.g., "add contact") → Bob is allowlisted.
- Alice removes Bob → Bob is de-listed, reverts to default PoW requirement.

The allowlist is stored server-side (it needs to be checked before accepting incoming messages) and is keyed by the sender's **identity public key**, not their address. This means:
- Bob can change servers (bob@old.com → bob@new.com) and remain allowlisted as long as he keeps the same identity key.
- Someone who registers bob@attacker.com with a different key is NOT allowlisted.

### 5.7 Layer 4: Account creation PoW

Account creation also requires proof of work. This prevents mass creation of throwaway accounts to circumvent per-sender PoW.

When a new account is created (either by a local user or by a remote server requesting a legacy email account — see Section 9.2), the request must include a PoW stamp at the `account_creation_difficulty` level published in the server's policy.

The account creation PoW is typically higher than the message PoW (default: 24 bits vs. 20 bits for messages), since accounts are created rarely but messages are sent frequently.

```
POST https://example.com/.well-known/sigil/accounts
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

When disabled, the `POST /.well-known/sigil/accounts` endpoint returns `403 Forbidden`. This is appropriate for personal servers or organization-only servers where the admin controls who gets an account.

Note: Local account creation (via the admin CLI) always works regardless of this setting, since the admin already controls the server.

### 5.8 Layer 5: Social trust signals (optional)

**Introduction field:**
- The envelope can include an optional plaintext `introduction` field (max 280 characters) visible to the receiving server (but not E2E encrypted).
- Servers can filter or flag messages based on this field.
- Use case: "Hi, I'm Bob from Acme Corp, we met at the conference."

**Cross-signing vouches:**
- Alice can sign a statement: "I vouch for `bob@example.com` (identity key: `...`)".
- Bob can attach this vouch to his messages to Alice's contacts.
- Carol's server, upon seeing a vouch from Alice (whom Carol trusts), reduces PoW requirements for Bob.
- This creates a lightweight web-of-trust for spam resistance without requiring a centralized reputation system.

### 5.9 Why this eliminates IP reputation

Email deliverability depends on IP reputation — a new server's emails go to spam for months until it "warms up." This protocol has **no concept of IP reputation:**

| Email problem | How this protocol solves it |
|---|---|
| Unknown IP → spam folder | Identity is cryptographic, not IP-based. A brand-new server with a fresh IP delivers messages just as well as an established one. |
| IP blocklists | No blocklists needed. PoW + signatures prevent abuse. |
| Shared IP risk (cloud hosting) | IP doesn't matter. Your cryptographic identity is unique. |
| SPF/DKIM/DMARC complexity | None of these exist. Authentication is per-message signatures. |

---

## 6. System 5: Transport — "How messages move"

### 6.1 Concept

All communication happens over **HTTPS**. No custom protocols, no special ports, no complex infrastructure. A server is a single binary with a single config file.

### 6.2 Server-to-server protocol

**Message delivery:**

When Bob's server needs to deliver a message to Alice's server:

```
POST https://example.com/.well-known/sigil/inbox/alice
Content-Type: application/x-sigil-envelope
Authorization: SigilServer sender.example.com <server-signature>
Content-Length: 4096

<binary envelope>
```

**Response codes:**

| Code | Meaning |
|---|---|
| `202 Accepted` | Message accepted and stored in inbox. |
| `400 Bad Request` | Malformed envelope. |
| `403 Forbidden` | Signature verification failed. |
| `404 Not Found` | Recipient does not exist on this server. |
| `422 Unprocessable` | PoW verification failed or difficulty too low. |
| `429 Too Many Requests` | Rate limited. Includes `Retry-After` header. |
| `507 Insufficient Storage` | Recipient's inbox is full. |

**Delivery retries:**
- If a message cannot be delivered (server down, network error), the sending server retries with exponential backoff (1 min, 5 min, 30 min, 2 hours, 8 hours) for up to 72 hours, then returns a bounce notification to the sender.

**Identity document retrieval:**

```
GET https://example.com/.well-known/sigil/identity/alice
Accept: application/json

→ 200 OK
Content-Type: application/json
Cache-Control: max-age=3600

{ ... identity document ... }
```

**Server identity:**

```
GET https://example.com/.well-known/sigil/server-identity
Accept: application/json

→ 200 OK
{ ... server identity document ... }
```

**Spam policy:**

```
GET https://example.com/.well-known/sigil/policy
Accept: application/json

→ 200 OK
{ ... policy document ... }
```

### 6.3 Client-to-server API

Alice's client communicates with her home server over HTTPS.

**Authentication:** Every request is signed with the device's Ed25519 key:
```
Authorization: SigilUser <device_id>:<signature-over-method-path-timestamp-body>
X-Sigil-Timestamp: 1712838400
```
The server verifies the signature against the device key registered in Alice's identity document. Requests with timestamps older than 5 minutes are rejected (replay protection).

**Endpoints:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/messages` | Fetch messages. Query params: `since` (timestamp), `limit` (default 50). |
| `GET` | `/api/v1/messages/{id}` | Fetch a single message by ID. |
| `DELETE` | `/api/v1/messages/{id}` | Delete a message from server storage. |
| `POST` | `/api/v1/messages/send` | Submit a message for relay. Body is a binary envelope. |
| `GET` | `/api/v1/contacts` | List contacts (allowlisted identity keys). |
| `POST` | `/api/v1/contacts` | Add a contact. |
| `DELETE` | `/api/v1/contacts/{id}` | Remove a contact. |
| `GET` | `/api/v1/stream` | WebSocket or SSE stream for real-time push notifications. |

**Message fetch response:**

```json
{
  "messages": [
    {
      "id": "uuid",
      "received": "2026-04-11T12:00:00Z",
      "envelope": "base64-encoded-binary-envelope"
    }
  ],
  "has_more": false
}
```

The envelope is returned as-is (binary, base64-encoded in JSON). Decryption happens client-side (Mode A) or can be done server-side (Mode B, if the server holds the key and the client requests decrypted content).

### 6.4 Server architecture

A server is a **single statically-linked binary** containing:

```
┌─────────────────────────────────────────┐
│              sigil-server                │
├─────────────────────────────────────────┤
│  HTTPS Server                           │
│  ├── Well-known endpoints (federation)  │
│  ├── Client API (/api/v1/*)             │
│  └── WebSocket/SSE (push notifications) │
├─────────────────────────────────────────┤
│  Message Store (SQLite)                 │
│  ├── Inbox (per-user message queue)     │
│  ├── Blob store (encrypted attachments) │
│  └── Contact lists                      │
├─────────────────────────────────────────┤
│  Outbound Relay                         │
│  ├── Queue for outgoing messages        │
│  ├── Retry logic (exponential backoff)  │
│  └── Remote identity document cache     │
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
# sigil.toml — the entire configuration file

domain = "mail.example.com"
storage = "./data"

# Optional overrides (all have sensible defaults)
# listen = "0.0.0.0:443"
# acme_email = "admin@example.com"
# max_account_size = "1GB"
# max_message_size = "25MB"
# blob_retention = "30d"
```

**Setup process:**
1. Install the binary (single file, no dependencies).
2. Point a domain to the server's IP (A/AAAA record).
3. Create the config file (2 lines minimum).
4. Start the server. It auto-provisions a TLS certificate via Let's Encrypt.
5. Add users locally: `sigil-server user add alice` (bypasses PoW for local admin).
6. Or users self-register via the accounts endpoint (requires account creation PoW).
7. Alice's client registers her public key (Mode A) or the server generates one for her (Mode B).

**Storage:**
- SQLite by default (embedded, zero-configuration, handles thousands of users easily).
- Optional PostgreSQL support for large deployments.
- Blob storage (encrypted attachments) as files on disk, organized by hash.

### 6.5 Deployment: co-hosting with a website

The protocol only uses paths under `/.well-known/sigil/` and `/api/v1/`. It coexists with a website on the same domain.

**Reverse proxy setup (recommended):**

```nginx
# nginx example
server {
    listen 443 ssl;
    server_name example.com;

    # Protocol server
    location /.well-known/sigil/ {
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

### 6.6 Self-hosting comparison

| Concern | Email | This protocol |
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

## 7. Wire Formats

### 7.1 Message envelope

The envelope is the outer, plaintext layer of a message. It is serialized using Protocol Buffers (compact binary encoding with schema evolution support).

```protobuf
syntax = "proto3";

enum EnvelopeType {
  MESSAGE = 0;                           // Normal message (default)
  REGISTER = 1;                          // Registration request (Section 5.5)
  UNREGISTER = 2;                        // Unregistration request (Section 5.5)
}

message Envelope {
  uint32 version = 1;                    // Protocol version (1)

  // Routing
  string sender = 2;                     // "bob@sender.example.com"
  string recipient = 3;                  // "alice@example.com"
  uint64 timestamp = 4;                  // Unix milliseconds
  bytes message_id = 5;                  // 16 bytes, random UUID
  bytes in_reply_to = 6;                 // Optional, for threading

  // Sender device
  uint32 sender_device_id = 7;

  // Encryption header (absent for REGISTER/UNREGISTER envelopes)
  EncryptionHeader encryption = 8;

  // Spam resistance
  ProofOfWork proof_of_work = 9;

  // Optional plaintext introduction (for first-contact filtering)
  string introduction = 10;             // Max 280 chars, optional

  // Sender authentication (Ed25519 signature over fields 1-10, 13)
  bytes envelope_signature = 11;        // 64 bytes

  // Encrypted payload (absent for REGISTER/UNREGISTER envelopes)
  bytes ciphertext = 12;                // ECIES-encrypted payload

  // Envelope type
  EnvelopeType type = 13;               // Default: MESSAGE
}

message EncryptionHeader {
  bytes ephemeral_key = 1;              // Sender's ephemeral X25519 public key (32 bytes)
  bytes nonce = 2;                      // AES-256-GCM nonce (12 bytes)
  string algorithm = 3;                 // "aes-256-gcm" or "chacha20-poly1305"
}

message ProofOfWork {
  string algorithm = 1;                 // "argon2id"
  bytes nonce = 2;                      // 16 bytes
  uint32 difficulty = 3;                // Number of leading zero bits required
  uint32 memory_cost = 4;              // Argon2 memory parameter (KB)
  uint32 time_cost = 5;                // Argon2 time parameter
  uint64 timestamp = 6;                // When PoW was computed (must be recent)
}
```

### 7.2 Encrypted payload

The payload is serialized with Protocol Buffers, then encrypted. The receiving client decrypts and deserializes.

```protobuf
message Payload {
  string content_type = 1;             // MIME type: "text/markdown", "text/plain", etc.
  bytes body = 2;                      // The message content

  repeated Attachment attachments = 3;

  uint32 flags = 4;                    // Bitfield: 0x01 = read receipt requested
}

message Attachment {
  string filename = 1;
  string content_type = 2;             // MIME type
  uint64 size = 3;                     // Size in bytes

  // Inline (small attachments)
  bytes data = 4;

  // External (large attachments, ECIES-encrypted with recipient's public key)
  string url = 5;                      // URL of encrypted blob
  bytes sha256 = 6;                    // Hash of the encrypted blob
}
```

### 7.3 Identity document

Identity documents are JSON (human-readable, served over HTTP). See Section 2.4 for the full schema.

### 7.4 Serialization rules

- **Envelope and payload:** Protocol Buffers (binary). Compact, efficient, schema-evolvable.
- **Identity documents, policy, server identity:** JSON. Human-readable, easy to debug with curl.
- **Signatures:** computed over the canonical protobuf serialization (deterministic encoding).
- **All binary values in JSON:** base64url encoding (RFC 4648, no padding).

---

## 8. Threat Model

### 8.1 What is protected

| Property | Guarantee |
|---|---|
| **Message confidentiality** | Only the holder of the recipient's private key can read message content. Servers see only ciphertext (Mode A). |
| **Sender authentication** | Messages are signed by the sender's device key. Forgery requires the private key. |
| **Integrity** | Any modification to the envelope invalidates the signature. Any modification to the ciphertext invalidates the AEAD tag. |
| **Spam resistance** | Bulk sending requires proportional computational resources (PoW). |
| **Message persistence** | All messages can be decrypted with the single identity key. No session state to lose. No messages become unrecoverable due to key rotation. |

### 8.2 What is NOT protected

| Risk | Details |
|---|---|
| **Metadata** | Sender address, recipient address, timestamp, message size, frequency of communication are visible to both servers and network observers. Same as email. |
| **Forward secrecy** | If the identity private key is compromised, all past and future messages can be decrypted. This is a deliberate tradeoff for simplicity and recoverability. See Section 9.1 for the forward secrecy extension. |
| **Mode B server trust** | If the server holds the private key (Mode B), the server can read all messages. The user is trusting the server, like they trust Gmail today. Self-hosters mitigate this by controlling the server. |

### 8.3 Compromise scenarios

**Scenario: Alice's server is compromised (Mode A — client-managed key)**
- Attacker can see metadata (who messages Alice, when, how often).
- Attacker **cannot** read message content (doesn't have Alice's private key).
- Attacker **cannot** forge messages from Alice (doesn't have her signing key).
- Attacker could serve a fake identity document with a different public key. Mitigations: (1) existing contacts have Alice's key pinned via TOFU, (2) verified contacts will see a safety number change warning.

**Scenario: Alice's server is compromised (Mode B — server-managed key)**
- Attacker gets Alice's private key from the server.
- Attacker **can** read all messages (past and future, until the key is rotated).
- Attacker **can** forge messages from Alice.
- This is the tradeoff of Mode B. Mitigation: use Mode A for high-security needs.

**Scenario: Alice's identity key is compromised (either mode)**
- Worst case. Attacker can impersonate Alice and decrypt all messages.
- No forward secrecy — all past messages encrypted to this key are compromised.
- Mitigation: Alice performs a key transition (Section 2.8). After transition, new messages use the new key and are safe.

**Scenario: Server-to-server traffic is intercepted (TLS broken)**
- Attacker sees encrypted envelopes in transit. They can see metadata (routing info in the envelope is plaintext).
- Attacker **cannot** read message content (E2E encrypted independent of TLS).
- Attacker **cannot** forge messages (envelope signatures are verified).
- TLS is defense-in-depth for metadata, not the primary security layer.

### 8.4 Trust assumptions

| Assumption | Consequence if violated |
|---|---|
| Ed25519 is secure | All identity and authentication breaks. |
| X25519 is secure | All encryption breaks. |
| AES-256-GCM / ChaCha20-Poly1305 is secure | Message confidentiality breaks. |
| Argon2id is memory-hard | PoW can be computed cheaply by attackers with specialized hardware. |
| User's seed phrase / private key is stored securely | Attacker can decrypt all messages and impersonate user. |
| TOFU on first contact is not intercepted | MITM on first key fetch allows interception until detected. |

---

## 9. Extensions

These are planned features not included in the core v1 protocol. They can be layered on top without breaking compatibility.

### 9.1 Forward Secrecy (optional mode)

A future version could add an optional **forward secrecy mode** for conversations between two users who both opt in. This would use the Signal protocol's Double Ratchet:

- Each message would use a unique ephemeral key, and old keys would be destroyed.
- Compromising the identity key would not expose past messages.
- The tradeoff: messages encrypted with destroyed keys become unrecoverable. Users who want message persistence would stay on the default mode.

This would be negotiated per-conversation (both parties must support and enable it) and would coexist with the default ECIES mode.

### 9.2 Legacy Email Interop

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
GET https://gateway.example.com/.well-known/sigil/identity/x-a7f3k2m9p4q8r2
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

The `type: legacy_email` and `notify: true` fields tell the server to send notification emails when messages arrive for this account.

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

The gateway is a protocol server that specializes in hosting accounts for legacy email recipients and sending notification emails. It uses a transactional email API (SendGrid, Postmark, etc.) to send notifications — it does not run an SMTP server or manage email deliverability directly.

The reference implementation includes a config option for which gateway to use:

```toml
domain = "mail.example.com"
storage = "./data"

# Where to create accounts for legacy email recipients.
# Defaults to the public gateway run by the protocol maintainers.
# Self-hosters can point this to their own server.
legacy_gateway = "gateway.sigil.io"
```

- The default (`gateway.sigil.io`) is a public gateway run by the protocol maintainers. It handles notification emails and hosts temporary accounts so that individual server operators don't need to set up email sending.
- Self-hosters can override this to use their own server as the gateway (requires configuring a transactional email provider for sending notifications).
- Any server can act as a gateway — it just needs the notification email capability.
- The gateway requires account creation PoW (Section 5.5), preventing abuse without API keys or registration.

**The gateway is also a natural onboarding point.** Carol, who received a message on the gateway, is already using the protocol via the web client. She might claim a real address, install a native client, or eventually migrate to her own server. The gateway acts as both infrastructure and front door for new users.

**What the gateway does NOT do:**
- Run an SMTP server for inbound email.
- Manage MX records, SPF, DKIM, or DMARC.
- Maintain IP reputation (the transactional email provider handles deliverability for the notification emails).

#### Method 2: Email Bridge (inbound from email users)

For protocol users who want to **receive** legacy email in their protocol inbox, a bridge service can forward incoming emails. This is a separate component from the notification link system.

**How it works:**
1. Alice configures a forwarding rule in her email provider: "forward all mail to `https://bridge.example.com/inbound/alice`" (webhook) or to a catch-all address handled by the bridge.
2. The bridge receives the forwarded email, parses it, wraps the content in a protocol envelope, and delivers it to Alice's protocol inbox.
3. The message is marked as "received via email (unencrypted)" in Alice's client.

**The bridge is much simpler than a full email system** because it only receives forwarded mail — it doesn't need MX records, spam filtering, or deliverability management. The user's existing email provider handles all of that.

**Outbound replies** to email senders can use the email provider's API (Gmail API, SMTP relay, etc.) or route through the notification link system described above.

**Security note:** Bridged inbound messages are not encrypted in transit (standard email has no encryption). The bridge sees plaintext during processing. These messages should be clearly distinguished from native protocol messages in the client UI.

### 9.3 Metadata Privacy

A future version could add onion routing or mixnet support to hide metadata (sender/recipient/timing) from servers and network observers. This is out of scope for v1 but the protocol's layered design (envelope vs. payload) makes it possible to add without changing the core message format.

---

## Appendix A: Cryptographic Algorithms Summary

| Purpose | Algorithm | Key Size | Output Size |
|---|---|---|---|
| Identity / signing | Ed25519 | 256-bit | 512-bit signature |
| Encryption key exchange | X25519 | 256-bit | 256-bit shared secret |
| Key derivation | HKDF-SHA256 | variable | variable |
| Message encryption | AES-256-GCM | 256-bit | ciphertext + 128-bit tag |
| Alt. message encryption | ChaCha20-Poly1305 | 256-bit | ciphertext + 128-bit tag |
| Proof of work | Argon2id | variable | 256-bit |
| Seed phrase | BIP-39 | 256-bit entropy | 24 words |

## Appendix B: Well-Known Endpoints Summary

All federation endpoints are under `https://<domain>/.well-known/sigil/`.

| Path | Method | Purpose |
|---|---|---|
| `identity/<user>` | GET | Fetch user's identity document (or alias redirect) |
| `server-identity` | GET | Fetch server's identity document |
| `policy` | GET | Fetch spam policy (PoW difficulty) |
| `inbox/<user>` | POST | Deliver a message to a user |
| `accounts` | POST | Create a new account (requires PoW) |

Client API endpoints are under `https://<domain>/api/v1/`.

| Path | Method | Purpose |
|---|---|---|
| `messages` | GET | Fetch messages |
| `messages/{id}` | GET | Fetch a single message |
| `messages/{id}` | DELETE | Delete a message |
| `messages/send` | POST | Send a message |
| `contacts` | GET | List contacts |
| `contacts` | POST | Add a contact |
| `contacts/{id}` | DELETE | Remove a contact |
| `stream` | GET | Real-time push (WebSocket/SSE) |
