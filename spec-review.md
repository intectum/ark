# Protocol Spec Review — Issues & Proposed Resolutions

> **Reviewed:** v0.3 (2026-04-14)
> **Date:** 2026-04-25

---

## Critical Issues

### 1. Single keypair for signing and encryption increases side-channel exposure

**Problem:** The protocol derives X25519 from Ed25519, using one keypair for both signing and encryption. While the mathematical conversion is safe, linking the keys means that a side-channel attack on the *signing* path — which is the more operationally exposed surface — automatically compromises the encryption key.

Every outgoing message requires an Ed25519 signing operation. That's frequent, happens on potentially untrusted hardware (mobile, shared VMs), and each operation is an opportunity for side-channel leakage (timing attacks, cache-timing, power analysis, speculative execution). The X25519 decryption key, by contrast, is used far less frequently and in a more controlled context (receiving messages).

With mathematically linked keys, a side-channel leak in the signing code path gives the attacker both capabilities: forging signatures *and* decrypting all messages. With independent keys, the same leak gives only the signing key — the attacker can impersonate Alice but cannot read her inbox, because the encryption key is different key material that was never involved in the vulnerable operation.

Note: this is *not* about storage compromise. If both keys are stored in the same place (same device, same seed phrase), an attacker who reads key material from disk gets both regardless. The benefit is specifically against side-channel attacks that target the *use* of the key during cryptographic operations.

**Proposed resolution:** Generate two independent keypairs at account creation:

- An **Ed25519 signing keypair** (for envelope signatures, identity).
- A separate **X25519 encryption keypair** (for ECIES).

Both are derived from the same seed phrase using distinct HKDF derivation paths:

```
signing_seed    = HKDF-SHA256(master_secret, info: "signing-key",    length: 32)
encryption_seed = HKDF-SHA256(master_secret, info: "encryption-key", length: 32)
```

The identity document already publishes both keys separately (`identity_key` and `encryption_key`), so this change is mostly internal. The seed phrase still recovers both keys. The only breaking change is that `encryption_key` is no longer mathematically derived from `identity_key` — verifiers can't cross-check them, but they shouldn't need to.

---

### 2. No forward secrecy exposes entire message history on key compromise

**Problem:** If Alice's identity key leaks (server breach, device theft, compelled disclosure), every message ever sent to her is retroactively compromised. This includes messages from senders who believed they were communicating securely. The "extension" in Section 9.1 is hand-wavy — retrofitting Double Ratchet onto a stateless protocol is a fundamental architecture change, not a bolt-on.

**Proposed resolution:** Add a **lightweight ratcheting mode** to v1 as a per-conversation upgrade. Not full Double Ratchet, but a simpler scheme:

1. After first contact, Alice and Bob perform a one-time X25519 key exchange to establish a **conversation root key**.
2. Each message includes a new ephemeral key. The message key is derived from both the ephemeral DH and the conversation root key:
   ```
   message_key = HKDF(ephemeral_dh || root_key, salt, info: "message-" || sequence_number)
   ```
3. After each exchange, the root key ratchets forward:
   ```
   new_root_key = HKDF(old_root_key || ephemeral_dh, salt, info: "ratchet")
   ```
4. Old root keys are deleted.

This gives **partial forward secrecy** — compromising the current root key doesn't expose messages from before the last ratchet step. It's simpler than Double Ratchet (no prekey bundles, no header encryption) but dramatically better than pure ECIES.

**Fallback:** Messages to new/unknown contacts still use stateless ECIES. The ratchet only activates after a bidirectional exchange. This preserves the "send to anyone without setup" property.

**For users who want message persistence** (the stated reason for no forward secrecy): let the client optionally re-encrypt messages to a long-term storage key before deleting the ratchet keys. The user explicitly trades forward secrecy for archival. This is a client-side decision, not a protocol-level one.

---

### 3. TOFU is dangerously weak for a general-purpose messaging system

**Problem:** A state-level attacker who can MITM the first HTTPS connection to `example.com/.well-known/sigil/identity/alice` can substitute their own public key and intercept all future messages. The "optional out-of-band verification" will be used by almost nobody. This is the same weakness SSH has, and it has been exploited.

**Proposed resolution:** Layer multiple discovery mechanisms so TOFU isn't the only line of defense:

1. **Key Transparency log (recommended).** Servers publish identity key bindings to an append-only, publicly auditable log (similar to Certificate Transparency). Clients can verify that the key they received matches what the server committed to publicly. A server that serves different keys to different requesters will be caught by auditors comparing log entries to served documents. This doesn't require a blockchain — a Merkle tree updated periodically (e.g., every hour) with signed tree heads is sufficient. The protocol spec should define the log format and verification algorithm.

2. **DNS-based key pinning (optional).** Publish a hash of the identity key in a TXT or TLSA record:
   ```
   _sigil.alice.example.com. IN TXT "v=sigil1; k=sha256:base64url-hash-of-identity-key"
   ```
   This gives a second channel (DNS vs. HTTPS) that an attacker must compromise simultaneously. Not perfect (DNS is spoofable), but raises the bar significantly.

3. **Promote verification UX.** Make safety number comparison a first-class flow, not an afterthought. On first contact, show a clear prompt: "You haven't verified Alice's identity. Messages are encrypted but could be intercepted. [Verify now] [Remind me later]." Persist the reminder.

---

### 4. Self-signed identity document provides circular trust

**Problem:** The identity document is signed by the key it contains. This proves internal consistency but not authenticity — anyone can generate a keypair and sign a document claiming to be `alice@example.com`. The actual trust comes from the TLS connection to `example.com`, which means the system depends on the CA infrastructure.

**Proposed resolution:** Acknowledge the CA dependency explicitly in the spec and add mitigations:

1. **State it clearly:** "Trust in an identity document on first contact is rooted in the TLS certificate for the server's domain. The self-signature provides tamper-detection for cached documents and protection against server compromise (Mode A), but does not establish initial authenticity."

2. **Add the Key Transparency log** (from issue #3) as the primary mitigation. The log provides a public commitment that can be verified by third parties, breaking the circular trust.

3. **Support cross-server endorsements.** Allow a user's identity document to include signatures from other servers or users who vouch for the binding. This is a lightweight web-of-trust that doesn't require centralized infrastructure:
   ```json
   {
     "endorsements": [
       {
         "endorser": "trustedserver.org",
         "signature": "base64url-server-signature-over-address-and-key",
         "timestamp": "2026-04-20T00:00:00Z"
       }
     ]
   }
   ```

---

### 5. Alias redirects are an open redirect / phishing vector

**Problem:** When a sender fetches an identity document and receives `{"type": "alias", "redirect": "alice@evil.com"}`, they follow it. The alias document is served by the domain but not signed by Alice's identity key. A compromised server (or rogue admin) can redirect a user's mail to an attacker-controlled address. The server migration flow in Section 2.10 creates cross-server redirects that amplify this risk.

**Proposed resolution:**

1. **Require alias documents to be signed by the identity key:**
   ```json
   {
     "version": 1,
     "type": "alias",
     "redirect": "alice@new-server.com",
     "identity_key": "base64url-encoded-identity-key",
     "signature": "base64url-signature-over-type-redirect-identity_key"
   }
   ```
   The sender verifies the signature against the identity key they have pinned (TOFU). If they don't have a pinned key, they verify it against the key in the target identity document (the redirect destination). If the keys don't match, reject the redirect.

2. **Clients should warn on cross-server redirects** the same way they warn on key changes. Display: "alice@old-server.com has moved to alice@new-server.com. [Accept] [Reject]"

3. **Limit redirect chains.** Follow at most 1 redirect. If the target is also an alias, reject it. This prevents redirect loops and multi-hop phishing chains.

---

### 6. Remote account creation is an abuse vector

**Problem:** "Any server can create an account on any other server by doing the work." An attacker with moderate compute (a few GPUs, even with Argon2id) can squat usernames on popular servers, create millions of throwaway accounts for future spam, or exhaust server storage with empty accounts.

**Proposed resolution:**

1. **Default `allow_remote_registration` to `false`.** Most servers should not allow strangers to create accounts. Flip the default — admins who want open registration opt in explicitly.

2. **Add a username reservation cost.** Require periodic PoW to keep an account active. If no messages are sent or received within a configurable period (e.g., 90 days), the account is flagged as dormant. After another period (e.g., 90 days), it's purged and the username is released. This makes mass squatting expensive to maintain.

3. **Rate-limit account creation per source IP** as defense-in-depth, even with PoW. The spec should recommend a default (e.g., 1 account per IP per hour).

4. **Empty account storage limits.** Set a minimal quota for accounts with no inbound contacts (e.g., 1MB). This prevents storage exhaustion from mass-created empty accounts.

---

## Significant Concerns

### 7. PoW is regressive and punishes low-powered devices

**Problem:** A Raspberry Pi or old phone takes 10-30x longer to compute PoW than a modern desktop. Users in developing countries or on cheap hardware are disproportionately penalized. Meanwhile, a well-funded spammer rents cloud instances and parallelizes Argon2id efficiently.

**Proposed resolution:**

1. **Allow the sender's home server to compute PoW on behalf of the sender.** The sender submits the envelope to their server, and the server computes the PoW before relaying. This moves the cost to server hardware (which the user chose to host on or trust) rather than the client device. The receiving server doesn't care who computed the PoW — only that it's valid.

2. **Reduce default PoW for known contacts aggressively.** The spec already says `known_contact_difficulty: 0`, which is good. Ensure clients add contacts to the allowlist automatically after first reply so the PoW burden drops quickly.

3. **Consider a PoW voucher system.** A server can pre-compute PoW stamps during idle time and distribute them to its users. This amortizes the cost and lets weak devices send without delay.

---

### 8. Argon2id PoW is insufficient against botnets

**Problem:** At difficulty 20, sending costs ~1 second. A botnet with 10,000 compromised machines sends 10,000 messages/second — 864 million spam messages/day. PoW only works against centralized spammers, not distributed botnets. Botnets are the actual spam threat today.

**Proposed resolution:** PoW is one layer, not the whole defense. Add explicit protocol support for:

1. **Per-sender rate limiting at the receiving server.** A given identity key can deliver at most N messages per hour to a given server (configurable, default e.g., 10 for unknown senders). This is cheap to enforce (a counter per sender key) and limits botnet throughput regardless of how fast individual nodes compute PoW.

2. **Reputation-free blocklists at the server level.** Allow servers to publish and subscribe to blocklists of identity keys (not IPs). A server that detects spam from key X can share that key with other servers. This is opt-in and decentralized — no single blocklist authority.

3. **Require PoW nonces to be bound to the sender's identity key.** This prevents a botnet from pre-computing PoW stamps with stolen keys and distributing them to nodes. Each node must have the sender's private key to construct a valid PoW challenge, which means each botnet node must use its own identity — making identity-based rate limiting effective.

---

### 9. No replay protection on PoW

**Problem:** The spec says "check that the timestamp is recent (within 1 hour)" but doesn't mandate a nonce registry. An attacker who intercepts an envelope can replay it within the 1-hour window.

**Proposed resolution:**

1. **Mandate a seen-nonce cache.** Receiving servers MUST maintain a set of `(message_id, sender)` tuples seen within the PoW validity window (1 hour). Duplicate `message_id` values from the same sender within the window are rejected with `409 Conflict`.

2. **Specify storage requirements.** At 16 bytes per message ID + 64 bytes per sender address, storing 1 million entries requires ~80MB. This is manageable. Entries expire after the PoW validity window.

3. **Persist across restarts.** The nonce cache should be written to disk (or WAL) so a server restart doesn't open a replay window. Alternatively, reduce the PoW timestamp validity to 5 minutes (shorter replay window, but requires tighter clock sync).

---

### 10. The `introduction` field is a phishing vector

**Problem:** A plaintext, unauthenticated-by-content field visible to the server and potentially shown to the user. Any sender can write "Hi, I'm your bank's fraud department." The envelope signature proves the sender's identity key signed it, but the user sees a freeform text claiming to be anyone.

**Proposed resolution:**

1. **Do not display the introduction to the end user.** It's a server-side filtering hint only. The client should never render it. Document this explicitly: "The `introduction` field is for server-side spam filtering. Clients MUST NOT display it to the user as part of the message."

2. **Alternatively, display it only with strong context:** "Unknown sender `x7k2m@suspicious.com` says: 'Hi, I'm your bank.' [This is unverified — anyone can write anything here.]" But this is hard to get right UX-wise. Safer to hide it entirely.

3. **Cap the length further.** 280 characters is generous for a server-side filter hint. 80 characters is sufficient and limits the phishing surface.

---

### 11. No group messaging

**Problem:** Email supports multiple recipients natively (To, CC, BCC). This spec has no concept of group conversations. For an email replacement, this is a significant functional gap. Adding it later is non-trivial — it requires encrypting to multiple keys, reply-all semantics, and group membership management.

**Proposed resolution:** Add a basic multi-recipient model to v1:

1. **Envelope supports multiple recipients:**
   ```protobuf
   repeated string recipients = 3;  // replaces singular "recipient"
   ```

2. **Encryption: one envelope per recipient.** The sender encrypts the payload separately for each recipient (different ephemeral key, different shared secret). This means N envelopes for N recipients, each delivered independently. This is simple, preserves the existing crypto model, and avoids the complexity of shared group keys.

3. **Threading context in the payload:**
   ```protobuf
   message Payload {
     // ... existing fields ...
     repeated string group_recipients = 5;  // all recipients, for reply-all
   }
   ```
   This lets clients show who else received the message and offer reply-all.

4. **BCC:** Simply omit the recipient from `group_recipients`. The BCC recipient gets their own envelope but isn't listed in anyone else's payload.

5. **Defer true group chat** (persistent groups with membership management, shared keys, etc.) to a future extension. The multi-recipient model covers the email use case.

---

### 12. Server identity has circular trust and no key transition

**Problem:** The server identity document (Section 4.3) has the same circular trust problem as user identity documents. Additionally, there is no key transition mechanism defined for server keys — if a server needs to rotate its key, there's no way for other servers to verify the transition is legitimate.

**Proposed resolution:**

1. **Define a server key transition document**, mirroring the user key transition format:
   ```json
   {
     "type": "server_key_transition",
     "domain": "example.com",
     "old_key": "base64url-old-server-key",
     "new_key": "base64url-new-server-key",
     "old_signs_new": "base64url-signature",
     "new_signs_old": "base64url-signature",
     "timestamp": "2026-04-25T00:00:00Z"
   }
   ```

2. **Servers should pin other servers' keys** (TOFU, same as user keys) and warn on unexpected changes.

3. **Publish server key hashes via DNS** (same mechanism as proposed for user keys in issue #3) as an additional verification channel.

---

### 13. Large attachment encryption is doubly expensive

**Problem:** Each large attachment is encrypted once for the recipient and once for the sender (sent copy). A 500MB attachment becomes 1GB of encrypted blobs, with double the compute and storage cost.

**Proposed resolution:**

1. **Encrypt the attachment once with a random symmetric key.** Upload one encrypted blob. Then encrypt only the symmetric key to each party (recipient's public key and sender's own public key). Include both encrypted key copies in the respective message payloads.

   ```
   attachment_key = random 32 bytes
   encrypted_blob = AES-256-GCM(attachment_key, nonce, plaintext_attachment)
   
   // In message to recipient:
   encrypted_attachment_key_for_recipient = ECIES(recipient_public_key, attachment_key)
   
   // In sent copy:
   encrypted_attachment_key_for_self = ECIES(sender_public_key, attachment_key)
   ```

2. **Store one blob, referenced by both messages.** The blob URL and SHA-256 hash are the same in both the sent copy and the delivered message. Storage cost: 1x instead of 2x. Compute cost for encryption: 1 AES-GCM pass + 2 tiny ECIES operations instead of 2 full AES-GCM passes.

3. **Update the Attachment protobuf:**
   ```protobuf
   message Attachment {
     // ... existing fields ...
     bytes encrypted_key = 7;  // ECIES-encrypted symmetric key for this attachment
   }
   ```

---

### 14. SQLite won't handle concurrent writes at scale

**Problem:** SQLite with thousands of concurrent writers (incoming federation messages from many servers simultaneously) will hit write-lock contention. WAL mode helps but doesn't solve it for high-throughput servers.

**Proposed resolution:**

1. **Use WAL mode by default** and document its limitations clearly.
2. **Recommend PostgreSQL for servers expecting >100 users** or high federation traffic.
3. **Use a write-ahead queue pattern.** Incoming messages are appended to a simple on-disk queue (append-only file or lightweight queue like BoltDB). A single writer goroutine drains the queue into SQLite. This serializes writes efficiently and absorbs bursts without lock contention.
4. **Benchmark and publish guidance.** Include concrete numbers: "SQLite handles ~X messages/second in WAL mode on typical hardware. For higher throughput, use PostgreSQL."

---

### 15. No way to reject oversized envelopes before receiving the full body

**Problem:** The receiving server must accept the full binary body before verifying PoW and signature. An attacker can send multi-megabyte garbage envelopes, wasting bandwidth and I/O. `Content-Length` headers are trivially spoofed.

**Proposed resolution:**

1. **Split the envelope into a fixed-size header and a variable body.** The first N bytes (e.g., 512 bytes) contain routing, PoW, and signature data — everything needed to verify the message before accepting the payload:
   ```
   [header_length: 4 bytes][header: variable][ciphertext: variable]
   ```
   The server reads and parses the header first, verifies PoW and signature, then accepts or rejects the connection before reading the ciphertext body.

2. **Enforce `Content-Length` strictly.** If the actual body exceeds the declared `Content-Length` by any amount, terminate the connection. If `Content-Length` exceeds `max_message_size`, reject immediately with `413 Payload Too Large`.

3. **Read with a hard byte limit.** The server reads at most `max_message_size` bytes per request, period. Anything beyond that is dropped and the connection is closed.

---

### 16. Default gateway is a centralization and trust chokepoint

**Problem:** The default gateway (`gateway.sigil.io`) holds Mode B keys for all legacy email recipients, sees all notification emails, and becomes a high-value target. Most users won't change the default config.

**Proposed resolution:**

1. **Don't ship a default gateway.** Require the admin to explicitly configure one if they want legacy email interop. This forces awareness of the trust implications.

2. **Allow the sending server to act as its own gateway.** If Bob's server has email-sending capability (transactional email API configured), it can host the legacy recipient's account directly instead of delegating to a third-party gateway. This keeps the trust boundary within Bob's infrastructure.

3. **Document the trust implications prominently:** "The gateway server holds private keys for legacy email accounts. It can read all messages to those accounts. Only use a gateway you trust or operate yourself."

4. **Support gateway federation.** Allow multiple gateways. When creating a legacy email account, the sender can choose which gateway to use. If the recipient already has an account on any gateway, reuse it (discoverable via the deterministic alias hash).

---

### 17. No revocation mechanism for compromised keys

**Problem:** Section 2.8 describes key transition but not key revocation. If Alice's key is compromised and the attacker controls her server, the attacker can prevent the transition. Contacts will keep trusting the compromised key indefinitely.

**Proposed resolution:**

1. **Define a revocation document** that can be published out-of-band:
   ```json
   {
     "type": "key_revocation",
     "address": "alice@example.com",
     "revoked_key": "base64url-identity-key",
     "reason": "compromised",
     "timestamp": "2026-04-25T00:00:00Z",
     "signature": "base64url-signature-by-revoked-key"
   }
   ```
   If Alice still has access to the key (but not the server), she can sign a revocation and distribute it.

2. **Publish revocations to the Key Transparency log** (from issue #3). Even if the server is compromised, the log is independent infrastructure. Clients checking the log will see the revocation.

3. **Allow contacts to revoke trust manually.** If Alice calls Bob and says "my key is compromised," Bob's client should have a "mark key as compromised" action that rejects all future messages from that key and warns on any new key claiming to be Alice.

4. **Pre-generate a revocation certificate at key creation time.** Like PGP's revocation certificate — Alice generates and stores it offline when she creates her key. If the key is compromised, she publishes the pre-signed revocation without needing current access to the key.

---

## Minor Issues

### 18. Protobuf deterministic encoding is not guaranteed

**Problem:** Section 7.4 says signatures are "computed over the canonical protobuf serialization (deterministic encoding)." Proto3 does NOT guarantee deterministic serialization across implementations. Field ordering, default value omission, and map ordering all vary.

**Proposed resolution:** Specify explicit canonical encoding rules:
- Fields serialized in field number order.
- Default values (zero, empty string, false) are included, not omitted.
- No unknown fields in canonical form.
- Alternatively, sign over a defined byte sequence constructed manually (like the signature input in Section 4.2) rather than over the protobuf serialization. This is already partially done — Section 4.2 shows `version || sender || recipient || ...` concatenation, not protobuf bytes. Make this the normative spec and ensure it covers all signed fields.

---

### 19. BIP-39 seed derivation is non-standard

**Problem:** BIP-39 includes PBKDF2 to derive a 512-bit seed from the mnemonic. The spec instead runs the mnemonic through HKDF-SHA256, which is unusual and may confuse implementers who expect standard BIP-39 derivation.

**Proposed resolution:** Either:
- Use BIP-39's built-in PBKDF2 derivation (standard, well-tested, expected by implementers), then derive Ed25519 keys from the resulting 512-bit seed using HKDF with domain separation.
- Or document explicitly why HKDF is used instead: e.g., "We use HKDF rather than BIP-39's PBKDF2 because [reason]. Implementations MUST NOT use standard BIP-39 derivation."

---

### 20. Message pagination has race conditions

**Problem:** `GET /api/v1/messages?since=<timestamp>` uses a timestamp cursor. Messages arriving at the same millisecond can be missed or duplicated depending on query timing.

**Proposed resolution:** Use an opaque cursor token instead of a timestamp:
```json
{
  "messages": [...],
  "cursor": "opaque-server-generated-token",
  "has_more": true
}
```
The server generates the cursor from an internal sequence number or message ID. The client passes it back: `GET /api/v1/messages?cursor=<token>&limit=50`. This eliminates timestamp collision issues.

---

### 21. WebSocket/SSE stream has no specified auth mechanism

**Problem:** The `GET /api/v1/stream` endpoint for real-time push has no authentication mechanism described. The standard `Authorization` header with timestamp-based replay protection doesn't work well for long-lived connections.

**Proposed resolution:** Define auth for the stream endpoint:
- **WebSocket:** Authenticate on the HTTP upgrade request using the standard `Authorization: SigilUser` header. The server validates the signature and device ID before upgrading. The authenticated session persists for the lifetime of the WebSocket connection. Optionally require periodic re-authentication (e.g., a signed ping every 5 minutes).
- **SSE:** Same — authenticate on the initial GET request. The connection stays open and authenticated. Recommend a maximum connection duration (e.g., 1 hour) after which the client must reconnect and re-authenticate.

---

### 22. No rate limiting specification

**Problem:** Section 6.2 returns `429 Too Many Requests` but doesn't specify any rate limiting algorithm or recommended defaults. Each server will implement differently, causing inconsistent sender experiences.

**Proposed resolution:** Define recommended defaults:
- **Per-sender-key rate limit:** 60 messages/hour to a given server from an unknown sender. 600/hour from a known (allowlisted) sender.
- **Per-server rate limit:** 1000 messages/hour from a given originating server.
- **Include rate limit headers in responses:**
  ```
  X-RateLimit-Limit: 60
  X-RateLimit-Remaining: 45
  X-RateLimit-Reset: 1712841600
  ```
- These are recommendations, not requirements. Servers can adjust based on their capacity.

---

### 23. Inbox exhaustion via targeted large messages

**Problem:** `max_account_size` defaults to 1GB. An attacker can fill a target's inbox by sending 40 messages at 25MB each. With size-scaled PoW at difficulty 24, that's ~40 x 15 seconds = 10 minutes of compute. The victim can't receive messages until they delete something.

**Proposed resolution:**

1. **Per-sender storage limits.** A single unknown sender can consume at most X% of a recipient's inbox (e.g., 10%). Once hit, further messages from that sender are rejected. Allowlisted contacts have higher or no limits.

2. **Inbox pressure signals.** When an inbox is >80% full, the server increases PoW difficulty for unknown senders dynamically (e.g., +4 bits). This makes targeted flooding progressively harder.

3. **Auto-expire messages from unknown senders.** Messages from non-allowlisted senders that are unread after a configurable period (e.g., 30 days) are automatically deleted. This prevents passive inbox exhaustion.

---

## Strategic Concern

### 24. Positioning as "email replacement" sets wrong expectations

**Problem:** Email works because of universal adoption. This protocol requires both parties to use it, or the legacy gateway — which reintroduces email's problems. The likely early adopters (security-conscious, self-hosters) will be disappointed by the lack of forward secrecy and won't switch from Signal for sensitive conversations.

**Proposed resolution:** Consider repositioning as **"self-hostable encrypted messaging for the open internet"** — emphasizing federation, self-hosting simplicity, and encryption rather than direct competition with email. The legacy interop gateway then becomes a bridge for gradual adoption rather than a core feature. Forward secrecy (issue #2) becomes essential rather than optional under this framing.
