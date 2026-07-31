# Ark Messaging Spec — Legacy Email Interop

> **Status:** Draft (extracted from [spec.md](spec.md))
> **Date:** 2026-07-24

Email-related additions to the core Ark protocol. Sections that reference "Section X.Y" or "Appendix X" without qualification refer to [spec.md](spec.md).

## Table of Contents

1. [Legacy Email Interop](#1-legacy-email-interop)
2. [Types](#2-types)

---

## 1. Legacy Email Interop

An optional system for communicating with legacy email users. There are two methods, which can be used independently or together.

### 1.1 Method 1: Notification Link (outbound to email users)

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
  "public_key": {
    "algorithm": "ed25519",
    "value": "base64url-encoded"
  },
  "notify": true,
  "signature": {
    "algorithm": "ed25519",
    "value": "base64url-encoded"
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

### 1.2 Method 2: Email Bridge (inbound from email users)

For protocol users who want to receive legacy email, a bridge service can forward incoming emails.

1. Alice configures a forwarding rule in her email provider to a webhook handled by the bridge.
2. The bridge receives the email, wraps the content in an Ark file, and delivers it to Alice's `apps/mail/inbox/` (or whatever path her mail app expects) as a file the bridge is authorized to write.
3. The file is marked as "received via email (unencrypted)" in Alice's client.

**Security note:** Bridged messages are not encrypted in transit. The bridge sees plaintext during processing. These files should be clearly distinguished from native Ark files in the client UI.

### 1.3 Server Configuration

The `legacy_gateway` field in `ark.toml` (Appendix A) enables legacy email interop:

| Field | Type | Required | Description |
|---|---|---|---|
| `legacy_gateway` | string | No | Gateway server address for legacy email interop. Default empty. |

---

## 2. Types

### 2.1 Legacy Email Identity Document

```json
{
  "version": 1,
  "type": "legacy_email",
  "address": "x-a7f3k2m9p4q8r2@gateway.example.com",
  "legacy_email": "carol@gmail.com",
  "public_key": {
    "algorithm": "ed25519",
    "value": "<base64url>"
  },
  "notify": true,
  "signature": {
    "algorithm": "ed25519",
    "value": "<base64url>"
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | `"legacy_email"`. |
| `legacy_email` | string | Yes | Original email address this account represents. |
| `notify` | boolean | Yes | Whether notification emails are sent on delivery. |
