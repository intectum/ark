# Ark in the Browser

> **Status:** Plan
> **Date:** 2026-09-21
> **Target:** `wasm32-unknown-unknown`

Ark is a synchronous Rust program that talks to a POSIX filesystem, extended attributes and a TCP socket. A browser has none of those. This document covers what it takes to run the client in one.

Wire-level details live in the [spec](spec.md); app-level patterns in the [guide](guide.md).

## Table of Contents

1. [Shape of the problem](#1-shape-of-the-problem)
2. [The three seams](#2-the-three-seams)
3. [Sync vs async](#3-sync-vs-async)
4. [Storage backend](#4-storage-backend)
5. [Network shim](#5-network-shim)
6. [Cargo changes](#6-cargo-changes)
7. [Order of work](#7-order-of-work)

---

## 1. Shape of the problem

`std::fs` is the small part. It compiles for `wasm32-unknown-unknown` but every call returns `Unsupported` at runtime, and the codebase already funnels nearly all of it through one module.

The genuine blockers are:

- **Extended attributes.** The whole metadata model is `user.ark.*` and `user.ark_local.*` attributes. No browser storage API offers them.
- **Asynchrony.** Every browser I/O API is promise-based. Every line of Ark is not.

`wasm32-wasip1` is not an option here — it has preopened directories and a working `std::fs`, but it is for server-side runtimes, not browsers.

### What is already done

Every filesystem call outside [`storage`](src/storage.rs) now routes through it, so the swap to a browser backend touches one file instead of five:

- `storage` gained root-taking variants beside each context-taking one — `read_to_string_raw`, `write_raw`, `exists_raw`, `create_dir_all_raw`, `to_fs_path_raw`. The context versions are one-line delegations.
- `read_identity_raw`, `write_identity_raw` and `write_identity_key_raw` take an account root plus an account path instead of a bare `&Path`, matching the `to_account_path_raw` convention already there.
- `resolve_identity` resolves a peer against the server root as an account path instead of joining a raw `&Path`. The peer name now passes through the containment check that resolves `..` and rejects escapes.
- `context` and `client::init` no longer import `std::fs`.

Two direct filesystem calls remain outside `storage`, both deliberate and both already cfg-gated:

| Site | Call | Why it stays |
| --- | --- | --- |
| `src/identity.rs:185` | `OpenOptions … .mode(0o600)` | Creates the private key readable only by its owner. Unix-only by definition; the `cfg(not(unix))` arm goes through `write_raw`, so wasm gets a working path free. |
| `src/client/watch.rs:51` | `fs::metadata(path).ino()` | Re-places the watch when the inode behind a path changes. The module depends on `notify`/inotify, which is native-only regardless. |

## 2. The three seams

Everything the browser cannot do crosses one of three function boundaries. The rest of the codebase is logic over bytes and streams.

| Seam | Where it narrows | State |
| --- | --- | --- |
| Filesystem and xattrs | `storage` — the only module calling `std::fs` or `xattr` | Needs backend |
| Network | `http::connect` → `Box<dyn ReadWrite>` (`src/http.rs:15`). One function, one caller: `src/client/request.rs:31` | Needs shim |
| Clock | `timestamp::now`, `timestamp::now_ms` | Needs feature flag |
| Stream codecs | `read_request`, `write_request`, `read_response`, `read_stream_events` — pure over `dyn Read`/`dyn Write` | Ports unchanged |
| Server | `src/server/**` — `TcpListener`, rustls, threads | cfg out |

Gating the server module behind `#[cfg(not(target_arch = "wasm32"))]` drops `TcpListener`, `rustls`, `ring`, `webpki-roots` and the threads in one line. That matters beyond tidiness: `ring` does not build for `wasm32-unknown-unknown`, and in the browser it is redundant — `fetch` does TLS.

## 3. Sync vs async

Ark is synchronous top to bottom: `io::Result` everywhere, `dyn Read` and `dyn Write` as the stream abstraction. OPFS, IndexedDB and `fetch` are all promise-based. This choice shapes everything that follows.

### Option A — Web Worker plus `Atomics.wait`

Ark runs in a dedicated worker. The worker blocks on `Atomics.wait` over a `SharedArrayBuffer` while the main thread performs the async operation, then wakes it with the result. Every line of Ark stays synchronous — `sync`, `get`, `put` untouched, native and browser sharing one codebase.

The cost is cross-origin isolation: COOP and COEP headers on everything served, which constrains embedding third-party content. This is what `wasi-fs-access`, wasmer-js and Pyodide's synchronous fetch all do.

### Option B — async refactor

`async fn` propagates from `read` up through `get`, `put`, `sync` and out to every caller. A rewrite of the client, and a permanent split between the native and browser paths.

**Take A.** The COOP/COEP requirement is a deployment constraint we control; a colour-of-function split through the entire client is not something we get back.

## 4. Storage backend

The instinct is to map `storage` onto OPFS, since OPFS is the one browser API with real file semantics. Recommend against it:

- **OPFS is not actually synchronous.** `FileSystemSyncAccessHandle` gives sync `read`, `write`, `getSize` and `flush`, and only inside a worker — but acquiring the handle, via `getDirectoryHandle` and `getFileHandle`, stays async. There is no sync-clean path even in a worker.
- **OPFS has no extended attributes.** That forces a sidecar file per entry, which breaks the atomic-rename guarantee `write_atomic_inner` depends on — renaming two files where the invariant needs one.
- **An in-memory tree makes xattrs trivial.** A node becomes `{ body, attrs, kind }`, and `write_attribute` is a map insert. `write_atomic` becomes a single map swap — stronger than the native rename it models.
- **The working set is small.** An account is one person's file tree.

So: hold the account in a `BTreeMap<String, Node>` in linear memory, hydrate from OPFS asynchronously before Ark starts, persist asynchronously at checkpoints.

Crash-atomicity is weaker than the native path — a crash between checkpoints loses the window. Say so in the module docs.

## 5. Network shim

`connect` returns a duplex stream, but `request` only uses it half-duplex: `write_request`, then `read_response`. So the browser implementation is a buffering shim — accumulate the writes, fire `fetch` on the first read, buffer the response, serve reads from the buffer. The codecs above it never know.

One exception needs its own path: `client::watch` consumes a long-lived SSE stream through `read_stream_events`. Buffering breaks that by construction. It needs either the native `EventSource` or a `ReadableStream` reader feeding the same Atomics channel as everything else.

## 6. Cargo changes

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
uuid      = { version = "1", features = ["v4", "js"] }
time      = { version = "0.3", features = ["wasm-bindgen"] }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
rustls       = { version = "0.23", ... }
webpki-roots = "0.26"
notify       = "6"
xattr        = "1"
```

The `time` feature bites silently. Without `wasm-bindgen`, `OffsetDateTime::now_utc()` returns the Unix epoch on wasm rather than failing — so every request signs with a 1970 timestamp and the server rejects it with an authentication error pointing nowhere near the cause.

## 7. Order of work

Sequenced so each step compiles, and the risky decisions come after the cheap proof that the toolchain works.

1. **The `_raw` refactor.** *(done)* Funnel every filesystem call through `storage`. Native-only, valuable on its own merits.
2. **Gate the native-only modules.** cfg out `server`, `watch_local`, `notify`, `rustls`. Get `cargo check --target wasm32-unknown-unknown` to pass with `storage`, `http` and `timestamp` stubbed as `unimplemented!()`.
3. **Real clock.** The smallest genuine backend. Proves the toolchain, the feature flags and the test harness before anything expensive is built on them.
4. **In-memory VFS behind `storage`.** Body plus attribute map per node. Where the xattr model stops being a blocker.
5. **Fetch shim behind `http::connect`.** Buffering half-duplex adapter. Everything above it in `http` is already portable.
6. **Atomics bridge and worker harness.** The COOP/COEP commitment lands here. Both backends above become genuinely blocking, and the sync codebase runs unmodified.
7. **SSE path for remote watch.** The one place the buffering shim cannot serve. Last because it is the only piece with no native analogue to check against.

Steps 2 and 3 are worth doing regardless of how the sync/async call lands — they are pure containment, and they make the cost of the remaining decisions visible before committing to either.
