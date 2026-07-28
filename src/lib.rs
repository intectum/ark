//! Reference implementation of the Ark protocol.
//!
//! Ark is a federated, end-to-end encrypted file protocol built on cryptographic
//! identities. Every file is a body plus signed metadata; membership drives
//! access.
//!
//! See [`README.md`](../../README.md) for the user-facing guide and [`spec.md`](../../spec.md)
//! for the wire protocol.
//!
//! # Entrypoints
//!
//! - [`client`] — file, membership, and sync operations.
//! - [`server`] — [`server::start_server`] runs a listener on the current
//!   working directory.
//! - [`context`] — build the [`types::IdentityContext`] passed to every client
//!   function.
//!
//! # Function shapes
//!
//! Most [`client`] operations take file paths and use stdin/stdout when a path
//! is absent, writing metadata to `user.ark.*` xattrs as a side effect.
//!
//! For `encrypt`, `decrypt`, `get`, and `put`, a `_stream` variant
//! (`encrypt_stream`, `decrypt_stream`, `get_stream`, `put_stream`) exposes the
//! same operation over [`std::io::Read`]/[`std::io::Write`] streams and returns
//! values instead of touching the filesystem.

pub mod client;
pub mod context;
pub mod crypto;
pub mod http;
pub mod identity;
pub mod metadata;
pub mod server;
pub mod timestamp;
pub mod types;
pub mod util;
