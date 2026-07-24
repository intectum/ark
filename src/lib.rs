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
//! - [`client`] — `get`, `put`, `head`, `delete`, `chmod_io`, `encrypt`,
//!   `decrypt`, `track_io`, `sync_io`, `init`, `init_io`, low-level `request`.
//! - [`server`] — [`server::start_server`] runs a listener on the current
//!   working directory.
//! - [`context`] — build the [`types::IdentityContext`] passed to every client
//!   function.
//!
//! # Function shapes
//!
//! Most client operations come in two forms. Plain (`get`, `put`, `head`,
//! `encrypt`, `decrypt`) operate on [`std::io::Read`]/[`std::io::Write`]
//! streams and return values. The `_io` variants (`get_io`, `put_io`,
//! `head_io`, `encrypt_io`, `decrypt_io`, `chmod_io`, `sync_io`, `track_io`)
//! wrap the CLI shape: optional file paths, stdio fallbacks, xattr side
//! effects, printed output.

pub mod client;
pub mod context;
pub mod crypto;
pub mod http;
pub mod identity;
pub mod metadata;
pub mod server;
pub mod types;
pub mod util;
