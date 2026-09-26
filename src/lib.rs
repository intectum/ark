//! Reference implementation of the Ark protocol.
//!
//! Ark is a federated, end-to-end encrypted file protocol built on cryptographic
//! identities. Every file is a body plus signed metadata; membership drives
//! access.
//!
//! See [`README.md`](../../README.md) for the user-facing guide and [`spec.md`](../../spec.md)
//! for the wire protocol.
//!
//! Everything is exported at the crate root — `ark::put`, `ark::Context`, and
//! so on. There are no submodules to reach through.
//!
//! # Entrypoints
//!
//! - [`init`], [`get`], [`put`], [`list`], [`sync`] — file, membership, and
//!   sync operations.
//! - [`start_server`] runs a listener on the current working directory.
//! - [`create_client_context`] builds the [`Context`] passed to every client
//!   function.
//! - [`read`], [`write()`], [`read_dir`] and the rest — the filesystem, reached
//!   by account path rather than filesystem path.
//!
//! # Function shapes
//!
//! [`get`], [`put`], [`encrypt`], and [`decrypt`] all take a single path and
//! act on the account's own copy of it, mirroring the server, writing metadata
//! to `user.ark.*` xattrs as a side effect.
//!
//! For `encrypt`, `decrypt`, `get`, and `put`, a `_stream` variant
//! (`encrypt_stream`, `decrypt_stream`, `get_stream`, `put_stream`) exposes the
//! same operation over [`std::io::Read`]/[`std::io::Write`] streams and returns
//! values instead of touching the filesystem.

mod client;
mod context;
mod crypto;
mod http;
mod identity;
mod lock;
mod metadata;
mod permissions;
mod server;
mod storage;
#[cfg(test)]
pub mod testing;
mod timestamp;
mod types;
mod util;

pub use client::*;
pub use context::*;
pub use crypto::*;
pub use http::*;
pub use identity::*;
pub use lock::*;
pub use metadata::*;
pub use permissions::*;
pub use server::*;
pub use storage::*;
pub use timestamp::*;
pub use types::*;
pub use util::*;
