//! Shared fixtures and harnesses for crate tests.
//!
//! - [`fs`] — temp dirs, accounts, signed metadata/files
//! - [`http`] — raw HTTP client against a live [`crate::server::start_test_server`]

pub mod fs;
pub mod http;
