//! Account paths, and the filesystem paths and URLs they name.
//!
//! An account path is the one form every operation takes its argument in: the
//! entry's place in the account tree, account-absolute. [`to_account_path`]
//! resolves the forms a caller writes — relative, account-absolute, address —
//! to it, and the rest of this module derives from it the path the filesystem
//! is reached by ([`to_fs_path`]) or the URL a server is reached by
//! ([`to_url`]).
//!
//! A `_raw` variant takes the account root in place of a [`Context`], for a
//! caller running before its own can be built.

use std::env::current_dir;
use std::io;
use std::path::{Component, Path, PathBuf};

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use url::Url;
use uuid::Uuid;

use crate::identity::parse_address;
use crate::types::Context;
use crate::util::{encode_base64url, is_loopback_host, parse_uuid};

const TEMP_INFIX: &str = ".tmp-";

// The separator must not survive into a name that stands as one entry, and the
// escape character has to be escaped alongside it — otherwise two names that
// differ could meet in the same entry, and one would be read under the other's
// key. Everything else is left readable.
const SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS.add(b'%').add(b'/');

/// The account-absolute form of a path argument, which every filesystem
/// function resolves its argument to first.
///
/// Accepts the same forms as the client operations: relative (`team.json`),
/// account-absolute (`/groups/team.json`), or address (`bob@host/team.json`).
/// The relative form is taken against the working directory, so callers with
/// no meaningful one — the server — must pass the account-absolute form.
///
/// `.` and `..` are resolved here rather than left to the filesystem, so the
/// account path of an entry is the same however it was named.
///
/// Errors if the path lies outside the account root, `..` included. That check
/// is what keeps every operation to the account tree, so it runs on every call.
pub fn to_account_path(ctx: &Context, path: &str) -> io::Result<String> {
    to_account_path_raw(&ctx.root, path)
}

/// The account-absolute form of a path argument, taken against `root`.
///
/// As [`to_account_path`], for a caller holding only the account root — one
/// running before its [`Context`] can be built.
pub fn to_account_path_raw(root: &Path, path: &str) -> io::Result<String> {
    // The absolute form is settled before the address one, so an entry whose
    // own name carries an `@` is still addressable — an address never starts
    // with a `/`.
    let local_path = if let Some(relative) = path.strip_prefix('/') {
        root.join(relative)
    } else if path.contains('@') {
        let (_, _, path_part) = parse_address(path)?;
        root.join(path_part.trim_start_matches('/'))
    } else {
        current_dir()?.join(path)
    };

    let relative = local_path.strip_prefix(root)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path outside account root"))?;

    let outside = || io::Error::new(io::ErrorKind::InvalidInput, "path outside account root");

    let mut names: Vec<&str> = Vec::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => { names.pop().ok_or_else(outside)?; }
            Component::Normal(name) => names.push(name.to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not valid UTF-8"))?),
            _ => return Err(outside()),
        }
    }

    Ok(format!("/{}", names.join("/")))
}

/// Where `path` sits on the filesystem, the one place an account path becomes
/// one the standard library can take.
///
/// For a caller writing the body itself, or handing the entry to something
/// that works in filesystem paths; the filesystem functions go through this.
pub fn to_fs_path(ctx: &Context, path: &str) -> io::Result<PathBuf> {
    to_fs_path_raw(&ctx.root, path)
}

/// As [`to_fs_path`], for a caller holding only the account root — one
/// running before its [`Context`] can be built.
pub fn to_fs_path_raw(root: &Path, path: &str) -> io::Result<PathBuf> {
    Ok(root.join(to_account_path_raw(root, path)?.trim_start_matches('/')))
}

/// The directory `path` sits in, or `None` when it names the account root or
/// carries no directory of its own.
pub fn parent_path(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches('/');

    match trimmed.rfind('/') {
        Some(0) => Some("/"),
        Some(slash) => Some(&trimmed[..slash]),
        None => None,
    }
}

/// `name` as an entry of the directory `path`.
pub fn join_path(path: &str, name: &str) -> String {
    format!("{}/{}", path.trim_end_matches('/'), name)
}

/// The last component of `path`, as [`std::path::Path::file_name`] gives it,
/// and empty where that gives nothing.
pub fn file_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');

    match trimmed.rfind('/') {
        Some(slash) => &trimmed[slash + 1..],
        None => trimmed,
    }
}

/// `name` as a single entry name, for a flat directory keyed by something that
/// is itself a path or an address.
///
/// Distinct names always give distinct entries, so nothing keyed this way can
/// be reached under another key's name.
pub fn to_path_segment(name: &str) -> String {
    utf8_percent_encode(name, SEGMENT_ENCODE_SET).to_string()
}

/// Where the account keeps the grant it signs on accepting the account path
/// `path` from another account.
pub fn grant_path_for(path: &str) -> String {
    // Named so it travels in a URL as it is.
    join_path("/.ark/grants", &encode_base64url(path.trim_end_matches('/').as_bytes()))
}

/// A unique sibling name for a temporary version of `path`.
///
/// Named `.<name>.tmp-<uuid>`. The leading dot marks it internal.
pub fn temp_path_for(path: &str) -> String {
    let name = format!(".{}{}{}", file_name(path), TEMP_INFIX, Uuid::new_v4().hyphenated());

    match parent_path(path) {
        Some(parent) => join_path(parent, &name),
        None => name,
    }
}

/// A sibling name for a copy of `path` the user is meant to find beside what
/// it refers to.
///
/// Named `<name>.<suffix>`, so it sits next to the entry rather than taking
/// its place.
pub fn sidecar_path_for(path: &str, suffix: &str) -> String {
    let name = format!("{}.{}", file_name(path), suffix);

    match parent_path(path) {
        Some(parent) => join_path(parent, &name),
        None => name,
    }
}

/// Whether the account path `path`, with or without its leading `/`, lies
/// under `/.ark/`, where protocol state is stored.
pub fn is_protocol_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');

    path == ".ark" || path.starts_with(".ark/")
}

/// Whether the account path `path`, with or without its leading `/`, lies
/// under `/.ark/requests/`, the request log, whose entries the server writes
/// and signs itself.
pub fn is_request_log_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');

    path == ".ark/requests" || path.starts_with(".ark/requests/")
}

/// Whether `path` names a temporary version of a file.
pub fn is_temp_path(path: &str) -> bool {
    let stem = match file_name(path).strip_prefix('.') {
        Some(s) => s,
        None => return false,
    };

    match stem.rfind(TEMP_INFIX) {
        Some(infix) => parse_uuid(&stem[infix + TEMP_INFIX.len()..]).is_ok(),
        None => false,
    }
}

/// Expand a CLI/library path argument into a fully-qualified address string
/// (`name@host[:port][/path]`).
///
/// Accepts the three forms used by put/get/list/identity:
/// - relative: `team.json` (cwd relative to account root)
/// - account-absolute: `/groups/team.json`
/// - address form: `bob@host/team.json` (optional scheme)
///
/// Relative and account-absolute forms take name/host from `ctx.identity.address`.
/// An omitted path stays omitted.
pub fn to_address(ctx: &Context, path: &str) -> io::Result<String> {
    let url = to_url(ctx, path)?;

    let name = url.username();
    let host = match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap_or(""), port),
        None => url.host_str().unwrap_or("").to_string(),
    };
    let account_path = url.path()
        .strip_prefix(&format!("/ark/{}", name)).unwrap_or("")
        .trim_end_matches('/');

    Ok(format!("{}@{}{}", name, host, account_path))
}

/// The URL a request on `path` is sent to.
///
/// Accepts the same forms as [`to_account_path`]; the relative and
/// account-absolute forms are addressed to `ctx`'s own account.
pub fn to_url(ctx: &Context, path: &str) -> io::Result<Url> {
    to_url_raw(&ctx.root, path, &ctx.identity.address)
}

/// As [`to_url`], for a caller holding only the account root and `address` —
/// one running before its [`Context`] can be built.
pub fn to_url_raw(root: &Path, path: &str, address: &str) -> io::Result<Url> {
    let mut s = path.to_string();
    if !s.contains('@') {
        s = format!("{}{}", address, to_account_path_raw(root, &s)?);
    }
    let had_scheme = s.contains("://");
    if !had_scheme {
        s = format!("https://{}", s);
    }

    let mut url = Url::parse(&s)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid URL {}: {}", path, e)))?;

    if !had_scheme && url.host_str().map(is_loopback_host).unwrap_or(false) {
        url.set_scheme("http").expect("http is a valid scheme");
    }

    url.set_path(&format!("/ark/{}{}", url.username(), url.path()));

    reject_path_traversal(&url)?;

    Ok(url)
}

/// The target of an inbound request — path and query — as a [`Url`], for
/// reading its segments and query pairs.
///
/// The host is a placeholder: a target names no host of its own. Errors on a
/// target that traverses out of the path it names.
pub fn parse_request_target(target: &str) -> io::Result<Url> {
    let url = Url::parse(&format!("http://localhost{}", target))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid URL {}: {}", target, e)))?;

    reject_path_traversal(&url)?;

    Ok(url)
}

fn reject_path_traversal(url: &Url) -> io::Result<()> {
    for component in Path::new(url.path()).components() {
        if matches!(component, Component::ParentDir) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path traversal not allowed"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::env::set_current_dir;
    use std::fs;
    use std::io::ErrorKind;

    use super::*;

    use crate::testing::fs::{TEST_ADDRESS, create_test_account, in_test_dir};

    fn account(temp_dir: &Path) -> Context {
        let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);

        Context {
            root: account_dir,
            identity,
            identity_key: Some(secret_key),
        }
    }

    #[test]
    fn to_account_path_address_without_path_is_the_account_root() {
        in_test_dir("ark_paths_test", |temp_dir| {
            let context = account(temp_dir);

            assert_eq!(to_account_path(&context, "bob@example.com").unwrap(), "/");
        });
    }

    #[test]
    fn to_account_path_address_with_path_is_under_the_account_root() {
        in_test_dir("ark_paths_test", |temp_dir| {
            let context = account(temp_dir);

            assert_eq!(to_account_path(&context, "bob@example.com/notes/todo.txt").unwrap(), "/notes/todo.txt");
        });
    }

    #[test]
    fn to_account_path_absolute_wins_over_an_at_in_the_name() {
        in_test_dir("ark_paths_test", |temp_dir| {
            let context = account(temp_dir);

            assert_eq!(to_account_path(&context, "/notes/mail@host.txt").unwrap(), "/notes/mail@host.txt");
        });
    }

    #[test]
    fn to_account_path_relative_is_under_the_working_directory() {
        in_test_dir("ark_paths_test", |temp_dir| {
            let context = account(temp_dir);
            let dir = context.root.join("notes");
            fs::create_dir_all(&dir).unwrap();
            set_current_dir(&dir).unwrap();

            assert_eq!(to_account_path(&context, "todo.txt").unwrap(), "/notes/todo.txt");
        });
    }

    #[test]
    fn a_path_climbing_out_of_the_account_root_errors() {
        in_test_dir("ark_paths_test", |temp_dir| {
            let context = account(temp_dir);

            let error = to_account_path(&context, "/../outside.txt").unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn a_path_outside_the_account_root_errors() {
        in_test_dir("ark_paths_test", |temp_dir| {
            let context = account(temp_dir);

            // The test's working directory is the server root, one above the
            // account's own.
            let error = to_account_path(&context, "outside.txt").unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn temp_path_for_is_recognised_and_real_names_are_not() {
        let path = "/notes/todo.txt";
        let temp = temp_path_for(path);
        assert!(is_temp_path(&temp));
        assert_eq!(parent_path(&temp), parent_path(path));
        assert!(file_name(&temp).starts_with(".todo.txt.tmp-"));

        assert!(!is_temp_path(path));
        assert!(!is_temp_path("/notes/.todo.txt.tmp-notauuid"));
        assert!(!is_temp_path("/notes/todo.txt.tmp-1e2b34d0-0000-4000-8000-000000000000"));
        assert!(!is_temp_path("/notes/todo.txt.remote-2026-08-10T00-00-00Z"));
    }

    #[test]
    fn a_sidecar_sits_beside_what_it_refers_to() {
        assert_eq!(sidecar_path_for("/notes/a.txt", "version-1"), "/notes/a.txt.version-1");
        assert_eq!(sidecar_path_for("a.txt", "remote-2"), "a.txt.remote-2");
    }

    #[test]
    fn path_parts_are_taken_account_absolute() {
        assert_eq!(parent_path("/notes/todo.txt"), Some("/notes"));
        assert_eq!(parent_path("/notes/"), Some("/"));
        assert_eq!(parent_path("/todo.txt"), Some("/"));
        assert_eq!(parent_path("todo.txt"), None);
        assert_eq!(parent_path("/"), None);

        assert_eq!(file_name("/notes/todo.txt"), "todo.txt");
        assert_eq!(file_name("/notes/"), "notes");
        assert_eq!(file_name("/"), "");

        assert_eq!(join_path("/", "notes"), "/notes");
        assert_eq!(join_path("/notes", "todo.txt"), "/notes/todo.txt");
        assert_eq!(join_path("/notes/", "todo.txt"), "/notes/todo.txt");
    }

    #[test]
    fn to_url_absolute() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = to_url_raw(Path::new(account_dir), "/path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/ark/gyan/path/to/file.txt");
    }

    #[test]
    fn to_url_relative_at_account_root() {
        let account_dir = env::current_dir().unwrap();
        let url = to_url_raw(&account_dir, "path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/ark/gyan/path/to/file.txt");
    }

    #[test]
    fn to_url_relative_in_subdir() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let dir = cwd.file_name().unwrap();
        let url = to_url_raw(account_dir, "path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), format!("/ark/gyan/{}{}", dir.to_string_lossy(), "/path/to/file.txt"));
    }

    #[test]
    fn to_url_address_with_path() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = to_url_raw(account_dir, "alice@example.com/path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/ark/alice/path/to/file.txt");
    }

    #[test]
    fn to_url_address_with_scheme_and_port_and_path() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = to_url_raw(account_dir, "http://alice@example.com:9000/path/to/file.txt", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), Some(9000));
        assert_eq!(url.path(), "/ark/alice/path/to/file.txt");
    }

    #[test]
    fn to_url_address_only() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = to_url_raw(account_dir, "alice@example.com", "gyan@127.0.0.1:8080").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/ark/alice/");
    }

    #[test]
    fn to_url_loopback_address_defaults_to_http() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = to_url_raw(account_dir, "alice@localhost:9000/x", "gyan@example.com").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.port(), Some(9000));
    }

    #[test]
    fn to_url_explicit_https_on_loopback_preserved() {
        let cwd = env::current_dir().unwrap();
        let account_dir = cwd.parent().unwrap();
        let url = to_url_raw(account_dir, "https://alice@127.0.0.1:9000/x", "gyan@example.com").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
    }

    #[test]
    fn parse_request_target_takes_a_placeholder_host() {
        let url = parse_request_target("/ark/gyan/notes.txt").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.path(), "/ark/gyan/notes.txt");
    }

    #[test]
    fn parse_request_target_keeps_the_query_out_of_the_path() {
        let url = parse_request_target("/ark/gyan/notes.txt?x=1").unwrap();
        assert_eq!(url.path(), "/ark/gyan/notes.txt");
    }
}
