mod auth;
mod delete;
mod stream;
mod get;
mod log;
mod put;
mod relay;
#[cfg(test)]
mod test_helpers;

use std::env;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::str::from_utf8;
use std::sync::Arc;
use std::thread;

use crate::context::{create_server_context, create_target_context};
use crate::http::{read_request, write_text};
use crate::identity::resolve_identity;
use crate::metadata::{read_metadata_attributes, read_metadata_headers};
use crate::types::{IdentityContext, Permission, RelayMode};
use crate::util::resolve_server_url;

use self::auth::{authenticate, authorize};
use self::delete::serve_delete;
use self::stream::serve_stream;
use self::get::serve_get;
use self::log::{LoggingStream, try_log_request};
use self::put::{serve_put, serve_put_init};
use self::relay::relay;

pub const MAX_CLOCK_SKEW_MS: u64 = 300_000;

/// Serve the current working directory as an ark server root on
/// `0.0.0.0:<port>` for `host`. Blocks. On first run, creates the server's
/// `ark@<host>` identity.
///
/// Panics if the current directory can't be read, the port can't be bound, or
/// the server identity can't be initialized.
pub fn start_server(port: u16, host: &str) {
    let root = env::current_dir().expect("cwd");
    let server_ctx = create_server_context(&root, host).expect("init server identity");
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    eprintln!("Ark serving {} on http://0.0.0.0:{}", root.display(), port);
    serve(listener, server_ctx, true);
}

#[cfg(test)]
pub fn start_test_server(root: PathBuf) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().unwrap().port();
    let server_ctx = create_server_context(&root, &format!("127.0.0.1:{}", port)).expect("init server identity");
    thread::spawn(move || serve(listener, server_ctx, false));
    port
}

pub fn serve(listener: TcpListener, server_ctx: IdentityContext, verbose: bool) {
    let server_ctx = Arc::new(server_ctx);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let server_ctx = Arc::clone(&server_ctx);
                thread::spawn(move || {
                    if let Err(e) = handle(s, &server_ctx, verbose) {
                        if verbose {
                            eprintln!("ERROR {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                if verbose {
                    eprintln!("ERROR {}", e);
                }
            }
        }
    }
}

fn handle(mut stream: TcpStream, server_ctx: &Arc<IdentityContext>, verbose: bool) -> io::Result<()> {
    let (method, target, headers, body) = read_request(&mut stream, false)?;
    if verbose {
        println!("{} {}", method, target);
    }

    handle_parsed(&mut stream, server_ctx, &method, &target, &headers, &body, verbose)
}

pub fn handle_parsed(
    stream: &mut dyn Write,
    server_ctx: &Arc<IdentityContext>,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
    verbose: bool,
) -> io::Result<()> {
    let mut logger = LoggingStream::new(stream);
    let result = handle_parsed_inner(&mut logger, server_ctx, method, target, headers, body, verbose);

    if let Err(e) = try_log_request(server_ctx, method, target, headers, &logger.captured) {
        if verbose {
            eprintln!("ERROR(log) {}", e);
        }
    }

    result
}

fn handle_parsed_inner(
    stream: &mut dyn Write,
    server_ctx: &Arc<IdentityContext>,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
    verbose: bool,
) -> io::Result<()> {
    let url = match resolve_server_url(target) {
        Ok(u) => u,
        Err(_) => return write_text(stream, 400, b"bad path"),
    };

    let segments: Vec<&str> = url.path_segments()
        .map(|s| s.filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    if segments.first() != Some(&"ark") || segments.len() < 2 {
        return write_text(stream, 403, b"forbidden");
    }
    if segments.len() == 2 && method != "GET" && method != "HEAD" {
        return write_text(stream, 405, b"method not allowed");
    }

    let server_root = server_ctx.root.parent().unwrap().parent().unwrap();
    let name = segments[1];
    let target_identity_path = server_root.join("ark").join(name).join(".ark").join("identity.json");

    if method == "PUT" && url.path() == format!("/ark/{}/.ark/identity.json", name) && !target_identity_path.exists() {
        let metadata = match read_metadata_headers(headers) {
            Ok(m) => m,
            Err(e) => return write_text(stream, 400, e.to_string().as_bytes()),
        };
        return serve_put_init(stream, &metadata, body, &target_identity_path);
    }

    let target_ctx = match create_target_context(server_root, name) {
        Ok(c) => c,
        Err(e) if e.kind() == ErrorKind::NotFound =>
            return write_text(stream, 403, b"forbidden"),
        Err(e) => return Err(e),
    };

    let fs_path = server_root.join(url.path().trim_start_matches('/'));

    if fs::symlink_metadata(&fs_path).map(|m| m.is_symlink()).unwrap_or(false) {
        return write_text(stream, 403, b"symlinks not allowed");
    }

    let existing_metadata = read_metadata_attributes(&fs_path).ok();
    if fs_path.is_file() && existing_metadata.is_none() {
        return write_text(stream, 500, b"file missing metadata");
    }

    let effective_members = match existing_metadata.as_ref() {
        Some(m) => Some(m.members.clone()),
        None => {
            let mut ancestor = None;
            let mut current = fs_path.parent();
            while let Some(dir) = current {
                if !dir.starts_with(&target_ctx.root) { break; }
                if let Ok(m) = read_metadata_attributes(dir) {
                    ancestor = Some(m.members);
                    break;
                }
                current = dir.parent();
            }
            ancestor
        }
    };

    let public_member = effective_members
        .as_deref()
        .and_then(|members| members.iter().find(|member| member.address == "*"));

    if public_member.is_some() && (method == "GET" || method == "HEAD") {
        return serve_get(&fs_path, stream, method == "GET");
    }

    let requestor_identity = match authenticate(server_ctx, &url, method, headers, body) {
        Ok(i) => i,
        Err(e) => return write_text(stream, 401, e.to_string().as_bytes())
    };

    let metadata = if method == "PUT" {
        match read_metadata_headers(headers) {
            Ok(m) => Some(m),
            Err(e) => return write_text(stream, 400, e.to_string().as_bytes()),
        }
    } else {
        None
    };

    let modifier_identity = if let Some(m) = metadata.as_ref() {
        match resolve_identity(server_ctx, &m.modified_by) {
            Ok(i) => Some(i),
            Err(e) => return write_text(stream, 403, e.to_string().as_bytes())
        }
    } else {
        None
    };

    let permission = match authorize(&target_ctx, &requestor_identity, modifier_identity.as_ref(), effective_members.as_deref()) {
        Ok(p) => p,
        Err(e) => return write_text(stream, 403, e.to_string().as_bytes())
    };

    if permission == Permission::Reader {
        match method {
            "PUT" | "DELETE" => return write_text(stream, 403, b"writer permission required"),
            _ => {}
        }
    }

    match method {
        "GET" => {
            let wants_stream = fs_path.is_dir() && headers.iter().any(|(n, v)|
                n.eq_ignore_ascii_case("accept") && v.contains("text/event-stream"));
            if wants_stream {
                return serve_stream(&fs_path, stream);
            }
            serve_get(&fs_path, stream, true)
        },
        "HEAD" => serve_get(&fs_path, stream, false),
        "PUT" => {
            let metadata = metadata.as_ref().expect("metadata presence checked above");
            let modifier = modifier_identity.as_ref().expect("modifier presence checked above");
            serve_put(&fs_path, stream, body, metadata, modifier, existing_metadata.as_ref(), permission)?;

            let relay_mode = headers.iter()
                .find_map(|(name, value)| if name.eq_ignore_ascii_case("x-ark-relay") { RelayMode::parse(value) } else { None });
            if let Some(mode) = relay_mode {
                let server_ctx = Arc::clone(server_ctx);
                let method = method.to_string();
                let url = url.clone();
                let headers = headers.to_vec();
                let body = body.to_vec();
                let metadata = metadata.clone();
                thread::spawn(move || {
                    if let Err(e) = relay(&server_ctx, &method, &url, &headers, &body, &metadata, mode, verbose) {
                        if verbose {
                            eprintln!("ERROR(relay) {}", e);
                        }
                    }
                });
            }

            Ok(())
        }
        "DELETE" => serve_delete(&fs_path, stream),
        _ => write_text(stream, 405, b"method not allowed"),
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use crate::crypto::{DEFAULT_SIGNING_ALGORITHM, create_secret_key};
    use crate::identity::create_identity;
    use crate::util::now;
    use crate::util::test::{TEST_ADDRESS, create_test_account, in_test_dir, write_plain_test_file};

    #[test]
    fn unsupported_method_returns_405() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &identity, &secret_key, "POST", "/ark/test/x", b"hello");
            println!("code: {}, body: {}", code, from_utf8(&body).unwrap());
            assert_eq!(code, 405);
        });
    }

    #[test]
    fn path_traversal_blocked() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/../../../etc/passwd", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn root_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = request(port, "GET", "/", &[], &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn non_ark_path_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = request(port, "GET", "/something/else", &[], &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn ark_without_subdir_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (c1, _, _) = request(port, "GET", "/ark", &[], &[]);
            let (c2, _, _) = request(port, "GET", "/ark/", &[], &[]);
            assert_eq!(c1, 403);
            assert_eq!(c2, 403);
        });
    }

    #[test]
    fn missing_auth_header_401() {
        in_test_dir("ark_server_test", |temp_dir| {
            create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = request(port, "GET", "/ark/test/anything", &[], &[]);
            assert_eq!(code, 401);
        });
    }

    #[test]
    fn missing_timestamp_param_401() {
        in_test_dir("ark_server_test", |temp_dir| {
            let key = [17u8; 32];
            create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let sig = sign(&key, port, "GET", "/ark/test/x", now(), &[]);
            let auth = format!("ArkIdentity address=\"test@example.com\", signature=\"{}\"", sig);
            let (code, _, _) = request(port, "GET", "/ark/test/x", &[], &[("Authorization", &auth)]);
            assert_eq!(code, 401);
        });
    }

    #[test]
    fn stale_timestamp_401() {
        in_test_dir("ark_server_test", |temp_dir| {
            let key = [18u8; 32];
            create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let old = now() - (MAX_CLOCK_SKEW_MS + 60_000);
            let sig = sign(&key, port, "GET", "/ark/test/x", old, &[]);
            let auth = build_auth("test@example.com", old, &sig);
            let (code, _, _) = request(port, "GET", "/ark/test/x", &[], &[("Authorization", &auth)]);
            assert_eq!(code, 401);
        });
    }

    #[test]
    fn wrong_signature_401() {
        in_test_dir("ark_server_test", |temp_dir| {
            let key = [19u8; 32];
            create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let ts = now();
            let sig = sign(&key, port, "GET", "/ark/test/somethingelse", ts, &[]);
            let auth = build_auth("test@example.com", ts, &sig);
            let (code, _, _) = request(port, "GET", "/ark/test/realtarget", &[], &[("Authorization", &auth)]);
            assert_eq!(code, 401);
        });
    }

    #[test]
    fn wrong_key_401() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, _, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let attacker_key = create_secret_key(DEFAULT_SIGNING_ALGORITHM).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &attacker_key, "GET", "/ark/test/x", &[]);
            assert_eq!(code, 401);
        });
    }

    #[test]
    fn no_identity_file_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (attacker_identity, attacker_key) = create_identity("ghost@example.com").unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &attacker_identity, &attacker_key, "GET", "/ark/ghost/x", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn created_identity_authenticates_with_server() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, "gyan@example.com");
            write_plain_test_file(&temp_dir.join("ark/gyan/hello.txt"), &identity, &secret_key, b"hi gyan");
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/gyan/hello.txt", &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"hi gyan");
        });
    }
}
