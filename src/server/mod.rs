mod auth;
mod delete;
mod get;
mod put;
#[cfg(test)]
mod test_helpers;

use std::env;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

use crate::http::{read_request, write_response};
use crate::identity::read_identity;
use crate::metadata::read_metadata_attributes;
use crate::types::{Member, Permission};
use crate::util::resolve_url;

use self::auth::{authenticate, authorize};
use self::delete::serve_delete;
use self::get::serve_get;
use self::put::{serve_put, serve_put_init};

pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

pub fn cmd_server(port: u16) {
    let root = env::current_dir().expect("cwd");
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    eprintln!("Ark serving {} on http://0.0.0.0:{}", root.display(), port);
    serve(listener, root, true);
}

#[cfg(test)]
pub fn start_test_server(root: PathBuf) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve(listener, root, false));
    port
}

pub fn serve(listener: TcpListener, root: PathBuf, verbose: bool) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let root = root.clone();
                thread::spawn(move || {
                    if let Err(e) = handle(s, &root, verbose) {
                        if verbose {
                            eprintln!("ERROR: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                if verbose {
                    eprintln!("ERROR: {}", e);
                }
            }
        }
    }
}

fn handle(mut stream: TcpStream, root: &Path, verbose: bool) -> std::io::Result<()> {
    let (method, target, headers, body) = read_request(&mut stream)?;

    if verbose {
        println!("{} {}", method, target)
    }

    let url = match resolve_url(&target, "", root, true) {
        Ok(u) => u,
        Err(_) => return write_status(&mut stream, 400, "Bad Request", b"bad path"),
    };

    let segments: Vec<&str> = url.path_segments()
        .map(|s| s.filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    if segments.first() != Some(&"ark") || segments.len() < 2 {
        return write_status(&mut stream, 403, "Forbidden", b"forbidden");
    }
    if segments.len() == 2 && method != "GET" && method != "HEAD" {
        return write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed");
    }

    let name = segments[1];
    let target_identity_path = root.join("ark").join(name).join(".ark").join("identity.json");

    if method == "PUT" && url.path() == format!("/ark/{}/.ark/identity.json", name) && !target_identity_path.exists() {
        return serve_put_init(&mut stream, &headers, &body, &target_identity_path);
    }

    let target_identity = match read_identity(&target_identity_path) {
        Ok(i) => i,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
            return write_status(&mut stream, 403, "Forbidden", b"forbidden"),
        Err(e) => return Err(e),
    };

    let fs_path = root.join(url.path().trim_start_matches('/'));
    let fs_account_path = root.join("ark").join(name);

    if fs::symlink_metadata(&fs_path).map(|m| m.is_symlink()).unwrap_or(false) {
        return write_status(&mut stream, 403, "Forbidden", b"symlinks not allowed");
    }

    let target_is_dir = url.path().ends_with('/') || fs_path.is_dir();

    let existing_members = read_metadata_attributes(&fs_path).ok().map(|metadata| metadata.members);
    if fs_path.is_file() && existing_members.is_none() {
        return write_status(&mut stream, 500, "Internal Server Error", b"file missing metadata");
    }

    let effective_members = match existing_members.clone() {
        Some(m) => Some(m),
        None => find_ancestor_members(&fs_path, &fs_account_path),
    };

    let public_member = effective_members
        .as_deref()
        .and_then(|members| members.iter().find(|member| member.address == "*"));

    if public_member.is_some() && (method == "GET" || method == "HEAD") {
        return serve_get(&fs_path, &mut stream, method == "GET");
    }

    let requestor_identity = match authenticate(&url, &method, &headers, &body) {
        Ok(i) => i,
        Err(e) => return write_status(&mut stream, 401, "Unauthorized", e.to_string().as_bytes())
    };

    let permission = match authorize(&target_identity, &&requestor_identity, effective_members.as_deref()) {
        Ok(p) => p,
        Err(e) => return write_status(&mut stream, 403, "Forbidden", e.to_string().as_bytes())
    };

    if permission == Permission::Read {
        match method.as_str() {
            "PUT" | "DELETE" => return write_status(&mut stream, 403, "Forbidden", b"write permission required"),
            _ => {}
        }
    }

    match method.as_str() {
        "GET" => serve_get(&fs_path, &mut stream, true),
        "HEAD" => serve_get(&fs_path, &mut stream, false),
        "PUT" => serve_put(&fs_path, &mut stream, &body, &headers, existing_members, permission, target_is_dir, None),
        "DELETE" => serve_delete(&fs_path, &mut stream),
        _ => write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed"),
    }
}

fn find_ancestor_members(fs_path: &Path, fs_account_path: &Path) -> Option<Vec<Member>> {
    let mut current = fs_path.parent()?;
    while current.starts_with(fs_account_path) {
        if let Ok(m) = read_metadata_attributes(current) {
            return Some(m.members);
        }
        current = current.parent()?;
    }
    None
}

pub fn write_status(stream: &mut TcpStream, status_code: u16, status_msg: &str, body: &[u8]) -> std::io::Result<()> {
    write_response(stream, status_code, status_msg, &[("Content-Type", "text/plain"), ("Connection", "close")], body)
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use crate::crypto::{DEFAULT_SIGNING_ALGORITHM, create_key};
    use crate::identity::create_identity;
    use crate::util::now_seconds;
    use crate::util::test::{TEST_ADDRESS, create_test_account, in_test_dir, write_plain_test_file};

    #[test]
    fn unsupported_method_returns_405() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &identity, &secret_key, "POST", "/ark/test/x", b"hello");
            println!("code: {}, body: {}", code, std::str::from_utf8(&body).unwrap());
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
            let sig = sign(&key, "GET", "/ark/test/x", now_seconds(), &[]);
            let auth = format!("ArkAccount address=\"test@example.com\", signature=\"{}\"", sig);
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
            let old = now_seconds() - (MAX_CLOCK_SKEW_SECS + 60);
            let sig = sign(&key, "GET", "/ark/test/x", old, &[]);
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
            let ts = now_seconds();
            let sig = sign(&key, "GET", "/ark/test/somethingelse", ts, &[]);
            let auth = build_auth("test@example.com", ts, &sig);
            let (code, _, _) = request(port, "GET", "/ark/test/realtarget", &[], &[("Authorization", &auth)]);
            assert_eq!(code, 401);
        });
    }

    #[test]
    fn wrong_key_401() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, _, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let attacker_key = create_key(DEFAULT_SIGNING_ALGORITHM).unwrap();
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
