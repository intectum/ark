use std::io;

use url::Url;

use crate::crypto::sign_bytes;
use crate::http::read_response;
use crate::types::{IdentityContext, Metadata};
use crate::util::{encode_base64url, io_err, now_seconds, request_to_bytes};

use super::handle_parsed;

pub fn relay_same_server(
    server_ctx: &IdentityContext,
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: &[u8],
    metadata: &Metadata,
    verbose: bool,
) -> io::Result<()> {
    let server_key = server_ctx.identity_key.as_ref()
        .ok_or_else(|| io_err("server context missing identity_key"))?;

    let server_host = server_ctx.identity.address.split('@').nth(1)
        .ok_or_else(|| io_err("server identity address missing host"))?;

    let path = url.path();
    let segments: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if segments.len() < 2 {
        return Ok(());
    }
    let source_name = segments[1];
    let rel = &segments[2..];

    for member in &metadata.members {
        if !is_identity_address(&member.address) {
            continue;
        }
        let member_name = match member.address.split_once('@') {
            Some((n, _)) => n,
            None => continue,
        };
        if member_name == source_name {
            continue;
        }

        let mut member_path = format!("/ark/{}", member_name);
        for seg in rel {
            member_path.push('/');
            member_path.push_str(seg);
        }
        if path.ends_with('/') && !member_path.ends_with('/') {
            member_path.push('/');
        }

        let timestamp = now_seconds();
        let signature_bytes = request_to_bytes(method, server_host, &member_path, timestamp, body);
        let signature = sign_bytes(server_key, &signature_bytes)?;
        let auth_header = format!(
            "ArkAccount address=\"{}\", timestamp=\"{}\", signature=\"{}\"",
            server_ctx.identity.address,
            timestamp,
            encode_base64url(signature.value),
        );

        let new_headers: Vec<(String, String)> = headers.iter()
            .filter(|(key, _)| !key.eq_ignore_ascii_case("x-ark-relay")
                && !key.eq_ignore_ascii_case("authorization")
                && !key.eq_ignore_ascii_case("host"))
            .cloned()
            .chain([
                ("Authorization".to_string(), auth_header),
                ("Host".to_string(), server_host.to_string()),
            ])
            .collect();

        if verbose {
            println!("{}(relay) {}", method, member_path);
        }

        let mut buf: Vec<u8> = Vec::new();
        if let Err(e) = handle_parsed(&mut buf, server_ctx, method, &member_path, &new_headers, body, verbose) {
            if verbose {
                eprintln!("ERROR(relay) {}: {}", member_path, e);
            }
            continue;
        }
        if verbose {
            match read_response(&mut buf.as_slice(), method) {
                Ok((code, _, body)) if !(200..300).contains(&code) => {
                    let msg = std::str::from_utf8(&body).unwrap_or("<non-utf8 body>");
                    eprintln!("ERROR(relay) {} {}: {}", code, member_path, msg);
                }
                Err(e) => eprintln!("ERROR(relay) parse response for {}: {}", member_path, e),
                _ => {}
            }
        }
    }

    Ok(())
}

fn is_identity_address(address: &str) -> bool {
    if address == "*" {
        return false;
    }
    if address.starts_with("groups:") || address.starts_with("passkeys:") || address.starts_with("passwords:") {
        return false;
    }
    address.contains('@')
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::start_test_server;
    use super::super::test_helpers::{seed_shared_dir, signed_put_dir_metadata_with_headers, signed_put_metadata_with_headers};
    use crate::metadata::{read_metadata_attributes, sign_metadata};
    use crate::types::{Member, Permission};
    use crate::util::test::{create_plain_test_metadata, create_test_account, in_test_dir};

    #[test]
    fn relay_writes_to_same_server_member_at_matching_path() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (alice_id, alice_key, _) = create_test_account(temp_dir, "alice@example.com");
            let (bob_id, bob_key, _) = create_test_account(temp_dir, "bob@example.com");

            seed_shared_dir(temp_dir, &bob_id, &bob_key, "ark/bob/shared", vec![
                Member { address: alice_id.address.clone(), permission: Permission::Write, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"todo body");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_id.address.clone(), permission: Permission::Write, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"todo body")).unwrap();

            let code = signed_put_metadata_with_headers(port, &alice_id, &alice_key, "/ark/alice/shared/todo.txt", b"todo body", &m, &[("X-Ark-Relay", "true")]);
            assert_eq!(code, 201);

            let alice_path = temp_dir.join("ark/alice/shared/todo.txt");
            let bob_path = temp_dir.join("ark/bob/shared/todo.txt");
            assert_eq!(fs::read(&alice_path).unwrap(), b"todo body");
            assert_eq!(fs::read(&bob_path).unwrap(), b"todo body");

            let bob_meta = read_metadata_attributes(&bob_path).unwrap();
            assert_eq!(bob_meta.id, m.id);
        });
    }

    #[test]
    fn relay_skips_member_not_authorized_in_dest_account() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (alice_id, alice_key, _) = create_test_account(temp_dir, "alice@example.com");
            let (bob_id, _, _) = create_test_account(temp_dir, "bob@example.com");

            let port = start_test_server(temp_dir.to_path_buf());

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"body");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_id.address.clone(), permission: Permission::Write, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"body")).unwrap();

            let code = signed_put_metadata_with_headers(port, &alice_id, &alice_key, "/ark/alice/shared/todo.txt", b"body", &m, &[("X-Ark-Relay", "true")]);
            assert_eq!(code, 201);

            assert!(temp_dir.join("ark/alice/shared/todo.txt").exists());
            assert!(!temp_dir.join("ark/bob/shared/todo.txt").exists());
        });
    }

    #[test]
    fn relay_replicates_directory_put() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (alice_id, alice_key, _) = create_test_account(temp_dir, "alice@example.com");
            let (bob_id, bob_key, _) = create_test_account(temp_dir, "bob@example.com");

            seed_shared_dir(temp_dir, &bob_id, &bob_key, "ark/bob/shared", vec![
                Member { address: alice_id.address.clone(), permission: Permission::Write, key: None },
            ]);
            fs::create_dir_all(temp_dir.join("ark/alice/shared")).unwrap();

            let port = start_test_server(temp_dir.to_path_buf());

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_id.address.clone(), permission: Permission::Write, key: None });
            sign_metadata(&alice_key, &mut m, None).unwrap();

            let code = signed_put_dir_metadata_with_headers(port, &alice_id, &alice_key, "/ark/alice/shared/sub/", &m, &[("X-Ark-Relay", "true")]);
            assert_eq!(code, 201);

            assert!(temp_dir.join("ark/alice/shared/sub").is_dir());
            assert!(temp_dir.join("ark/bob/shared/sub").is_dir());
        });
    }

    #[test]
    fn relay_ignores_public_and_group_members() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (alice_id, alice_key, _) = create_test_account(temp_dir, "alice@example.com");

            let port = start_test_server(temp_dir.to_path_buf());

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"pub");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: "*".to_string(), permission: Permission::Read, key: None });
            m.members.push(Member { address: "groups:contacts".to_string(), permission: Permission::Read, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"pub")).unwrap();

            let code = signed_put_metadata_with_headers(port, &alice_id, &alice_key, "/ark/alice/public.txt", b"pub", &m, &[("X-Ark-Relay", "true")]);
            assert_eq!(code, 201);
            assert!(temp_dir.join("ark/alice/public.txt").exists());
        });
    }
}
