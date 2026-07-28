use std::collections::HashSet;
use std::io;
use std::str::from_utf8;
use std::sync::Arc;

use url::Url;

use crate::client::request;
use crate::http::read_response;
use crate::identity::parse_address;
use crate::types::{IdentityContext, Metadata, RelayMode};
use crate::util::{create_authorization_header, io_err, is_loopback_host, now};

use super::handle_parsed;

pub fn relay(
    server_ctx: &Arc<IdentityContext>,
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: &[u8],
    metadata: &Metadata,
    mode: RelayMode,
    metadata_only: bool,
    verbose: bool,
) -> io::Result<()> {
    let (_, server_host, _) = parse_address(&server_ctx.identity.address)?;

    let path = url.path();
    let segments: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if segments.len() < 2 {
        return Ok(());
    }

    let source_name = segments[1];
    let relative_path: Vec<&str> = segments[2..].to_vec();

    let mut remote_hosts: HashSet<String> = HashSet::new();

    for member in &metadata.members {
        let (member_name, member_host, _) = match parse_address(&member.address) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let same_host = member_host.eq_ignore_ascii_case(&server_host);
        if same_host {
            if member_name == source_name {
                continue;
            }
        } else if mode != RelayMode::Full || !remote_hosts.insert(member_host.to_ascii_lowercase()) {
            continue;
        }

        let outbound_relay = if same_host { None } else { Some(RelayMode::Internal) };
        let member_target = build_member_target(&member_name, &relative_path, outbound_relay, metadata_only);

        let mut final_headers: Vec<(String, String)> = headers.iter()
            .filter(|(key, _)| !key.eq_ignore_ascii_case("authorization")
                && !key.eq_ignore_ascii_case("host")
                && !key.eq_ignore_ascii_case("content-length")
                && !key.eq_ignore_ascii_case("connection"))
            .cloned()
            .collect();

        if same_host {
            let authorization = create_authorization_header(server_ctx, method, &server_host, &member_target, now(), body)?;
            final_headers.push(("Authorization".to_string(), authorization));
            final_headers.push(("Host".to_string(), server_host.clone()));
        }

        let result = if same_host {
            if verbose { println!("{}(relay) {}", method, member_target); }

            let mut buf: Vec<u8> = Vec::new();
            handle_parsed(&mut buf, server_ctx, method, &member_target, &final_headers, body, false)?;
            read_response(&mut buf.as_slice(), method == "HEAD")
        } else {
            let bare_host = member_host.split(':').next().unwrap_or(&member_host);
            let scheme = if is_loopback_host(bare_host) { "http" } else { "https" };
            let url_string = format!("{}://{}{}", scheme, member_host, member_target);
            if verbose { println!("{}(relay) {}", method, url_string); }

            let url = Url::parse(&url_string).map_err(|e| io_err(&format!("invalid remote URL {}: {}", url_string, e)))?;
            let ref_headers: Vec<(&str, &str)> = final_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
            request(Some(server_ctx.as_ref()), method, &url, &ref_headers, body)
        };

        if verbose {
            match result {
                Ok((response_code, _, response_body)) if !(200..300).contains(&response_code) => {
                    let response_string = from_utf8(&response_body).unwrap_or("<non-utf8 body>");
                    eprintln!("ERROR(relay) {}", response_string);
                }
                Err(e) => eprintln!("ERROR(relay) {}", e),
                _ => {}
            }
        }
    }

    Ok(())
}

fn build_member_target(member_name: &str, rel: &[&str], relay_mode: Option<RelayMode>, metadata_only: bool) -> String {
    let mut target = format!("/ark/{}", member_name);
    for seg in rel {
        target.push('/');
        target.push_str(seg);
    }

    let mut params: Vec<String> = Vec::new();
    if let Some(mode) = relay_mode {
        params.push(format!("relay={}", mode.as_str()));
    }
    if metadata_only {
        params.push("metadata".to_string());
    }

    if !params.is_empty() {
        target.push('?');
        target.push_str(&params.join("&"));
    }

    target
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use super::super::start_test_server;
    use super::super::test_helpers::{seed_shared_dir, signed_put_dir_metadata_with_headers, signed_put_metadata_with_headers};
    use crate::metadata::{create_metadata, read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::types::{Key, Member, Permission};
    use crate::util::test::{create_plain_test_metadata, create_test_account, in_test_dir};

    fn make_identity_public(root: &Path, name: &str, address: &str, key: &Key) {
        let path = root.join("ark").join(name).join(".ark").join("identity.json");
        let body = fs::read(&path).unwrap();
        let mut meta = create_metadata(address, None);
        meta.members[0].key = None;
        meta.members.push(Member { address: "*".to_string(), permission: Permission::Reader, key: None });
        sign_metadata(key, &mut meta, Some(&body)).unwrap();
        write_metadata_attributes(&path, &meta).unwrap();
    }

    fn wait_for<F: Fn() -> bool>(check: F) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if check() {
                return;
            }
            sleep(Duration::from_millis(20));
        }
        panic!("wait_for timed out");
    }

    fn wait_for_not<F: Fn() -> bool>(check: F) {
        sleep(Duration::from_millis(300));
        assert!(!check(), "condition should not become true");
    }

    #[test]
    fn relay_writes_to_same_server_member_at_matching_path() {
        in_test_dir("ark_server_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_id, alice_key, _) = create_test_account(temp_dir, &format!("alice@127.0.0.1:{}", port));
            let (bob_id, bob_key, _) = create_test_account(temp_dir, &format!("bob@127.0.0.1:{}", port));

            seed_shared_dir(temp_dir, &bob_id, &bob_key, "ark/bob/shared", vec![
                Member { address: alice_id.address.clone(), permission: Permission::Writer, key: None },
            ]);

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"todo body");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_id.address.clone(), permission: Permission::Writer, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"todo body")).unwrap();

            let code = signed_put_metadata_with_headers(port, &alice_id, &alice_key, "/ark/alice/shared/todo.txt?relay=full", b"todo body", &m, &[]);
            assert_eq!(code, 201);

            let alice_path = temp_dir.join("ark/alice/shared/todo.txt");
            let bob_path = temp_dir.join("ark/bob/shared/todo.txt");
            assert_eq!(fs::read(&alice_path).unwrap(), b"todo body");
            wait_for(|| bob_path.exists());
            assert_eq!(fs::read(&bob_path).unwrap(), b"todo body");

            let bob_meta = read_metadata_attributes(&bob_path).unwrap();
            assert_eq!(bob_meta.id, m.id);
        });
    }

    #[test]
    fn relay_skips_member_not_authorized_in_dest_account() {
        in_test_dir("ark_server_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_id, alice_key, _) = create_test_account(temp_dir, &format!("alice@127.0.0.1:{}", port));
            let (bob_id, _, _) = create_test_account(temp_dir, &format!("bob@127.0.0.1:{}", port));

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"body");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_id.address.clone(), permission: Permission::Writer, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"body")).unwrap();

            let code = signed_put_metadata_with_headers(port, &alice_id, &alice_key, "/ark/alice/shared/todo.txt?relay=full", b"body", &m, &[]);
            assert_eq!(code, 201);

            assert!(temp_dir.join("ark/alice/shared/todo.txt").exists());
            wait_for_not(|| temp_dir.join("ark/bob/shared/todo.txt").exists());
        });
    }

    #[test]
    fn relay_replicates_directory_put() {
        in_test_dir("ark_server_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_id, alice_key, _) = create_test_account(temp_dir, &format!("alice@127.0.0.1:{}", port));
            let (bob_id, bob_key, _) = create_test_account(temp_dir, &format!("bob@127.0.0.1:{}", port));

            seed_shared_dir(temp_dir, &bob_id, &bob_key, "ark/bob/shared", vec![
                Member { address: alice_id.address.clone(), permission: Permission::Writer, key: None },
            ]);
            fs::create_dir_all(temp_dir.join("ark/alice/shared")).unwrap();

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_id.address.clone(), permission: Permission::Writer, key: None });
            m.body_hash = None;
            sign_metadata(&alice_key, &mut m, None).unwrap();

            let code = signed_put_dir_metadata_with_headers(port, &alice_id, &alice_key, "/ark/alice/shared/sub/?relay=full", &m, &[]);
            assert_eq!(code, 201);

            assert!(temp_dir.join("ark/alice/shared/sub").is_dir());
            wait_for(|| temp_dir.join("ark/bob/shared/sub").is_dir());
        });
    }

    #[test]
    fn relay_ignores_public_and_group_members() {
        in_test_dir("ark_server_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_id, alice_key, _) = create_test_account(temp_dir, &format!("alice@127.0.0.1:{}", port));

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"pub");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: "*".to_string(), permission: Permission::Reader, key: None });
            m.members.push(Member { address: "groups:contacts".to_string(), permission: Permission::Reader, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"pub")).unwrap();

            let code = signed_put_metadata_with_headers(port, &alice_id, &alice_key, "/ark/alice/public.txt?relay=full", b"pub", &m, &[]);
            assert_eq!(code, 201);
            assert!(temp_dir.join("ark/alice/public.txt").exists());
        });
    }

    #[test]
    fn relay_full_writes_to_remote_server_once_per_host() {
        in_test_dir("ark_server_test", |temp_dir| {
            let server_a_root = temp_dir.join("server_a");
            let server_b_root = temp_dir.join("server_b");
            fs::create_dir_all(&server_a_root).unwrap();
            fs::create_dir_all(&server_b_root).unwrap();

            let port_b = start_test_server(server_b_root.clone());
            let bob_address = format!("bob@127.0.0.1:{}", port_b);
            let carol_address = format!("carol@127.0.0.1:{}", port_b);
            let (bob_id, bob_key, _) = create_test_account(&server_b_root, &bob_address);
            let (carol_id, carol_key, _) = create_test_account(&server_b_root, &carol_address);

            let port_a = start_test_server(server_a_root.clone());
            let alice_address = format!("alice@127.0.0.1:{}", port_a);
            let (alice_id, alice_key, _) = create_test_account(&server_a_root, &alice_address);
            make_identity_public(&server_a_root, "alice", &alice_address, &alice_key);

            seed_shared_dir(&server_b_root, &bob_id, &bob_key, "ark/bob/shared", vec![
                Member { address: alice_id.address.clone(), permission: Permission::Writer, key: None },
                Member { address: carol_id.address.clone(), permission: Permission::Writer, key: None },
            ]);
            seed_shared_dir(&server_b_root, &carol_id, &carol_key, "ark/carol/shared", vec![
                Member { address: alice_id.address.clone(), permission: Permission::Writer, key: None },
                Member { address: bob_id.address.clone(), permission: Permission::Writer, key: None },
            ]);

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"hello");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_id.address.clone(), permission: Permission::Writer, key: None });
            m.members.push(Member { address: carol_id.address.clone(), permission: Permission::Writer, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"hello")).unwrap();

            let code = signed_put_metadata_with_headers(port_a, &alice_id, &alice_key, "/ark/alice/shared/todo.txt?relay=full", b"hello", &m, &[]);
            assert_eq!(code, 201);

            assert_eq!(fs::read(server_a_root.join("ark/alice/shared/todo.txt")).unwrap(), b"hello");
            let bob_path = server_b_root.join("ark/bob/shared/todo.txt");
            let carol_path = server_b_root.join("ark/carol/shared/todo.txt");
            wait_for(|| bob_path.exists() && carol_path.exists());
            assert_eq!(fs::read(&bob_path).unwrap(), b"hello");
            assert_eq!(fs::read(&carol_path).unwrap(), b"hello");
        });
    }

    #[test]
    fn relay_internal_skips_remote_hosts() {
        in_test_dir("ark_server_test", |temp_dir| {
            let server_a_root = temp_dir.join("server_a");
            let server_b_root = temp_dir.join("server_b");
            fs::create_dir_all(&server_a_root).unwrap();
            fs::create_dir_all(&server_b_root).unwrap();

            let port_b = start_test_server(server_b_root.clone());
            let bob_address = format!("bob@127.0.0.1:{}", port_b);
            let (bob_id, bob_key, _) = create_test_account(&server_b_root, &bob_address);

            let port_a = start_test_server(server_a_root.clone());
            let alice_address = format!("alice@127.0.0.1:{}", port_a);
            let (alice_id, alice_key, _) = create_test_account(&server_a_root, &alice_address);

            seed_shared_dir(&server_b_root, &bob_id, &bob_key, "ark/bob/shared", vec![
                Member { address: alice_id.address.clone(), permission: Permission::Writer, key: None },
            ]);

            let mut m = create_plain_test_metadata(&alice_id, &alice_key, b"hello");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_id.address.clone(), permission: Permission::Writer, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"hello")).unwrap();

            let code = signed_put_metadata_with_headers(port_a, &alice_id, &alice_key, "/ark/alice/shared/todo.txt?relay=internal", b"hello", &m, &[]);
            assert_eq!(code, 201);

            assert!(server_a_root.join("ark/alice/shared/todo.txt").exists());
            wait_for_not(|| server_b_root.join("ark/bob/shared/todo.txt").exists());
        });
    }
}
