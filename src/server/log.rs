use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::identity::read_identity;
use crate::metadata::{create_metadata, read_metadata_attributes, sign_metadata, write_metadata_attributes};
use crate::types::{IdentityContext, Member, Permission};
use crate::util::{io_err, now_iso};

const LOG_CAPTURE_LIMIT: usize = 16 * 1024;

pub struct LoggingStream<W: Write> {
    inner: W,
    pub captured: Vec<u8>,
    capturing: bool,
}

impl<W: Write> LoggingStream<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, captured: Vec::new(), capturing: true }
    }
}

impl<W: Write> Write for LoggingStream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.capturing {
            let remaining = LOG_CAPTURE_LIMIT.saturating_sub(self.captured.len());
            let take = buf.len().min(remaining);
            self.captured.extend_from_slice(&buf[..take]);
            if let Some(idx) = find_double_crlf(&self.captured) {
                self.captured.truncate(idx + 4);
                self.capturing = false;
            } else if self.captured.len() >= LOG_CAPTURE_LIMIT {
                self.capturing = false;
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn try_log_request(
    server_ctx: &IdentityContext,
    method: &str,
    target: &str,
    request_headers: &[(String, String)],
    captured_response: &[u8],
) -> io::Result<()> {
    if target.contains("/.ark/requests/") {
        return Ok(());
    }

    let name = match extract_account_name(target) {
        Some(n) => n,
        None => return Ok(()),
    };

    let server_root = server_ctx.root.parent().and_then(|p| p.parent())
        .ok_or_else(|| io_err("server root not resolvable"))?;
    let target_root = server_root.join("ark").join(name);
    let requests_dir = target_root.join(".ark").join("requests");

    if !requests_dir.is_dir() {
        return Ok(());
    }

    let dir_metadata = match read_metadata_attributes(&requests_dir) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    let ark_authorized = dir_metadata.members.iter().any(|member|
        member.address == server_ctx.identity.address
            && matches!(member.permission, Permission::Write | Permission::Owner));
    if !ark_authorized {
        return Ok(());
    }

    let mut entry: Vec<u8> = Vec::new();
    write!(entry, "{} {} HTTP/1.1\r\n", method, target)?;
    for (name, value) in request_headers {
        write!(entry, "{}: {}\r\n", name, value)?;
    }
    entry.extend_from_slice(b"\r\n");
    entry.extend_from_slice(captured_response);
    if !entry.ends_with(b"\r\n") {
        entry.extend_from_slice(b"\r\n");
    }

    let target_identity = read_identity(&target_root.join(".ark").join("identity.json"))?;

    let entry_path = allocate_entry_path(&requests_dir)?;
    fs::write(&entry_path, &entry)?;

    let mut metadata = create_metadata(&server_ctx.identity.address, None);
    metadata.members = vec![
        Member {
            address: target_identity.address,
            permission: Permission::Owner,
            key: None,
        },
        Member {
            address: server_ctx.identity.address.clone(),
            permission: Permission::Write,
            key: None,
        },
    ];
    let secret_key = server_ctx.identity_key.as_ref()
        .ok_or_else(|| io_err("server context missing identity_key"))?;
    sign_metadata(secret_key, &mut metadata, Some(&entry))?;
    write_metadata_attributes(&entry_path, &metadata)?;

    Ok(())
}

fn extract_account_name(target: &str) -> Option<&str> {
    let mut parts = target.trim_start_matches('/').split('/');
    let ark = parts.next()?;
    if ark != "ark" {
        return None;
    }
    let name = parts.next()?;
    if name.is_empty() { None } else { Some(name) }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn allocate_entry_path(dir: &Path) -> io::Result<std::path::PathBuf> {
    let timestamp = now_iso();
    for seq in 0..1000 {
        let name = format!("{}_{:03}.http", timestamp, seq);
        let candidate = dir.join(&name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io_err("could not allocate unique log filename"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::super::start_test_server;
    use super::super::test_helpers::{signed_request, signed_put_with_default_metadata};
    use crate::identity::read_identity;
    use crate::metadata::{create_metadata, read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::types::{Identity, Key, Member, Permission};
    use crate::util::test::{create_test_account, in_test_dir};

    fn ark_identity(temp_dir: &Path) -> Identity {
        read_identity(&temp_dir.join("ark/ark/.ark/identity.json")).unwrap()
    }

    fn grant_ark_write_on_requests(
        temp_dir: &Path,
        account_name: &str,
        account_identity: &Identity,
        account_key: &Key,
        ark: &Identity,
    ) {
        let requests_dir = temp_dir.join("ark").join(account_name).join(".ark").join("requests");
        fs::create_dir_all(&requests_dir).unwrap();

        let mut metadata = create_metadata(&account_identity.address, None);
        metadata.members.push(Member {
            address: ark.address.clone(),
            permission: Permission::Write,
            key: None,
        });
        sign_metadata(account_key, &mut metadata, None).unwrap();
        write_metadata_attributes(&requests_dir, &metadata).unwrap();
    }

    fn list_log_entries(temp_dir: &Path, account_name: &str) -> Vec<std::path::PathBuf> {
        let requests_dir = temp_dir.join("ark").join(account_name).join(".ark").join("requests");
        if !requests_dir.is_dir() {
            return Vec::new();
        }
        fs::read_dir(&requests_dir)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension().and_then(|s| s.to_str()) == Some("http") {
                    Some(path)
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn logs_request_when_ark_has_write_access() {
        in_test_dir("ark_log_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let (identity, secret_key, _) = create_test_account(temp_dir, &address);
            let ark = ark_identity(temp_dir);
            grant_ark_write_on_requests(temp_dir, "alice", &identity, &secret_key, &ark);

            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/alice/missing.txt", &[]);
            assert_eq!(code, 404);

            let entries = list_log_entries(temp_dir, "alice");
            assert_eq!(entries.len(), 1, "expected one log entry");
            let content = fs::read_to_string(&entries[0]).unwrap();
            assert!(content.starts_with("GET /ark/alice/missing.txt HTTP/1.1\r\n"), "content was:\n{}", content);
            assert!(content.contains("\r\n\r\nHTTP/1.1 404"), "content was:\n{}", content);
        });
    }

    #[test]
    fn skips_logging_when_requests_dir_missing() {
        in_test_dir("ark_log_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let (identity, secret_key, _) = create_test_account(temp_dir, &address);

            let (_, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/alice/missing.txt", &[]);

            let entries = list_log_entries(temp_dir, "alice");
            assert!(entries.is_empty(), "no log dir → no entries");
        });
    }

    #[test]
    fn skips_logging_when_ark_lacks_write_permission() {
        in_test_dir("ark_log_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let (identity, secret_key, _) = create_test_account(temp_dir, &address);

            let requests_dir = temp_dir.join("ark/alice/.ark/requests");
            fs::create_dir_all(&requests_dir).unwrap();
            let mut metadata = create_metadata(&identity.address, None);
            sign_metadata(&secret_key, &mut metadata, None).unwrap();
            write_metadata_attributes(&requests_dir, &metadata).unwrap();

            let (_, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/alice/missing.txt", &[]);

            let entries = list_log_entries(temp_dir, "alice");
            assert!(entries.is_empty(), "ark not authorized → no entries");
        });
    }

    #[test]
    fn skips_logging_for_requests_dir_itself() {
        in_test_dir("ark_log_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let (identity, secret_key, _) = create_test_account(temp_dir, &address);
            let ark = ark_identity(temp_dir);
            grant_ark_write_on_requests(temp_dir, "alice", &identity, &secret_key, &ark);

            let (_, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/alice/.ark/requests/foo.http", &[]);

            let entries = list_log_entries(temp_dir, "alice");
            assert!(entries.is_empty(), "requests-dir requests must not be logged");
        });
    }

    #[test]
    fn logs_relayed_write_in_recipient_account() {
        use super::super::test_helpers::{seed_shared_dir, signed_put_metadata_with_headers};
        use crate::util::test::create_plain_test_metadata;

        in_test_dir("ark_log_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_identity, alice_key, _) = create_test_account(temp_dir, &format!("alice@127.0.0.1:{}", port));
            let (bob_identity, bob_key, _) = create_test_account(temp_dir, &format!("bob@127.0.0.1:{}", port));
            let ark = ark_identity(temp_dir);

            grant_ark_write_on_requests(temp_dir, "alice", &alice_identity, &alice_key, &ark);
            grant_ark_write_on_requests(temp_dir, "bob", &bob_identity, &bob_key, &ark);

            seed_shared_dir(temp_dir, &bob_identity, &bob_key, "ark/bob/shared", vec![
                Member { address: alice_identity.address.clone(), permission: Permission::Write, key: None },
            ]);

            let mut m = create_plain_test_metadata(&alice_identity, &alice_key, b"body");
            m.encryption_algorithm = None;
            m.members[0].key = None;
            m.members.push(Member { address: bob_identity.address.clone(), permission: Permission::Write, key: None });
            sign_metadata(&alice_key, &mut m, Some(b"body")).unwrap();

            let code = signed_put_metadata_with_headers(port, &alice_identity, &alice_key, "/ark/alice/shared/todo.txt", b"body", &m, &[("X-Ark-Relay", "full")]);
            assert_eq!(code, 201);

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if !list_log_entries(temp_dir, "bob").is_empty() { break; }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }

            let alice_entries = list_log_entries(temp_dir, "alice");
            let bob_entries = list_log_entries(temp_dir, "bob");
            assert!(!alice_entries.is_empty(), "alice should have log entry for her PUT");
            assert!(!bob_entries.is_empty(), "bob should have log entry for relayed PUT");

            let bob_content = fs::read_to_string(&bob_entries[0]).unwrap();
            assert!(bob_content.starts_with("PUT /ark/bob/shared/todo.txt HTTP/1.1\r\n"), "content was:\n{}", bob_content);
        });
    }

    #[test]
    fn log_entry_is_signed_by_ark() {
        in_test_dir("ark_log_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let (identity, secret_key, _) = create_test_account(temp_dir, &address);
            let ark = ark_identity(temp_dir);
            grant_ark_write_on_requests(temp_dir, "alice", &identity, &secret_key, &ark);

            let (code, _, _) = signed_put_with_default_metadata(port, &identity, &secret_key, "/ark/alice/new.txt", b"payload");
            assert_eq!(code, 201);

            let entries = list_log_entries(temp_dir, "alice");
            assert!(!entries.is_empty());
            let meta = read_metadata_attributes(&entries[0]).unwrap();
            assert_eq!(meta.modified_by, ark.address);
            assert!(meta.members.iter().any(|m| m.address == identity.address && m.permission == Permission::Owner));
            assert!(meta.members.iter().any(|m| m.address == ark.address && m.permission == Permission::Write));
        });
    }
}
