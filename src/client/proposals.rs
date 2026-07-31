use std::io;

use super::{delete, get_stream, head, list, request};

use crate::identity::parse_address;
use crate::metadata::{read_metadata_headers, write_metadata_headers};
use crate::types::{IdentityContext, Metadata, Permission, Proposal};
use crate::util::{io_err, io_invalid_input, parse_request_entry, resolve_client_url, sha256};

/// List pending share proposals — requests where another account's PUT was
/// rejected with `403` at a path the current account owns. Returned in
/// chronological order.
///
/// Empty when the account has no request log (see [`crate::client::init`],
/// which sets it up).
pub fn list_proposals(ctx: &IdentityContext) -> io::Result<Vec<Proposal>> {
    let entries = list(ctx, "/.ark/requests/", Some("PUT_403_"))?;

    let mut proposals = Vec::new();
    for entry in entries {
        if !entry.name.ends_with(".http") { continue; }

        let entry_path = format!("/.ark/requests/{}", entry.name);
        let mut entry_body: Vec<u8> = Vec::new();
        if get_stream(ctx, &entry_path, &mut entry_body, false).is_err() {
            continue;
        }

        if let Some(proposal) = parse_proposal(&entry.name, &entry_body)? {
            proposals.push(proposal);
        }
    }

    proposals.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(proposals)
}

/// Accept a share proposal. `index_or_id`: 1-based index (from
/// [`list_proposals`]) or a log entry filename.
///
/// Pulls the current file/dir from the modifier's server, checks it has not
/// been maliciously altered since the proposal (id unchanged, no unauthorised
/// member additions/upgrades, current account not downgraded), and applies it
/// to the target path on the current account. The log entry is removed on
/// success.
///
/// With `force=true`, accepts the current metadata as-is even if members were
/// added or the current account was downgraded since the proposal.
pub fn accept_proposal(ctx: &IdentityContext, index_or_id: &str, force: bool) -> io::Result<()> {
    let id = resolve_id(ctx, index_or_id)?;
    let entry_path = format!("/.ark/requests/{}", id);
    let mut entry_body: Vec<u8> = Vec::new();
    get_stream(ctx, &entry_path, &mut entry_body, false)?;
    let proposal = parse_proposal(&id, &entry_body)?
        .ok_or_else(|| io_invalid_input("entry is not a valid proposal"))?;

    let (account_name, _, _) = parse_address(&ctx.identity.address)?;
    let prefix = format!("/ark/{}/", account_name);
    let relative_path = proposal.target.strip_prefix(&prefix)
        .ok_or_else(|| io_invalid_input("target path is not within this account"))?
        .to_string();

    let target_is_dir = proposal.metadata.body_hash.is_none();
    let modifier_path = if target_is_dir {
        format!("{}/{}/", proposal.metadata.modified_by, relative_path.trim_end_matches('/'))
    } else {
        format!("{}/{}", proposal.metadata.modified_by, relative_path)
    };

    let (current_metadata, body) = if target_is_dir {
        let (_, metadata) = head(ctx, &modifier_path)?;
        (metadata, Vec::new())
    } else {
        let mut buf: Vec<u8> = Vec::new();
        let (metadata, _) = get_stream(ctx, &modifier_path, &mut buf, false)?;
        let expected_hash = metadata.body_hash.as_ref()
            .ok_or_else(|| io_err("file metadata missing body_hash"))?;
        if sha256(&buf) != expected_hash.value {
            return Err(io_err("fetched body hash does not match metadata"));
        }
        (metadata, buf)
    };

    if !force {
        verify_metadata_changes(&proposal.metadata, &current_metadata, &ctx.identity.address)?;
    }

    let own_path = if target_is_dir {
        format!("/{}/", relative_path.trim_end_matches('/'))
    } else {
        format!("/{}", relative_path)
    };
    let own_url = resolve_client_url(ctx, &own_path)?;

    let headers = write_metadata_headers(&current_metadata);
    let header_refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    let (code, _, resp_body) = request(Some(ctx), "PUT", &own_url, &header_refs, &body)?;
    if code != 201 && code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&resp_body))));
    }

    delete(ctx, &entry_path)?;

    Ok(())
}

/// Reject a share proposal by deleting its log entry. `index_or_id` may be a
/// 1-based index (as returned by [`list_proposals`]) or a log entry filename.
/// The current file/dir on the modifier's server is untouched; any future
/// attempt by the same account will simply produce a new log entry.
pub fn reject_proposal(ctx: &IdentityContext, index_or_id: &str) -> io::Result<()> {
    let id = resolve_id(ctx, index_or_id)?;
    let entry_path = format!("/.ark/requests/{}", id);
    delete(ctx, &entry_path)?;

    Ok(())
}

fn resolve_id(ctx: &IdentityContext, index_or_id: &str) -> io::Result<String> {
    if let Ok(index) = index_or_id.parse::<usize>() {
        let proposals = list_proposals(ctx)?;
        if index == 0 || index > proposals.len() {
            return Err(io_invalid_input(&format!("no proposal at index {}", index)));
        }
        Ok(proposals[index - 1].id.clone())
    } else {
        Ok(index_or_id.to_string())
    }
}

fn parse_proposal(filename: &str, entry_bytes: &[u8]) -> io::Result<Option<Proposal>> {
    let entry = parse_request_entry(entry_bytes)?;

    if entry.method != "PUT" { return Ok(None); }
    if entry.status != 403 { return Ok(None); }

    let metadata = read_metadata_headers(&entry.request_headers)?;

    let target = entry.target.split_once('?').map(|(p, _)| p.to_string()).unwrap_or(entry.target);

    Ok(Some(Proposal {
        id: filename.to_string(),
        target,
        metadata,
    }))
}

fn verify_metadata_changes(proposal: &Metadata, current: &Metadata, self_address: &str) -> io::Result<()> {
    if current.id != proposal.id {
        return Err(io_err("id is wrong"));
    }

    if let Some(msg) = check_member_changes(proposal, current, self_address) {
        let mut listing = String::new();
        for member in &current.members {
            listing.push_str(&format!("\n  {} = {}", member.address, member.permission.as_str()));
        }
        return Err(io_err(&format!("{}. Current members:{}\nUse --force to accept anyway.", msg, listing)));
    }

    Ok(())
}

fn check_member_changes(proposal: &Metadata, current: &Metadata, self_address: &str) -> Option<&'static str> {
    if let (Some(proposed), Some(current_self)) = (
        proposal.members.iter().find(|m| m.address == self_address),
        current.members.iter().find(|m| m.address == self_address),
    ) {
        if current_self.permission.rank() < proposed.permission.rank() {
            return Some("your permission was downgraded since proposal");
        }
    }

    let modifier_is_owner = proposal.members.iter().find(|m| m.address == current.modified_by)
        .map(|m| m.permission) == Some(Permission::Owner);
    if modifier_is_owner {
        return None;
    }

    for member in &current.members {
        match proposal.members.iter().find(|m| m.address == member.address) {
            None => return Some("member added since proposal"),
            Some(proposed) if member.permission.rank() > proposed.permission.rank() => {
                return Some("member permission upgraded since proposal");
            }
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use std::env::{current_dir, set_current_dir};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use super::*;

    use crate::client::{init, put};
    use crate::context::create_client_context;
    use crate::permissions::reader;
    use crate::testing::fs::in_test_dir;
    use crate::testing::http::start_test_server;
    use crate::types::Permissions;

    fn setup(temp_dir: &Path, port: u16) -> (IdentityContext, IdentityContext) {
        let alice_dir = temp_dir.join("alice_client");
        let bob_dir = temp_dir.join("bob_client");
        fs::create_dir_all(&alice_dir).unwrap();
        fs::create_dir_all(&bob_dir).unwrap();

        set_current_dir(&alice_dir).unwrap();
        init(&current_dir().unwrap(), &format!("alice@127.0.0.1:{}", port), None, false).unwrap();
        let alice_ctx = create_client_context().unwrap();

        set_current_dir(&bob_dir).unwrap();
        init(&current_dir().unwrap(), &format!("bob@127.0.0.1:{}", port), None, false).unwrap();
        let bob_ctx = create_client_context().unwrap();

        (alice_ctx, bob_ctx)
    }

    fn write_payload(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn list_proposals_returns_403_puts() {
        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (_alice_ctx, bob_ctx) = setup(temp_dir, port);

            set_current_dir(temp_dir.join("bob_client")).unwrap();
            let payload = write_payload(&temp_dir.join("bob_client"), "payload.bin", b"hello");
            let target = format!("alice@127.0.0.1:{}/apps/notes/foo.md", port);
            let _ = put(&bob_ctx, &target, Some(payload.to_str().unwrap()), &Permissions::default(), Some("none"), false);

            set_current_dir(temp_dir.join("alice_client")).unwrap();
            let alice_ctx = create_client_context().unwrap();
            let proposals = list_proposals(&alice_ctx).unwrap();

            assert_eq!(proposals.len(), 1);
            assert_eq!(proposals[0].metadata.modified_by, bob_ctx.identity.address);
            assert_eq!(proposals[0].target, "/ark/alice/apps/notes/foo.md");
        });
    }

    #[test]
    fn reject_proposal_deletes_log_entry() {
        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (_alice_ctx, bob_ctx) = setup(temp_dir, port);

            set_current_dir(temp_dir.join("bob_client")).unwrap();
            let payload = write_payload(&temp_dir.join("bob_client"), "payload.bin", b"hello");
            let target = format!("alice@127.0.0.1:{}/apps/notes/foo.md", port);
            let _ = put(&bob_ctx, &target, Some(payload.to_str().unwrap()), &Permissions::default(), Some("none"), false);

            set_current_dir(temp_dir.join("alice_client")).unwrap();
            let alice_ctx = create_client_context().unwrap();
            let proposals = list_proposals(&alice_ctx).unwrap();
            assert_eq!(proposals.len(), 1);

            reject_proposal(&alice_ctx, &proposals[0].id).unwrap();

            assert_eq!(list_proposals(&alice_ctx).unwrap().len(), 0);
        });
    }

    #[test]
    fn accept_proposal_creates_dir_and_pulls_file() {
        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (_alice_ctx, bob_ctx) = setup(temp_dir, port);

            set_current_dir(temp_dir.join("bob_client")).unwrap();
            let payload = write_payload(&temp_dir.join("bob_client"), "payload.bin", b"hello alice");
            put(&bob_ctx, "apps/notes/foo.md", Some(payload.to_str().unwrap()), &Permissions::default(), Some("none"), false).unwrap();

            let alice_addr = format!("alice@127.0.0.1:{}", port);
            put(&bob_ctx, "apps/notes/foo.md", Some(payload.to_str().unwrap()), &reader(alice_addr.clone()), Some("none"), false).unwrap();

            set_current_dir(temp_dir.join("alice_client")).unwrap();
            let alice_ctx = create_client_context().unwrap();

            let deadline = Instant::now() + Duration::from_secs(5);
            let proposals = loop {
                let p = list_proposals(&alice_ctx).unwrap();
                if !p.is_empty() || Instant::now() >= deadline { break p; }
                sleep(Duration::from_millis(20));
            };
            assert_eq!(proposals.len(), 1, "expected one proposal");

            accept_proposal(&alice_ctx, &proposals[0].id, false).unwrap();

            let alice_file = temp_dir.join("ark/alice/apps/notes/foo.md");
            assert!(alice_file.exists(), "file should exist on alice's server");
            assert_eq!(fs::read(&alice_file).unwrap(), b"hello alice");

            assert_eq!(list_proposals(&alice_ctx).unwrap().len(), 0, "log entry should be deleted");
        });
    }

    #[test]
    fn parse_proposal_extracts_fields() {
        let entry = concat!(
            "PUT /ark/alice/foo HTTP/1.1\r\n",
            "Host: h\r\n",
            "Authorization: ArkIdentity address=\"ark@h\", timestamp=\"123\", signature=\"sig\"\r\n",
            "X-Ark-Meta-Id: id1\r\n",
            "X-Ark-Meta-Created: 2026-01-01T00:00:00.000Z\r\n",
            "X-Ark-Meta-Modified: 2026-01-02T00:00:00.000Z\r\n",
            "X-Ark-Meta-Modified-By: bob@h\r\n",
            "X-Ark-Meta-Member-0-Address: bob@h\r\n",
            "X-Ark-Meta-Member-0-Permission: owner\r\n",
            "X-Ark-Meta-Signature-Algorithm: ed25519\r\n",
            "X-Ark-Meta-Signature-Value: dGVzdA\r\n",
            "\r\n",
            "HTTP/1.1 403 Forbidden\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let p = parse_proposal("entry.http", entry.as_bytes()).unwrap().expect("proposal");
        assert_eq!(p.metadata.modified_by, "bob@h");
        assert_eq!(p.target, "/ark/alice/foo");
    }

    #[test]
    fn parse_proposal_rejects_non_403() {
        let entry = concat!(
            "PUT /ark/alice/foo HTTP/1.1\r\n",
            "\r\n",
            "HTTP/1.1 201 Created\r\n",
            "\r\n",
        );
        assert!(parse_proposal("entry.http", entry.as_bytes()).unwrap().is_none());
    }

    #[test]
    fn parse_proposal_rejects_non_put() {
        let entry = concat!(
            "GET /ark/alice/foo HTTP/1.1\r\n",
            "\r\n",
            "HTTP/1.1 403 Forbidden\r\n",
            "\r\n",
        );
        assert!(parse_proposal("entry.http", entry.as_bytes()).unwrap().is_none());
    }
}
