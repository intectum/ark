use std::io;

use crate::client::delete::delete;
use crate::client::get::get;
use crate::client::head::head;
use crate::client::request::request;
use crate::identity::parse_address;
use crate::metadata::{get_member, read_metadata_headers, write_metadata_headers};
use crate::types::{DirectoryEntry, IdentityContext, Metadata, Permission, Proposal};
use crate::util::{io_err, io_invalid_input, parse_request_entry, resolve_client_url, sha256};

/// List pending share proposals — request-log entries where another account's
/// PUT was rejected with `403` at a path the current account owns. Each entry
/// is fetched from `.ark/requests/`, parsed, and returned in filename
/// (chronological) order.
///
/// Missing `.ark/requests/` returns an empty list — request logging is only
/// enabled when the Ark server account has been granted write access to the
/// directory (see [`crate::client::init`]).
pub fn list_proposals(ctx: &IdentityContext) -> io::Result<Vec<Proposal>> {
    let requests_url = resolve_client_url(ctx, "/.ark/requests/")?;
    let (code, _, body) = request(Some(ctx), "GET", &requests_url, &[], &[])?;
    if code == 404 {
        return Ok(Vec::new());
    }
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    let entries: Vec<DirectoryEntry> = serde_json::from_slice(&body)
        .map_err(|e| io_err(&format!("dir listing: {}", e)))?;

    let mut proposals = Vec::new();
    for entry in entries {
        if !entry.name.ends_with(".http") { continue; }

        let entry_path = format!("/.ark/requests/{}", entry.name);
        let mut entry_body: Vec<u8> = Vec::new();
        if get(ctx, &entry_path, &mut entry_body, false).is_err() {
            continue;
        }

        if let Some(proposal) = parse_proposal(&entry.name, &entry_body) {
            proposals.push(proposal);
        }
    }

    proposals.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(proposals)
}

/// CLI wrapper for [`list_proposals`]. Prints each proposal with its index,
/// modifier address, target kind (`file` or `dir`), target path, log entry id,
/// and proposed member list.
pub fn list_proposals_io(ctx: &IdentityContext) -> io::Result<()> {
    let proposals = list_proposals(ctx)?;
    if proposals.is_empty() {
        println!("No pending proposals.");
        return Ok(());
    }

    let (account_name, _, _) = parse_address(&ctx.identity.address)?;
    let account_prefix = format!("/ark/{}", account_name);

    for (index, proposal) in proposals.iter().enumerate() {
        let kind = proposal.metadata.body_hash.as_ref().map(|_| "file").unwrap_or("dir");
        let display_target = match proposal.target.strip_prefix(&account_prefix) {
            Some("") => "/",
            Some(rest) => rest,
            None => &proposal.target,
        };
        println!("{:>3}  {}  {}  {}  ({})", index + 1, proposal.metadata.modified_by, kind, display_target, proposal.id);
        for member in &proposal.metadata.members {
            println!("       {} = {}", member.address, member.permission.as_str());
        }
    }

    Ok(())
}

/// Accept a share proposal by log entry id.
///
/// Fetches the current file/dir from the modifier's server (HEAD for dirs, GET
/// for files), verifies fetched metadata against the proposal snapshot (id
/// match, no unauthorised member additions/upgrades, self not downgraded),
/// verifies the fetched body against the current `body_hash`, and PUTs the
/// verified metadata + body to the target path on the current account. On
/// success the log entry is deleted.
///
/// When `force` is true, the metadata-change verification is skipped — the
/// current metadata is trusted as-is even if members were added or the current
/// user was downgraded since the proposal was made.
pub fn accept_proposal(ctx: &IdentityContext, id: &str, force: bool) -> io::Result<()> {
    let entry_path = format!("/.ark/requests/{}", id);
    let mut entry_body: Vec<u8> = Vec::new();
    get(ctx, &entry_path, &mut entry_body, false)?;
    let proposal = parse_proposal(id, &entry_body)
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
        let (metadata, _) = get(ctx, &modifier_path, &mut buf, false)?;
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

/// CLI wrapper for [`accept_proposal`]. `index_or_id` may be a 1-based index
/// (as printed by [`list_proposals_io`]) or a log entry filename.
pub fn accept_proposal_io(ctx: &IdentityContext, index_or_id: &str, force: bool) -> io::Result<()> {
    let id = resolve_id(ctx, index_or_id)?;
    accept_proposal(ctx, &id, force)
}

/// Reject a share proposal by deleting its log entry. The current file/dir on
/// the modifier's server is untouched; any future attempt by the same account
/// will simply produce a new log entry.
pub fn reject_proposal(ctx: &IdentityContext, id: &str) -> io::Result<()> {
    let entry_path = format!("/.ark/requests/{}", id);
    delete(ctx, &entry_path)?;

    Ok(())
}

/// CLI wrapper for [`reject_proposal`]. `index_or_id` may be a 1-based index
/// (as printed by [`list_proposals_io`]) or a log entry filename.
pub fn reject_proposal_io(ctx: &IdentityContext, index_or_id: &str) -> io::Result<()> {
    let id = resolve_id(ctx, index_or_id)?;
    reject_proposal(ctx, &id)
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

fn parse_proposal(filename: &str, entry_bytes: &[u8]) -> Option<Proposal> {
    let entry = parse_request_entry(entry_bytes)
        .map_err(|e| eprintln!("bad log entry: {}", e))
        .ok()?;

    if entry.method != "PUT" { return None; }
    if entry.status != 403 { return None; }

    let metadata = read_metadata_headers(&entry.request_headers)
        .map_err(|e| eprintln!("bad log entry metadata: {}", e))
        .ok()?;

    Some(Proposal {
        id: filename.to_string(),
        target: entry.target,
        metadata,
    })
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
        get_member(&proposal.members, self_address),
        get_member(&current.members, self_address),
    ) {
        if current_self.permission.rank() < proposed.permission.rank() {
            return Some("your permission was downgraded since proposal");
        }
    }

    let modifier_is_owner = get_member(&proposal.members, &current.modified_by)
        .map(|m| m.permission) == Some(Permission::Owner);
    if modifier_is_owner {
        return None;
    }

    for member in &current.members {
        match get_member(&proposal.members, &member.address) {
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
    use std::env;
    use std::path::Path;

    use super::*;
    use crate::client::{init, put_io};
    use crate::context::create_client_context;
    use crate::server::start_test_server;
    use crate::util::test::in_test_dir;

    fn setup(temp_dir: &Path, port: u16) -> (IdentityContext, IdentityContext) {
        let alice_dir = temp_dir.join("alice_client");
        let bob_dir = temp_dir.join("bob_client");
        std::fs::create_dir_all(&alice_dir).unwrap();
        std::fs::create_dir_all(&bob_dir).unwrap();

        env::set_current_dir(&alice_dir).unwrap();
        init(&format!("alice@127.0.0.1:{}", port), None).unwrap();
        let alice_ctx = create_client_context().unwrap();

        env::set_current_dir(&bob_dir).unwrap();
        init(&format!("bob@127.0.0.1:{}", port), None).unwrap();
        let bob_ctx = create_client_context().unwrap();

        (alice_ctx, bob_ctx)
    }

    fn write_payload(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn list_proposals_returns_403_puts() {
        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (_alice_ctx, bob_ctx) = setup(temp_dir, port);

            env::set_current_dir(temp_dir.join("bob_client")).unwrap();
            let payload = write_payload(&temp_dir.join("bob_client"), "payload.bin", b"hello");
            let target = format!("alice@127.0.0.1:{}/apps/notes/foo.md", port);
            let _ = put_io(&bob_ctx, &target, Some(payload.to_str().unwrap()), Some("none"));

            env::set_current_dir(temp_dir.join("alice_client")).unwrap();
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

            env::set_current_dir(temp_dir.join("bob_client")).unwrap();
            let payload = write_payload(&temp_dir.join("bob_client"), "payload.bin", b"hello");
            let target = format!("alice@127.0.0.1:{}/apps/notes/foo.md", port);
            let _ = put_io(&bob_ctx, &target, Some(payload.to_str().unwrap()), Some("none"));

            env::set_current_dir(temp_dir.join("alice_client")).unwrap();
            let alice_ctx = create_client_context().unwrap();
            let proposals = list_proposals(&alice_ctx).unwrap();
            assert_eq!(proposals.len(), 1);

            reject_proposal(&alice_ctx, &proposals[0].id).unwrap();

            assert_eq!(list_proposals(&alice_ctx).unwrap().len(), 0);
        });
    }

    #[test]
    fn accept_proposal_creates_dir_and_pulls_file() {
        use crate::client::chmod_io;

        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (_alice_ctx, bob_ctx) = setup(temp_dir, port);

            env::set_current_dir(temp_dir.join("bob_client")).unwrap();
            let payload = write_payload(&temp_dir.join("bob_client"), "payload.bin", b"hello alice");
            put_io(&bob_ctx, "apps/notes/foo.md", Some(payload.to_str().unwrap()), Some("none")).unwrap();

            let alice_addr = format!("alice@127.0.0.1:{}", port);
            chmod_io(&bob_ctx, payload.to_str().unwrap(), &[], &[], &[alice_addr.clone()], &[]).unwrap();
            put_io(&bob_ctx, "apps/notes/foo.md", Some(payload.to_str().unwrap()), Some("none")).unwrap();

            env::set_current_dir(temp_dir.join("alice_client")).unwrap();
            let alice_ctx = create_client_context().unwrap();

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let proposals = loop {
                let p = list_proposals(&alice_ctx).unwrap();
                if !p.is_empty() || std::time::Instant::now() >= deadline { break p; }
                std::thread::sleep(std::time::Duration::from_millis(20));
            };
            assert_eq!(proposals.len(), 1, "expected one proposal");

            accept_proposal(&alice_ctx, &proposals[0].id, false).unwrap();

            let alice_file = temp_dir.join("ark/alice/apps/notes/foo.md");
            assert!(alice_file.exists(), "file should exist on alice's server");
            assert_eq!(std::fs::read(&alice_file).unwrap(), b"hello alice");

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
            "X-Ark-Meta-Created: c\r\n",
            "X-Ark-Meta-Modified: m\r\n",
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
        let p = parse_proposal("entry.http", entry.as_bytes()).expect("proposal");
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
        assert!(parse_proposal("entry.http", entry.as_bytes()).is_none());
    }

    #[test]
    fn parse_proposal_rejects_non_put() {
        let entry = concat!(
            "GET /ark/alice/foo HTTP/1.1\r\n",
            "\r\n",
            "HTTP/1.1 403 Forbidden\r\n",
            "\r\n",
        );
        assert!(parse_proposal("entry.http", entry.as_bytes()).is_none());
    }
}
