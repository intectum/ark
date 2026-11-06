use std::collections::HashSet;
use std::io;

use super::{get_stream, head, list, put_stream, request, watch_remote};

use crate::http::check_response_code;
use crate::identity::parse_address;
use crate::metadata::{read_metadata_headers, sign_metadata, write_metadata_headers};
use crate::paths::{grant_path_for, to_account_path, to_url};
use crate::timestamp;
use crate::types::{Context, EntryAction, Metadata, Permission, Permissions, Proposal};
use crate::util::{parse_request_entry, sha256};
use crate::versions::to_version;

/// List pending share proposals — requests where another account's PUT was
/// rejected with `403` at a path the current account owns. Returned in
/// chronological order.
///
/// Empty when the account has no request log (see [`crate::client::init`],
/// which sets it up).
pub fn list_proposals(ctx: &Context) -> io::Result<Vec<Proposal>> {
    let entries = list(ctx, "/.ark/requests/", Some("PUT_403_"))?;
    let (account_name, _, _) = parse_address(&ctx.identity.address)?;

    let mut proposals = Vec::new();
    for entry in entries {
        if !entry.name.ends_with(".http") { continue; }

        let entry_path = format!("/.ark/requests/{}", entry.name);
        let mut entry_body: Vec<u8> = Vec::new();
        if get_stream(ctx, &entry_path, &mut entry_body, false, None).is_err() {
            continue;
        }

        if let Some(proposal) = parse_proposal(&account_name, &entry.name, &entry_body)? {
            proposals.push(proposal);
        }
    }

    proposals.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(proposals)
}

/// Watch for share proposals arriving at `path` or below it and invoke
/// `on_proposal` for each. Blocks; auto-reconnects like
/// [`crate::client::watch_remote`]. Either callback returning `true` stops the
/// watcher; `on_error` receives stream and fetch errors.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`); use `/` for every path in the account.
///
/// Only proposals logged after the call started are reported, so callers
/// wanting the pending ones too should call [`list_proposals`] first.
pub fn watch_proposals<F, G>(ctx: &Context, path: &str, mut on_proposal: F, on_error: G) -> io::Result<()>
where
    F: FnMut(Proposal) -> bool,
    G: Fn(io::Error) -> bool,
{
    let path_prefix = to_account_path(ctx, path)?.trim_end_matches('/').to_string();
    let requests_url = to_url(ctx, "/.ark/requests/")?;

    let mut reported: HashSet<String> = HashSet::new();

    watch_remote(ctx, &requests_url, |event| {
        match event.action {
            EntryAction::Created | EntryAction::Modified => {}
            _ => return false,
        }

        let id = event.path.to_string_lossy().into_owned();
        if !id.starts_with("PUT_403_") || !id.ends_with(".http") { return false; }
        if reported.contains(&id) { return false; }

        let proposal = match fetch_proposal(ctx, &id) {
            Ok(Some(p)) => p,
            Ok(None) => return false,
            Err(e) => {
                on_error(io::Error::other(format!("proposal {}: {}", id, e)));
                return false;
            }
        };

        reported.insert(id);

        let under_path = proposal.path == path_prefix
            || proposal.path.starts_with(&format!("{}/", path_prefix));
        if !under_path { return false; }

        on_proposal(proposal)
    }, &on_error)
}

/// Accept a share proposal. `index_or_id`: 1-based index (from
/// [`list_proposals`]) or a log entry filename.
///
/// Pulls the current file/dir from the author's server, checks it has not
/// been maliciously altered since the proposal (id unchanged, no unauthorised
/// member additions/upgrades, current account not downgraded), and applies it
/// to the target path on the current account. The account signs a grant for
/// the version it accepted, under `/.ark/grants/`, which is what lets its
/// devices trust a path another account wrote; deleting the grant withdraws
/// that. The log entry is removed on success.
///
/// With `force=true`, accepts the current metadata as-is even if members were
/// added or the current account was downgraded since the proposal.
pub fn accept_proposal(ctx: &Context, index_or_id: &str, force: bool) -> io::Result<()> {
    let id = resolve_id(ctx, index_or_id)?;
    let entry_path = format!("/.ark/requests/{}", id);
    let mut entry_body: Vec<u8> = Vec::new();
    let (entry_metadata, _) = get_stream(ctx, &entry_path, &mut entry_body, false, None)?;
    let (account_name, _, _) = parse_address(&ctx.identity.address)?;
    let proposal = parse_proposal(&account_name, &id, &entry_body)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entry is not a valid proposal"))?;

    let relative_path = proposal.path.trim_start_matches('/');

    let target_is_dir = proposal.metadata.body_hash.is_none();
    let author_path = if target_is_dir {
        format!("{}/{}/", proposal.metadata.author, relative_path.trim_end_matches('/'))
    } else {
        format!("{}/{}", proposal.metadata.author, relative_path)
    };

    let (metadata, body) = if target_is_dir {
        let (_, metadata) = head(ctx, &author_path)?;
        (metadata, Vec::new())
    } else {
        let mut buf: Vec<u8> = Vec::new();
        let (metadata, _) = get_stream(ctx, &author_path, &mut buf, false, None)?;
        let expected_hash = metadata.body_hash.as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "file metadata missing body_hash"))?;
        if sha256(&buf) != expected_hash.value {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "fetched body hash does not match metadata"));
        }
        (metadata, buf)
    };

    if !force {
        validate_metadata_changes(&proposal.metadata, &metadata, &ctx.identity.address)?;
    }

    let version = to_version(&metadata);
    let path = if target_is_dir {
        format!("/{}/", relative_path.trim_end_matches('/'))
    } else {
        format!("/{}", relative_path)
    };

    let grant_path = grant_path_for(&path);
    let existing_grant_metadata = match head(ctx, &grant_path) {
        Ok((_, grant_metadata)) => Some(grant_metadata),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    put_stream(ctx, &grant_path, Some(&mut version.as_bytes()), &Permissions::default(), Some("none"), existing_grant_metadata, None, false)?;

    let url = to_url(ctx, &path)?;
    let headers = write_metadata_headers(&metadata);
    let header_refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    let (code, _, resp_body) = request(Some(ctx), "PUT", &url, &header_refs, &body)?;
    check_response_code(code, &resp_body)?;

    delete_entry(ctx, &entry_path, &entry_metadata)?;

    Ok(())
}

/// Reject a share proposal by deleting its log entry. `index_or_id` may be a
/// 1-based index (as returned by [`list_proposals`]) or a log entry filename.
/// The current file/dir on the author's server is untouched; any future
/// attempt by the same account will simply produce a new log entry.
pub fn reject_proposal(ctx: &Context, index_or_id: &str) -> io::Result<()> {
    let id = resolve_id(ctx, index_or_id)?;
    let entry_path = format!("/.ark/requests/{}", id);
    let (_, entry_metadata) = head(ctx, &entry_path)?;
    delete_entry(ctx, &entry_path, &entry_metadata)?;

    Ok(())
}

fn delete_entry(ctx: &Context, entry_path: &str, entry_metadata: &Metadata) -> io::Result<()> {
    let mut metadata = entry_metadata.clone();
    metadata.parent_version = Some(to_version(entry_metadata));
    metadata.author = ctx.identity.address.clone();
    metadata.author_date = timestamp::now();
    metadata.deleted = true;

    sign_metadata(ctx.identity_key.as_ref().expect("client context missing identity_key"), &mut metadata, None)?;

    let headers = write_metadata_headers(&metadata);
    let header_refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    let (code, _, body) = request(Some(ctx), "DELETE", &to_url(ctx, entry_path)?, &header_refs, &[])?;
    check_response_code(code, &body)
}

fn resolve_id(ctx: &Context, index_or_id: &str) -> io::Result<String> {
    if let Ok(index) = index_or_id.parse::<usize>() {
        let proposals = list_proposals(ctx)?;
        if index == 0 || index > proposals.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("no proposal at index {}", index)));
        }
        Ok(proposals[index - 1].id.clone())
    } else {
        Ok(index_or_id.to_string())
    }
}

fn fetch_proposal(ctx: &Context, id: &str) -> io::Result<Option<Proposal>> {
    let entry_path = format!("/.ark/requests/{}", id);

    let mut entry_body: Vec<u8> = Vec::new();
    get_stream(ctx, &entry_path, &mut entry_body, false, None)?;

    let (account_name, _, _) = parse_address(&ctx.identity.address)?;
    parse_proposal(&account_name, id, &entry_body)
}

fn parse_proposal(account_name: &str, filename: &str, entry_bytes: &[u8]) -> io::Result<Option<Proposal>> {
    let entry = parse_request_entry(entry_bytes)?;

    if entry.method != "PUT" { return Ok(None); }
    if entry.status != 403 { return Ok(None); }

    let server_path = entry.target.split_once('?').map(|(path, _)| path).unwrap_or(&entry.target);
    let path = match server_path.strip_prefix(&format!("/ark/{}", account_name)) {
        Some("") | Some("/") => "/".to_string(),
        Some(rest) if rest.starts_with('/') => rest.trim_end_matches('/').to_string(),
        _ => return Ok(None),
    };

    let metadata = read_metadata_headers(&entry.request_headers)?;

    Ok(Some(Proposal {
        id: filename.to_string(),
        path,
        metadata,
    }))
}

fn validate_metadata_changes(proposal: &Metadata, current: &Metadata, self_address: &str) -> io::Result<()> {
    if current.id != proposal.id {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "id is wrong"));
    }

    if let Some(msg) = check_member_changes(proposal, current, self_address) {
        let mut listing = String::new();
        for member in &current.members {
            listing.push_str(&format!("\n  {} = {}", member.address, member.permission.as_str()));
        }
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}. Current members:{}\nUse --force to accept anyway.", msg, listing)));
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

    let author_is_owner = proposal.members.iter().find(|m| m.address == current.author)
        .map(|m| m.permission) == Some(Permission::Owner);
    if author_is_owner {
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
    use std::sync::mpsc::channel;
    use std::thread::{sleep, spawn};
    use std::time::{Duration, Instant};

    use super::*;

    use crate::client::{get, init, put};
    use crate::context::create_client_context;
    use crate::permissions::reader;
    use crate::testing::fs::{in_test_dir, write_plain_test_file};
    use crate::testing::http::start_test_server;

    fn setup(temp_dir: &Path, port: u16) -> (Context, Context) {
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
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn list_proposals_returns_403_puts() {
        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (_alice_ctx, bob_ctx) = setup(temp_dir, port);

            set_current_dir(temp_dir.join("bob_client")).unwrap();
            write_payload(&temp_dir.join("bob_client"), "apps/notes/foo.md", b"hello");
            let target = format!("alice@127.0.0.1:{}/apps/notes/foo.md", port);
            let _ = put(&bob_ctx, &target, &Permissions::default(), Some("none"), false);

            set_current_dir(temp_dir.join("alice_client")).unwrap();
            let alice_ctx = create_client_context().unwrap();
            let proposals = list_proposals(&alice_ctx).unwrap();

            assert_eq!(proposals.len(), 1);
            assert_eq!(proposals[0].metadata.author, bob_ctx.identity.address);
            assert_eq!(proposals[0].path, "/apps/notes/foo.md");
        });
    }

    #[test]
    fn reject_proposal_deletes_log_entry() {
        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (_alice_ctx, bob_ctx) = setup(temp_dir, port);

            set_current_dir(temp_dir.join("bob_client")).unwrap();
            write_payload(&temp_dir.join("bob_client"), "apps/notes/foo.md", b"hello");
            let target = format!("alice@127.0.0.1:{}/apps/notes/foo.md", port);
            let _ = put(&bob_ctx, &target, &Permissions::default(), Some("none"), false);

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
            write_payload(&temp_dir.join("bob_client"), "apps/notes/foo.md", b"hello alice");
            put(&bob_ctx, "apps/notes/foo.md", &Permissions::default(), Some("none"), false).unwrap();

            let alice_addr = format!("alice@127.0.0.1:{}", port);
            put(&bob_ctx, "apps/notes/foo.md", &reader(alice_addr.clone()), Some("none"), false).unwrap();

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

            // Bob wrote it, but the account's grant vouches for it on a device
            // holding nothing of it yet.
            fs::remove_dir_all(temp_dir.join("alice_client/.ark/versions")).unwrap();
            get(&alice_ctx, "/apps/notes/foo.md", false).unwrap();
            assert_eq!(fs::read(temp_dir.join("alice_client/apps/notes/foo.md")).unwrap(), b"hello alice");
        });
    }

    #[test]
    fn a_grant_the_account_did_not_sign_is_ignored() {
        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (_alice_ctx, bob_ctx) = setup(temp_dir, port);

            set_current_dir(temp_dir.join("bob_client")).unwrap();
            write_payload(&temp_dir.join("bob_client"), "apps/notes/foo.md", b"hello alice");
            put(&bob_ctx, "apps/notes/foo.md", &Permissions::default(), Some("none"), false).unwrap();
            let alice_addr = format!("alice@127.0.0.1:{}", port);
            put(&bob_ctx, "apps/notes/foo.md", &reader(alice_addr.clone()), Some("none"), false).unwrap();

            set_current_dir(temp_dir.join("alice_client")).unwrap();
            let alice_ctx = create_client_context().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let proposals = loop {
                let p = list_proposals(&alice_ctx).unwrap();
                if !p.is_empty() || Instant::now() >= deadline { break p; }
                sleep(Duration::from_millis(20));
            };
            accept_proposal(&alice_ctx, &proposals[0].id, false).unwrap();

            // The same grant, signed by Bob rather than the account.
            let grant_file = temp_dir.join("ark/alice").join(grant_path_for("/apps/notes/foo.md").trim_start_matches('/'));
            let grant = fs::read(&grant_file).unwrap();
            write_plain_test_file(&grant_file, &bob_ctx.identity, bob_ctx.identity_key.as_ref().unwrap(), &grant);

            // A device holding nothing of it yet.
            fs::remove_dir_all(temp_dir.join("alice_client/.ark/versions")).unwrap();
            let err = get(&alice_ctx, "/apps/notes/foo.md", false).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{}", err);
        });
    }

    #[test]
    fn watch_proposals_reports_new_403_puts_under_path() {
        in_test_dir("ark_proposals_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let (alice_ctx, bob_ctx) = setup(temp_dir, port);

            let (tx, rx) = channel();
            // Detached: on failure `watch_proposals` never returns, so joining
            // it would hang the test rather than fail it.
            spawn(move || {
                let _ = watch_proposals(&alice_ctx, "/apps/notes", |proposal| {
                    let _ = tx.send(proposal);
                    true
                }, |_| false);
            });
            sleep(Duration::from_millis(500));

            set_current_dir(temp_dir.join("bob_client")).unwrap();
            write_payload(&temp_dir.join("bob_client"), "docs/other.md", b"hello");
            let outside_target = format!("alice@127.0.0.1:{}/docs/other.md", port);
            let _ = put(&bob_ctx, &outside_target, &Permissions::default(), Some("none"), false);
            write_payload(&temp_dir.join("bob_client"), "apps/notes/foo.md", b"hello");
            let target = format!("alice@127.0.0.1:{}/apps/notes/foo.md", port);
            let _ = put(&bob_ctx, &target, &Permissions::default(), Some("none"), false);

            let proposal = rx.recv_timeout(Duration::from_secs(10)).expect("expected a proposal");
            assert_eq!(proposal.path, "/apps/notes/foo.md");
            assert_eq!(proposal.metadata.author, bob_ctx.identity.address);
        });
    }

    #[test]
    fn parse_proposal_extracts_fields() {
        let entry = concat!(
            "PUT /ark/alice/foo HTTP/1.1\r\n",
            "Host: h\r\n",
            "Authorization: ArkIdentity address=\"ark@h\", timestamp=\"123\", signature=\"sig\"\r\n",
            "X-Ark-Meta-Id: 0f3e1c62-9a4b-4d7e-8c11-2b5a6d9e4f30\r\n",
            "X-Ark-Meta-Author: bob@h\r\n",
            "X-Ark-Meta-Author-Date: 2026-01-02T00:00:00.000Z\r\n",
            "X-Ark-Meta-Member-0-Address: bob@h\r\n",
            "X-Ark-Meta-Member-0-Permission: owner\r\n",
            "X-Ark-Meta-Signature-Algorithm: ed25519\r\n",
            "X-Ark-Meta-Signature-Value: dGVzdA\r\n",
            "\r\n",
            "HTTP/1.1 403 Forbidden\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let p = parse_proposal("alice", "entry.http", entry.as_bytes()).unwrap().expect("proposal");
        assert_eq!(p.metadata.author, "bob@h");
        assert_eq!(p.path, "/foo");
        assert!(parse_proposal("alicebob", "entry.http", entry.as_bytes()).unwrap().is_none(), "a PUT to another account is no proposal for this one");
    }

    #[test]
    fn parse_proposal_rejects_non_403() {
        let entry = concat!(
            "PUT /ark/alice/foo HTTP/1.1\r\n",
            "\r\n",
            "HTTP/1.1 201 Created\r\n",
            "\r\n",
        );
        assert!(parse_proposal("alice", "entry.http", entry.as_bytes()).unwrap().is_none());
    }

    #[test]
    fn parse_proposal_rejects_non_put() {
        let entry = concat!(
            "GET /ark/alice/foo HTTP/1.1\r\n",
            "\r\n",
            "HTTP/1.1 403 Forbidden\r\n",
            "\r\n",
        );
        assert!(parse_proposal("alice", "entry.http", entry.as_bytes()).unwrap().is_none());
    }
}
