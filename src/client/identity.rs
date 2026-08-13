use std::fs;
use std::io;

use super::{put, put_content, put_permissions};

use crate::identity::{
    create_identity as create_identity_raw, read_identity, read_identity_key, sign_identity,
    validate_identity, write_identity, write_identity_key,
};
use crate::permissions::{reader, readers};
use crate::types::{Identity, IdentityContext, Key, Permissions};
use crate::util::{resolve_address, resolve_local_path};

/// Create an identity (keypair document) at `path`.
///
/// `path` must end with `.json` and accepts relative, absolute account (leading
/// `/`), or address form (`<name>@<host>/...`). Writes a companion private key
/// beside it with the same stem and a `.key` suffix.
///
/// Publishes the identity document as a public-readable file and the private
/// key encrypted for the account owner (and any group members).
///
/// When `members` is non-empty, creates a group: listed addresses appear in the
/// identity document and each is granted `reader` on the encrypted private key.
/// Members must be regular account addresses — nested groups are not supported.
/// With no members, the identity has no `members` field.
///
/// Returns the new [`Identity`] and its secret [`Key`].
pub fn create_identity(ctx: &IdentityContext, path: &str, members: &[String]) -> io::Result<(Identity, Key)> {
    if !path.ends_with(".json") {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path must end with .json"));
    }

    let local_path = resolve_local_path(ctx, path)?;
    let address = resolve_address(ctx, path)?;
    let key_path = local_path.with_extension("key");

    if local_path.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", local_path.display())));
    }

    if key_path.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", key_path.display())));
    }

    let final_members = if members.is_empty() {
        None
    } else {
        let mut unique_members: Vec<String> = Vec::new();
        for member_address in members {
            if !unique_members.contains(member_address) {
                unique_members.push(member_address.clone());
            }
        }
        Some(unique_members)
    };

    let (identity, secret_key) = create_identity_raw(&address, final_members.clone())?;
    validate_identity(&identity)?;

    if let Some(parent) = local_path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }

    write_identity(&local_path, &identity)?;
    write_identity_key(&key_path, &secret_key.value)?;

    let self_address = ctx.identity.address.as_str();
    let key_permissions = match &final_members {
        Some(list) => readers(list.iter().filter(|address| *address != self_address).cloned()),
        None => Permissions::default(),
    };

    put(ctx, &address, local_path.to_str(), &reader("public"), Some("none"), false)?;
    put(ctx, &key_path_for(path), key_path.to_str(), &key_permissions, None, false)?;

    Ok((identity, secret_key))
}

/// Add and/or drop members on an identity at `path`.
///
/// `path` must end with `.json` and accepts relative, absolute account (leading
/// `/`), or address form (`<name>@<host>/...`). At least one of `add` or
/// `drop` must be non-empty.
///
/// Adds each address in `add`; removes each address in `drop`. Adds apply
/// first, then drops (drop supersedes add). Both are idempotent. Adding
/// members promotes a regular identity to a group.
///
/// Re-signs and publishes the identity document, and adjusts `reader` access on
/// the encrypted private key for net membership changes. Does not rotate the
/// group keypair.
pub fn change_identity_members(
    ctx: &IdentityContext,
    path: &str,
    add: &[String],
    drop: &[String],
) -> io::Result<()> {
    if !path.ends_with(".json") {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path must end with .json"));
    }

    if add.is_empty() && drop.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "at least one add or drop address is required"));
    }

    let local_path = resolve_local_path(ctx, path)?;

    let mut identity = read_identity(&local_path)?;
    let secret_key = Key {
        algorithm: identity.public_key.algorithm.clone(),
        value: read_identity_key(&local_path.with_extension("key"))?,
    };

    let mut members = identity.members.take().unwrap_or_default();
    let original = members.clone();

    for member_address in add {
        if !members.contains(member_address) {
            members.push(member_address.clone());
        }
    }
    for member_address in drop {
        members.retain(|m| m != member_address);
    }

    if members == original {
        return Ok(());
    }

    let readers: Vec<String> = members
        .iter()
        .filter(|m| !original.contains(m) && *m != &ctx.identity.address)
        .cloned()
        .collect();
    let drops: Vec<String> = original
        .iter()
        .filter(|m| !members.contains(m) && *m != &ctx.identity.address)
        .cloned()
        .collect();

    identity.members = Some(members);

    sign_identity(&secret_key, &mut identity)?;
    validate_identity(&identity)?;

    write_identity(&local_path, &identity)?;

    put_content(ctx, path)?;
    if !readers.is_empty() || !drops.is_empty() {
        let permissions = Permissions {
            readers,
            drops,
            ..Permissions::default()
        };
        put_permissions(ctx, &key_path_for(path), &permissions)?;
    }

    Ok(())
}

fn key_path_for(json_path: &str) -> String {
    format!("{}.key", json_path.strip_suffix(".json").unwrap_or(json_path))
}

#[cfg(test)]
mod tests {
    use std::env::set_current_dir;
    use std::path::Path;

    use super::*;

    use crate::client::init_local;
    use crate::context::create_client_context;
    use crate::crypto::DEFAULT_ENCRYPTION_ALGORITHM;
    use crate::identity::{read_identity, write_identity};
    use crate::metadata::read_metadata_attributes;
    use crate::testing::fs::{create_test_account, in_test_dir, init_with_server};
    use crate::testing::http::start_test_server;
    use crate::types::Identity;

    fn cache_identity(root: &Path, identity: &Identity) {
        let cache_dir = root.join(".ark").join("identities");
        fs::create_dir_all(&cache_dir).unwrap();
        write_identity(&cache_dir.join(format!("{}.json", identity.address)), identity).unwrap();
    }

    #[test]
    fn create_identity_publishes_identity_and_key() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            let (identity, _) = create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();

            let expected_address = format!("{}/team.json", alice_address);

            assert_eq!(identity.address, expected_address);
            let members = identity.members.as_ref().expect("members set");
            assert_eq!(members, &vec![bob_address.clone()]);

            let server_identity_path = temp_dir.join("ark/alice/team.json");
            assert!(server_identity_path.exists(), "server identity uploaded");
            let server_identity = read_identity(&server_identity_path).unwrap();
            assert_eq!(server_identity.members.as_ref().unwrap(), members);

            let server_key_path = temp_dir.join("ark/alice/team.key");
            assert!(server_key_path.exists(), "server key uploaded");
            let key_metadata = read_metadata_attributes(&server_key_path).unwrap();
            assert_eq!(key_metadata.encryption_algorithm.as_deref(), Some(DEFAULT_ENCRYPTION_ALGORITHM));
            // Creator is key owner; listed members get reader.
            assert!(key_metadata.members.iter().any(|m| m.address == alice_address));
            assert!(key_metadata.members.iter().any(|m| m.address == bob_address));
        });
    }

    #[test]
    fn create_identity_rejects_duplicate_path() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            create_identity(&ctx, "team.json", &[]).unwrap();
            let err = create_identity(&ctx, "team.json", &[]).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        });
    }

    #[test]
    fn create_identity_without_members_is_not_a_group() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let (identity, secret_key) = create_identity(&ctx, "team.json", &[]).unwrap();

            assert!(identity.members.is_none());
            assert_eq!(identity.address, format!("{}/team.json", address));
            assert!(!secret_key.value.is_empty());

            let key_path = temp_dir.join("team.key");
            assert!(key_path.exists());
            let body = fs::read_to_string(&key_path).unwrap();
            assert!(!body.is_empty());
        });
    }

    #[test]
    fn create_identity_nested_relative_path() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let (identity, _) = create_identity(&ctx, "contacts/team.json", &[]).unwrap();

            assert_eq!(identity.address, format!("{}/contacts/team.json", address));
            assert!(temp_dir.join("contacts/team.key").exists());
            assert!(temp_dir.join("ark/alice/contacts/team.json").exists());
        });
    }

    #[test]
    fn create_identity_requires_json_suffix() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let err = create_identity(&ctx, "team", &[]).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn create_identity_account_absolute_path() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let (identity, _) = create_identity(&ctx, "/groups/team.json", &[]).unwrap();

            assert_eq!(identity.address, format!("{}/groups/team.json", address));
            assert!(temp_dir.join("groups/team.key").exists());
            assert!(temp_dir.join("ark/alice/groups/team.json").exists());
        });
    }

    #[test]
    fn create_identity_address_form_path() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &alice_address);

            // Same-account address form; local files still land under the path portion
            // of the address.
            let path = format!("{}/team.json", alice_address);
            let (identity, _) = create_identity(&ctx, &path, &[]).unwrap();

            assert_eq!(identity.address, format!("{}/team.json", alice_address));
            assert!(temp_dir.join("team.key").exists());
            assert!(temp_dir.join("ark/alice/team.json").exists());
        });
    }

    #[test]
    fn create_identity_rejects_bare_address_without_path() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let err = create_identity(&ctx, &address, &[]).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn init_local_still_produces_non_group_identity() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let (identity, _) = init_local(temp_dir, "alice@example.com").unwrap();
            assert!(identity.members.is_none());
        });
    }

    #[test]
    fn group_member_can_get_shared_file_via_group() {
        use crate::metadata::{sign_metadata, write_metadata_attributes};
        use crate::testing::fs::create_plain_test_metadata;
        use crate::testing::http::signed_request;
        use crate::types::{Member, Permission};

        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, bob_key, _) = create_test_account(temp_dir, &bob_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            let group_address = format!("{}/team.json", alice_address);

            let shared_path = temp_dir.join("ark/alice/shared.txt");
            let mut meta = create_plain_test_metadata(&ctx.identity, ctx.identity_key.as_ref().unwrap(), b"secret");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            meta.members.push(Member {
                address: group_address.clone(),
                permission: Permission::Reader,
                key: None,
            });
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut meta, Some(b"secret")).unwrap();
            fs::write(&shared_path, b"secret").unwrap();
            write_metadata_attributes(&shared_path, &meta).unwrap();

            let (code, body, _) = signed_request(port, &bob_identity, &bob_key, "GET", "/ark/alice/shared.txt", &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"secret");
        });
    }

    #[test]
    fn non_group_member_gets_forbidden() {
        use crate::metadata::{sign_metadata, write_metadata_attributes};
        use crate::testing::fs::create_plain_test_metadata;
        use crate::testing::http::signed_request;
        use crate::types::{Member, Permission};

        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let charlie_address = format!("charlie@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let (charlie_identity, charlie_key, _) = create_test_account(temp_dir, &charlie_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            let group_address = format!("{}/team.json", alice_address);

            let shared_path = temp_dir.join("ark/alice/shared.txt");
            let mut meta = create_plain_test_metadata(&ctx.identity, ctx.identity_key.as_ref().unwrap(), b"secret");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            meta.members.push(Member {
                address: group_address.clone(),
                permission: Permission::Reader,
                key: None,
            });
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut meta, Some(b"secret")).unwrap();
            fs::write(&shared_path, b"secret").unwrap();
            write_metadata_attributes(&shared_path, &meta).unwrap();

            let (code, _, _) = signed_request(port, &charlie_identity, &charlie_key, "GET", "/ark/alice/shared.txt", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn nested_group_rejected() {
        use crate::identity::create_identity as generate_identity;
        use crate::metadata::{sign_metadata, write_metadata_attributes};
        use crate::testing::fs::create_plain_test_metadata;
        use crate::testing::http::signed_request;
        use crate::types::{Member, Permission};

        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, bob_key, _) = create_test_account(temp_dir, &bob_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            let inner_address = format!("{}/inner.json", alice_address);
            let (inner_identity, _inner_key) =
                generate_identity(&inner_address, Some(vec![bob_address.clone()])).unwrap();
            let inner_path = temp_dir.join("ark/alice/inner.json");
            fs::create_dir_all(inner_path.parent().unwrap()).unwrap();
            write_identity(&inner_path, &inner_identity).unwrap();
            let inner_body = fs::read(&inner_path).unwrap();
            let mut inner_meta = create_plain_test_metadata(&ctx.identity, ctx.identity_key.as_ref().unwrap(), &inner_body);
            inner_meta.encryption_algorithm = None;
            inner_meta.members[0].key = None;
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut inner_meta, Some(&inner_body)).unwrap();
            write_metadata_attributes(&inner_path, &inner_meta).unwrap();

            let outer_address = format!("{}/outer.json", alice_address);
            let (outer_identity, _outer_key) =
                generate_identity(&outer_address, Some(vec![inner_address.clone()])).unwrap();
            let outer_path = temp_dir.join("ark/alice/outer.json");
            write_identity(&outer_path, &outer_identity).unwrap();
            let outer_body = fs::read(&outer_path).unwrap();
            let mut outer_meta = create_plain_test_metadata(&ctx.identity, ctx.identity_key.as_ref().unwrap(), &outer_body);
            outer_meta.encryption_algorithm = None;
            outer_meta.members[0].key = None;
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut outer_meta, Some(&outer_body)).unwrap();
            write_metadata_attributes(&outer_path, &outer_meta).unwrap();

            let shared_path = temp_dir.join("ark/alice/shared.txt");
            let mut meta = create_plain_test_metadata(&ctx.identity, ctx.identity_key.as_ref().unwrap(), b"secret");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            meta.members.push(Member {
                address: outer_address.clone(),
                permission: Permission::Reader,
                key: None,
            });
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut meta, Some(b"secret")).unwrap();
            fs::write(&shared_path, b"secret").unwrap();
            write_metadata_attributes(&shared_path, &meta).unwrap();

            let (code, _, _) = signed_request(port, &bob_identity, &bob_key, "GET", "/ark/alice/shared.txt", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn create_identity_self_signature_verifies() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let (identity, _) = create_identity(&ctx, "team.json", &[]).unwrap();

            set_current_dir(temp_dir).unwrap();
            let _ = create_client_context().unwrap();

            validate_identity(&identity).unwrap();
        });
    }

    #[test]
    fn change_identity_members_add_updates_identity_and_key() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let charlie_address = format!("charlie@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let (charlie_identity, _, _) = create_test_account(temp_dir, &charlie_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);
            cache_identity(&ctx.root, &charlie_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            change_identity_members(&ctx, "team.json", std::slice::from_ref(&charlie_address), &[]).unwrap();

            let identity = read_identity(&temp_dir.join("team.json")).unwrap();
            let members = identity.members.as_ref().unwrap();
            assert_eq!(members, &vec![bob_address.clone(), charlie_address.clone()]);
            validate_identity(&identity).unwrap();

            let server_identity = read_identity(&temp_dir.join("ark/alice/team.json")).unwrap();
            assert_eq!(server_identity.members.as_ref().unwrap(), members);

            let key_metadata = read_metadata_attributes(&temp_dir.join("ark/alice/team.key")).unwrap();
            assert!(key_metadata.members.iter().any(|m| m.address == charlie_address));
        });
    }

    #[test]
    fn change_identity_members_add_is_idempotent() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            change_identity_members(&ctx, "team.json", std::slice::from_ref(&bob_address), &[]).unwrap();

            let identity = read_identity(&temp_dir.join("team.json")).unwrap();
            assert_eq!(identity.members.as_ref().unwrap(), &vec![bob_address.clone()]);
        });
    }

    #[test]
    fn change_identity_members_drop_updates_identity_and_key() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            change_identity_members(&ctx, "team.json", &[], std::slice::from_ref(&bob_address)).unwrap();

            let identity = read_identity(&temp_dir.join("team.json")).unwrap();
            let members = identity.members.as_ref().unwrap();
            assert!(members.is_empty());
            validate_identity(&identity).unwrap();

            let key_metadata = read_metadata_attributes(&temp_dir.join("ark/alice/team.key")).unwrap();
            assert!(!key_metadata.members.iter().any(|m| m.address == bob_address));
            assert!(key_metadata.members.iter().any(|m| m.address == alice_address));
        });
    }

    #[test]
    fn change_identity_members_drop_is_idempotent() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            change_identity_members(&ctx, "team.json", &[], std::slice::from_ref(&bob_address)).unwrap();
            change_identity_members(&ctx, "team.json", &[], std::slice::from_ref(&bob_address)).unwrap();

            let identity = read_identity(&temp_dir.join("team.json")).unwrap();
            assert!(identity.members.as_ref().unwrap().is_empty());
        });
    }

    #[test]
    fn change_identity_members_can_drop_account_owner() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let ctx = init_with_server(temp_dir, &address);
            cache_identity(&ctx.root, &bob_identity);

            create_identity(&ctx, "team.json", &[address.clone(), bob_address.clone()]).unwrap();
            change_identity_members(&ctx, "team.json", &[], std::slice::from_ref(&address)).unwrap();

            let identity = read_identity(&temp_dir.join("team.json")).unwrap();
            assert_eq!(identity.members.as_ref().unwrap(), &vec![bob_address.clone()]);

            let key_metadata = read_metadata_attributes(&temp_dir.join("ark/alice/team.key")).unwrap();
            assert!(key_metadata.members.iter().any(|m| m.address == address));
        });
    }

    #[test]
    fn change_identity_members_drop_supersedes_add() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            // Drop wins: bob is not a member afterwards.
            change_identity_members(
                &ctx,
                "team.json",
                std::slice::from_ref(&bob_address),
                std::slice::from_ref(&bob_address),
            )
            .unwrap();

            let identity = read_identity(&temp_dir.join("team.json")).unwrap();
            assert!(identity.members.as_ref().unwrap().is_empty());
        });
    }

    #[test]
    fn change_identity_members_drop_then_access_denied() {
        use crate::metadata::{sign_metadata, write_metadata_attributes};
        use crate::testing::fs::create_plain_test_metadata;
        use crate::testing::http::signed_request;
        use crate::types::{Member, Permission};

        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, bob_key, _) = create_test_account(temp_dir, &bob_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            let group_address = format!("{}/team.json", alice_address);

            let shared_path = temp_dir.join("ark/alice/shared.txt");
            let mut meta = create_plain_test_metadata(&ctx.identity, ctx.identity_key.as_ref().unwrap(), b"secret");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            meta.members.push(Member {
                address: group_address.clone(),
                permission: Permission::Reader,
                key: None,
            });
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut meta, Some(b"secret")).unwrap();
            fs::write(&shared_path, b"secret").unwrap();
            write_metadata_attributes(&shared_path, &meta).unwrap();

            let (code, body, _) = signed_request(port, &bob_identity, &bob_key, "GET", "/ark/alice/shared.txt", &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"secret");

            change_identity_members(&ctx, "team.json", &[], std::slice::from_ref(&bob_address)).unwrap();

            let (code, _, _) = signed_request(port, &bob_identity, &bob_key, "GET", "/ark/alice/shared.txt", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn change_identity_members_add_promotes_to_group() {
        use crate::metadata::{sign_metadata, write_metadata_attributes};
        use crate::testing::fs::create_plain_test_metadata;
        use crate::testing::http::signed_request;
        use crate::types::{Member, Permission};

        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let (bob_identity, bob_key, _) = create_test_account(temp_dir, &bob_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);

            let (identity, _) = create_identity(&ctx, "team.json", &[]).unwrap();
            assert!(identity.members.is_none());

            let group_address = format!("{}/team.json", alice_address);

            let shared_path = temp_dir.join("ark/alice/shared.txt");
            let mut meta = create_plain_test_metadata(&ctx.identity, ctx.identity_key.as_ref().unwrap(), b"secret");
            meta.encryption_algorithm = None;
            meta.members[0].key = None;
            meta.members.push(Member {
                address: group_address.clone(),
                permission: Permission::Reader,
                key: None,
            });
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut meta, Some(b"secret")).unwrap();
            fs::write(&shared_path, b"secret").unwrap();
            write_metadata_attributes(&shared_path, &meta).unwrap();

            let (code, _, _) = signed_request(port, &bob_identity, &bob_key, "GET", "/ark/alice/shared.txt", &[]);
            assert_eq!(code, 403);

            change_identity_members(&ctx, "team.json", std::slice::from_ref(&bob_address), &[]).unwrap();

            let identity = read_identity(&temp_dir.join("team.json")).unwrap();
            assert_eq!(identity.members.as_ref().unwrap(), &vec![bob_address.clone()]);

            let (code, body, _) = signed_request(port, &bob_identity, &bob_key, "GET", "/ark/alice/shared.txt", &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"secret");
        });
    }

    #[test]
    fn change_identity_members_add_and_drop_in_one_call() {
        in_test_dir("ark_identity_client_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let alice_address = format!("alice@127.0.0.1:{}", port);
            let bob_address = format!("bob@127.0.0.1:{}", port);
            let charlie_address = format!("charlie@127.0.0.1:{}", port);
            let (bob_identity, _, _) = create_test_account(temp_dir, &bob_address);
            let (charlie_identity, _, _) = create_test_account(temp_dir, &charlie_address);
            let ctx = init_with_server(temp_dir, &alice_address);
            cache_identity(&ctx.root, &bob_identity);
            cache_identity(&ctx.root, &charlie_identity);

            create_identity(&ctx, "team.json", std::slice::from_ref(&bob_address)).unwrap();
            change_identity_members(
                &ctx,
                "team.json",
                std::slice::from_ref(&charlie_address),
                std::slice::from_ref(&bob_address),
            )
            .unwrap();

            let identity = read_identity(&temp_dir.join("team.json")).unwrap();
            assert_eq!(identity.members.as_ref().unwrap(), &vec![charlie_address.clone()]);

            let key_metadata = read_metadata_attributes(&temp_dir.join("ark/alice/team.key")).unwrap();
            assert!(!key_metadata.members.iter().any(|m| m.address == bob_address));
            assert!(key_metadata.members.iter().any(|m| m.address == charlie_address));
        });
    }
}
