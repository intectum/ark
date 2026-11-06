use std::io;

use time::OffsetDateTime;

use crate::client::{get_stream, list_versions, request};
use crate::http::check_response_code;
use crate::identity::resolve_identity;
use crate::metadata::{members_changed, read_inherited_metadata_attributes, read_metadata_attributes, read_metadata_headers, resolve_member_permission, verify_metadata, verify_metadata_signature};
use crate::paths::{grant_path_for, is_request_log_path, parent_path, to_account_path, to_address, to_url};
use crate::storage::{exists, read};
use crate::types::{Context, Member, Metadata, Permission};
use crate::versions::{get_version_chain, read_version_metadata_attributes, to_version, version_path_for, write_version};

/// Checks that `metadata`, with `body` where it arrived with one, can be
/// trusted as an entry of `path` by the account `ctx` belongs to.
///
/// It must be signed by its author, and `body` must be the one it names. Then
/// the account signed it, or granted it on accepting `path` from another
/// account, or its author was allowed to make it by the version it was made
/// against, which the account must trust in turn. A first version answers to
/// the directory above it, as that directory's history held it then. An entry
/// of the request log is the server's own record, and only its signature is
/// checked.
///
/// `path` accepts relative, absolute account, or address form. `body` is
/// `None` on a directory or a delete, which have none, and on a file whose
/// body is not checked: a past version, or a change to a file's metadata
/// alone, which must then keep the body the copy held has. What the account
/// trusts is its own copy and its version store.
///
/// `version`: the id `metadata` must be the version of, where it was asked
/// for as a past version — the id travels outside what the request signature
/// covers, so a server answering with a different version, or with the
/// current file, is refused here. It is not checked against the copy held: it
/// may be older, and may be of a file the path held before a removal. With
/// `None`, where the account holds its own copy of `path`, `metadata` must
/// have been made on that copy, or on versions made on it in turn: a fork off
/// an older version, or an unrelated file, is refused, unless the account
/// granted it.
///
/// `server_ctx`: the server's own context, where the check runs on the server
/// holding the account, with `ctx` the account's; identities resolve through
/// it. `None` on a client: there, where the version `metadata` was made
/// against is not held, its metadata is fetched from the account's server
/// first, checked the same way, back to a version the account trusts or the
/// first, and stored in the version store; bodies are left until
/// [`get_version`](crate::get_version) asks for one. A server has nowhere to
/// fetch from, and refuses what it does not hold.
///
/// `Err` carries the kind the rejection corresponds to, as
/// [`crate::http::error_response_code`] maps it: `InvalidData` where the
/// metadata does not verify or is not the version asked for, `NotFound` where
/// a change to metadata alone has no copy to keep the body of,
/// `AlreadyExists` where it was not made on the copy held, and
/// `PermissionDenied` where nothing the account trusts vouches for it.
pub fn validate_entry(ctx: &Context, path: &str, metadata: &Metadata, body: Option<&[u8]>, version: Option<&str>, server_ctx: Option<&Context>) -> io::Result<()> {
    let identity_ctx = server_ctx.unwrap_or(ctx);

    // An unresolvable author is a verification failure, not a missing
    // target, and must not read as one to callers matching on the kind.
    let author_identity = resolve_identity(identity_ctx, &metadata.author)
        .map_err(|e| io::Error::other(format!("author {}: {}", metadata.author, e)))?;
    if metadata.deleted || (body.is_none() && metadata.body_hash.is_some()) {
        verify_metadata_signature(&author_identity.public_key, metadata)?;
    } else {
        verify_metadata(&author_identity.public_key, metadata, body)?;
    }

    let existing_metadata = read_metadata_attributes(ctx, path).ok();

    match version {
        Some(id) => {
            if to_version(metadata) != id {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("served version is not {}", id)));
            }
        }
        None => {
            if !metadata.deleted && body.is_none() && metadata.body_hash.is_some() {
                let existing_metadata = existing_metadata.as_ref()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "metadata-only update requires existing file"))?;
                if existing_metadata.body_hash.as_ref().map(|hash| &hash.value) != metadata.body_hash.as_ref().map(|hash| &hash.value) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "metadata-only update must not change body_hash"));
                }
            }
        }
    }

    if is_request_log_path(&to_account_path(ctx, path)?) {
        return Ok(());
    }

    let address = to_address(ctx, path)?;
    let account_address = address.split_once('/').map_or(address.as_str(), |(account, _)| account);
    let is_trusted_version = exists(ctx, &version_path_for(ctx, &address, &to_version(metadata))?);

    if !is_trusted_version && server_ctx.is_none() {
        if let Some(parent_id) = &metadata.parent_version {
            if !exists(ctx, &version_path_for(ctx, &address, parent_id)?) {
                match fetch_version(ctx, &address, parent_id) {
                    Ok(_) => {}
                    // Not on the server, so only a grant vouches for what
                    // came after.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }

    if version.is_none() {
        validate_made_on_copy(ctx, path, metadata, server_ctx)?;
    }

    if is_trusted_version || metadata.author == account_address {
        return Ok(());
    }

    // Made by someone the version before, as the account holds it, allowed,
    // or a first version by someone the directory above allowed.
    let checked = match &metadata.parent_version {
        Some(parent_id) => match read_version_metadata_attributes(ctx, &address, parent_id)? {
            Some(parent_metadata) if parent_metadata.id != metadata.id || metadata.author_date < parent_metadata.author_date => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("history of {} does not hold together", address)));
            }
            Some(parent_metadata) => validate_author(identity_ctx, metadata, Some(&parent_metadata), account_address, Some(&parent_metadata.members)),
            None => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: not held, so nothing vouches for what came after {}", address, parent_id))),
        },
        None => members_at(ctx, &address, metadata.author_date, server_ctx).and_then(|members| {
            validate_author(identity_ctx, metadata, None, account_address, members.as_deref())
        }),
    };

    match checked {
        // Or the account granted it.
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            if get_granted_version(ctx, &address, account_address, server_ctx)? == Some(to_version(metadata)) {
                return Ok(());
            }
            Err(error)
        }
        checked => checked,
    }
}

/// Checks that `metadata`, a version of `path` checked by [`validate_entry`],
/// may replace the account's own copy of `path`: it was made on that copy, or
/// on versions made on it in turn, or the account granted it. A fork off an
/// older version, or an unrelated file, is refused. Passes where the account
/// holds no copy.
///
/// `path` accepts relative, absolute account, or address form. `server_ctx` is
/// as for [`validate_entry`].
///
/// `Err` is `AlreadyExists` where it may not.
pub fn validate_made_on_copy(ctx: &Context, path: &str, metadata: &Metadata, server_ctx: Option<&Context>) -> io::Result<()> {
    let Ok(existing_metadata) = read_metadata_attributes(ctx, path) else {
        return Ok(());
    };

    let address = to_address(ctx, path)?;
    let account_address = address.split_once('/').map_or(address.as_str(), |(account, _)| account);

    if get_version_chain(ctx, &address, metadata)?.contains(&to_version(&existing_metadata)) {
        return Ok(());
    }
    if get_granted_version(ctx, &address, account_address, server_ctx)? == Some(to_version(metadata)) {
        return Ok(());
    }

    Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{}: not made on the copy held", path)))
}

// Whether the author of `metadata` was allowed to make it as a change to
// `existing_metadata`, in the tree of the account at `account_address`: the
// account may make any change, anyone else must be a writer among
// `trusted_members`, and an owner to change the members.
fn validate_author(
    ctx: &Context,
    metadata: &Metadata,
    existing_metadata: Option<&Metadata>,
    account_address: &str,
    trusted_members: Option<&[Member]>,
) -> io::Result<()> {
    if metadata.author == account_address { return Ok(()); }

    let Some(trusted_members) = trusted_members else {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "no trusted members to check the author against"));
    };

    let public_permission = trusted_members.iter()
        .find(|member| member.address == "*")
        .map(|member| member.permission);
    let permission = [resolve_member_permission(ctx, trusted_members, &metadata.author)?, public_permission]
        .into_iter()
        .flatten()
        .max_by_key(|permission| permission.rank());

    let changes_members = existing_metadata.is_some_and(|existing_metadata| members_changed(&existing_metadata.members, &metadata.members));
    if changes_members {
        if permission != Some(Permission::Owner) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "owner permission required to change members"));
        }
    } else if !matches!(permission, Some(Permission::Writer | Permission::Owner)) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "writer permission required"));
    }

    Ok(())
}

// The metadata of the version of `path` that `id` names, fetched from the
// account's server, checked as `validate_entry` checks it, and stored in the
// version store without its body.
fn fetch_version(ctx: &Context, path: &str, id: &str) -> io::Result<Metadata> {
    let mut url = to_url(ctx, path)?;
    url.query_pairs_mut().append_pair("version", id);

    let (code, headers, body) = request(Some(ctx), "HEAD", &url, &[], &[])?;
    check_response_code(code, &body)?;
    let metadata = read_metadata_headers(&headers)?;

    validate_entry(ctx, path, &metadata, None, Some(id), None)?;
    write_version(ctx, path, &[], &metadata)?;

    Ok(metadata)
}

// The members a path first written at `date` inherited: those of the nearest
// directory above it carrying metadata. On a server as it holds them now, which
// is what a write arriving now answers to; on a client as the directory's
// history held them then.
fn members_at(ctx: &Context, path: &str, date: OffsetDateTime, server_ctx: Option<&Context>) -> io::Result<Option<Vec<Member>>> {
    if server_ctx.is_some() {
        return Ok(read_inherited_metadata_attributes(ctx, path)?.map(|metadata| metadata.members));
    }

    let mut current = parent_path(path);

    while let Some(dir) = current {
        let versions = list_versions(ctx, dir)?;
        if !versions.is_empty() {
            let version = versions.iter()
                .find(|version| !version.deleted && version.author_date <= date)
                .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, format!("{} held nothing then", dir)))?;
            let metadata = match read_version_metadata_attributes(ctx, dir, &version.id)? {
                Some(metadata) => metadata,
                None => fetch_version(ctx, dir, &version.id)?,
            };
            return Ok(Some(metadata.members));
        }

        current = parent_path(dir);
    }

    Ok(None)
}

// The version of `path` the account accepted from another account, by the
// grant it signed when it did, where there is one.
fn get_granted_version(ctx: &Context, path: &str, account_address: &str, server_ctx: Option<&Context>) -> io::Result<Option<String>> {
    let account_path = to_account_path(ctx, path)?;
    let grant_path = format!("{}{}", account_address, grant_path_for(&account_path));

    let (metadata, body) = match server_ctx {
        // Held here, so checked as it was put.
        Some(_) => match read_metadata_attributes(ctx, &grant_path) {
            Ok(metadata) => (metadata, read(ctx, &grant_path)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        },
        None => {
            let mut body = Vec::new();
            match get_stream(ctx, &grant_path, &mut body, false, None) {
                Ok((metadata, _)) => (metadata, body),
                // Only the account reads its grants; held back, one only
                // ever refuses.
                Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
    };

    // Anything the account did not sign is no grant of its own.
    if metadata.author != account_address { return Ok(None); }

    Ok(Some(String::from_utf8_lossy(&body).trim().to_string()))
}
