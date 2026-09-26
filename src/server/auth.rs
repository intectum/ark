use std::io;

use url::Url;

use super::MAX_CLOCK_SKEW_MS;

use crate::crypto::verify_bytes;
use crate::identity::{parse_address, resolve_identity};
use crate::metadata::read_metadata_attributes;
use crate::storage::parent_path;
use crate::timestamp;
use crate::types::{Context, Identity, Member, Permission, Signature};
use crate::util::{decode_base64url, parse_authorization_header, request_to_bytes};

pub fn authenticate(
    server_ctx: &Context,
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> io::Result<Identity> {
    let authorization_opt = headers.iter().find_map(|(name, value)| if name.eq_ignore_ascii_case("authorization") { Some(value) } else { None });
    let authorization= match authorization_opt {
        Some(h) => h,
        None => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "missing Authorization header")),
    };

    let host_header = headers.iter()
        .find_map(|(name, value)| if name.eq_ignore_ascii_case("host") { Some(value.as_str()) } else { None })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Host header"))?;
    let request_host = host_header.to_ascii_lowercase();
    let (_, server_host, _) = parse_address(&server_ctx.identity.address)?;
    let server_host = server_host.to_ascii_lowercase();
    if request_host != server_host {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Host header does not match server"));
    }

    let (address, timestamp_str, signature_b64) = parse_authorization_header(authorization)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unsupported or malformed Authorization header"))?;

    let requestor_identity = resolve_identity(server_ctx, &address)?;

    let signature = decode_base64url(&signature_b64).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "auth signature not base64url encoded"))?;

    let ts: u64 = timestamp_str.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid timestamp in Authorization"))?;
    if timestamp::now_ms().abs_diff(ts) > MAX_CLOCK_SKEW_MS {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "timestamp outside allowed window"));
    }

    let bytes = request_to_bytes(method, &request_host, url.path(), ts, body);
    verify_bytes(&requestor_identity.public_key, &Signature { algorithm: requestor_identity.public_key.algorithm.clone(), value: signature }, &bytes).map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "signature verification failed"))?;

    Ok(requestor_identity)
}

/// The members `path` inherits from the nearest directory above it carrying
/// metadata, where there is one. The walk ends at the account root.
///
/// Errors rather than walking past a directory whose metadata is present but
/// unreadable — taking the members of something further up would widen access
/// without saying so.
pub fn inherited_members(ctx: &Context, path: &str) -> io::Result<Option<Vec<Member>>> {
    let mut current = parent_path(path);

    while let Some(dir) = current {
        match read_metadata_attributes(ctx, dir) {
            Ok(metadata) => return Ok(Some(metadata.members)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        current = parent_path(dir);
    }

    Ok(None)
}

pub fn authorize(
    server_ctx: &Context,
    target_ctx: &Context,
    requestor_identity: &Identity,
    modifier_identity: Option<&Identity>,
    existing_members: Option<&[Member]>,
) -> io::Result<Permission> {
    if requestor_identity.address == target_ctx.identity.address {
        return Ok(Permission::Owner);
    }

    let members = match existing_members {
        Some(m) => m,
        None => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "forbidden")),
    };

    let requestor_permission = resolve_member_permission(server_ctx, members, &requestor_identity.address)?;
    let modifier_permission = match modifier_identity {
        Some(m) => resolve_member_permission(server_ctx, members, &m.address)?,
        None => None,
    };

    let public_permission = members.iter()
        .find(|member| member.address == "*")
        .map(|member| member.permission);

    [requestor_permission, modifier_permission, public_permission]
        .into_iter()
        .flatten()
        .max_by_key(|permission| permission.rank())
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "forbidden"))
}

fn resolve_member_permission(
    ctx: &Context,
    members: &[Member],
    address: &str,
) -> io::Result<Option<Permission>> {
    if let Some(member) = members.iter().find(|member| member.address == address) {
        return Ok(Some(member.permission));
    }

    let mut best: Option<Permission> = None;
    for member in members {
        if member.address == "*" || member.address == address {
            continue;
        }

        let member_identity = match resolve_identity(ctx, &member.address) {
            Ok(i) => i,
            Err(_) => continue,
        };

        let group_members = match member_identity.members.as_ref() {
            Some(m) => m,
            None => continue,
        };

        if !group_members.iter().any(|entry| entry == address) {
            continue;
        }

        for entry in group_members {
            let entry_identity = match resolve_identity(ctx, entry) {
                Ok(i) => i,
                Err(_) => continue,
            };

            if entry_identity.members.is_some() {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "nested groups not supported"));
            }
        }

        best = match best {
            Some(current) if current.rank() >= member.permission.rank() => Some(current),
            _ => Some(member.permission),
        };
    }

    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
    use crate::storage::{create_dir_all, write_attribute};
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_test_account, in_test_dir};
    use crate::types::Permission;

    // `/top` carries members, `/top/mid` is what the walk has to get past, and
    // `/top/mid/leaf` carries nothing of its own.
    fn tree(temp_dir: &std::path::Path) -> Context {
        let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
        let (context, _) = account_context(&account_dir);

        create_dir_all(&context, "/top/mid/leaf").unwrap();

        let mut top = create_metadata(&identity.address, None);
        top.members.push(Member { address: "*".to_string(), permission: Permission::Reader, key: None });
        sign_metadata(&secret_key, &mut top, None).unwrap();
        write_metadata_attributes(&context, "/top", &top, None).unwrap();

        context
    }

    #[test]
    fn a_directory_carrying_nothing_is_walked_past() {
        in_test_dir("ark_auth_test", |temp_dir| {
            let context = tree(temp_dir);

            let members = inherited_members(&context, "/top/mid/leaf").unwrap().expect("no members found");
            assert!(members.iter().any(|member| member.address == "*"));
        });
    }

    #[test]
    fn a_directory_whose_metadata_cannot_be_read_stops_the_walk() {
        in_test_dir("ark_auth_test", |temp_dir| {
            let context = tree(temp_dir);

            // Part of a record and nothing set aside to put it back, as an update
            // interrupted before any of this existed would have left it.
            write_attribute(&context, "/top/mid", "user.ark.member_0_address", b"someone@example.com").unwrap();

            // Carrying on to `/top` would hand out the public read that the
            // unreadable record sits between.
            match inherited_members(&context, "/top/mid/leaf") {
                Ok(members) => panic!("walked past an unreadable directory and found {:?}", members.map(|m| m.len())),
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
            }
        });
    }

    #[test]
    fn nothing_above_carrying_metadata_is_not_an_error() {
        in_test_dir("ark_auth_test", |temp_dir| {
            let (_, _, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let (context, _) = account_context(&account_dir);
            create_dir_all(&context, "/top/mid/leaf").unwrap();

            assert!(inherited_members(&context, "/top/mid/leaf").unwrap().is_none());
        });
    }
}

