use std::io;

use url::Url;

use super::MAX_CLOCK_SKEW_MS;

use crate::crypto::verify_bytes;
use crate::identity::{parse_address, resolve_identity};
use crate::metadata::resolve_member_permission;
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

pub fn authorize(
    server_ctx: &Context,
    target_ctx: &Context,
    requestor_identity: &Identity,
    author_identity: Option<&Identity>,
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
    let author_permission = match author_identity {
        Some(m) => resolve_member_permission(server_ctx, members, &m.address)?,
        None => None,
    };

    let public_permission = members.iter()
        .find(|member| member.address == "*")
        .map(|member| member.permission);

    [requestor_permission, author_permission, public_permission]
        .into_iter()
        .flatten()
        .max_by_key(|permission| permission.rank())
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "forbidden"))
}


