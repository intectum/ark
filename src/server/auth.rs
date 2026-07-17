use std::io::Result;

use url::Url;

use crate::crypto::verify_bytes;
use crate::identity::resolve_identity;
use crate::metadata::get_member;
use crate::types::{Identity, IdentityContext, Member, Permission, Signature};
use crate::util::{decode_base64url, io_err, now_seconds, request_to_bytes};

use super::MAX_CLOCK_SKEW_SECS;

pub fn authenticate(
    server_ctx: &IdentityContext,
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Identity> {
    let authorization_opt = headers.iter().find_map(|(name, value)| if name.eq_ignore_ascii_case("authorization") { Some(value) } else { None });
    let authorization= match authorization_opt {
        Some(h) => h,
        None => return Err(io_err("missing Authorization header")),
    };

    let host_header = headers.iter()
        .find_map(|(name, value)| if name.eq_ignore_ascii_case("host") { Some(value.as_str()) } else { None })
        .ok_or_else(|| io_err("missing Host header"))?;
    let request_host = host_header.to_ascii_lowercase();
    let server_host = server_ctx.identity.address.split_once('@').map(|(_, h)| h).unwrap_or("").to_ascii_lowercase();
    if request_host != server_host {
        return Err(io_err("Host header does not match server"));
    }

    let params = match parse_auth_params(authorization) {
        Some(p) => p,
        None => return Err(io_err("unsupported Authorization scheme")),
    };

    let address = params.get("address").ok_or_else(|| io_err("missing address in Authorization"))?;
    let signature_b64 = params.get("signature").ok_or_else(|| io_err("missing signature in Authorization"))?;
    let timestamp_str = params.get("timestamp").ok_or_else(|| io_err("missing timestamp in Authorization"))?;

    let requestor_identity = resolve_identity(server_ctx, address)?;

    let signature = decode_base64url(signature_b64).map_err(|_| io_err("auth signature not base64url encoded"))?;

    let timestamp: u64 = timestamp_str.parse().map_err(|_| io_err("invalid timestamp in Authorization"))?;
    if now_seconds().abs_diff(timestamp) > MAX_CLOCK_SKEW_SECS {
        return Err(io_err("timestamp outside allowed window"));
    }

    let bytes = request_to_bytes(method, &request_host, url.path(), timestamp, body);
    verify_bytes(&requestor_identity.public_key, &Signature { algorithm: requestor_identity.public_key.algorithm.clone(), value: signature }, &bytes).map_err(|_| io_err("signature verification failed"))?;

    Ok(requestor_identity)
}

pub fn authorize(
    target_ctx: &IdentityContext,
    requestor_identity: &Identity,
    modifier_identity: Option<&Identity>,
    existing_members: Option<&[Member]>,
) -> Result<Permission> {
    if requestor_identity.address == target_ctx.identity.address {
        return Ok(Permission::Owner);
    }

    let requestor_member = existing_members
        .and_then(|members| get_member(members, &requestor_identity.address));

    let modifier_member = modifier_identity
        .and_then(|identity| existing_members.and_then(|members| get_member(members, &identity.address)));

    let public_member = existing_members
        .and_then(|members| members.iter().find(|member| member.address == "*"));

    [requestor_member, modifier_member, public_member]
        .into_iter()
        .flatten()
        .map(|member| member.permission)
        .max_by_key(|permission| permission_rank(*permission))
        .ok_or_else(|| io_err("actor not a member"))
}

fn permission_rank(permission: Permission) -> u8 {
    match permission {
        Permission::Read => 0,
        Permission::Write => 1,
        Permission::Owner => 2,
    }
}

fn parse_auth_params(value: &str) -> Option<std::collections::HashMap<String, String>> {
    let rest = value.strip_prefix("ArkAccount ")?.trim();
    let mut out = std::collections::HashMap::new();
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        out.insert(k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string());
    }
    Some(out)
}
