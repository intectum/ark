use std::io;

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::sign_bytes;
use crate::http::{read_request, read_response};
use crate::metadata::{verify_metadata, verify_metadata_signature};
use crate::types::{Context, Key, Metadata, RequestEntry};

pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub fn request_to_bytes(method: &str, host: &str, path: &str, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let host_lower = host.to_ascii_lowercase();
    let timestamp_string = timestamp.to_string();
    let mut bytes = Vec::with_capacity(method.len() + host_lower.len() + path.len() + timestamp_string.len() + body.len() + 4);
    bytes.extend_from_slice(method.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(host_lower.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(timestamp_string.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(body);
    bytes
}

pub fn parse_request_entry(entry_bytes: &[u8]) -> io::Result<RequestEntry> {
    let boundary = entry_bytes.windows(4).position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no header separator"))?;

    let request_bytes = &entry_bytes[..boundary];
    let response_bytes = &entry_bytes[boundary + 4..];

    let (method, target, request_headers, _) = read_request(&mut &request_bytes[..], true)?;
    let (status, _, _) = read_response(&mut &response_bytes[..], true)?;

    Ok(RequestEntry { method, target, request_headers, status })
}

pub fn create_authorization_header(ctx: &Context, method: &str, host: &str, path: &str, timestamp: u64, body: &[u8]) -> io::Result<String> {
    let identity_key = ctx.identity_key.as_ref().ok_or_else(|| io::Error::other("context missing identity_key"))?;
    let request_bytes = request_to_bytes(method, host, path, timestamp, body);
    let signature = sign_bytes(identity_key, &request_bytes)?;
    Ok(format_authorization_header(
        &ctx.identity.address,
        timestamp,
        &encode_base64url(signature.value),
    ))
}

pub fn format_authorization_header(address: &str, timestamp: u64, signature_b64: &str) -> String {
    format!(
        "ArkIdentity address=\"{}\", timestamp=\"{}\", signature=\"{}\"",
        address, timestamp, signature_b64,
    )
}

pub fn parse_authorization_header(value: &str) -> Option<(String, String, String)> {
    let mut address = None;
    let mut timestamp = None;
    let mut signature = None;

    let rest = value.strip_prefix("ArkIdentity ")?.trim();
    for part in rest.split(',') {
        let (key, value) = part.trim().split_once('=')?;
        let value = value.trim().trim_matches('"').to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "address" => address = Some(value),
            "timestamp" => timestamp = Some(value),
            "signature" => signature = Some(value),
            _ => {},
        }
    }

    Some((address?, timestamp?, signature?))
}

pub fn encode_base64url<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub fn decode_base64url<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize().to_vec()
}

/// Validate a change received from another node, against the copy of the file
/// it replaces.
///
/// Checks that the metadata is signed by the account that made the change and
/// matches the body that arrived with it, and that `existing_metadata` — the
/// copy being replaced, where there is one — is being continued rather than
/// overwritten by an unrelated or older file.
///
/// Whether the change is a directory is taken from the metadata, which carries
/// a `body_hash` only for a file. A change may not turn one into the other.
///
/// `body` is what arrived with the metadata. `None` on a directory, which has
/// no body; `None` on a file means the change keeps the body the existing copy
/// already has, so only the signature is checked and `existing_metadata` is
/// required.
///
/// `Err` carries the kind the rejection corresponds to, as
/// [`crate::http::error_response_code`] maps it: `InvalidData` where the
/// metadata does not verify or is malformed, `NotFound` where the copy it
/// continues is missing, `AlreadyExists` where it loses to the copy already
/// held.
///
/// Whether the author was allowed to change the members is not covered: that
/// needs the authoritative member list, which only the account's own server
/// holds.
pub fn validate_update(
    author_public_key: &Key,
    metadata: &Metadata,
    existing_metadata: Option<&Metadata>,
    body: Option<&[u8]>,
) -> io::Result<()> {
    validate_version(author_public_key, metadata, existing_metadata, body)?;

    if let Some(existing_metadata) = existing_metadata {
        if existing_metadata.id != metadata.id {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "id is wrong"));
        }
        if metadata.author_date < existing_metadata.author_date {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "author_date is older than existing"));
        }
    }

    Ok(())
}

/// As [`validate_update`], for a past version of the path `existing_metadata`
/// describes rather than a change to it: everything is checked except that it
/// is no older, since a version is older by definition, and that it has the
/// same `id`, since a path removed and written again keeps the versions of the
/// file it held before.
///
/// It must still be a file where `existing_metadata` is one, and a directory
/// where it is one.
pub fn validate_version(
    author_public_key: &Key,
    metadata: &Metadata,
    existing_metadata: Option<&Metadata>,
    body: Option<&[u8]>,
) -> io::Result<()> {
    let is_dir = metadata.body_hash.is_none();

    if body.is_none() && !is_dir {
        let existing_metadata = match existing_metadata {
            Some(m) => m,
            None => return Err(io::Error::new(io::ErrorKind::NotFound, "metadata-only update requires existing file")),
        };

        let new_hash = metadata.body_hash.as_ref().map(|h| &h.value);
        let old_hash = existing_metadata.body_hash.as_ref().map(|h| &h.value);
        if new_hash != old_hash {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "metadata-only update must not change body_hash"));
        }

        verify_metadata_signature(author_public_key, metadata)?;
    } else {
        verify_metadata(author_public_key, metadata, body)?;
    }

    if let Some(existing_metadata) = existing_metadata {
        if existing_metadata.body_hash.is_none() != is_dir {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, if is_dir { "existing is a file" } else { "existing is a dir" }));
        }
    }

    Ok(())
}

/// The UUID `value` spells.
///
/// Only the plain hyphenated lowercase form is accepted — the braced, URN and
/// unhyphenated forms parse as UUIDs but carry characters, or a case, that a
/// value read from outside is not expected to use, and such a value may become
/// a path segment.
pub fn parse_uuid(value: &str) -> io::Result<Uuid> {
    let uuid = Uuid::try_parse(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("not a uuid: {}", value)))?;

    if uuid.hyphenated().to_string() != value {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("uuid is not hyphenated lowercase: {}", value)));
    }

    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_accepts_only_the_plain_hyphenated_lowercase_form() {
        let id = "0f3e1c62-9a4b-4d7e-8c11-2b5a6d9e4f30";
        assert_eq!(parse_uuid(id).unwrap().hyphenated().to_string(), id);
        assert!(parse_uuid(&format!("{{{}}}", id)).is_err());
        assert!(parse_uuid(&format!("urn:uuid:{}", id)).is_err());
        assert!(parse_uuid(&id.replace('-', "")).is_err());
        assert!(parse_uuid(&id.to_uppercase()).is_err());
        assert!(parse_uuid("../../etc").is_err());
        assert!(parse_uuid("").is_err());
    }
}
