use std::io;

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::sign_bytes;
use crate::http::{read_request, read_response};
use crate::types::{Context, RequestEntry};

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
