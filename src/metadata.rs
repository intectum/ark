use std::io;
use std::path::Path;

use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, DEFAULT_HASH_ALGORITHM, DEFAULT_SIGNING_ALGORITHM, sign_json, verify_json};
use crate::types::{Hash, Member, Metadata, Signature};
use crate::util::{decode_base64url, encode_base64url, io_err, sha256};

const ATTRIBUTE_PREFIX: &str = "user.ark.";
const HEADER_PREFIX: &str = "X-Ark-Meta-";

const FIELD_ID: &str = "id";
const FIELD_CREATED: &str = "created";
const FIELD_MODIFIED: &str = "modified";
const FIELD_MODIFIED_BY: &str = "modified_by";
const FIELD_ENCRYPTION: &str = "encryption";
const FIELD_MEMBER_PREFIX: &str = "member_";
const FIELD_MEMBER_ADDRESS: &str = "address";
const FIELD_MEMBER_PERMISSION: &str = "permission";
const FIELD_MEMBER_WRAPPED_KEY: &str = "wrapped_key";
const FIELD_BODY_HASH_ALGORITHM: &str = "body_hash_algorithm";
const FIELD_BODY_HASH_VALUE: &str = "body_hash_value";
const FIELD_SIGNATURE_ALGORITHM: &str = "signature_algorithm";
const FIELD_SIGNATURE_VALUE: &str = "signature_value";
const FIELD_ENCRYPTED: &str = "encrypted";

pub fn get_member<'a>(members: &'a [Member], address: &str) -> Option<&'a Member> {
    members.iter().find(|m| m.address == address)
}

pub fn read_metadata_attributes(path: &Path) -> io::Result<Metadata> {
    let mut partial_metadata = PartialMetadata::default();

    for attribute in xattr::list(path)? {
        let name = attribute.to_string_lossy().into_owned();

        let value = match xattr::get(path, &name)? {
            Some(v) => String::from_utf8(v)
                .map_err(|_| io_err(&format!("xattr {} not utf8", name)))?,
            None => continue,
        };

        apply_field(&mut partial_metadata, &name, &value)?;
    }

    validate_partial_metadata(&partial_metadata)?;

    let metadata = build_metadata(partial_metadata)?;
    validate_metadata(&metadata)?;

    Ok(metadata)
}

pub fn write_metadata_attributes(path: &Path, metadata: &Metadata) -> io::Result<()> {
    for attribute in xattr::list(path)? {
        let name = attribute.to_string_lossy();
        if name.starts_with(ATTRIBUTE_PREFIX) {
            xattr::remove(path, &*name)?;
        }
    }

    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_ID), metadata.id.as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_CREATED), metadata.created.as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_MODIFIED), metadata.modified.as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_MODIFIED_BY), metadata.modified_by.as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_ENCRYPTION), metadata.encryption.as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_BODY_HASH_ALGORITHM), metadata.body_hash.algorithm.as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_BODY_HASH_VALUE), encode_base64url(&metadata.body_hash.value).as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_SIGNATURE_ALGORITHM), metadata.signature.algorithm.as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_SIGNATURE_VALUE), encode_base64url(&metadata.signature.value).as_bytes())?;

    for (index, member) in metadata.members.iter().enumerate() {
        xattr::set(path, &format!("{}member_{}_address", ATTRIBUTE_PREFIX, index), member.address.as_bytes())?;
        xattr::set(path, &format!("{}member_{}_permission", ATTRIBUTE_PREFIX, index), member.permission.as_bytes())?;
        xattr::set(path, &format!("{}member_{}_wrapped_key", ATTRIBUTE_PREFIX, index), encode_base64url(member.wrapped_key.clone()).as_bytes())?;
    }

    if let Some(encrypted) = metadata.encrypted {
        xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_ENCRYPTED), if encrypted { b"true" } else { b"false" })?;
    }

    Ok(())
}

pub fn read_metadata_headers(headers: &[(String, String)]) -> io::Result<Metadata> {
    let mut partial_metadata = PartialMetadata::default();

    for (name, value) in headers {
        apply_field(&mut partial_metadata, name, value)?;
    }

    validate_partial_metadata(&partial_metadata)?;

    let mut metadata = build_metadata(partial_metadata)?;
    metadata.encrypted = None;
    validate_metadata(&metadata)?;

    Ok(metadata)
}

pub fn write_metadata_headers(metadata: &Metadata) -> Vec<(String, String)> {
    let mut out = Vec::new();

    out.push((format!("{}Id", HEADER_PREFIX), metadata.id.clone()));
    out.push((format!("{}Created", HEADER_PREFIX), metadata.created.clone()));
    out.push((format!("{}Modified", HEADER_PREFIX), metadata.modified.clone()));
    out.push((format!("{}Modified-By", HEADER_PREFIX), metadata.modified_by.clone()));
    out.push((format!("{}Encryption", HEADER_PREFIX), metadata.encryption.clone()));
    out.push((format!("{}Body-Hash-Algorithm", HEADER_PREFIX), metadata.body_hash.algorithm.clone()));
    out.push((format!("{}Body-Hash-Value", HEADER_PREFIX), encode_base64url(&metadata.body_hash.value)));
    out.push((format!("{}Signature-Algorithm", HEADER_PREFIX), metadata.signature.algorithm.clone()));
    out.push((format!("{}Signature-Value", HEADER_PREFIX), encode_base64url(&metadata.signature.value)));

    for (index, member) in metadata.members.iter().enumerate() {
        out.push((format!("{}Member-{}-Address", HEADER_PREFIX, index), member.address.clone()));
        out.push((format!("{}Member-{}-Permission", HEADER_PREFIX, index), member.permission.clone()));
        out.push((format!("{}Member-{}-Wrapped-Key", HEADER_PREFIX, index), encode_base64url(member.wrapped_key.clone())));
    }

    out
}

pub fn validate_metadata(metadata: &Metadata) -> io::Result<()> {
    if metadata.encryption != DEFAULT_ENCRYPTION_ALGORITHM.to_string() && metadata.encryption != "none" {
        return Err(io_err(&format!("unsupported encryption algorithm: {}", metadata.encryption.clone())));
    }

    if !metadata.members.iter().any(|m| m.permission == "owner") {
        return Err(io_err("metadata must contain at least one owner"));
    }

    Ok(())
}

pub fn sign_metadata(key: &[u8], metadata: &mut Metadata, body: &[u8]) {
    metadata.body_hash = Hash {
        algorithm: DEFAULT_HASH_ALGORITHM.to_string(),
        value: sha256(body),
    };
    metadata.signature.algorithm = DEFAULT_SIGNING_ALGORITHM.to_string();
    let json = serde_json::to_value(metadata_for_signing(metadata)).expect("serialize metadata");
    metadata.signature.value = sign_json(key, &json);
}

pub fn verify_metadata_signature(public_key: &[u8], metadata: &Metadata) -> io::Result<()> {
    let json = serde_json::to_value(metadata_for_signing(metadata)).expect("serialize metadata");
    verify_json(public_key, &metadata.signature.value, &json)
        .map_err(|_| io_err("metadata signature verification failed"))
}

pub fn verify_metadata(public_key: &[u8], metadata: &Metadata, body: &[u8]) -> io::Result<()> {
    verify_metadata_signature(public_key, metadata)?;

    if metadata.body_hash.value != sha256(body) {
        return Err(io_err("body hash mismatch"));
    }

    Ok(())
}

fn metadata_for_signing(metadata: &Metadata) -> Metadata {
    let mut clone = metadata.clone();
    clone.encrypted = None;
    clone.signature.value = Vec::new();
    clone
}

#[derive(Default)]
struct PartialMetadata {
    id: Option<String>,
    modified_by: Option<String>,
    created: Option<String>,
    modified: Option<String>,
    encryption: Option<String>,
    members: Vec<PartialMember>,
    body_hash_algorithm: Option<String>,
    body_hash_value: Option<Vec<u8>>,
    signature_algorithm: Option<String>,
    signature_value: Option<Vec<u8>>,

    encrypted: Option<bool>,
}

#[derive(Default)]
struct PartialMember {
    address: Option<String>,
    permission: Option<String>,
    wrapped_key: Option<Vec<u8>>,
}

fn build_metadata(partial: PartialMetadata) -> io::Result<Metadata> {
    Ok(Metadata {
        id: partial.id.unwrap(),
        created: partial.created.unwrap(),
        modified: partial.modified.unwrap(),
        modified_by: partial.modified_by.unwrap(),
        encryption: partial.encryption.unwrap(),
        members: partial.members.into_iter().map(|member| Member {
            address: member.address.unwrap(),
            permission: member.permission.unwrap(),
            wrapped_key: member.wrapped_key.unwrap(),
        }).collect(),
        body_hash: Hash {
            algorithm: partial.body_hash_algorithm.unwrap(),
            value: partial.body_hash_value.unwrap(),
        },
        signature: Signature {
            algorithm: partial.signature_algorithm.unwrap(),
            value: partial.signature_value.unwrap(),
        },

        encrypted: partial.encrypted,
    })
}

fn apply_field(metadata: &mut PartialMetadata, key: &str, value: &str) -> io::Result<()> {
    let metadata_key = match get_metadata_key(key) {
        Some(s) => s,
        None => return Ok(())
    };

    match metadata_key.as_str() {
        FIELD_ID => metadata.id = Some(value.to_string()),
        FIELD_CREATED => metadata.created = Some(value.to_string()),
        FIELD_MODIFIED => metadata.modified = Some(value.to_string()),
        FIELD_MODIFIED_BY => metadata.modified_by = Some(value.to_string()),
        FIELD_ENCRYPTION => metadata.encryption = Some(value.to_string()),
        FIELD_BODY_HASH_ALGORITHM => metadata.body_hash_algorithm = Some(value.to_string()),
        FIELD_BODY_HASH_VALUE => metadata.body_hash_value = Some(decode_base64url(value)
            .map_err(|_| io_err("body_hash_value is not base64url encoded"))?),
        FIELD_SIGNATURE_ALGORITHM => metadata.signature_algorithm = Some(value.to_string()),
        FIELD_SIGNATURE_VALUE => metadata.signature_value = Some(decode_base64url(value)
            .map_err(|_| io_err("signature is not base64url encoded"))?),
        FIELD_ENCRYPTED => {
            metadata.encrypted = match value.trim() {
                "true" => Some(true),
                "false" => Some(false),
                other => return Err(io_err(&format!("encrypted metadata invalid: {}", other))),
            };
        }
        _ => {
            if let Some((index, member_field_key)) = split_member_key(&metadata_key) {
                while metadata.members.len() <= index {
                    metadata.members.push(PartialMember::default());
                }

                match member_field_key.as_str() {
                    FIELD_MEMBER_ADDRESS => metadata.members[index].address = Some(value.to_string()),
                    FIELD_MEMBER_PERMISSION => metadata.members[index].permission = Some(value.to_string()),
                    FIELD_MEMBER_WRAPPED_KEY => metadata.members[index].wrapped_key = Some(decode_base64url(value)
                        .map_err(|_| io_err("wrapped_key is not base64url encoded"))?),
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn validate_partial_metadata(metadata: &PartialMetadata) -> io::Result<()> {
    if metadata.id.is_none() { return Err(io_err("missing id field")); }
    if metadata.created.is_none() { return Err(io_err("missing created field")); }
    if metadata.modified.is_none() { return Err(io_err("missing modified field")); }
    if metadata.modified_by.is_none() { return Err(io_err("missing modified_by field")); }
    if metadata.encryption.is_none() { return Err(io_err("missing encryption field")); }
    if metadata.body_hash_algorithm.is_none() { return Err(io_err("missing body_hash_algorithm field")); }
    if metadata.body_hash_value.is_none() { return Err(io_err("missing body_hash_value field")); }
    if metadata.signature_algorithm.is_none() { return Err(io_err("missing signature_algorithm field")); }
    if metadata.signature_value.is_none() { return Err(io_err("missing signature field")); }

    for member in &metadata.members {
        if member.address.is_none() { return Err(io_err("missing member address field")); }
        if member.permission.is_none() { return Err(io_err("missing member permission field")); }
        if member.wrapped_key.is_none() { return Err(io_err("missing member wrapped_key field")); }
    }

    Ok(())
}

pub fn get_metadata_key(key: &str) -> Option<String> {
    let attribute_prefix_length = ATTRIBUTE_PREFIX.len();
    let header_prefix_length = HEADER_PREFIX.len();
    if key.len() > attribute_prefix_length && key[..attribute_prefix_length].eq_ignore_ascii_case(ATTRIBUTE_PREFIX) {
        Some(key[attribute_prefix_length..].to_ascii_lowercase())
    } else if key.len() > header_prefix_length && key[..header_prefix_length].eq_ignore_ascii_case(HEADER_PREFIX) {
        Some(key[header_prefix_length..].replace("-", "_").to_ascii_lowercase())
    } else {
        None
    }
}

fn split_member_key(key: &str) -> Option<(usize, String)> {
    if let Some(member_key) = key.strip_prefix(FIELD_MEMBER_PREFIX) {
        let sep_pos = member_key.find("_")?;
        let idx: usize = member_key[..sep_pos].parse().ok()?;
        Some((idx, member_key[sep_pos + 1..].to_string()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::crypto::to_public_key;
    use crate::util::test::{TEST_ADDRESS, TempDir, get_default_test_metadata};

    fn sample_member(addr: &str, key_b: u8) -> Member {
        Member {
            address: addr.to_string(),
            permission: "owner".to_string(),
            wrapped_key: [key_b.wrapping_add(1); 32].to_vec(),
        }
    }

    #[test]
    fn get_metadata_key_case_insensitive() {
        assert_eq!(get_metadata_key("X-Ark-Meta-Encryption"), Some("encryption".to_string()));
        assert_eq!(get_metadata_key("x-ark-meta-foo"), Some("foo".to_string()));
        assert_eq!(get_metadata_key("X-Custom-Foo"), None);
        assert_eq!(get_metadata_key("X-Ark-Meta-"), None);
        assert_eq!(get_metadata_key(""), None);
    }

    #[test]
    fn write_headers_emits_all_fields() {
        let m = get_default_test_metadata(&[10u8; 32], TEST_ADDRESS, b"body");
        let headers = write_metadata_headers(&m);
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Id"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Created"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Modified"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Modified-By"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Encryption"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Member-0-Address"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Body-Hash-Algorithm"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Body-Hash-Value"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Signature-Algorithm"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Signature-Value"));
    }

    #[test]
    fn header_round_trip_preserves_all_fields() {
        let m = get_default_test_metadata(&[11u8; 32], TEST_ADDRESS, b"hello");
        let headers = write_metadata_headers(&m);
        let back = read_metadata_headers(&headers).unwrap();
        assert_eq!(back.id, m.id);
        assert_eq!(back.created, m.created);
        assert_eq!(back.modified, m.modified);
        assert_eq!(back.modified_by, m.modified_by);
        assert_eq!(back.encryption, m.encryption);
        assert_eq!(back.members[0].address, m.members[0].address);
        assert_eq!(back.body_hash.algorithm, m.body_hash.algorithm);
        assert_eq!(back.body_hash.value, m.body_hash.value);
        assert_eq!(back.signature.value, m.signature.value);
    }

    #[test]
    fn attribute_round_trip_preserves_all_fields_and_encrypted() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let mut m = get_default_test_metadata(&[12u8; 32], TEST_ADDRESS, b"x");
        m.encrypted = Some(true);
        write_metadata_attributes(&p, &m).unwrap();
        let back = read_metadata_attributes(&p).unwrap();
        assert_eq!(back.id, m.id);
        assert_eq!(back.signature.value, m.signature.value);
        assert_eq!(back.encrypted, Some(true));
    }

    #[test]
    fn attributes_to_headers_round_trip_drops_encrypted() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let mut m = get_default_test_metadata(&[13u8; 32], TEST_ADDRESS, b"x");
        m.encrypted = Some(true);
        write_metadata_attributes(&p, &m).unwrap();
        let attrs = read_metadata_attributes(&p).unwrap();
        let headers = write_metadata_headers(&attrs);
        let back = read_metadata_headers(&headers).unwrap();
        assert_eq!(back.encrypted, None, "encrypted is client-only");
    }

    #[test]
    fn get_member_filters_by_address() {
        let members = [sample_member("a@x", 4), sample_member("b@y", 9)];
        let got = get_member(&members, "b@y").unwrap();
        assert_eq!(got.address, "b@y");
        assert!(get_member(&members, "nope@z").is_none());
    }

    #[test]
    fn sign_and_verify_metadata_round_trip() {
        let key = [20u8; 32];
        let body = b"signed payload";
        let m = get_default_test_metadata(&key, TEST_ADDRESS, body);
        let public_key = to_public_key(&key);
        verify_metadata(&public_key, &m, body).unwrap();
    }

    #[test]
    fn verify_metadata_detects_body_tampering() {
        let key = [21u8; 32];
        let m = get_default_test_metadata(&key, TEST_ADDRESS, b"original");
        let public_key = to_public_key(&key);
        let err = verify_metadata(&public_key, &m, b"tampered").unwrap_err();
        assert!(err.to_string().contains("body hash mismatch"));
    }

    #[test]
    fn verify_metadata_detects_metadata_tampering() {
        let key = [22u8; 32];
        let body = b"body";
        let mut m = get_default_test_metadata(&key, TEST_ADDRESS, body);
        m.modified_by = "attacker@evil".to_string();
        let public_key = to_public_key(&key);
        let err = verify_metadata(&public_key, &m, body).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn verify_metadata_ignores_encrypted_flag_changes() {
        let key = [23u8; 32];
        let body = b"x";
        let mut m = get_default_test_metadata(&key, TEST_ADDRESS, body);
        m.encrypted = Some(true);
        let public_key = to_public_key(&key);
        verify_metadata(&public_key, &m, body).unwrap();
        m.encrypted = Some(false);
        verify_metadata(&public_key, &m, body).unwrap();
    }

    #[test]
    fn validate_metadata_rejects_no_owner() {
        let mut m = get_default_test_metadata(&[24u8; 32], TEST_ADDRESS, b"x");
        m.members[0].permission = "read".to_string();
        let err = match validate_metadata(&m) {
            Err(e) => e,
            Ok(_) => panic!("expected owner-missing error"),
        };
        assert!(err.to_string().contains("at least one owner"), "msg was {}", err);
    }

    #[test]
    fn validate_metadata_rejects_empty_members() {
        let mut m = get_default_test_metadata(&[25u8; 32], TEST_ADDRESS, b"x");
        m.members = vec![];
        let err = match validate_metadata(&m) {
            Err(e) => e,
            Ok(_) => panic!("expected owner-missing error"),
        };
        assert!(err.to_string().contains("at least one owner"));
    }

    #[test]
    fn read_headers_rejects_sparse_member_indexes() {
        let m = get_default_test_metadata(&[26u8; 32], TEST_ADDRESS, b"x");
        let mut headers = write_metadata_headers(&m);
        headers.push(("X-Ark-Meta-Member-2-Address".to_string(), "c@z".to_string()));
        headers.push(("X-Ark-Meta-Member-2-Permission".to_string(), "read".to_string()));
        headers.push(("X-Ark-Meta-Member-2-Wrapped-Key".to_string(), encode_base64url([5u8; 32])));
        let err = match read_metadata_headers(&headers) {
            Err(e) => e,
            Ok(_) => panic!("expected sparse member error"),
        };
        assert!(err.to_string().contains("missing"), "msg was {}", err);
    }

    #[test]
    fn read_headers_rejects_invalid_base64_in_member_field() {
        let m = get_default_test_metadata(&[27u8; 32], TEST_ADDRESS, b"x");
        let mut headers = write_metadata_headers(&m);
        for entry in headers.iter_mut() {
            if entry.0 == "X-Ark-Meta-Member-0-Wrapped-Key" {
                entry.1 = "!!not-base64!!".to_string();
            }
        }
        let err = match read_metadata_headers(&headers) {
            Err(e) => e,
            Ok(_) => panic!("expected base64 error"),
        };
        assert!(err.to_string().contains("wrapped_key is not base64url"), "msg was {}", err);
    }

    #[test]
    fn write_metadata_attributes_removes_stale_member_xattrs() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let key = [28u8; 32];
        let mut two = get_default_test_metadata(&key, TEST_ADDRESS, b"x");
        two.members.push(sample_member("b@y", 2));
        sign_metadata(&key, &mut two, b"x");
        write_metadata_attributes(&p, &two).unwrap();
        assert!(xattr::get(&p, "user.ark.member_1_address").unwrap().is_some());

        let one = get_default_test_metadata(&key, TEST_ADDRESS, b"x");
        write_metadata_attributes(&p, &one).unwrap();
        assert_eq!(xattr::get(&p, "user.ark.member_1_address").unwrap(), None);

        let loaded = read_metadata_attributes(&p).unwrap();
        assert_eq!(loaded.members.len(), 1);
    }

    #[test]
    fn write_metadata_attributes_clears_old_encrypted_flag() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let key = [29u8; 32];
        let mut with_flag = get_default_test_metadata(&key, TEST_ADDRESS, b"x");
        with_flag.encrypted = Some(true);
        write_metadata_attributes(&p, &with_flag).unwrap();
        assert!(xattr::get(&p, "user.ark.encrypted").unwrap().is_some());

        let without_flag = get_default_test_metadata(&key, TEST_ADDRESS, b"x");
        write_metadata_attributes(&p, &without_flag).unwrap();
        assert_eq!(xattr::get(&p, "user.ark.encrypted").unwrap(), None);
    }
}
