use std::io;
use std::path::Path;

use uuid::Uuid;

use crate::crypto::{DEFAULT_HASH_ALGORITHM, encrypt_bytes, sign_json, verify_json};
use crate::types::IdentityContext;
use crate::identity::resolve_identity;
use crate::types::{Hash, Key, LocalMetadata, Member, Metadata, Permission, Signature};
use crate::util::{decode_base64url, encode_base64url, io_err, now_iso, sha256};

const ATTRIBUTE_PREFIX: &str = "user.ark.";
const LOCAL_ATTRIBUTE_PREFIX: &str = "user.ark_local.";
const HEADER_PREFIX: &str = "X-Ark-Meta-";

const FIELD_ID: &str = "id";
const FIELD_CREATED: &str = "created";
const FIELD_MODIFIED: &str = "modified";
const FIELD_MODIFIED_BY: &str = "modified_by";
const FIELD_ENCRYPTION_ALGORITHM: &str = "encryption_algorithm";
const FIELD_MEMBER_PREFIX: &str = "member_";
const FIELD_MEMBER_ADDRESS: &str = "address";
const FIELD_MEMBER_PERMISSION: &str = "permission";
const FIELD_MEMBER_KEY_ALGORITHM: &str = "key_algorithm";
const FIELD_MEMBER_KEY_VALUE: &str = "key_value";
const FIELD_BODY_HASH_ALGORITHM: &str = "body_hash_algorithm";
const FIELD_BODY_HASH_VALUE: &str = "body_hash_value";
const FIELD_SIGNATURE_ALGORITHM: &str = "signature_algorithm";
const FIELD_SIGNATURE_VALUE: &str = "signature_value";

const LOCAL_FIELD_ENCRYPTED: &str = "encrypted";
const LOCAL_FIELD_SYNC_HASH: &str = "sync_hash";

pub fn get_member<'a>(members: &'a [Member], address: &str) -> Option<&'a Member> {
    members.iter().find(|m| m.address == address)
}

pub fn create_metadata(owner_address: &str, encryption_algorithm: Option<&str>) -> Metadata {
    let now = now_iso();

    Metadata {
        id: Uuid::new_v4().to_string(),
        created: now.clone(),
        modified: now.clone(),
        modified_by: owner_address.to_string(),
        encryption_algorithm: encryption_algorithm.map(|s| s.to_string()),
        members: vec![Member {
            address: owner_address.to_string(),
            permission: Permission::Owner,
            key: None
        }],
        body_hash: None,
        signature: Signature {
            algorithm: String::new(),
            value: Vec::new()
        },
    }
}

pub fn read_metadata_attributes(path: &Path) -> io::Result<Metadata> {
    let mut partial_metadata = PartialMetadata::default();

    for attribute in xattr::list(path)? {
        let name = attribute.to_string_lossy().into_owned();
        if !name.starts_with(ATTRIBUTE_PREFIX) {
            continue;
        }

        let value = match xattr::get(path, &name)? {
            Some(v) => String::from_utf8(v)
                .map_err(|_| io_err(&format!("xattr {} not utf8", name)))?,
            None => continue,
        };

        apply_field(&mut partial_metadata, &name, &value)?;
    }

    validate_partial_metadata(&partial_metadata)?;

    let metadata = metadata_from_partial(partial_metadata)?;
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
    if let Some(alg) = &metadata.encryption_algorithm {
        xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_ENCRYPTION_ALGORITHM), alg.as_bytes())?;
    }
    if let Some(body_hash) = &metadata.body_hash {
        xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_BODY_HASH_ALGORITHM), body_hash.algorithm.as_bytes())?;
        xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_BODY_HASH_VALUE), encode_base64url(&body_hash.value).as_bytes())?;
    }
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_SIGNATURE_ALGORITHM), metadata.signature.algorithm.as_bytes())?;
    xattr::set(path, &format!("{}{}", ATTRIBUTE_PREFIX, FIELD_SIGNATURE_VALUE), encode_base64url(&metadata.signature.value).as_bytes())?;

    for (index, member) in metadata.members.iter().enumerate() {
        xattr::set(path, &format!("{}member_{}_address", ATTRIBUTE_PREFIX, index), member.address.as_bytes())?;
        xattr::set(path, &format!("{}member_{}_permission", ATTRIBUTE_PREFIX, index), member.permission.as_str().as_bytes())?;
        if let Some(key) = &member.key {
            xattr::set(path, &format!("{}member_{}_key_algorithm", ATTRIBUTE_PREFIX, index), key.algorithm.as_bytes())?;
            xattr::set(path, &format!("{}member_{}_key_value", ATTRIBUTE_PREFIX, index), encode_base64url(&key.value).as_bytes())?;
        }
    }

    Ok(())
}

pub fn read_local_metadata_attributes(path: &Path) -> io::Result<LocalMetadata> {
    let mut local = LocalMetadata::default();

    for attribute in xattr::list(path)? {
        let name = attribute.to_string_lossy().into_owned();
        let field = match name.strip_prefix(LOCAL_ATTRIBUTE_PREFIX) {
            Some(f) => f,
            None => continue,
        };

        let value = match xattr::get(path, &name)? {
            Some(v) => String::from_utf8(v)
                .map_err(|_| io_err(&format!("xattr {} not utf8", name)))?,
            None => continue,
        };

        match field {
            LOCAL_FIELD_ENCRYPTED => {
                local.encrypted = match value.trim() {
                    "true" => Some(true),
                    "false" => Some(false),
                    other => return Err(io_err(&format!("encrypted local attribute invalid: {}", other))),
                };
            }
            LOCAL_FIELD_SYNC_HASH => {
                local.sync_hash = Some(decode_base64url(value)
                    .map_err(|_| io_err("sync_hash is not base64url encoded"))?);
            }
            _ => {}
        }
    }

    Ok(local)
}

pub fn write_local_metadata_attributes(path: &Path, local: &LocalMetadata) -> io::Result<()> {
    for attribute in xattr::list(path)? {
        let name = attribute.to_string_lossy();
        if name.starts_with(LOCAL_ATTRIBUTE_PREFIX) {
            xattr::remove(path, &*name)?;
        }
    }

    if let Some(encrypted) = local.encrypted {
        xattr::set(path, &format!("{}{}", LOCAL_ATTRIBUTE_PREFIX, LOCAL_FIELD_ENCRYPTED), if encrypted { b"true" } else { b"false" })?;
    }
    if let Some(sync_hash) = &local.sync_hash {
        xattr::set(path, &format!("{}{}", LOCAL_ATTRIBUTE_PREFIX, LOCAL_FIELD_SYNC_HASH), encode_base64url(sync_hash).as_bytes())?;
    }

    Ok(())
}

pub fn read_metadata_headers(headers: &[(String, String)]) -> io::Result<Metadata> {
    let mut partial_metadata = PartialMetadata::default();

    for (name, value) in headers {
        apply_field(&mut partial_metadata, name, value)?;
    }

    validate_partial_metadata(&partial_metadata)?;

    let metadata = metadata_from_partial(partial_metadata)?;
    validate_metadata(&metadata)?;

    Ok(metadata)
}

pub fn write_metadata_headers(metadata: &Metadata) -> Vec<(String, String)> {
    let mut out = Vec::new();

    out.push((format!("{}Id", HEADER_PREFIX), metadata.id.clone()));
    out.push((format!("{}Created", HEADER_PREFIX), metadata.created.clone()));
    out.push((format!("{}Modified", HEADER_PREFIX), metadata.modified.clone()));
    out.push((format!("{}Modified-By", HEADER_PREFIX), metadata.modified_by.clone()));
    if let Some(alg) = &metadata.encryption_algorithm {
        out.push((format!("{}Encryption-Algorithm", HEADER_PREFIX), alg.clone()));
    }
    if let Some(body_hash) = &metadata.body_hash {
        out.push((format!("{}Body-Hash-Algorithm", HEADER_PREFIX), body_hash.algorithm.clone()));
        out.push((format!("{}Body-Hash-Value", HEADER_PREFIX), encode_base64url(&body_hash.value)));
    }
    out.push((format!("{}Signature-Algorithm", HEADER_PREFIX), metadata.signature.algorithm.clone()));
    out.push((format!("{}Signature-Value", HEADER_PREFIX), encode_base64url(&metadata.signature.value)));

    for (index, member) in metadata.members.iter().enumerate() {
        out.push((format!("{}Member-{}-Address", HEADER_PREFIX, index), member.address.clone()));
        out.push((format!("{}Member-{}-Permission", HEADER_PREFIX, index), member.permission.as_str().to_string()));
        if let Some(key) = &member.key {
            out.push((format!("{}Member-{}-Key-Algorithm", HEADER_PREFIX, index), key.algorithm.clone()));
            out.push((format!("{}Member-{}-Key-Value", HEADER_PREFIX, index), encode_base64url(&key.value)));
        }
    }

    out
}

pub fn validate_metadata(metadata: &Metadata) -> io::Result<()> {
    if !metadata.members.iter().any(|m| m.permission == Permission::Owner) {
        return Err(io_err("metadata must contain at least one owner"));
    }

    Ok(())
}

pub fn apply_key_to_metadata(
    ctx: &IdentityContext,
    metadata: &mut Metadata,
    secret_key: &Key,
) -> std::io::Result<()> {
    for member in metadata.members.iter_mut() {
        if member.address == "*" {
            member.key = None;
            continue;
        }

        let recipient_identity = resolve_identity(ctx, &member.address)?;
        let (algorithm, value) = encrypt_bytes(&recipient_identity.public_key, &secret_key.value)?;
        member.key = Some(Key {
            algorithm,
            value
        });
    }

    Ok(())
}

pub fn sign_metadata(secret_key: &Key, metadata: &mut Metadata, body: Option<&[u8]>) -> io::Result<()> {
    metadata.body_hash = body.map(|b| Hash {
        algorithm: DEFAULT_HASH_ALGORITHM.to_string(),
        value: sha256(b),
    });

    let json = serde_json::to_value(metadata_for_signing(metadata)).expect("serialize metadata");
    metadata.signature = sign_json(secret_key, &json)?;

    Ok(())
}

pub fn verify_metadata_signature(public_key: &Key, metadata: &Metadata) -> io::Result<()> {
    let json = serde_json::to_value(metadata_for_signing(metadata)).expect("serialize metadata");
    verify_json(public_key, &metadata.signature, &json)
        .map_err(|_| io_err("metadata signature verification failed"))
}

pub fn verify_metadata(public_key: &Key, metadata: &Metadata, body: Option<&[u8]>) -> io::Result<()> {
    verify_metadata_signature(public_key, metadata)?;

    match (body, &metadata.body_hash) {
        (Some(b), Some(hash)) => {
            if hash.value != sha256(b) {
                return Err(io_err("body hash mismatch"));
            }
        }
        (Some(_), None) => return Err(io_err("file metadata must contain body_hash")),
        (None, Some(_)) => return Err(io_err("dir metadata must not contain body_hash")),
        (None, None) => {}
    }

    Ok(())
}

fn metadata_for_signing(metadata: &Metadata) -> Metadata {
    let mut clone = metadata.clone();
    clone.signature.algorithm = String::new();
    clone.signature.value = Vec::new();
    clone
}

#[derive(Default)]
struct PartialMetadata {
    id: Option<String>,
    modified_by: Option<String>,
    created: Option<String>,
    modified: Option<String>,
    encryption_algorithm: Option<String>,
    members: Vec<PartialMember>,
    body_hash_algorithm: Option<String>,
    body_hash_value: Option<Vec<u8>>,
    signature_algorithm: Option<String>,
    signature_value: Option<Vec<u8>>,
}

#[derive(Default)]
struct PartialMember {
    address: Option<String>,
    permission: Option<Permission>,
    key_algorithm: Option<String>,
    key_value: Option<Vec<u8>>,
}

fn metadata_from_partial(partial: PartialMetadata) -> io::Result<Metadata> {
    Ok(Metadata {
        id: partial.id.unwrap(),
        created: partial.created.unwrap(),
        modified: partial.modified.unwrap(),
        modified_by: partial.modified_by.unwrap(),
        encryption_algorithm: partial.encryption_algorithm,
        members: partial.members.into_iter().map(|member| Member {
            address: member.address.unwrap(),
            permission: member.permission.unwrap(),
            key: match (member.key_algorithm, member.key_value) {
                (Some(algorithm), Some(value)) => Some(Key { algorithm, value }),
                _ => None,
            },
        }).collect(),
        body_hash: match (partial.body_hash_algorithm, partial.body_hash_value) {
            (Some(algorithm), Some(value)) => Some(Hash { algorithm, value }),
            _ => None,
        },
        signature: Signature {
            algorithm: partial.signature_algorithm.unwrap(),
            value: partial.signature_value.unwrap(),
        },
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
        FIELD_ENCRYPTION_ALGORITHM => metadata.encryption_algorithm = Some(value.to_string()),
        FIELD_BODY_HASH_ALGORITHM => metadata.body_hash_algorithm = Some(value.to_string()),
        FIELD_BODY_HASH_VALUE => metadata.body_hash_value = Some(decode_base64url(value)
            .map_err(|_| io_err("body_hash_value is not base64url encoded"))?),
        FIELD_SIGNATURE_ALGORITHM => metadata.signature_algorithm = Some(value.to_string()),
        FIELD_SIGNATURE_VALUE => metadata.signature_value = Some(decode_base64url(value)
            .map_err(|_| io_err("signature is not base64url encoded"))?),
        _ => {
            if let Some((index, member_field_key)) = split_member_key(&metadata_key) {
                while metadata.members.len() <= index {
                    metadata.members.push(PartialMember::default());
                }

                match member_field_key.as_str() {
                    FIELD_MEMBER_ADDRESS => metadata.members[index].address = Some(value.to_string()),
                    FIELD_MEMBER_PERMISSION => metadata.members[index].permission = Some(
                        Permission::parse(value).ok_or_else(|| io_err(&format!("unknown permission: {}", value)))?
                    ),
                    FIELD_MEMBER_KEY_ALGORITHM => metadata.members[index].key_algorithm = Some(value.to_string()),
                    FIELD_MEMBER_KEY_VALUE => metadata.members[index].key_value = Some(decode_base64url(value)
                        .map_err(|_| io_err("key_value is not base64url encoded"))?),
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
    if metadata.signature_algorithm.is_none() { return Err(io_err("missing signature_algorithm field")); }
    if metadata.signature_value.is_none() { return Err(io_err("missing signature field")); }

    for member in &metadata.members {
        if member.address.is_none() { return Err(io_err("missing member address field")); }
        if member.permission.is_none() { return Err(io_err("missing member permission field")); }
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
    use crate::crypto::DEFAULT_ENCRYPTION_ALGORITHM;
    use crate::identity::create_identity;
    use crate::util::test::{TEST_ADDRESS, create_plain_test_metadata, in_test_dir};

    #[test]
    fn get_metadata_key_case_insensitive() {
        assert_eq!(get_metadata_key("X-Ark-Meta-Encryption-Algorithm"), Some("encryption_algorithm".to_string()));
        assert_eq!(get_metadata_key("x-ark-meta-foo"), Some("foo".to_string()));
        assert_eq!(get_metadata_key("X-Custom-Foo"), None);
        assert_eq!(get_metadata_key("X-Ark-Meta-"), None);
        assert_eq!(get_metadata_key(""), None);
    }

    #[test]
    fn write_headers_emits_all_fields() {
        let (owner, owner_key) = create_identity(TEST_ADDRESS).unwrap();
        let mut m = create_metadata(&owner.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
        sign_metadata(&owner_key, &mut m, Some(b"body")).unwrap();
        let headers = write_metadata_headers(&m);
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Id"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Created"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Modified"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Modified-By"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Encryption-Algorithm"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Member-0-Address"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Body-Hash-Algorithm"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Body-Hash-Value"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Signature-Algorithm"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Signature-Value"));
    }

    #[test]
    fn header_round_trip_preserves_all_fields() {
        let (owner, owner_key) = create_identity(TEST_ADDRESS).unwrap();
        let mut m = create_metadata(&owner.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
        m.members[0].key = Some(Key {
            algorithm: "hpke-x25519-hkdf-sha256-aes256gcm".to_string(),
            value: vec![0u8; 32],
        });
        sign_metadata(&owner_key, &mut m, Some(b"body")).unwrap();
        let headers = write_metadata_headers(&m);
        let back = read_metadata_headers(&headers).unwrap();
        assert_eq!(back.id, m.id);
        assert_eq!(back.created, m.created);
        assert_eq!(back.modified, m.modified);
        assert_eq!(back.modified_by, m.modified_by);
        assert_eq!(back.encryption_algorithm, m.encryption_algorithm);
        assert_eq!(back.members[0].address, m.members[0].address);
        let (back_hash, m_hash) = (back.body_hash.as_ref().unwrap(), m.body_hash.as_ref().unwrap());
        assert_eq!(back_hash.algorithm, m_hash.algorithm);
        assert_eq!(back_hash.value, m_hash.value);
        assert_eq!(back.signature.value, m.signature.value);
    }

    #[test]
    fn attribute_round_trip_preserves_all_fields() {
        in_test_dir("ark_metadata_test", |temp_dir| {
            let p = temp_dir.join("file");
            fs::write(&p, b"x").unwrap();
            let (owner, owner_key) = create_identity(TEST_ADDRESS).unwrap();
            let m = create_plain_test_metadata(&owner, &owner_key, b"x");
            write_metadata_attributes(&p, &m).unwrap();
            let back = read_metadata_attributes(&p).unwrap();
            assert_eq!(back.id, m.id);
            assert_eq!(back.signature.value, m.signature.value);
        });
    }

    #[test]
    fn local_attribute_round_trip_preserves_all_fields() {
        in_test_dir("ark_metadata_test", |temp_dir| {
            let p = temp_dir.join("file");
            fs::write(&p, b"x").unwrap();
            let local = LocalMetadata { encrypted: Some(true), sync_hash: Some(vec![0xAB, 0xCD]) };
            write_local_metadata_attributes(&p, &local).unwrap();
            let back = read_local_metadata_attributes(&p).unwrap();
            assert_eq!(back.encrypted, Some(true));
            assert_eq!(back.sync_hash.as_deref(), Some(&[0xAB, 0xCD][..]));
        });
    }

    #[test]
    fn write_local_metadata_attributes_clears_stale_fields() {
        in_test_dir("ark_metadata_test", |temp_dir| {
            let p = temp_dir.join("file");
            fs::write(&p, b"x").unwrap();
            let full = LocalMetadata { encrypted: Some(true), sync_hash: Some(vec![1, 2, 3]) };
            write_local_metadata_attributes(&p, &full).unwrap();
            let cleared = LocalMetadata::default();
            write_local_metadata_attributes(&p, &cleared).unwrap();
            assert_eq!(xattr::get(&p, "user.ark_local.encrypted").unwrap(), None);
            assert_eq!(xattr::get(&p, "user.ark_local.sync_hash").unwrap(), None);
        });
    }

    #[test]
    fn get_member_filters_by_address() {
        let members = [
            Member { address: "a@x".to_string(), permission: Permission::Owner, key: None },
            Member { address: "b@y".to_string(), permission: Permission::Owner, key: None },
        ];
        let got = get_member(&members, "b@y").unwrap();
        assert_eq!(got.address, "b@y");
        assert!(get_member(&members, "nope@z").is_none());
    }

    #[test]
    fn sign_and_verify_metadata_round_trip() {
        let (owner, owner_key) = create_identity(TEST_ADDRESS).unwrap();
        let body = b"signed payload";
        let m = create_plain_test_metadata(&owner, &owner_key, body);
        verify_metadata(&owner.public_key, &m, Some(body)).unwrap();
    }

    #[test]
    fn verify_metadata_detects_body_tampering() {
        let (owner, owner_key) = create_identity(TEST_ADDRESS).unwrap();
        let m = create_plain_test_metadata(&owner, &owner_key, b"original");
        let err = verify_metadata(&owner.public_key, &m, Some(b"tampered")).unwrap_err();
        assert!(err.to_string().contains("body hash mismatch"));
    }

    #[test]
    fn verify_metadata_detects_metadata_tampering() {
        let (owner, owner_key) = create_identity(TEST_ADDRESS).unwrap();
        let body = b"body";
        let mut m = create_plain_test_metadata(&owner, &owner_key, body);
        m.modified_by = "attacker@evil".to_string();
        let err = verify_metadata(&owner.public_key, &m, Some(body)).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn validate_metadata_rejects_no_owner() {
        let mut m = create_metadata(TEST_ADDRESS, None);
        m.members[0].permission = Permission::Read;
        let err = match validate_metadata(&m) {
            Err(e) => e,
            Ok(_) => panic!("expected owner-missing error"),
        };
        assert!(err.to_string().contains("at least one owner"), "msg was {}", err);
    }

    #[test]
    fn validate_metadata_rejects_empty_members() {
        let mut m = create_metadata(TEST_ADDRESS, None);
        m.members = vec![];
        let err = match validate_metadata(&m) {
            Err(e) => e,
            Ok(_) => panic!("expected owner-missing error"),
        };
        assert!(err.to_string().contains("at least one owner"));
    }

    #[test]
    fn read_headers_rejects_sparse_member_indexes() {
        let m = create_metadata(TEST_ADDRESS, None);
        let mut headers = write_metadata_headers(&m);
        headers.push(("X-Ark-Meta-Member-2-Address".to_string(), "c@z".to_string()));
        headers.push(("X-Ark-Meta-Member-2-Permission".to_string(), "read".to_string()));
        headers.push(("X-Ark-Meta-Member-2-Key-Algorithm".to_string(), "x25519".to_string()));
        headers.push(("X-Ark-Meta-Member-2-Key-Value".to_string(), encode_base64url([5u8; 32])));
        let err = match read_metadata_headers(&headers) {
            Err(e) => e,
            Ok(_) => panic!("expected sparse member error"),
        };
        assert!(err.to_string().contains("missing"), "msg was {}", err);
    }

    #[test]
    fn read_headers_rejects_invalid_base64_in_member_field() {
        let mut m = create_metadata(TEST_ADDRESS, None);
        m.members[0].key = Some(Key {
            algorithm: "hpke-x25519-hkdf-sha256-aes256gcm".to_string(),
            value: vec![0u8; 32],
        });
        let mut headers = write_metadata_headers(&m);
        for entry in headers.iter_mut() {
            if entry.0 == "X-Ark-Meta-Member-0-Key-Value" {
                entry.1 = "!!not-base64!!".to_string();
            }
        }
        let err = match read_metadata_headers(&headers) {
            Err(e) => e,
            Ok(_) => panic!("expected base64 error"),
        };
        assert!(err.to_string().contains("key_value is not base64url"), "msg was {}", err);
    }

    #[test]
    fn write_metadata_attributes_removes_stale_member_xattrs() {
        in_test_dir("ark_metadata_test", |temp_dir| {
            let p = temp_dir.join("file");
            fs::write(&p, b"x").unwrap();
            let (owner, owner_key) = create_identity(TEST_ADDRESS).unwrap();
            let mut two = create_plain_test_metadata(&owner, &owner_key, b"x");
            two.members.push(Member { address: "b@y".to_string(), permission: Permission::Owner, key: None });
            sign_metadata(&owner_key, &mut two, Some(b"x")).unwrap();
            write_metadata_attributes(&p, &two).unwrap();
            assert!(xattr::get(&p, "user.ark.member_1_address").unwrap().is_some());

            let one = create_plain_test_metadata(&owner, &owner_key, b"x");
            write_metadata_attributes(&p, &one).unwrap();
            assert_eq!(xattr::get(&p, "user.ark.member_1_address").unwrap(), None);

            let loaded = read_metadata_attributes(&p).unwrap();
            assert_eq!(loaded.members.len(), 1);
        });
    }

}
