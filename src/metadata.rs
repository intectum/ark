use std::io;
use std::path::Path;

use crate::crypto::DEFAULT_ENCRYPTION_ALGORITHM;
use crate::types::{Member, Metadata};
use crate::util::{decode_base64url, encode_base64url, io_err};

const ATTRIBUTE_PREFIX: &str = "user.ark.";
const HEADER_PREFIX: &str = "X-Ark-Meta-";

const FIELD_ENCRYPTION: &str = "encryption";
const FIELD_ENCRYPTED: &str = "encrypted";
const FIELD_MEMBER_PREFIX: &str = "member_";
const FIELD_MEMBER_ADDRESS: &str = "address";
const FIELD_MEMBER_IDENTITY_KEY: &str = "identity_key";
const FIELD_MEMBER_PERMISSION: &str = "permission";
const FIELD_MEMBER_WRAPPED_FILE_KEY: &str = "wrapped_file_key";

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

    let metadata = Metadata {
        encryption: partial_metadata.encryption.unwrap(),
        encrypted: partial_metadata.encrypted,
        members: partial_metadata.members.into_iter().map(|m| Member {
            address: m.address.unwrap(),
            identity_key: m.identity_key.unwrap(),
            permission: m.permission.unwrap(),
            wrapped_file_key: m.wrapped_file_key.unwrap()
        }).collect()
    };

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

    xattr::set(path, &format!("{}encryption", ATTRIBUTE_PREFIX), metadata.encryption.as_bytes())?;
    if let Some(encrypted) = metadata.encrypted {
        xattr::set(path, &format!("{}encrypted", ATTRIBUTE_PREFIX), if encrypted { "true".as_bytes() } else { "false".as_bytes() })?;
    }

    for (index, member) in metadata.members.iter().enumerate() {
        xattr::set(path, &format!("{}member_{}_address", ATTRIBUTE_PREFIX, index), member.address.as_bytes())?;
        xattr::set(path, &format!("{}member_{}_identity_key", ATTRIBUTE_PREFIX, index), encode_base64url(member.identity_key.clone()).as_bytes())?;
        xattr::set(path, &format!("{}member_{}_permission", ATTRIBUTE_PREFIX, index), member.permission.as_bytes())?;
        xattr::set(path, &format!("{}member_{}_wrapped_file_key", ATTRIBUTE_PREFIX, index), encode_base64url(member.wrapped_file_key.clone()).as_bytes())?;
    }

    Ok(())
}

pub fn read_metadata_headers(headers: &[(String, String)]) -> io::Result<Metadata> {
    let mut partial_metadata = PartialMetadata::default();

    for (name, value) in headers {
        apply_field(&mut partial_metadata, name, value)?;
    }

    validate_partial_metadata(&partial_metadata)?;

    let metadata = Metadata {
        encryption: partial_metadata.encryption.unwrap(),
        encrypted: None,
        members: partial_metadata.members.into_iter().map(|m| Member {
            address: m.address.unwrap(),
            identity_key: m.identity_key.unwrap(),
            permission: m.permission.unwrap(),
            wrapped_file_key: m.wrapped_file_key.unwrap()
        }).collect()
    };

    validate_metadata(&metadata)?;

    Ok(metadata)
}

pub fn write_metadata_headers(metadata: &Metadata) -> Vec<(String, String)> {
    let mut out = Vec::new();

    out.push((format!("{}Encryption", HEADER_PREFIX), metadata.encryption.clone()));

    for (index, member) in metadata.members.iter().enumerate() {
        out.push((format!("{}Member-{}-Address", HEADER_PREFIX, index), member.address.clone()));
        out.push((format!("{}Member-{}-Identity-Key", HEADER_PREFIX, index), encode_base64url(member.identity_key.clone())));
        out.push((format!("{}Member-{}-Permission", HEADER_PREFIX, index), member.permission.clone()));
        out.push((format!("{}Member-{}-Wrapped-File-Key", HEADER_PREFIX, index), encode_base64url(member.wrapped_file_key.clone())));
    }

    out
}

pub fn validate_metadata(metadata: &Metadata) -> io::Result<()> {
    if metadata.encryption != DEFAULT_ENCRYPTION_ALGORITHM.to_string() {
        return Err(io_err(&format!("unsupported encryption algorithm: {}", metadata.encryption.clone())));
    }

    if !metadata.members.iter().any(|m| m.permission == "owner") {
        return Err(io_err("metadata must contain at least one owner"));
    }

    Ok(())
}

#[derive(Default)]
struct PartialMetadata {
    encryption: Option<String>,
    encrypted: Option<bool>,
    members: Vec<PartialMember>,
}

#[derive(Default)]
struct PartialMember {
    address: Option<String>,
    identity_key: Option<Vec<u8>>,
    permission: Option<String>,
    wrapped_file_key: Option<Vec<u8>>,
}

fn apply_field(metadata: &mut PartialMetadata, key: &str, value: &str) -> io::Result<()> {
    let metadata_key = match get_metadata_key(key) {
        Some(s) => s,
        None => return Ok(())
    };

    if metadata_key == FIELD_ENCRYPTION {
        metadata.encryption = Some(value.to_string());
    }

    if metadata_key == FIELD_ENCRYPTED {
        metadata.encrypted = match value.trim() {
            "true" => Some(true),
            "false" => Some(false),
            other => return Err(io_err(&format!("encrypted metadata invalid: {}", other))),
        };
    };

    if let Some((index, member_field_key)) = split_member_key(&metadata_key) {
        while metadata.members.len() <= index {
            metadata.members.push(PartialMember::default());
        }

        match member_field_key.as_str() {
            FIELD_MEMBER_ADDRESS => metadata.members[index].address = Some(value.to_string()),
            FIELD_MEMBER_IDENTITY_KEY => metadata.members[index].identity_key = Some(decode_base64url(value)
                .map_err(|_| io_err("identity_key is not base64url encoded"))?),
            FIELD_MEMBER_PERMISSION => metadata.members[index].permission = Some(value.to_string()),
            FIELD_MEMBER_WRAPPED_FILE_KEY => metadata.members[index].wrapped_file_key = Some(decode_base64url(value)
                .map_err(|_| io_err("wrapped_file_key is not base64url encoded"))?),
            _ => {}
        }
    }

    Ok(())
}

fn validate_partial_metadata(metadata: &PartialMetadata) -> io::Result<()> {
    if metadata.encryption == None {
        return Err(io_err("missing encryption field"));
    }

    for member in &metadata.members {
        if member.address == None {
            return Err(io_err("missing address field"));
        }

        if member.identity_key == None {
            return Err(io_err("missing identity key field"));
        }

        if member.permission == None {
            return Err(io_err("missing permission field"));
        }

        if member.wrapped_file_key == None {
            return Err(io_err("missing wrapped file key field"));
        }
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
    use super::*;
    use crate::util::test::TempDir;
    use std::fs;

    fn sample_member(addr: &str, key_b: u8) -> Member {
        Member {
            address: addr.to_string(),
            identity_key: [key_b; 32].to_vec(),
            permission: "owner".to_string(),
            wrapped_file_key: [key_b.wrapping_add(1); 32].to_vec(),
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
    fn write_headers_emits_encryption_and_members() {
        let meta = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![sample_member("a@x", 7)],
        };
        let headers = write_metadata_headers(&meta);
        assert!(headers.iter().any(|(k, v)| k == "X-Ark-Meta-Encryption" && v == "aes-256-gcm"));
        assert!(headers.iter().any(|(k, v)| k == "X-Ark-Meta-Member-0-Address" && v == "a@x"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Member-0-Identity-Key"));
        assert!(headers.iter().any(|(k, v)| k == "X-Ark-Meta-Member-0-Permission" && v == "owner"));
        assert!(headers.iter().any(|(k, _)| k == "X-Ark-Meta-Member-0-Wrapped-File-Key"));
    }

    #[test]
    fn read_headers_parses_member_fields() {
        let key = [9u8; 32];
        let headers = vec![
            ("x-ark-meta-encryption".to_string(), "aes-256-gcm".to_string()),
            ("x-ark-meta-member-0-address".to_string(), "alice@x".to_string()),
            ("x-ark-meta-member-0-identity-key".to_string(), encode_base64url([1u8; 32])),
            ("x-ark-meta-member-0-permission".to_string(), "owner".to_string()),
            ("x-ark-meta-member-0-wrapped-file-key".to_string(), encode_base64url(key)),
        ];
        let m = read_metadata_headers(&headers).unwrap();
        assert_eq!(m.encryption, "aes-256-gcm");
        assert_eq!(m.members.len(), 1);
        assert_eq!(m.members[0].address, "alice@x");
        assert_eq!(m.members[0].permission, "owner");
        assert_eq!(m.members[0].wrapped_file_key, key);
    }

    #[test]
    fn read_headers_parses_multiple_members() {
        let headers = vec![
            ("X-Ark-Meta-Encryption".to_string(), "aes-256-gcm".to_string()),
            ("X-Ark-Meta-Member-0-Address".to_string(), "a@x".to_string()),
            ("X-Ark-Meta-Member-0-Identity-Key".to_string(), encode_base64url([1u8; 32])),
            ("X-Ark-Meta-Member-0-Permission".to_string(), "owner".to_string()),
            ("X-Ark-Meta-Member-0-Wrapped-File-Key".to_string(), encode_base64url([3u8; 32])),
            ("X-Ark-Meta-Member-1-Address".to_string(), "b@y".to_string()),
            ("X-Ark-Meta-Member-1-Identity-Key".to_string(), encode_base64url([2u8; 32])),
            ("X-Ark-Meta-Member-1-Permission".to_string(), "read".to_string()),
            ("X-Ark-Meta-Member-1-Wrapped-File-Key".to_string(), encode_base64url([4u8; 32])),
        ];
        let m = read_metadata_headers(&headers).unwrap();
        assert_eq!(m.members.len(), 2);
        assert_eq!(m.members[0].address, "a@x");
        assert_eq!(m.members[1].address, "b@y");
    }

    #[test]
    fn header_attribute_round_trip_with_members() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let meta = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: Some(true),
            members: vec![sample_member("a@x", 7)],
        };
        write_metadata_attributes(&p, &meta).unwrap();
        let loaded = read_metadata_attributes(&p).unwrap();
        assert_eq!(loaded.encryption, meta.encryption);
        assert_eq!(loaded.encrypted, Some(true));
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0].address, "a@x");
        assert_eq!(loaded.members[0].wrapped_file_key, meta.members[0].wrapped_file_key);
    }

    #[test]
    fn attributes_to_headers_round_trip_drops_encrypted() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let meta = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: Some(true),
            members: vec![sample_member("a@x", 5)],
        };
        write_metadata_attributes(&p, &meta).unwrap();
        let attrs = read_metadata_attributes(&p).unwrap();
        let headers = write_metadata_headers(&attrs);
        let back = read_metadata_headers(&headers).unwrap();
        assert_eq!(back.encryption, meta.encryption);
        assert_eq!(back.encrypted, None, "encrypted is client-only");
        assert_eq!(back.members.len(), 1);
        assert_eq!(back.members[0].wrapped_file_key, meta.members[0].wrapped_file_key);
    }

    #[test]
    fn get_member_filters_by_address() {
        let members = [sample_member("a@x", 4), sample_member("b@y", 9)];
        let got = get_member(&members, "b@y").unwrap();
        assert_eq!(got.address, "b@y");
        assert!(get_member(&members, "nope@z").is_none());
    }

    #[test]
    fn validate_metadata_rejects_no_owner() {
        let mut reader = sample_member("a@x", 1);
        reader.permission = "read".to_string();
        let meta = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![reader],
        };
        let err = match validate_metadata(&meta) {
            Err(e) => e,
            Ok(_) => panic!("expected owner-missing error"),
        };
        assert!(err.to_string().contains("at least one owner"), "msg was {}", err);
    }

    #[test]
    fn validate_metadata_rejects_empty_members() {
        let meta = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![],
        };
        let err = match validate_metadata(&meta) {
            Err(e) => e,
            Ok(_) => panic!("expected owner-missing error"),
        };
        assert!(err.to_string().contains("at least one owner"));
    }

    #[test]
    fn validate_metadata_accepts_with_owner() {
        let meta = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![sample_member("a@x", 1)],
        };
        validate_metadata(&meta).unwrap();
    }

    #[test]
    fn read_headers_rejects_sparse_member_indexes() {
        let headers = vec![
            ("X-Ark-Meta-Encryption".to_string(), "aes-256-gcm".to_string()),
            ("X-Ark-Meta-Member-0-Address".to_string(), "a@x".to_string()),
            ("X-Ark-Meta-Member-0-Identity-Key".to_string(), encode_base64url([1u8; 32])),
            ("X-Ark-Meta-Member-0-Permission".to_string(), "owner".to_string()),
            ("X-Ark-Meta-Member-0-Wrapped-File-Key".to_string(), encode_base64url([3u8; 32])),
            ("X-Ark-Meta-Member-2-Address".to_string(), "c@z".to_string()),
            ("X-Ark-Meta-Member-2-Identity-Key".to_string(), encode_base64url([4u8; 32])),
            ("X-Ark-Meta-Member-2-Permission".to_string(), "read".to_string()),
            ("X-Ark-Meta-Member-2-Wrapped-File-Key".to_string(), encode_base64url([5u8; 32])),
        ];
        let err = match read_metadata_headers(&headers) {
            Err(e) => e,
            Ok(_) => panic!("expected error for sparse member indexes"),
        };
        let msg = err.to_string();
        assert!(msg.contains("missing"), "msg was {}", msg);
    }

    #[test]
    fn read_headers_parses_identity_key_field() {
        let identity_key = [42u8; 32];
        let headers = vec![
            ("X-Ark-Meta-Encryption".to_string(), "aes-256-gcm".to_string()),
            ("X-Ark-Meta-Member-0-Address".to_string(), "alice@x".to_string()),
            ("X-Ark-Meta-Member-0-Identity-Key".to_string(), encode_base64url(identity_key)),
            ("X-Ark-Meta-Member-0-Permission".to_string(), "owner".to_string()),
            ("X-Ark-Meta-Member-0-Wrapped-File-Key".to_string(), encode_base64url([3u8; 32])),
        ];
        let m = read_metadata_headers(&headers).unwrap();
        assert_eq!(m.members[0].identity_key, identity_key.to_vec());
    }

    #[test]
    fn read_headers_rejects_invalid_base64_in_member_field() {
        let headers = vec![
            ("X-Ark-Meta-Encryption".to_string(), "aes-256-gcm".to_string()),
            ("X-Ark-Meta-Member-0-Address".to_string(), "alice@x".to_string()),
            ("X-Ark-Meta-Member-0-Identity-Key".to_string(), "!!not-base64!!".to_string()),
            ("X-Ark-Meta-Member-0-Permission".to_string(), "owner".to_string()),
            ("X-Ark-Meta-Member-0-Wrapped-File-Key".to_string(), encode_base64url([3u8; 32])),
        ];
        let err = match read_metadata_headers(&headers) {
            Err(e) => e,
            Ok(_) => panic!("expected base64 decode error"),
        };
        assert!(err.to_string().contains("identity_key is not base64url"), "msg was {}", err);
    }

    #[test]
    fn write_metadata_attributes_removes_stale_member_xattrs() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let two = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![sample_member("a@x", 1), sample_member("b@y", 2)],
        };
        write_metadata_attributes(&p, &two).unwrap();
        assert!(xattr::get(&p, "user.ark.member_1_address").unwrap().is_some());

        let one = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![sample_member("a@x", 1)],
        };
        write_metadata_attributes(&p, &one).unwrap();
        assert_eq!(xattr::get(&p, "user.ark.member_1_address").unwrap(), None);
        assert_eq!(xattr::get(&p, "user.ark.member_1_wrapped_file_key").unwrap(), None);

        let loaded = read_metadata_attributes(&p).unwrap();
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0].address, "a@x");
    }

    #[test]
    fn write_metadata_attributes_clears_old_encrypted_flag() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let with_flag = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: Some(true),
            members: vec![sample_member("a@x", 1)],
        };
        write_metadata_attributes(&p, &with_flag).unwrap();
        assert!(xattr::get(&p, "user.ark.encrypted").unwrap().is_some());

        let without_flag = Metadata {
            encryption: "aes-256-gcm".to_string(),
            encrypted: None,
            members: vec![sample_member("a@x", 1)],
        };
        write_metadata_attributes(&p, &without_flag).unwrap();
        assert_eq!(xattr::get(&p, "user.ark.encrypted").unwrap(), None);
    }
}
