use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    #[serde(rename = "type")]
    pub kind: DirectoryEntryKind,
    pub name: String,
    pub size: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryEntryKind {
    Dir,
    File,
    Symlink,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Hash {
    pub algorithm: String,
    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub public_key: Key,
    pub address: String,
    pub modified: String,
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    pub algorithm: String,
    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Member {
    pub address: String,
    #[serde(with = "base64url")]
    pub identity_key: Vec<u8>,
    pub permission: String,
    #[serde(with = "base64url")]
    pub wrapped_key: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub id: String,
    pub created: String,
    pub modified: String,
    pub modified_by: String,
    pub encryption: String,
    pub members: Vec<Member>,
    pub body_hash: Hash,
    pub signature: Signature,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

mod base64url {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_entry_serializes_with_renamed_type_field() {
        let e = DirectoryEntry {
            kind: DirectoryEntryKind::File,
            name: "a.txt".to_string(),
            size: 42,
        };
        let s = serde_json::to_string(&e).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["type"], "file");
        assert_eq!(v["name"], "a.txt");
        assert_eq!(v["size"], 42);
    }

    #[test]
    fn directory_entry_kind_serializes_as_snake_case_strings() {
        assert_eq!(serde_json::to_string(&DirectoryEntryKind::Dir).unwrap(), "\"dir\"");
        assert_eq!(serde_json::to_string(&DirectoryEntryKind::File).unwrap(), "\"file\"");
        assert_eq!(serde_json::to_string(&DirectoryEntryKind::Symlink).unwrap(), "\"symlink\"");
    }

    #[test]
    fn directory_entry_round_trip() {
        let original = DirectoryEntry {
            kind: DirectoryEntryKind::Symlink,
            name: "link".to_string(),
            size: 7,
        };
        let s = serde_json::to_string(&original).unwrap();
        let back: DirectoryEntry = serde_json::from_str(&s).unwrap();
        assert!(matches!(back.kind, DirectoryEntryKind::Symlink));
        assert_eq!(back.name, "link");
        assert_eq!(back.size, 7);
    }

    #[test]
    fn directory_entry_rejects_unknown_kind() {
        let bad = r#"{"type":"bogus","name":"x","size":0}"#;
        let res: Result<DirectoryEntry, _> = serde_json::from_str(bad);
        assert!(res.is_err());
    }
}
