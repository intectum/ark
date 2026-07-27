use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Runtime context for an ark account.
///
/// Passed to every client operation. Clients have `identity_key` set (they
/// can sign requests and unwrap file keys); server-side target contexts have
/// it as `None` (the server does not hold other accounts' private keys).
pub struct IdentityContext {
    /// Account root — the directory containing `.ark/`.
    pub root: PathBuf,
    /// The account's identity document (address + public key).
    pub identity: Identity,
    /// The account's private key, when known.
    pub identity_key: Option<Key>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    #[serde(rename = "type")]
    pub kind: DirectoryEntryKind,
    pub name: String,
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

/// Public identity of an ark account: address, public key, and a self-signature
/// binding the two. Served as `.ark/identity.json` and used to verify request
/// signatures and wrap file keys for members.
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Public key used to verify request signatures and wrap file keys for
    /// this account.
    pub public_key: Key,
    /// Account address in `name@host[:port]` form.
    pub address: String,
    /// ISO 8601 timestamp of the most recent identity change.
    pub modified: String,
    /// Signature over the other fields, produced by the account's private key.
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    pub algorithm: String,
    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

/// Local-only companion to [`Metadata`], stored as `user.ark_local.*` xattrs.
/// Not part of the wire protocol.
#[derive(Clone, Default)]
pub struct LocalMetadata {
    /// Whether the file's bytes on disk are ciphertext.
    pub encrypted: Option<bool>,
    /// Hash of the last-synced plaintext body. Absent = do not sync.
    pub sync_body_hash: Option<Hash>,
    /// `Metadata.modified` at the last successful sync. Baseline for detecting
    /// local metadata drift (e.g. `chmod` since last sync).
    pub sync_modified: Option<String>,
}

/// A member entry in a file or directory's metadata: address, permission,
/// and (for encrypted files) the file key wrapped for this member's public
/// key. Address `*` is the public wildcard.
#[derive(Clone, Serialize, Deserialize)]
pub struct Member {
    pub address: String,
    pub permission: Permission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<Key>,
}

/// Signed metadata for a file or directory. Stored as `user.ark.*` xattrs at
/// rest, `X-Ark-Meta-*` HTTP headers in transit. See `spec.md` §8.
#[derive(Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub id: String,
    pub created: String,
    pub modified: String,
    pub modified_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_algorithm: Option<String>,
    pub members: Vec<Member>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<Hash>,
    pub signature: Signature,
}

/// Permission tier for a [`Member`]. Ordered: `Owner` > `Writer` > `Reader`.
/// See `spec.md` §3.3 for the read/modify/change-members matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Owner,
    Writer,
    Reader,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Owner => "owner",
            Permission::Writer => "writer",
            Permission::Reader => "reader",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Permission::Owner),
            "writer" => Some(Permission::Writer),
            "reader" => Some(Permission::Reader),
            _ => None,
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Permission::Reader => 0,
            Permission::Writer => 1,
            Permission::Owner => 2,
        }
    }
}

/// Member/permission changes applied to a file or directory. Addresses may
/// include the literal `"public"` for the wildcard `*`.
#[derive(Default)]
pub struct Permissions {
    /// Grant `owner` to each address.
    pub owners: Vec<String>,
    /// Grant `writer` to each address.
    pub writers: Vec<String>,
    /// Grant `reader` to each address.
    pub readers: Vec<String>,
    /// Drop each address from the member list.
    pub drops: Vec<String>,
}

pub struct Proposal {
    pub id: String,
    pub target: String,
    pub metadata: Metadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayMode {
    Full,
    Internal,
}

impl RelayMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelayMode::Full => "full",
            RelayMode::Internal => "internal",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "full" => Some(RelayMode::Full),
            "internal" => Some(RelayMode::Internal),
            _ => None,
        }
    }
}

pub struct RequestEntry {
    pub method: String,
    pub target: String,
    pub request_headers: Vec<(String, String)>,
    pub status: u16,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct StreamEvent {
    #[allow(dead_code)]
    pub id: String,
    pub event: String,
    pub data: String,
}

#[derive(Clone)]
pub enum WatchAction {
    Created,
    Deleted,
    Keepalive,
    Modified,
}

impl WatchAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            WatchAction::Created => "created",
            WatchAction::Deleted => "deleted",
            WatchAction::Keepalive => "keepalive",
            WatchAction::Modified => "modified",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(WatchAction::Created),
            "deleted" => Some(WatchAction::Deleted),
            "keepalive" => Some(WatchAction::Keepalive),
            "modified" => Some(WatchAction::Modified),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct WatchEvent {
    pub action: WatchAction,
    pub kind: Option<DirectoryEntryKind>,
    pub path: PathBuf,
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
        };
        let s = serde_json::to_string(&e).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["type"], "file");
        assert_eq!(v["name"], "a.txt");
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
        };
        let s = serde_json::to_string(&original).unwrap();
        let back: DirectoryEntry = serde_json::from_str(&s).unwrap();
        assert!(matches!(back.kind, DirectoryEntryKind::Symlink));
        assert_eq!(back.name, "link");
    }

    #[test]
    fn directory_entry_rejects_unknown_kind() {
        let bad = r#"{"type":"bogus","name":"x"}"#;
        let res: Result<DirectoryEntry, _> = serde_json::from_str(bad);
        assert!(res.is_err());
    }
}
