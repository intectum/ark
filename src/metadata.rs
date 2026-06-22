use std::io;
use std::path::Path;

use base64::Engine;

use crate::util::{B64, io_err};

const ATTRIBUTE_PREFIX: &str = "user.ark.";
const HEADER_PREFIX: &str = "X-Ark-Meta-";

const FIELD_ENCRYPTION: &str = "encryption";
const FIELD_FILE_KEY: &str = "filekey";

pub struct Metadata {
    pub encryption: Option<String>,
    pub file_key: Option<[u8; 32]>,
}

pub fn read_metadata_headers(headers: &[(String, String)]) -> Metadata {
    let mut encryption = None;
    let mut file_key = None;
    for (k, v) in headers {
        let field = match strip_metadata_header_prefix(k) {
            Some(s) => s.to_ascii_lowercase(),
            None => continue,
        };
        match field.as_str() {
            FIELD_ENCRYPTION => encryption = Some(v.clone()),
            FIELD_FILE_KEY => {
                if let Ok(bytes) = B64.decode(v.trim()) {
                    if let Ok(arr) = bytes.try_into() {
                        file_key = Some(arr);
                    }
                }
            }
            _ => {}
        }
    }
    Metadata { encryption, file_key }
}

pub fn write_metadata_headers(metadata: &Metadata) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(a) = &metadata.encryption {
        out.push((format!("{}Encryption", HEADER_PREFIX), a.clone()));
    }
    if let Some(k) = &metadata.file_key {
        out.push((format!("{}FileKey", HEADER_PREFIX), B64.encode(k)));
    }
    out
}

pub fn read_metadata_attributes(path: &Path) -> io::Result<Metadata> {
    let encryption = get_attribute(path, FIELD_ENCRYPTION)?;
    let file_key = match get_attribute(path, FIELD_FILE_KEY)? {
        Some(s) => {
            let bytes = B64
                .decode(s.trim())
                .map_err(|e| io_err(&format!("filekey decode: {}", e)))?;
            Some(
                bytes
                    .try_into()
                    .map_err(|_| io_err("filekey wrong length"))?,
            )
        }
        None => None,
    };
    Ok(Metadata { encryption, file_key })
}

pub fn write_metadata_attributes(path: &Path, metadata: &Metadata) -> io::Result<()> {
    if let Some(a) = &metadata.encryption {
        set_attribute(path, FIELD_ENCRYPTION, a)?;
    }
    if let Some(k) = &metadata.file_key {
        set_attribute(path, FIELD_FILE_KEY, &B64.encode(k))?;
    }
    Ok(())
}

pub fn strip_metadata_header_prefix(key: &str) -> Option<&str> {
    let n = HEADER_PREFIX.len();
    if key.len() > n && key[..n].eq_ignore_ascii_case(HEADER_PREFIX) {
        Some(&key[n..])
    } else {
        None
    }
}

fn get_attribute(path: &Path, name: &str) -> io::Result<Option<String>> {
    let full = format!("{}{}", ATTRIBUTE_PREFIX, name);
    match xattr::get(path, &full)? {
        Some(v) => Ok(Some(String::from_utf8(v).map_err(|_| io_err(&format!("xattr {} not utf8", full)))?)),
        None => Ok(None),
    }
}

fn set_attribute(path: &Path, name: &str, value: &str) -> io::Result<()> {
    let full = format!("{}{}", ATTRIBUTE_PREFIX, name);
    xattr::set(path, &full, value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testutil::TempDir;
    use std::fs;

    #[test]
    fn strip_meta_header_prefix_case_insensitive() {
        assert_eq!(strip_metadata_header_prefix("X-Ark-Meta-Encryption"), Some("Encryption"));
        assert_eq!(strip_metadata_header_prefix("x-ark-meta-foo"), Some("foo"));
        assert_eq!(strip_metadata_header_prefix("X-Custom-Foo"), None);
        assert_eq!(strip_metadata_header_prefix("X-Ark-Meta-"), None);
        assert_eq!(strip_metadata_header_prefix(""), None);
    }

    #[test]
    fn write_headers_emits_present_fields() {
        let meta = Metadata { encryption: Some("aes-256-gcm".to_string()), file_key: Some([7u8; 32]) };
        let headers = write_metadata_headers(&meta);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "X-Ark-Meta-Encryption");
        assert_eq!(headers[0].1, "aes-256-gcm");
        assert_eq!(headers[1].0, "X-Ark-Meta-FileKey");
        assert_eq!(B64.decode(&headers[1].1).unwrap(), vec![7u8; 32]);
    }

    #[test]
    fn write_headers_skips_none_fields() {
        let meta = Metadata { encryption: None, file_key: None };
        assert!(write_metadata_headers(&meta).is_empty());
    }

    #[test]
    fn read_headers_parses_known_fields_and_drops_unknown() {
        let headers = vec![
            ("X-Ark-Meta-Encryption".to_string(), "aes-256-gcm".to_string()),
            ("X-Ark-Meta-FileKey".to_string(), B64.encode([9u8; 32])),
            ("X-Ark-Meta-Unknown".to_string(), "drop".to_string()),
            ("X-Other".to_string(), "ignore".to_string()),
        ];
        let m = read_metadata_headers(&headers);
        assert_eq!(m.encryption.as_deref(), Some("aes-256-gcm"));
        assert_eq!(m.file_key, Some([9u8; 32]));
    }

    #[test]
    fn read_headers_is_case_insensitive() {
        let headers = vec![("x-ark-meta-encryption".to_string(), "aes-256-gcm".to_string())];
        let m = read_metadata_headers(&headers);
        assert_eq!(m.encryption.as_deref(), Some("aes-256-gcm"));
    }

    #[test]
    fn header_attribute_round_trip() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let meta = Metadata { encryption: Some("aes-256-gcm".to_string()), file_key: Some([42u8; 32]) };
        write_metadata_attributes(&p, &meta).unwrap();
        let loaded = read_metadata_attributes(&p).unwrap();
        assert_eq!(loaded.encryption, meta.encryption);
        assert_eq!(loaded.file_key, meta.file_key);
    }

    #[test]
    fn attributes_to_headers_round_trip() {
        let td = TempDir::new("ark_metadata_test");
        let p = td.0.join("file");
        fs::write(&p, b"x").unwrap();
        let meta = Metadata { encryption: Some("aes-256-gcm".to_string()), file_key: Some([55u8; 32]) };
        write_metadata_attributes(&p, &meta).unwrap();
        let attrs = read_metadata_attributes(&p).unwrap();
        let headers = write_metadata_headers(&attrs);
        let back = read_metadata_headers(&headers);
        assert_eq!(back.encryption, meta.encryption);
        assert_eq!(back.file_key, meta.file_key);
    }
}
