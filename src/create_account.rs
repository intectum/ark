use std::env;
use std::fs;
use std::path::{Path};

use crate::identity::{create_identity, validate_identity, write_identity, write_identity_key};
use crate::util::resolve_url;

pub fn cmd_create_account(address: &str) -> std::io::Result<()> {
    let root = env::current_dir()?;
    create_account(&root, address)?;

    Ok(())
}

pub fn create_account(root: &Path, address: &str) -> std::io::Result<Vec<u8>> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    create_account_with_key(root, address, &key)?;

    Ok(key.to_vec())
}

pub fn create_account_with_key(root: &Path, address: &str, key: &[u8]) -> std::io::Result<()> {
    let url = resolve_url("", address, Path::new(""))?;
    let dot_ark_dir = root.join("ark").join(&url.username()).join(".ark");
    let identity_path = dot_ark_dir.join("identity.json");
    let identity_key_path = dot_ark_dir.join("identity.key");
    if identity_path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} already exists", identity_path.display())));
    }
    if identity_key_path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} already exists", identity_key_path.display())));
    }

    let identity = create_identity(key, address);
    validate_identity(&identity)?;

    fs::create_dir_all(&dot_ark_dir)?;
    write_identity(&identity_path, &identity)?;
    write_identity_key(&identity_key_path, key)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::util::decode_base64url;
    use crate::util::test::TempDir;

    #[test]
    fn create_account_writes_identity_file() {
        let td = TempDir::new("ark_create_account_test");
        let key = [54u8; 32];
        create_account_with_key(&td.0, "gyan@example.com:8080", &key).unwrap();
        let identity_path = td.0.join("ark/gyan/.ark/identity.json");
        assert!(Path::new(&identity_path).exists());

        let content = fs::read_to_string(&identity_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(v["key"]["algorithm"].as_str(), Some("ed25519"));
        let pk_b64 = v["key"]["public_key"].as_str().unwrap();
        let pk_bytes = decode_base64url(pk_b64).unwrap();
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        assert_eq!(pk_arr.to_vec(), SigningKey::from_bytes(&key).verifying_key().to_bytes());

        assert_eq!(v["address"].as_str(), Some("gyan@example.com:8080"));
        let modified = v["modified"].as_str().unwrap();
        time::OffsetDateTime::parse(modified, &time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|e| panic!("modified is not RFC 3339: {} ({})", modified, e));
        assert_eq!(v["signature"]["algorithm"].as_str(), Some("ed25519"));
    }

    #[test]
    fn create_account_writes_identity_key_file() {
        let td = TempDir::new("ark_create_account_test");
        let key = [55u8; 32];
        create_account_with_key(&td.0, "gyan@example.com", &key).unwrap();
        let identity_key_path = td.0.join("ark/gyan/.ark/identity.key");
        assert!(Path::new(&identity_key_path).exists());

        let content = fs::read_to_string(&identity_key_path).unwrap();
        let decoded = decode_base64url(content.trim()).unwrap();
        let decoded_arr: [u8; 32] = decoded.try_into().unwrap();
        assert_eq!(decoded_arr, key);
    }

    #[test]
    fn create_account_rejects_invalid_addresses() {
        let td = TempDir::new("ark_create_account_test");
        let bad: &[&str] = &[
            "",
            "noatsign",
            "@host",
            "name@",
            "UPPER@host",
            "with/slash@host",
            "name@host:abc",
            &format!("{}@host", "a".repeat(65)),
        ];
        for b in bad {
            let err = create_account(&td.0, b).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{} should be InvalidInput", b);
        }
    }

    #[test]
    fn create_account_rejects_duplicate() {
        let td = TempDir::new("ark_create_account_test");
        create_account(&td.0, "gyan@example.com").unwrap();
        let err = create_account(&td.0, "gyan@example.com").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    }

}
