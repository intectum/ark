use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;

use crate::identity::{
    key_from_verifying_key, new_signed_identity, parse_address, write_identity, write_signing_key,
};

pub fn cmd_create_account(address: &str) -> std::io::Result<()> {
    let root = env::current_dir()?;
    let (sk, id_path) = create_account(&root, address)?;
    let key_path = id_path.with_file_name("identity.key");
    let key = key_from_verifying_key(&sk.verifying_key());
    println!("identity:    {}", id_path.display());
    println!("identity key: {}", key_path.display());
    println!("address:     {}", address);
    println!("public key (b64url): {}", key.public_key);
    println!("KEEP {} SECRET. Required to sign requests.", key_path.display());
    Ok(())
}

pub fn create_account(root: &Path, address: &str) -> std::io::Result<(SigningKey, PathBuf)> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    create_account_with_seed(root, address, seed)
}

pub fn create_account_with_seed(root: &Path, address: &str, seed: [u8; 32]) -> std::io::Result<(SigningKey, PathBuf)> {
    let (name, _host) = parse_address(address)?;
    let dir = root.join("ark").join(&name).join(".ark");
    let id_path = dir.join("identity.json");
    let key_path = dir.join("identity.key");
    if id_path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} already exists", id_path.display())));
    }
    if key_path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} already exists", key_path.display())));
    }

    let sk = SigningKey::from_bytes(&seed);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let identity = new_signed_identity(&sk, address, now)?;

    fs::create_dir_all(&dir)?;
    write_identity(&id_path, &identity)?;
    write_signing_key(&key_path, &sk)?;
    Ok((sk, id_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::B64;
    use crate::util::testutil::TempDir;
    use base64::Engine;

    #[test]
    fn create_account_writes_identity_file() {
        let td = TempDir::new("ark_create_account_test");
        let (sk, id_path) = create_account(&td.0, "gyan@example.com:8080").unwrap();
        assert_eq!(id_path, td.0.join("ark/gyan/.ark/identity.json"));
        assert!(id_path.exists());

        let content = fs::read_to_string(&id_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(v["key"]["algorithm"].as_str(), Some("ed25519"));
        let pk_b64 = v["key"]["public_key"].as_str().unwrap();
        let pk_bytes = B64.decode(pk_b64).unwrap();
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        assert_eq!(pk_arr, sk.verifying_key().to_bytes());

        assert_eq!(v["address"].as_str(), Some("gyan@example.com:8080"));
        let updated = v["updated"].as_str().unwrap();
        assert!(updated.ends_with("Z") && updated.len() == 20, "bad updated: {}", updated);
        assert_eq!(v["signature"]["algorithm"].as_str(), Some("ed25519"));
    }

    #[test]
    fn create_account_writes_identity_key_file() {
        let td = TempDir::new("ark_create_account_test");
        let (sk, id_path) = create_account_with_seed(&td.0, "gyan@example.com", [55u8; 32]).unwrap();
        let key_path = id_path.with_file_name("identity.key");
        assert!(key_path.exists());

        let content = fs::read_to_string(&key_path).unwrap();
        let decoded = B64.decode(content.trim()).unwrap();
        let seed: [u8; 32] = decoded.try_into().unwrap();
        assert_eq!(seed, [55u8; 32]);

        let derived = SigningKey::from_bytes(&seed);
        assert_eq!(derived.verifying_key().to_bytes(), sk.verifying_key().to_bytes());
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
            "name@bad_host",
            "name@host:0",
            "name@host:abc",
            "name@-bad.com",
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
