use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};

use base64::Engine;

use crate::util::{B64, canonicalize_for_sig, is_valid_account_name, is_valid_host_port, unix_to_iso8601};

pub fn cmd_create_account(address: &str) -> std::io::Result<()> {
    let root = env::current_dir()?;
    let (sk, id_path) = create_account(&root, address)?;
    let pk = sk.verifying_key();
    let key_path = id_path.with_file_name("identity.key");
    println!("identity:    {}", id_path.display());
    println!("identity key: {}", key_path.display());
    println!("address:     {}", address);
    println!("public key (b64url): {}", B64.encode(pk.to_bytes()));
    println!("KEEP {} SECRET. Required to sign requests.", key_path.display());
    Ok(())
}

pub fn create_account(root: &Path, address: &str) -> std::io::Result<(SigningKey, PathBuf)> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    create_account_with_seed(root, address, seed)
}

pub fn create_account_with_seed(root: &Path, address: &str, seed: [u8; 32]) -> std::io::Result<(SigningKey, PathBuf)> {
    let (name, host) = address.split_once('@').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "address must be in the form <name>@<host>[:<port>]",
        )
    })?;
    if !is_valid_account_name(name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid account name (must be lowercase alphanumeric, dots, hyphens, underscores; 1-64 chars; not pure dots)",
        ));
    }
    if !is_valid_host_port(host) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid host[:port] in address",
        ));
    }
    let dir = root.join("ark").join(name).join(".ark");
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
    let doc = build_signed_identity(&sk, address, now);

    fs::create_dir_all(&dir)?;
    let pretty = serde_json::to_string_pretty(&doc)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    fs::write(&id_path, pretty)?;
    write_identity_key(&key_path, &seed)?;
    Ok((sk, id_path))
}

#[cfg(unix)]
fn write_identity_key(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(B64.encode(seed).as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_identity_key(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    fs::write(path, B64.encode(seed))
}

fn build_signed_identity(sk: &SigningKey, address: &str, now_secs: u64) -> serde_json::Value {
    let pk = sk.verifying_key();
    let mut doc = serde_json::json!({
        "key": { "algorithm": "ed25519", "public_key": B64.encode(pk.to_bytes()) },
        "address": address,
        "updated": unix_to_iso8601(now_secs),
        "signature": { "algorithm": "ed25519", "signature": "" }
    });
    let canonical = canonicalize_for_sig(&doc);
    let sig = sk.sign(&canonical);
    doc["signature"]["signature"] = serde_json::Value::String(B64.encode(sig.to_bytes()));
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let p = env::temp_dir().join(format!("ark_create_account_test_{}_{}", std::process::id(), nanos));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn create_account_writes_identity_file() {
        let td = TempDir::new();
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
        let td = TempDir::new();
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

    #[cfg(unix)]
    #[test]
    fn identity_key_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new();
        let (_sk, id_path) = create_account_with_seed(&td.0, "gyan@example.com", [56u8; 32]).unwrap();
        let key_path = id_path.with_file_name("identity.key");
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn create_account_rejects_invalid_addresses() {
        let td = TempDir::new();
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
        let td = TempDir::new();
        create_account(&td.0, "gyan@example.com").unwrap();
        let err = create_account(&td.0, "gyan@example.com").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn identity_self_signature_verifies() {
        let td = TempDir::new();
        let (sk, id_path) = create_account_with_seed(&td.0, "alice@example.com", [42u8; 32]).unwrap();
        let content = fs::read_to_string(&id_path).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();

        let sig_b64 = doc["signature"]["signature"].as_str().unwrap();
        assert!(!sig_b64.is_empty());
        let sig_bytes: [u8; 64] = B64.decode(sig_b64).unwrap().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);

        let canonical = canonicalize_for_sig(&doc);
        assert!(sk.verifying_key().verify(&canonical, &sig).is_ok());
    }

    #[test]
    fn identity_self_signature_detects_tampering() {
        let td = TempDir::new();
        let (sk, id_path) = create_account_with_seed(&td.0, "alice@example.com", [43u8; 32]).unwrap();
        let content = fs::read_to_string(&id_path).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        let sig_b64 = doc["signature"]["signature"].as_str().unwrap().to_string();
        let sig_bytes: [u8; 64] = B64.decode(&sig_b64).unwrap().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);

        doc["address"] = serde_json::Value::String("mallory@example.com".to_string());
        let canonical = canonicalize_for_sig(&doc);
        assert!(sk.verifying_key().verify(&canonical, &sig).is_err());
    }
}
