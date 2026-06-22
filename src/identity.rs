use std::fs;
use std::io;
use std::path::Path;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::util::{B64, canonicalize_for_sig, is_valid_account_name, is_valid_host_port, unix_to_iso8601};

pub const ED25519: &str = "ed25519";

pub struct Key {
    pub algorithm: String,
    pub public_key: String,
}

pub struct Signature {
    pub algorithm: String,
    pub signature: String,
}

pub struct Identity {
    pub key: Key,
    pub address: String,
    pub updated: String,
    pub signature: Signature,
}

pub fn parse_address(address: &str) -> io::Result<(String, String)> {
    let (name, host) = address.split_once('@').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "address must be in the form <name>@<host>[:<port>]",
        )
    })?;
    if !is_valid_account_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid account name (must be lowercase alphanumeric, dots, hyphens, underscores; 1-64 chars; not pure dots)",
        ));
    }
    if !is_valid_host_port(host) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid host[:port] in address",
        ));
    }
    Ok((name.to_string(), host.to_string()))
}

pub fn verifying_key_from_key(key: &Key) -> io::Result<VerifyingKey> {
    if key.algorithm != ED25519 {
        return Err(io_err("unsupported key algorithm"));
    }
    let bytes = B64
        .decode(&key.public_key)
        .map_err(|e| io_err(&format!("public_key decode: {}", e)))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| io_err("public_key wrong length"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| io_err("public_key invalid"))
}

pub fn key_from_verifying_key(vk: &VerifyingKey) -> Key {
    Key {
        algorithm: ED25519.to_string(),
        public_key: B64.encode(vk.to_bytes()),
    }
}

pub fn new_signed_identity(sk: &SigningKey, address: &str, now_secs: u64) -> io::Result<Identity> {
    parse_address(address)?;
    let key = key_from_verifying_key(&sk.verifying_key());
    let updated = unix_to_iso8601(now_secs);
    let unsigned = serde_json::json!({
        "key": key_to_json(&key),
        "address": address,
        "updated": updated,
        "signature": { "algorithm": ED25519, "signature": "" }
    });
    let canonical = canonicalize_for_sig(&unsigned);
    let sig = sk.sign(&canonical);
    Ok(Identity {
        key,
        address: address.to_string(),
        updated,
        signature: Signature {
            algorithm: ED25519.to_string(),
            signature: B64.encode(sig.to_bytes()),
        },
    })
}

pub fn key_from_json(v: &serde_json::Value) -> io::Result<Key> {
    let algorithm = v
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io_err("missing key algorithm"))?
        .to_string();
    let public_key = v
        .get("public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io_err("missing public_key"))?
        .to_string();
    Ok(Key { algorithm, public_key })
}

pub fn key_to_json(key: &Key) -> serde_json::Value {
    serde_json::json!({
        "algorithm": key.algorithm,
        "public_key": key.public_key,
    })
}

pub fn signature_from_json(v: &serde_json::Value) -> io::Result<Signature> {
    let algorithm = v
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io_err("missing signature algorithm"))?
        .to_string();
    let signature = v
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io_err("missing signature"))?
        .to_string();
    Ok(Signature { algorithm, signature })
}

pub fn signature_to_json(sig: &Signature) -> serde_json::Value {
    serde_json::json!({
        "algorithm": sig.algorithm,
        "signature": sig.signature,
    })
}

pub fn identity_from_json(v: &serde_json::Value) -> io::Result<Identity> {
    let key = key_from_json(v.get("key").ok_or_else(|| io_err("missing key field"))?)?;
    let address = v
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io_err("identity.json missing address"))?
        .to_string();
    let updated = v
        .get("updated")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let signature = signature_from_json(
        v.get("signature").ok_or_else(|| io_err("missing signature field"))?,
    )?;
    Ok(Identity { key, address, updated, signature })
}

pub fn identity_to_json(identity: &Identity) -> serde_json::Value {
    serde_json::json!({
        "key": key_to_json(&identity.key),
        "address": identity.address,
        "updated": identity.updated,
        "signature": signature_to_json(&identity.signature),
    })
}

pub fn read_identity(path: &Path) -> io::Result<Identity> {
    let content = fs::read_to_string(path)?;
    let v: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| io_err(&format!("identity.json parse: {}", e)))?;
    identity_from_json(&v)
}

pub fn write_identity(path: &Path, identity: &Identity) -> io::Result<()> {
    let pretty = serde_json::to_string_pretty(&identity_to_json(identity))
        .map_err(|e| io_err(&e.to_string()))?;
    fs::write(path, pretty)
}

pub fn read_signing_key(path: &Path) -> io::Result<SigningKey> {
    let key_b64 = fs::read_to_string(path)?;
    let decoded = B64
        .decode(key_b64.trim())
        .map_err(|e| io_err(&format!("identity.key decode: {}", e)))?;
    let seed: [u8; 32] = decoded
        .try_into()
        .map_err(|_| io_err("identity.key wrong length"))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(unix)]
pub fn write_signing_key(path: &Path, sk: &SigningKey) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(B64.encode(sk.to_bytes()).as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
pub fn write_signing_key(path: &Path, sk: &SigningKey) -> io::Result<()> {
    fs::write(path, B64.encode(sk.to_bytes()))
}

fn io_err(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature as DalekSig, Verifier};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let p = std::env::temp_dir().join(format!("ark_identity_test_{}_{}", std::process::id(), nanos));
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
    fn parse_address_accepts_valid() {
        let (name, host) = parse_address("alice@example.com:8080").unwrap();
        assert_eq!(name, "alice");
        assert_eq!(host, "example.com:8080");

        let (name, host) = parse_address("bob@127.0.0.1").unwrap();
        assert_eq!(name, "bob");
        assert_eq!(host, "127.0.0.1");
    }

    #[test]
    fn parse_address_rejects_invalid() {
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
        ];
        for b in bad {
            let err = parse_address(b).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{} should be InvalidInput", b);
        }
    }

    #[test]
    fn new_signed_identity_has_valid_signature() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let identity = new_signed_identity(&sk, "alice@example.com", 1_700_000_000).unwrap();
        assert_eq!(identity.address, "alice@example.com");
        assert_eq!(identity.key.algorithm, ED25519);
        assert_eq!(identity.signature.algorithm, ED25519);

        let doc = identity_to_json(&identity);
        let canonical = canonicalize_for_sig(&doc);
        let sig_bytes: [u8; 64] = B64.decode(&identity.signature.signature).unwrap().try_into().unwrap();
        let sig = DalekSig::from_bytes(&sig_bytes);
        assert!(sk.verifying_key().verify(&canonical, &sig).is_ok());
    }

    #[test]
    fn new_signed_identity_signature_detects_tampering() {
        let sk = SigningKey::from_bytes(&[43u8; 32]);
        let identity = new_signed_identity(&sk, "alice@example.com", 1_700_000_000).unwrap();
        let mut doc = identity_to_json(&identity);
        let sig_bytes: [u8; 64] = B64.decode(&identity.signature.signature).unwrap().try_into().unwrap();
        let sig = DalekSig::from_bytes(&sig_bytes);

        doc["address"] = serde_json::Value::String("mallory@example.com".to_string());
        let canonical = canonicalize_for_sig(&doc);
        assert!(sk.verifying_key().verify(&canonical, &sig).is_err());
    }

    #[test]
    fn identity_json_round_trip() {
        let sk = SigningKey::from_bytes(&[44u8; 32]);
        let identity = new_signed_identity(&sk, "alice@example.com", 1_700_000_000).unwrap();
        let doc = identity_to_json(&identity);
        let parsed = identity_from_json(&doc).unwrap();
        assert_eq!(parsed.address, identity.address);
        assert_eq!(parsed.updated, identity.updated);
        assert_eq!(parsed.key.algorithm, identity.key.algorithm);
        assert_eq!(parsed.key.public_key, identity.key.public_key);
        assert_eq!(parsed.signature.algorithm, identity.signature.algorithm);
        assert_eq!(parsed.signature.signature, identity.signature.signature);
    }

    #[test]
    fn read_write_identity_round_trip() {
        let td = TempDir::new();
        let sk = SigningKey::from_bytes(&[45u8; 32]);
        let identity = new_signed_identity(&sk, "alice@example.com", 1_700_000_000).unwrap();
        let path = td.0.join("identity.json");
        write_identity(&path, &identity).unwrap();
        let loaded = read_identity(&path).unwrap();
        assert_eq!(loaded.address, identity.address);
        assert_eq!(loaded.key.public_key, identity.key.public_key);
        assert_eq!(loaded.signature.signature, identity.signature.signature);
    }

    #[test]
    fn verifying_key_from_key_rejects_wrong_algorithm() {
        let key = Key { algorithm: "rsa".to_string(), public_key: B64.encode([0u8; 32]) };
        let err = verifying_key_from_key(&key).unwrap_err();
        assert!(err.to_string().contains("unsupported key algorithm"));
    }

    #[test]
    fn verifying_key_from_key_rejects_bad_base64() {
        let key = Key { algorithm: ED25519.to_string(), public_key: "!!!not-b64!!!".to_string() };
        assert!(verifying_key_from_key(&key).is_err());
    }

    #[test]
    fn verifying_key_from_key_rejects_wrong_length() {
        let key = Key { algorithm: ED25519.to_string(), public_key: B64.encode([1u8; 16]) };
        let err = verifying_key_from_key(&key).unwrap_err();
        assert!(err.to_string().contains("wrong length"));
    }

    #[test]
    fn read_write_signing_key_round_trip() {
        let td = TempDir::new();
        let sk = SigningKey::from_bytes(&[77u8; 32]);
        let path = td.0.join("identity.key");
        write_signing_key(&path, &sk).unwrap();
        let loaded = read_signing_key(&path).unwrap();
        assert_eq!(loaded.to_bytes(), sk.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn write_signing_key_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new();
        let sk = SigningKey::from_bytes(&[78u8; 32]);
        let path = td.0.join("identity.key");
        write_signing_key(&path, &sk).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
