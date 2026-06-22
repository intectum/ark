use sha2::{Digest, Sha256};

pub const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn canonicalize_for_sig(doc: &serde_json::Value) -> Vec<u8> {
    let mut clone = doc.clone();
    if let Some(obj) = clone.as_object_mut() {
        obj.remove("signature");
    }
    serde_jcs::to_vec(&clone).expect("jcs serialize")
}

#[allow(dead_code)]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn unix_to_iso8601(secs: u64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(secs as i64).expect("valid unix ts");
    dt.format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 format")
}

pub fn is_valid_host_port(s: &str) -> bool {
    let (host, port_str) = match s.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (s, None),
    };
    if !is_valid_host(host) {
        return false;
    }
    if let Some(p) = port_str {
        match p.parse::<u16>() {
            Ok(n) if n > 0 => {}
            _ => return false,
        }
    }
    true
}

fn is_valid_host(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return is_valid_ipv4(s);
    }
    is_valid_hostname(s)
}

fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u8>().is_ok())
}

fn is_valid_hostname(s: &str) -> bool {
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

pub fn is_valid_account_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let allowed = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_');
    if !allowed {
        return false;
    }
    name.chars().any(|c| c != '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_omits_signature_and_sorts_keys() {
        let doc = serde_json::json!({
            "z": 1,
            "a": 2,
            "signature": { "algorithm": "ed25519", "signature": "abc" }
        });
        let bytes = canonicalize_for_sig(&doc);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(s, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn canonicalize_is_stable_regardless_of_key_order() {
        let a = serde_json::json!({"b":1,"a":2,"c":{"y":1,"x":2}});
        let b = serde_json::json!({"c":{"x":2,"y":1},"a":2,"b":1});
        assert_eq!(canonicalize_for_sig(&a), canonicalize_for_sig(&b));
    }

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn host_port_validation() {
        let valid = [
            "example.com",
            "localhost",
            "a.b.c.d",
            "sub.example.com",
            "example.com:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
            "10.0.0.1:443",
            "single",
            "x-y.z",
        ];
        for h in valid {
            assert!(is_valid_host_port(h), "{} should be valid", h);
        }
        let invalid = [
            "",
            ":",
            ":8080",
            "host:",
            "host:abc",
            "host:0",
            "host:99999",
            "host:-1",
            "-leading.com",
            "trailing-.com",
            "white space",
            "host..com",
            "127.0.0.256",
            "127.0.0",
            "127.0.0.1.2",
            "host:8080:9090",
        ];
        for h in invalid {
            assert!(!is_valid_host_port(h), "{} should be invalid", h);
        }
    }

    #[test]
    fn account_name_validation_matches_spec() {
        let valid = ["a", "gyan", "alice123", "user.name", "user-name", "user_name", "a.b-c_d.0", &"a".repeat(64)];
        for n in valid {
            assert!(is_valid_account_name(n), "{} should be valid", n);
        }
        let invalid: &[&str] = &[
            "",
            ".",
            "..",
            "...",
            "Alice",
            "ALICE",
            "user@host",
            "user name",
            "user/slash",
            "user\\back",
            "user+plus",
            "user#hash",
            "café",
            &"a".repeat(65),
        ];
        for n in invalid {
            assert!(!is_valid_account_name(n), "{} should be invalid", n);
        }
    }
}
