use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::util::io_err;

pub const DEFAULT_SIGNING_ALGORITHM: &str = "ed25519";
pub const DEFAULT_ENCRYPTION_ALGORITHM: &str = "aes-256-gcm";
pub const DEFAULT_HASH_ALGORITHM: &str = "sha-256";

// TODO: take Key, Signature, Hash as param and then delegate per alg, error is unsupported. No need
// to validate alg on read

pub fn to_public_key(key: &[u8]) -> Vec<u8> {
    let key_array: [u8; 32] = key.try_into().expect("32 byte key");
    SigningKey::from_bytes(&key_array).verifying_key().to_bytes().to_vec()
}

pub fn sign_bytes(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key_array: [u8; 32] = key.try_into().expect("32 byte key");
    SigningKey::from_bytes(&key_array).sign(&bytes).to_bytes().to_vec()
}

pub fn verify_bytes(public_key: &[u8], signature: &[u8], bytes: Vec<u8>) -> Result<(), SignatureError> {
    let public_key_array: [u8; 32] = public_key.try_into().expect("32 byte public key");
    let signature_array: [u8; 64] = signature.try_into().expect("64 byte signature");
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)?;
    verifying_key.verify(&bytes, &Signature::from_bytes(&signature_array))
}

pub fn sign_json(key: &[u8], json: &serde_json::Value) -> Vec<u8> {
    let jcs = serde_jcs::to_vec(json).expect("jcs serialize");
    sign_bytes(key, &jcs)
}

pub fn verify_json(public_key: &[u8], signature: &[u8], json: &serde_json::Value) -> Result<(), SignatureError> {
    let jcs = serde_jcs::to_vec(json).expect("jcs serialize");
    verify_bytes(public_key, signature, jcs)
}

pub fn encrypt_bytes(key: &[u8], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| io_err(&e.to_string()))?;

    let cipher = Aes256Gcm::new(key.into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| io_err(&format!("encrypt: {}", e)))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

pub fn decrypt_bytes(key: &[u8], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(io_err("ciphertext too short"));
    }

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&ciphertext[..12]);

    cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|e| io_err(&format!("decrypt: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [9u8; 32];
        let plaintext = b"secret payload";
        let ct = encrypt_bytes(&key, plaintext).unwrap();
        assert_ne!(&ct[12..], plaintext);
        let pt = decrypt_bytes(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn decrypt_short_ciphertext_errors() {
        let err = decrypt_bytes(&[0u8; 32], b"short").unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn decrypt_wrong_key_errors() {
        let ct = encrypt_bytes(&[1u8; 32], b"x").unwrap();
        assert!(decrypt_bytes(&[9u8; 32], &ct).is_err());
    }
}
