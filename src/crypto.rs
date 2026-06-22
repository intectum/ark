use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::util::io_err;

pub const ENCRYPTION_ALGORITHM: &str = "aes-256-gcm";

pub fn encrypt_body_with(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> std::io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| io_err(&format!("encrypt: {}", e)))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_body_with(ciphertext: &[u8], key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
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
        let nonce = [3u8; 12];
        let plaintext = b"secret payload";
        let ct = encrypt_body_with(plaintext, &key, &nonce).unwrap();
        assert_eq!(&ct[..12], &nonce);
        assert_ne!(&ct[12..], plaintext);
        let pt = decrypt_body_with(&ct, &key).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn decrypt_short_ciphertext_errors() {
        let err = decrypt_body_with(b"short", &[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn decrypt_wrong_key_errors() {
        let ct = encrypt_body_with(b"x", &[1u8; 32], &[2u8; 12]).unwrap();
        assert!(decrypt_body_with(&ct, &[9u8; 32]).is_err());
    }
}
