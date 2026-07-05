use std::io;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use getrandom::getrandom;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    single_shot_open, single_shot_seal,
    Deserializable, Kem as HpkeKem, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

use crate::types::{Key, Signature};
use crate::util::io_err;

pub const DEFAULT_SIGNING_ALGORITHM: &str = "ed25519";
pub const DEFAULT_ENCRYPTION_ALGORITHM: &str = "aes-256-gcm";
pub const DEFAULT_HASH_ALGORITHM: &str = "sha-256";

const HPKE_INFO: &[u8] = b"ark-hpke-v1";

pub fn create_key(algorithm: &str) -> std::io::Result<Key> {
    let mut key = [0u8; 32];
    getrandom(&mut key)
        .map_err(|e| io_err(&e.to_string()))?;

    Ok(Key {
        algorithm: algorithm.to_string(),
        value: key.to_vec()
    })
}

pub fn to_public_key(secret_key: &Key) -> io::Result<Key> {
    match secret_key.algorithm.as_str() {
        "ed25519" => {
            let secret_key_arr: [u8; 32] = secret_key.value.clone().try_into()
                .map_err(|_| io_err("ed25519 requires a 32 byte private key"))?;
            let secret_key_obj = SigningKey::from_bytes(&secret_key_arr);

            Ok(Key {
                algorithm: "ed25519".to_string(),
                value: secret_key_obj.verifying_key().to_bytes().to_vec()
            })
        },
        _ => Err(io_err("unsupported algorithm"))
    }
}

pub fn sign_bytes(secret_key: &Key, bytes: &[u8]) -> io::Result<Signature> {
    match secret_key.algorithm.as_str() {
        "ed25519" => {
            let secret_key_arr: [u8; 32] = secret_key.value.clone().try_into()
                .map_err(|_| io_err("ed25519 requires a 32 byte private key"))?;
            let secret_key_obj = SigningKey::from_bytes(&secret_key_arr);

            Ok(Signature {
                algorithm: "ed25519".to_string(),
                value: secret_key_obj.sign(&bytes).to_bytes().to_vec()
            })
        },
        _ => Err(io_err("unsupported signing algorithm"))
    }
}

pub fn sign_json(secret_key: &Key, json: &serde_json::Value) -> io::Result<Signature> {
    let jcs = serde_jcs::to_vec(json)
        .map_err(|_| io_err("failed to canonicalize json"))?;

    sign_bytes(secret_key, &jcs)
}

pub fn verify_bytes(public_key: &Key, signature: &Signature, bytes: Vec<u8>) -> io::Result<()> {
    match public_key.algorithm.as_str() {
        "ed25519" if signature.algorithm == "ed25519" => {
            let public_key_arr: [u8; 32] = public_key.value.clone().try_into()
                .map_err(|_| io_err("ed25519 requires a 32 byte public key"))?;
            let public_key_obj = VerifyingKey::from_bytes(&public_key_arr)
                .map_err(|e| io_err(&e.to_string()))?;

            let signature_arr: [u8; 64] = signature.value.clone().try_into()
                .map_err(|_| io_err("ed25519 requires a 64 byte signature"))?;
            let signature_obj = ed25519_dalek::Signature::from_bytes(&signature_arr);

            public_key_obj.verify(&bytes, &signature_obj)
                .map_err(|e| io_err(&e.to_string()))
        },
        _ => Err(io_err("unsupported signature algorithm"))
    }
}

pub fn verify_json(key: &Key, signature: &Signature, json: &serde_json::Value) -> io::Result<()> {
    let jcs = serde_jcs::to_vec(json)
        .map_err(|_| io_err("failed to canonicalize json"))?;

    verify_bytes(key, signature, jcs)
}

// TODO: EncodedValue return type (with named alts e.g. Key)
pub fn encrypt_bytes(public_key: &Key, plaintext: &[u8]) -> io::Result<(String, Vec<u8>)> {
    match public_key.algorithm.as_str() {
        "aes-256-gcm" => {
            let mut nonce = [0u8; 12];
            getrandom::getrandom(&mut nonce).map_err(|e| io_err(&e.to_string()))?;

            let public_key_arr: [u8; 32] = public_key.value.clone().try_into()
                .map_err(|_| io_err("aes-256-gcm requires a 32 byte key"))?;
            let cipher = Aes256Gcm::new(public_key_arr.as_ref().into());
            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce), plaintext)
                .map_err(|e| io_err(&format!("encrypt: {}", e)))?;

            let mut out = Vec::with_capacity(12 + ciphertext.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);

            Ok(("aes-256-gcm".to_string(), out))
        },
        "ed25519" => {
            let public_key_x25519 = derive_public_x25519_from_ed25519(public_key)?;
            let public_key_obj = <X25519HkdfSha256 as HpkeKem>::PublicKey::from_bytes(&public_key_x25519.value)
                .map_err(|e| io_err(&format!("hpke pubkey: {}", e)))?;

            let (encapped_key, ciphertext) = single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &public_key_obj,
                HPKE_INFO,
                plaintext,
                b"",
                &mut OsRng,
            ).map_err(|e| io_err(&format!("hpke seal: {}", e)))?;

            let mut out = Vec::with_capacity(encapped_key.to_bytes().len() + ciphertext.len());
            out.extend_from_slice(encapped_key.to_bytes().as_slice());
            out.extend_from_slice(&ciphertext);

            Ok(("hpke-x25519-hkdf-sha256-aes256gcm".to_string(), out))
        },
        _ => Err(io_err("unsupported encryption algorithm"))
    }
}

pub fn decrypt_bytes(secret_key: &Key, ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
    match secret_key.algorithm.as_str() {
        "aes-256-gcm" => {
            if ciphertext.len() < 12 {
                return Err(io_err("ciphertext too short"));
            }

            let (nonce, ciphertext) = ciphertext.split_at(12);

            let secret_key_arr: [u8; 32] = secret_key.value.clone().try_into()
                .map_err(|_| io_err("aes-256-gcm requires a 32 byte secret key"))?;
            let cipher = Aes256Gcm::new(secret_key_arr.as_ref().into());

            cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| io_err(&format!("decrypt: {}", e)))
        },
        "hpke-x25519-hkdf-sha256-aes256gcm" => {
            if ciphertext.len() < 32 {
                return Err(io_err("ciphertext too short"));
            }

            let (encapped_key, ciphertext) = ciphertext.split_at(32);

            let secret_key_x25519 = derive_secret_x25519_from_ed25519(secret_key);
            let secret_key_obj = <X25519HkdfSha256 as HpkeKem>::PrivateKey::from_bytes(&secret_key_x25519.value)
                .map_err(|e| io_err(&format!("hpke privkey: {}", e)))?;
            let encapped_key_obj = <X25519HkdfSha256 as HpkeKem>::EncappedKey::from_bytes(encapped_key)
                .map_err(|e| io_err(&format!("hpke encapped: {}", e)))?;

            single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &secret_key_obj,
                &encapped_key_obj,
                HPKE_INFO,
                ciphertext,
                b"",
            ).map_err(|e| io_err(&format!("hpke open: {}", e)))
        },
        _ => Err(io_err("unsupported encryption algorithm"))
    }
}

pub fn derive_public_x25519_from_ed25519(public_key: &Key) -> io::Result<Key> {
    let public_key_arr: [u8; 32] = public_key.value.clone().try_into()
        .map_err(|_| io_err("ed25519 requires a 32 byte public key"))?;
    let public_key_point = CompressedEdwardsY(public_key_arr)
        .decompress()
        .ok_or_else(|| io_err("ed25519 public key is not a valid point"))?;

    Ok(Key {
        algorithm: "x25519".to_string(),
        value: public_key_point.to_montgomery().to_bytes().to_vec()
    })
}

fn derive_secret_x25519_from_ed25519(secret_key: &Key) -> Key {
    let digest = Sha512::digest(&secret_key.value);
    let mut secret_key_x25519 = [0u8; 32];
    secret_key_x25519.copy_from_slice(&digest[..32]);
    secret_key_x25519[0] &= 248;
    secret_key_x25519[31] &= 127;
    secret_key_x25519[31] |= 64;

    Key {
        algorithm: "x25519".to_string(),
        value: secret_key_x25519.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_aes_256_gcm_round_trip() {
        let key = Key {
            algorithm: "aes-256-gcm".to_string(),
            value: [9u8; 32].to_vec()
        };
        let plaintext = b"secret payload";

        let (_, ciphertext) = encrypt_bytes(&key, plaintext).unwrap();
        assert_ne!(&ciphertext[12..], plaintext);

        let decrypted_plaintext = decrypt_bytes(&key, &ciphertext).unwrap();
        assert_eq!(decrypted_plaintext, plaintext);
    }

    #[test]
    fn decrypt_aes_256_gcm_short_ciphertext_errors() {
        let key = Key {
            algorithm: "aes-256-gcm".to_string(),
            value: [0u8; 32].to_vec()
        };

        let err = decrypt_bytes(&key, b"short").unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn decrypt_aes_256_gcm_wrong_key_errors() {
        let mut key = Key {
            algorithm: "aes-256-gcm".to_string(),
            value: [1u8; 32].to_vec()
        };

        let (_, ciphertext) = encrypt_bytes(&key, b"x").unwrap();
        key.value = [9u8; 32].to_vec();
        assert!(decrypt_bytes(&key, &ciphertext).is_err());
    }

    #[test]
    fn encrypt_decrypt_ed25519_round_trip() {
        let secret_seed = [7u8; 32].to_vec();
        let ed_secret = Key { algorithm: "ed25519".to_string(), value: secret_seed.clone() };
        let public_key = to_public_key(&ed_secret).unwrap();
        let plaintext = b"secret payload";

        let (wrap_alg, ciphertext) = encrypt_bytes(&public_key, plaintext).unwrap();
        assert_ne!(&ciphertext[32..], plaintext);

        let decrypt_key = Key { algorithm: wrap_alg, value: secret_seed };
        let decrypted_plaintext = decrypt_bytes(&decrypt_key, &ciphertext).unwrap();
        assert_eq!(decrypted_plaintext, plaintext);
    }

    #[test]
    fn decrypt_ed25519_short_ciphertext_errors() {
        let key = Key {
            algorithm: "hpke-x25519-hkdf-sha256-aes256gcm".to_string(),
            value: [0u8; 32].to_vec()
        };

        let err = decrypt_bytes(&key, b"short").unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn decrypt_ed25519_wrong_key_errors() {
        let ed_secret = Key { algorithm: "ed25519".to_string(), value: [8u8; 32].to_vec() };
        let public_key = to_public_key(&ed_secret).unwrap();

        let (wrap_alg, ciphertext) = encrypt_bytes(&public_key, b"x").unwrap();
        let wrong = Key { algorithm: wrap_alg, value: [9u8; 32].to_vec() };
        assert!(decrypt_bytes(&wrong, &ciphertext).is_err());
    }

    #[test]
    fn encrypt_ed25519_distinct() {
        let secret_key = Key {
            algorithm: "ed25519".to_string(),
            value: [7u8; 32].to_vec()
        };
        let public_key = to_public_key(&secret_key).unwrap();
        let plaintext = b"secret payload";

        let (_, a) = encrypt_bytes(&public_key, plaintext).unwrap();
        let (_, b) = encrypt_bytes(&public_key, plaintext).unwrap();
        assert_ne!(a, b);
    }
}
