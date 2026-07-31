use std::io;
use std::str::from_utf8;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::{Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::getrandom;
use hkdf::Hkdf;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    single_shot_open, single_shot_seal,
    Deserializable, Kem as HpkeKem, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};

use crate::types::{Identity, Key, Signature};
use crate::util::{io_err, sha256};

pub const DEFAULT_ENCRYPTION_ALGORITHM: &str = "aes-256-gcm";
pub const DEFAULT_HASH_ALGORITHM: &str = "sha-256";
pub const DEFAULT_PASSWORD_ALGORITHM: &str = "argon2id-ed25519";
pub const DEFAULT_SIGNING_ALGORITHM: &str = "ed25519";

pub const PASSWORD_VERIFIER_LEN: usize = 32;
pub const PASSWORD_SALT_LEN: usize = 16;
pub const PASSWORD_PUBKEY_LEN: usize = 32;

const HPKE_INFO: &[u8] = b"ark-hpke-v1";
const PASSWORD_AUTH_INFO: &[u8] = b"ark-auth-v1";
const PASSWORD_ED25519_INFO: &[u8] = b"ark-ed25519-v1";

pub fn create_secret_key(algorithm: &str) -> io::Result<Key> {
    match algorithm {
        DEFAULT_ENCRYPTION_ALGORITHM | DEFAULT_SIGNING_ALGORITHM => {
            let mut key = [0u8; 32];
            getrandom(&mut key)
                .map_err(|e| io_err(&e.to_string()))?;

            Ok(Key {
                algorithm: algorithm.to_string(),
                value: key.to_vec()
            })
        },
        _ => Err(io_err("unsupported algorithm"))
    }
}

pub fn restore_secret_key_from_password(identity: &Identity, password: &str) -> io::Result<Key> {
    match identity.public_key.algorithm.as_str() {
        DEFAULT_PASSWORD_ALGORITHM => {
            if identity.public_key.value.len() != PASSWORD_VERIFIER_LEN + PASSWORD_SALT_LEN + PASSWORD_PUBKEY_LEN {
                return Err(io_err("public key is wrong length"));
            }

            let verifier = &identity.public_key.value[..PASSWORD_VERIFIER_LEN];
            let salt = &identity.public_key.value[PASSWORD_VERIFIER_LEN..PASSWORD_VERIFIER_LEN + PASSWORD_SALT_LEN];
            let (expanded_verifier, _) = expand_argon2id_ed25519(password, salt)?;
            if expanded_verifier != verifier {
                return Err(io_err("password verifier mismatch"));
            }

            let mut value = Vec::with_capacity(PASSWORD_SALT_LEN + password.len());
            value.extend_from_slice(salt);
            value.extend_from_slice(password.as_bytes());

            Ok(Key {
                algorithm: DEFAULT_PASSWORD_ALGORITHM.to_string(),
                value,
            })
        },
        _ => Err(io_err("unsupported algorithm"))
    }
}

pub fn create_secret_key_from_password(algorithm: &str, password: &str) -> io::Result<Key> {
    match algorithm {
        DEFAULT_PASSWORD_ALGORITHM => {
            let mut salt = [0u8; PASSWORD_SALT_LEN];
            getrandom(&mut salt)
                .map_err(|e| io_err(&e.to_string()))?;

            let mut value = Vec::with_capacity(PASSWORD_SALT_LEN + password.len());
            value.extend_from_slice(&salt);
            value.extend_from_slice(password.as_bytes());

            Ok(Key {
                algorithm: algorithm.to_string(),
                value,
            })
        },
        _ => Err(io_err("unsupported algorithm"))
    }
}

pub fn to_public_key(secret_key: &Key) -> io::Result<Key> {
    match secret_key.algorithm.as_str() {
        DEFAULT_PASSWORD_ALGORITHM => {
            if secret_key.value.len() < PASSWORD_SALT_LEN {
                return Err(io_err("secret key is too short"));
            }

            let (salt, password) = secret_key.value.split_at(PASSWORD_SALT_LEN);
            let password_str = from_utf8(password)
                .map_err(|_| io_err("password not valid utf-8"))?;
            let (verifier, secret_key_ed25519) = expand_argon2id_ed25519(password_str, salt)?;

            let mut value = Vec::with_capacity(PASSWORD_VERIFIER_LEN + PASSWORD_SALT_LEN + PASSWORD_PUBKEY_LEN);
            value.extend_from_slice(&verifier);
            value.extend_from_slice(salt);
            value.extend_from_slice(&to_public_key(&secret_key_ed25519)?.value);

            Ok(Key {
                algorithm: DEFAULT_PASSWORD_ALGORITHM.to_string(),
                value,
            })
        },
        DEFAULT_SIGNING_ALGORITHM => {
            let secret_key_arr: [u8; 32] = secret_key.value.clone().try_into()
                .map_err(|_| io_err("ed25519 requires a 32 byte private key"))?;
            let secret_key_obj = SigningKey::from_bytes(&secret_key_arr);

            Ok(Key {
                algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(),
                value: secret_key_obj.verifying_key().to_bytes().to_vec()
            })
        },
        _ => Err(io_err("unsupported algorithm"))
    }
}

pub fn sign_bytes(secret_key: &Key, bytes: &[u8]) -> io::Result<Signature> {
    match secret_key.algorithm.as_str() {
        DEFAULT_PASSWORD_ALGORITHM => {
            let secret_key_ed25519 = derive_secret_ed25519_from_argon2id_ed25519(secret_key)?;
            sign_bytes(&secret_key_ed25519, bytes)
        },
        DEFAULT_SIGNING_ALGORITHM => {
            let secret_key_arr: [u8; 32] = secret_key.value.clone().try_into()
                .map_err(|_| io_err("ed25519 requires a 32 byte private key"))?;
            let secret_key_obj = SigningKey::from_bytes(&secret_key_arr);

            Ok(Signature {
                algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(),
                value: secret_key_obj.sign(bytes).to_bytes().to_vec()
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

// TODO: check why these diff combinations would occur, does it make sense?
pub fn verify_bytes(public_key: &Key, signature: &Signature, bytes: &[u8]) -> io::Result<()> {
    match public_key.algorithm.as_str() {
        DEFAULT_PASSWORD_ALGORITHM if signature.algorithm == DEFAULT_PASSWORD_ALGORITHM => {
            let ed25519_signature = Signature {
                algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(),
                value: signature.value.clone()
            };
            verify_bytes(public_key, &ed25519_signature, bytes)
        },
        DEFAULT_PASSWORD_ALGORITHM if signature.algorithm == DEFAULT_SIGNING_ALGORITHM => {
            let public_key_ed25519 = derive_public_ed25519_from_argon2id_ed25519(public_key)?;
            verify_bytes(&public_key_ed25519, signature, bytes)
        },
        DEFAULT_SIGNING_ALGORITHM if signature.algorithm == DEFAULT_SIGNING_ALGORITHM => {
            let public_key_arr: [u8; 32] = public_key.value.clone().try_into()
                .map_err(|_| io_err("ed25519 requires a 32 byte public key"))?;
            let public_key_obj = VerifyingKey::from_bytes(&public_key_arr)
                .map_err(|e| io_err(&e.to_string()))?;

            let signature_arr: [u8; 64] = signature.value.clone().try_into()
                .map_err(|_| io_err("ed25519 requires a 64 byte signature"))?;
            let signature_obj = ed25519_dalek::Signature::from_bytes(&signature_arr);

            public_key_obj.verify(bytes, &signature_obj)
                .map_err(|e| io_err(&e.to_string()))
        },
        _ => Err(io_err("unsupported signing algorithm"))
    }
}

pub fn verify_json(key: &Key, signature: &Signature, json: &serde_json::Value) -> io::Result<()> {
    let jcs = serde_jcs::to_vec(json)
        .map_err(|_| io_err("failed to canonicalize json"))?;

    verify_bytes(key, signature, &jcs)
}

// TODO: EncodedValue return type (with named alts e.g. Key)
pub fn encrypt_bytes(public_key: &Key, plaintext: &[u8]) -> io::Result<(String, Vec<u8>)> {
    match public_key.algorithm.as_str() {
        DEFAULT_ENCRYPTION_ALGORITHM => {
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

            Ok((DEFAULT_ENCRYPTION_ALGORITHM.to_string(), out))
        },
        DEFAULT_PASSWORD_ALGORITHM => {
            let public_key_ed25519 = derive_public_ed25519_from_argon2id_ed25519(public_key)?;
            encrypt_bytes(&public_key_ed25519, plaintext)
        },
        DEFAULT_SIGNING_ALGORITHM => {
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

pub fn decrypt_bytes(secret_key: &Key, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    match secret_key.algorithm.as_str() {
        DEFAULT_ENCRYPTION_ALGORITHM => {
            if ciphertext.len() < 12 {
                return Err(io_err("ciphertext is too short"));
            }

            let (nonce, ciphertext) = ciphertext.split_at(12);

            let secret_key_arr: [u8; 32] = secret_key.value.clone().try_into()
                .map_err(|_| io_err("aes-256-gcm requires a 32 byte secret key"))?;
            let cipher = Aes256Gcm::new(secret_key_arr.as_ref().into());

            cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| io_err(&format!("decrypt: {}", e)))
        },
        DEFAULT_PASSWORD_ALGORITHM => {
            let secret_key_ed25519 = derive_secret_ed25519_from_argon2id_ed25519(secret_key)?;
            let secret_key_hpke = Key {
                algorithm: "hpke-x25519-hkdf-sha256-aes256gcm".to_string(),
                value: secret_key_ed25519.value,
            };
            decrypt_bytes(&secret_key_hpke, ciphertext)
        },
        DEFAULT_SIGNING_ALGORITHM => {
            let secret_key_hpke = Key {
                algorithm: "hpke-x25519-hkdf-sha256-aes256gcm".to_string(),
                value: secret_key.value.clone(),
            };
            decrypt_bytes(&secret_key_hpke, ciphertext)
        },
        "hpke-x25519-hkdf-sha256-aes256gcm" => {
            if ciphertext.len() < 32 {
                return Err(io_err("ciphertext is too short"));
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

fn expand_argon2id_ed25519(password: &str, salt: &[u8]) -> io::Result<(Vec<u8>, Key)> {
    let argon = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, Argon2Params::default());

    let mut argon_out = [0u8; 32];
    argon.hash_password_into(password.as_bytes(), salt, &mut argon_out)
        .map_err(|e| io_err(&format!("argon2: {}", e)))?;

    let hkdf = Hkdf::<Sha256>::new(None, &argon_out);

    let mut auth_secret = [0u8; 32];
    hkdf.expand(PASSWORD_AUTH_INFO, &mut auth_secret)
        .map_err(|e| io_err(&format!("hkdf {}: {}", String::from_utf8_lossy(PASSWORD_AUTH_INFO), e)))?;

    let mut secret_key = [0u8; 32];
    hkdf.expand(PASSWORD_ED25519_INFO, &mut secret_key)
        .map_err(|e| io_err(&format!("hkdf {}: {}", String::from_utf8_lossy(PASSWORD_ED25519_INFO), e)))?;

    let verifier = sha256(&auth_secret);

    Ok((verifier, Key { algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(), value: secret_key.to_vec() }))
}

fn derive_public_ed25519_from_argon2id_ed25519(public_key: &Key) -> io::Result<Key> {
    let offset = PASSWORD_VERIFIER_LEN + PASSWORD_SALT_LEN;
    if public_key.value.len() < offset + PASSWORD_PUBKEY_LEN {
        return Err(io_err("public key is too short"));
    }

    Ok(Key {
        algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(),
        value: public_key.value[offset..offset + PASSWORD_PUBKEY_LEN].to_vec(),
    })
}

fn derive_secret_ed25519_from_argon2id_ed25519(secret_key: &Key) -> io::Result<Key> {
    if secret_key.value.len() < PASSWORD_SALT_LEN {
        return Err(io_err("secret key is too short"));
    }

    let (salt, password) = secret_key.value.split_at(PASSWORD_SALT_LEN);
    let password_str = from_utf8(password)
        .map_err(|_| io_err("password not valid utf-8"))?;
    let (_, secret_key_ed25519) = expand_argon2id_ed25519(password_str, salt)?;

    Ok(secret_key_ed25519)
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
            algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(),
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
            algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(),
            value: [0u8; 32].to_vec()
        };

        let err = decrypt_bytes(&key, b"short").unwrap_err();
        assert!(err.to_string().contains("is too short"));
    }

    #[test]
    fn decrypt_aes_256_gcm_wrong_key_errors() {
        let mut key = Key {
            algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(),
            value: [1u8; 32].to_vec()
        };

        let (_, ciphertext) = encrypt_bytes(&key, b"x").unwrap();
        key.value = [9u8; 32].to_vec();
        assert!(decrypt_bytes(&key, &ciphertext).is_err());
    }

    #[test]
    fn encrypt_decrypt_ed25519_round_trip() {
        let secret_seed = [7u8; 32].to_vec();
        let ed_secret = Key { algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(), value: secret_seed.clone() };
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
        assert!(err.to_string().contains("is too short"));
    }

    #[test]
    fn decrypt_ed25519_wrong_key_errors() {
        let ed_secret = Key { algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(), value: [8u8; 32].to_vec() };
        let public_key = to_public_key(&ed_secret).unwrap();

        let (wrap_alg, ciphertext) = encrypt_bytes(&public_key, b"x").unwrap();
        let wrong = Key { algorithm: wrap_alg, value: [9u8; 32].to_vec() };
        assert!(decrypt_bytes(&wrong, &ciphertext).is_err());
    }

    #[test]
    fn encrypt_ed25519_distinct() {
        let secret_key = Key {
            algorithm: DEFAULT_SIGNING_ALGORITHM.to_string(),
            value: [7u8; 32].to_vec()
        };
        let public_key = to_public_key(&secret_key).unwrap();
        let plaintext = b"secret payload";

        let (_, a) = encrypt_bytes(&public_key, plaintext).unwrap();
        let (_, b) = encrypt_bytes(&public_key, plaintext).unwrap();
        assert_ne!(a, b);
    }
}
