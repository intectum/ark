use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::client::init_local;
use crate::context::create_client_context;
use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_secret_key, encrypt_bytes};
use crate::identity::{parse_address, write_identity};
use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
use crate::types::{IdentityContext, Identity, Key, Metadata};

static CWD_LOCK: Mutex<()> = Mutex::new(());
pub const TEST_ADDRESS: &str = "test@example.com";

pub fn in_test_dir<R>(prefix: &str, f: impl FnOnce(&Path) -> R) -> R {
    let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = env::current_dir().unwrap_or_else(|_| env::temp_dir());

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = env::temp_dir().join(format!("{}_{}_{}", prefix, process::id(), nanos));
    fs::create_dir_all(&dir).unwrap();

    struct Cleanup(PathBuf, PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.0);
            let _ = fs::remove_dir_all(&self.1);
        }
    }
    let _cleanup = Cleanup(prev, dir.clone());

    env::set_current_dir(&dir).unwrap();
    f(&dir)
}

pub fn create_test_account(temp_dir: &Path, address: &str) -> (Identity, Key, PathBuf) {
    let (name, _, _) = parse_address(address).unwrap();
    let account_dir = temp_dir.join("ark").join(&name);
    fs::create_dir_all(&account_dir).unwrap();
    let (identity, secret_key) = init_local(&account_dir, address).unwrap();
    (identity, secret_key, account_dir)
}

pub fn init_with_server(temp_dir: &Path, address: &str) -> IdentityContext {
    let (identity, _) = init_local(temp_dir, address).unwrap();
    let (name, _, _) = parse_address(address).unwrap();
    let server_dot_ark = temp_dir.join("ark").join(&name).join(".ark");
    fs::create_dir_all(&server_dot_ark).unwrap();
    write_identity(&server_dot_ark.join("identity.json"), &identity).unwrap();
    create_client_context().unwrap()
}

pub fn create_plain_test_metadata(owner: &Identity, owner_key: &Key, body: &[u8]) -> Metadata {
    let mut metadata = create_metadata(&owner.address, None);
    sign_metadata(owner_key, &mut metadata, Some(body)).unwrap();
    metadata
}

pub fn write_plain_test_file(path: &Path, owner: &Identity, owner_key: &Key, body: &[u8]) {
    let metadata = create_plain_test_metadata(owner, owner_key, body);
    fs::write(path, body).unwrap();
    write_metadata_attributes(path, &metadata).unwrap();
}

pub fn create_encrypted_test_metadata(owner: &Identity, owner_key: &Key, plaintext: &[u8]) -> (Metadata, Vec<u8>) {
    let mut metadata = create_metadata(&owner.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
    let file_key = create_secret_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
    let (_, ciphertext) = encrypt_bytes(&file_key, plaintext).unwrap();
    let (wrap_alg, wrapped) = encrypt_bytes(&owner.public_key, &file_key.value).unwrap();
    metadata.members[0].key = Some(Key { algorithm: wrap_alg, value: wrapped });
    sign_metadata(owner_key, &mut metadata, Some(&ciphertext)).unwrap();
    (metadata, ciphertext)
}

pub fn write_encrypted_test_file(path: &Path, owner: &Identity, owner_key: &Key, plaintext: &[u8]) {
    let (metadata, ciphertext) = create_encrypted_test_metadata(owner, owner_key, plaintext);
    fs::write(path, ciphertext).unwrap();
    write_metadata_attributes(path, &metadata).unwrap();
}
