use std::fs;
use std::io;
use std::path::Path;

use crate::identity::{create_identity, read_identity, read_identity_key, write_identity, write_identity_key};
use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
use crate::types::{IdentityContext, Key, Member, Permission};
use crate::util::find_account_root;

/// Load the [`IdentityContext`] for the ark account containing the current
/// working directory. `identity_key` is set.
///
/// Errors with `NotFound` if the current directory is not inside an ark
/// account.
pub fn create_client_context() -> io::Result<IdentityContext> {
    let root = find_account_root()?;

    read_context(&root)
}

pub fn create_server_context(server_root: &Path, host: &str) -> io::Result<IdentityContext> {
    let root = server_root.join("ark").join("ark");
    let dot_ark_dir = root.join(".ark");
    let identity_path = dot_ark_dir.join("identity.json");
    let key_path = dot_ark_dir.join("identity.key");

    if !identity_path.exists() {
        let (identity, secret_key) = create_identity(&format!("ark@{}", host))?;
        fs::create_dir_all(&dot_ark_dir)?;
        write_identity(&identity_path, &identity)?;
        write_identity_key(&key_path, &secret_key.value)?;

        let body = fs::read(&identity_path)?;
        let mut metadata = create_metadata(&identity.address, None);
        metadata.members.push(Member {
            address: "*".to_string(),
            permission: Permission::Reader,
            key: None,
        });
        sign_metadata(&secret_key, &mut metadata, Some(&body))?;
        write_metadata_attributes(&identity_path, &metadata)?;
    }

    read_context(&root)
}

pub fn create_target_context(server_root: &Path, name: &str) -> io::Result<IdentityContext> {
    let root = server_root.join("ark").join(name);
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;

    Ok(IdentityContext { root, identity, identity_key: None })
}

fn read_context(root: &Path) -> io::Result<IdentityContext> {
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;
    let key_bytes = read_identity_key(&root.join(".ark").join("identity.key"))?;
    let identity_key = Some(Key {
        algorithm: identity.public_key.algorithm.clone(),
        value: key_bytes,
    });

    Ok(IdentityContext { root: root.to_path_buf(), identity, identity_key })
}
