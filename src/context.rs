use std::env::current_dir;
use std::io;
use std::path::Path;

use crate::identity::{create_identity, read_identity_key, read_identity_raw, write_identity, write_identity_key};
use crate::metadata::{create_metadata, sign_metadata, write_metadata_attributes};
use crate::storage::{create_dir_all, exists_raw, read};
use crate::types::{Context, Key, Member, Permission};

/// Load the [`Context`] for the ark account containing the current
/// working directory. `identity_key` is set.
///
/// Errors with `NotFound` if the current directory is not inside an ark
/// account.
pub fn create_client_context() -> io::Result<Context> {
    let current = current_dir()?;
    let mut root = current.as_path();
    while !exists_raw(root, "/.ark") {
        root = root
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no .ark dir found"))?;
    }

    read_context(root)
}

pub fn create_server_context(server_root: &Path, host: &str) -> io::Result<Context> {
    let root = server_root.join("ark").join("ark");

    if !exists_raw(&root, "/.ark/identity.json") {
        let (identity, secret_key) = create_identity(&format!("ark@{}", host), None)?;

        let ctx = Context {
            root,
            identity: identity.clone(),
            identity_key: Some(secret_key.clone())
        };

        create_dir_all(&ctx, "/.ark")?;
        write_identity(&ctx, "/.ark/identity.json", &identity)?;
        write_identity_key(&ctx, "/.ark/identity.key", &secret_key.value)?;

        let body = read(&ctx, "/.ark/identity.json")?;
        let mut metadata = create_metadata(&identity.address, None);
        metadata.members.push(Member {
            address: "*".to_string(),
            permission: Permission::Reader,
            key: None,
        });
        sign_metadata(&secret_key, &mut metadata, Some(&body))?;

        write_metadata_attributes(&ctx, "/.ark/identity.json", &metadata)?;

        return Ok(ctx);
    }

    read_context(&root)
}

pub fn create_target_context(server_root: &Path, name: &str) -> io::Result<Context> {
    let root = server_root.join("ark").join(name);
    let identity = read_identity_raw(&root, "/.ark/identity.json")?;

    Ok(Context { root, identity, identity_key: None })
}

fn read_context(root: &Path) -> io::Result<Context> {
    let identity = read_identity_raw(root, "/.ark/identity.json")?;

    let mut ctx = Context {
        root: root.to_path_buf(),
        identity,
        identity_key: None
    };

    let key_bytes = read_identity_key(&ctx, "/.ark/identity.key")?;
    ctx.identity_key = Some(Key {
        algorithm: ctx.identity.public_key.algorithm.clone(),
        value: key_bytes
    });

    Ok(ctx)
}
