use std::io;
use std::io::Read;

use super::encrypt_stream;

use crate::client::request;
use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, DEFAULT_HASH_ALGORITHM, create_secret_key};
use crate::http::check_response_code;
use crate::metadata::{apply_key_to_metadata, apply_permissions, create_metadata, has_metadata_attributes, read_local_metadata_attributes, read_metadata_attributes, resolve_key_from_members, sign_metadata, write_metadata_attributes, write_metadata_headers};
use crate::storage::{Body, is_dir, read, write_atomic_with_metadata};
use crate::timestamp;
use crate::types::{Context, Hash, LocalMetadata, Metadata, Permissions};
use crate::util::{resolve_client_url, sha256};

/// Upload the body of a local file (or create a directory) at `path`.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). The local file is read from the account root at
/// the path portion; for address form the address selects the upload
/// destination while the local file is still read from the account root.
///
/// Missing intermediate parent directories on `path` are created on the
/// server automatically. Writes are relayed to co-members.
pub fn put_content(ctx: &Context, path: &str) -> io::Result<()> {
    put(ctx, path, &Permissions::default(), None, false)
}

/// Change members and permissions on a file or directory at `path`.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`).
///
/// Adds or promotes each address in `permissions.owners`/`writers`/`readers`;
/// removes each address in `permissions.drops`. The literal `"public"` maps
/// to the wildcard address `*` (rejected for encrypted files). At least one
/// owner must remain.
///
/// Requires the file to exist locally and on the server. The caller must be
/// an owner. Writes are relayed to co-members.
pub fn put_permissions(ctx: &Context, path: &str, permissions: &Permissions) -> io::Result<()> {
    put(ctx, path, permissions, None, true)
}

/// Upload a file body (or create a directory) at `path`, with optional
/// permission changes and encryption control.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). The body is read from the account's own copy of
/// `path`, which must exist; a directory there uploads an empty-body
/// directory entry.
///
/// `permissions` applies member/permission changes to the metadata before
/// the upload — on the initial upload this seeds who else can read/write;
/// on subsequent uploads it grants or drops members. The literal `"public"`
/// maps to the wildcard address `*` (rejected for encrypted files). At least
/// one owner must remain.
///
/// `encryption_algorithm`: `None` reuses the local file's existing algorithm
/// (or defaults to AES-256-GCM); `Some("none")` uploads raw plaintext.
/// Directories reject any `encryption_algorithm`.
///
/// With `metadata_only = true`, the body is not uploaded; only the metadata
/// (including any member/permission changes) is sent to the server. Requires
/// the file to exist on the server. Rejects any `encryption_algorithm`.
///
/// The signed metadata is written back to the local copy as `user.ark.*`
/// xattrs, plus local metadata as `user.ark_local.*` xattrs.
///
/// Missing intermediate parent directories on `path` are created on the
/// server automatically. Writes are relayed to co-members.
pub fn put(ctx: &Context, path: &str, permissions: &Permissions, encryption_algorithm: Option<&str>, metadata_only: bool) -> io::Result<()> {
    let existing_metadata = match has_metadata_attributes(ctx, path)? {
        true => Some(read_metadata_attributes(ctx, path)?),
        false => None,
    };
    let existing_local_metadata = read_local_metadata_attributes(ctx, path)?;

    let is_dir = is_dir(ctx, path);

    let file_body;
    let mut body_reader;
    let body: Option<&mut dyn Read> = if is_dir || metadata_only {
        None
    } else {
        file_body = read(ctx, path)?;
        body_reader = file_body.as_slice();
        Some(&mut body_reader)
    };

    let (metadata, local_metadata) = put_stream(ctx, path, body, permissions, encryption_algorithm, existing_metadata, Some(existing_local_metadata), metadata_only)?;

    if is_dir {
        write_metadata_attributes(ctx, path, &metadata, Some(&local_metadata))?;
    } else {
        write_atomic_with_metadata(ctx, path, Body::CopyOf(path), &metadata, Some(&local_metadata))?;
    }

    Ok(())
}

/// Upload a body (or create a directory) at `path`, with optional permission
/// changes and encryption control. Returns the signed metadata pair.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). Reads the body from `body` (or produces a directory
/// PUT when `None`).
///
/// `permissions` applies member/permission changes to the metadata before
/// the upload — on the initial upload this seeds who else can read/write;
/// on subsequent uploads it grants or drops members. The literal `"public"`
/// maps to the wildcard address `*` (rejected for encrypted files). At least
/// one owner must remain.
///
/// `encryption_algorithm`: `None` reuses `existing_metadata`'s algorithm
/// (or defaults to AES-256-GCM); `Some("none")` uploads raw plaintext.
/// Directories reject any `encryption_algorithm`.
///
/// `existing_metadata` / `existing_local_metadata`: when present, update in
/// place rather than minting fresh metadata.
///
/// With `metadata_only = true`, `body` is ignored; only metadata is sent to
/// the server. Requires `existing_metadata`. Rejects any
/// `encryption_algorithm`.
///
/// Missing intermediate parent directories on `path` are created on the
/// server automatically. Writes are relayed to co-members.
pub fn put_stream(
    ctx: &Context,
    path: &str,
    body: Option<&mut dyn Read>,
    permissions: &Permissions,
    encryption_algorithm: Option<&str>,
    existing_metadata: Option<Metadata>,
    existing_local_metadata: Option<LocalMetadata>,
    metadata_only: bool,
) -> io::Result<(Metadata, LocalMetadata)> {
    let mut url = resolve_client_url(ctx, path)?;
    let query = if metadata_only { "relay=full&metadata" } else { "relay=full" };
    url.set_query(Some(query));

    let is_dir = body.is_none() && !metadata_only;

    if is_dir && encryption_algorithm.is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "--encryption-algorithm not supported for directories"));
    }
    if metadata_only && encryption_algorithm.is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "--encryption-algorithm not supported for metadata-only puts"));
    }

    let mut metadata = match existing_metadata {
        Some(mut m) => {
            if let Some(a) = encryption_algorithm {
                m.encryption_algorithm = Some(a.to_string());
            }
            m
        }
        None => {
            if metadata_only {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "metadata-only put requires existing metadata"));
            }
            create_metadata(&ctx.identity.address, Some(encryption_algorithm.unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM)))
        }
    };

    if !metadata.members.iter().any(|m| m.address == ctx.identity.address) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "no member entry for current account"));
    }

    if is_dir || encryption_algorithm == Some("none") {
        metadata.encryption_algorithm = None;
    }

    let existing_file_key = if metadata_only && metadata.encryption_algorithm.is_some() {
        resolve_key_from_members(ctx, &metadata.members)?
    } else {
        None
    };
    apply_permissions(ctx, &mut metadata, permissions, existing_file_key.as_deref())?;

    let mut local_metadata = existing_local_metadata.unwrap_or_default();

    let final_body = if is_dir || metadata_only {
        Vec::new()
    } else {
        let body_bytes = if let Some(r) = body {
            let mut buf = Vec::new();
            r.read_to_end(&mut buf)?;
            buf
        } else {
            Vec::new()
        };

        let skip_encrypt = metadata.encryption_algorithm.is_none();
        let already_encrypted = local_metadata.encrypted == Some(true);

        local_metadata.sync_body_hash = if !already_encrypted {
            Some(Hash { algorithm: DEFAULT_HASH_ALGORITHM.to_string(), value: sha256(&body_bytes) })
        } else {
            None
        };

        if already_encrypted || skip_encrypt {
            if skip_encrypt {
                for member in metadata.members.iter_mut() {
                    member.key = None;
                }
            }
            body_bytes
        } else {
            let encryption_algorithm = metadata.encryption_algorithm.as_deref().unwrap();
            let file_key = create_secret_key(encryption_algorithm)?;
            apply_key_to_metadata(ctx, &mut metadata, &file_key)?;
            let mut ciphertext = Vec::new();
            encrypt_stream(ctx, &metadata, &mut body_bytes.as_slice(), &mut ciphertext)?;
            local_metadata.encrypted = Some(false);
            ciphertext
        }
    };

    metadata.modified = timestamp::now();
    metadata.modified_by = ctx.identity.address.clone();

    let sign_body = if is_dir || metadata_only { None } else { Some(final_body.as_slice()) };
    sign_metadata(ctx.identity_key.as_ref().expect("client context missing identity_key"), &mut metadata, sign_body)?;

    local_metadata.sync_modified = Some(metadata.modified);

    let metadata_headers = write_metadata_headers(&metadata);
    let headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();

    let (response_code, _, response_body) = request(Some(ctx), "PUT", &url, &headers, &final_body)?;
    check_response_code(response_code, &response_body)?;

    Ok((metadata, local_metadata))
}

#[cfg(test)]
mod tests {
    use std::env::set_current_dir;
    use std::fs;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};

    use super::*;

    use crate::context::create_client_context;
    use crate::metadata::read_metadata_attributes;
    use crate::storage::{create_dir_all, to_fs_path, write};
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, decrypt_bytes, encrypt_bytes};
    use crate::identity::{create_identity, identity_cache_path, write_identity};
    use crate::metadata::verify_metadata;
    use crate::permissions::{drop, reader, writer};
    use crate::testing::fs::{account_context, in_test_dir, init_with_server, write_plain_test_file};
    use crate::testing::http::start_test_server;
    use crate::types::{Context, Identity, Key, Permission};

    fn cache_identity(ctx: &Context, identity: &Identity) {
        create_dir_all(ctx, "/.ark/identities").unwrap();
        write_identity(ctx, &identity_cache_path(&identity.address), identity).unwrap();
    }

    fn put_plain(ctx: &Context, dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        put(ctx, name, &Permissions::default(), Some("none"), false).unwrap();
        path
    }

    fn put_encrypted(ctx: &Context, dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        put(ctx, name, &Permissions::default(), None, false).unwrap();
        path
    }

    fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        decrypt_bytes(&Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: key.to_vec() }, ciphertext)
    }

    fn put_from_cwd(temp_dir: &Path, arg: &str, plaintext: &[u8], cwd_subpath: &str) -> PathBuf {
        let cwd = temp_dir.join(cwd_subpath);
        fs::create_dir_all(&cwd).unwrap();
        set_current_dir(&cwd).unwrap();
        let ctx = create_client_context().unwrap();

        let local_path = to_fs_path(&ctx, arg).unwrap();
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        write(&ctx, arg, plaintext).unwrap();

        put(&ctx, arg, &Permissions::default(), None, false).unwrap();
        local_path
    }

    fn unwrap_first_member_key(path: &Path, identity_seed: &[u8]) -> Vec<u8> {
        let (context, account_path) = account_context(path);
        let m = read_metadata_attributes(&context, &account_path).unwrap();
        let key = m.members[0].key.as_ref().expect("key set");
        decrypt_bytes(&Key { algorithm: key.algorithm.clone(), value: identity_seed.to_vec() }, &key.value).expect("unwrap")
    }

    #[test]
    fn put_encrypts_body_and_stores_meta_xattr() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            put_from_cwd(temp_dir, "notes.txt", b"plaintext", "");

            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let on_disk = fs::read(&server_path).unwrap();
            assert_ne!(on_disk, b"plaintext");

            let alg = xattr::get(&server_path, "user.ark.encryption_algorithm").unwrap();
            assert_eq!(alg.as_deref(), Some(DEFAULT_ENCRYPTION_ALGORITHM.as_bytes()));
            let file_key = unwrap_first_member_key(&server_path, &ctx.identity_key.as_ref().unwrap().value);
            let decrypted = aes_decrypt(&file_key, &on_disk).unwrap();
            assert_eq!(decrypted, b"plaintext");
        });
    }

    #[test]
    fn put_writes_metadata_back_to_input_file() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = put_from_cwd(temp_dir, "out.bin", b"hello", "");
            assert_eq!(
                xattr::get(&input, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(DEFAULT_ENCRYPTION_ALGORITHM.as_bytes())
            );
            let _file_key = unwrap_first_member_key(&input, &ctx.identity_key.as_ref().unwrap().value);
        });
    }

    #[test]
    fn put_rotates_filekey_over_existing_metadata() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = temp_dir.join("notes.txt");
            write_plain_test_file(&input, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"hello");
            let mut preset_meta = create_metadata(&ctx.identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            let preset_file_key = create_secret_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
            apply_key_to_metadata(&ctx, &mut preset_meta, &preset_file_key).unwrap();
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut preset_meta, Some(b"hello")).unwrap();
            write_metadata_attributes(&ctx, "/notes.txt", &preset_meta, None).unwrap();

            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();

            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let server_key = unwrap_first_member_key(&server_path, &ctx.identity_key.as_ref().unwrap().value);
            assert_ne!(server_key, preset_file_key.value);

            let ciphertext = fs::read(&server_path).unwrap();
            let plaintext = aes_decrypt(&server_key, &ciphertext).unwrap();
            assert_eq!(plaintext, b"hello");
        });
    }

    #[test]
    fn put_rotates_filekey_on_every_put() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let account_key = ctx.identity_key.as_ref().unwrap().value.clone();

            let input = temp_dir.join("notes.txt");
            fs::write(&input, b"v1").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();
            let key1 = unwrap_first_member_key(&input, &account_key);

            fs::write(&input, b"v2").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap();
            let key2 = unwrap_first_member_key(&input, &account_key);

            assert_ne!(key1, key2);

            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let ciphertext = fs::read(&server_path).unwrap();
            let plaintext = aes_decrypt(&key2, &ciphertext).unwrap();
            assert_eq!(plaintext, b"v2");
        });
    }

    #[test]
    fn put_creates_at_relative_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);

            put_from_cwd(temp_dir, "notes.txt", b"hello", "");

            assert!(temp_dir.join("ark/gyan/notes.txt").exists());
        });
    }

    #[test]
    fn put_overwrites_existing_file() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = temp_dir.join("x.txt");
            fs::write(&input, b"old").unwrap();
            put(&ctx, "x.txt", &Permissions::default(), None, false).unwrap();
            fs::write(&input, b"new plaintext").unwrap();
            put(&ctx, "x.txt", &Permissions::default(), None, false).unwrap();

            let on_disk = fs::read(temp_dir.join("ark/gyan/x.txt")).unwrap();
            assert_ne!(on_disk, b"old");
            assert_ne!(on_disk, b"new plaintext");
        });
    }

    #[test]
    fn put_from_subdir_uses_relative_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);
            let server_notes = temp_dir.join("ark/gyan/notes");
            fs::create_dir_all(&server_notes).unwrap();

            put_from_cwd(temp_dir, "todo.txt", b"buy milk", "notes");

            assert!(temp_dir.join("ark/gyan/notes/todo.txt").exists());
        });
    }

    #[test]
    fn put_absolute_url_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);

            put_from_cwd(temp_dir, "/sub/file.txt", b"absolute", "");

            assert!(temp_dir.join("ark/gyan/sub/file.txt").exists());
        });
    }

    #[test]
    fn put_via_explicit_address_form() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);

            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            put_from_cwd(temp_dir, &arg, b"via address", "");

            assert!(temp_dir.join("ark/gyan/explicit.txt").exists());
        });
    }

    #[test]
    fn put_sends_already_encrypted_body_unchanged() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let file_key = create_secret_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
            let ciphertext = encrypt_bytes(&file_key, b"hidden").unwrap().1;
            let input = temp_dir.join("file.bin");
            fs::write(&input, &ciphertext).unwrap();
            let mut m = create_metadata(&ctx.identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            apply_key_to_metadata(&ctx, &mut m, &file_key).unwrap();
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut m, Some(&ciphertext)).unwrap();
            let local = LocalMetadata { encrypted: Some(true), sync_body_hash: None, sync_modified: None };
            write_metadata_attributes(&ctx, "/file.bin", &m, Some(&local)).unwrap();

            put(&ctx, "file.bin", &Permissions::default(), None, false).unwrap();

            let server_path = temp_dir.join("ark/gyan/file.bin");
            let server_body = fs::read(&server_path).unwrap();
            assert_eq!(server_body, ciphertext, "server received raw input bytes");
            assert_eq!(
                xattr::get(&input, "user.ark_local.encrypted").unwrap().as_deref(),
                Some(b"true".as_slice())
            );
            let unwrapped = unwrap_first_member_key(&input, &ctx.identity_key.as_ref().unwrap().value);
            assert_eq!(aes_decrypt(&unwrapped, &server_body).unwrap(), b"hidden");
        });
    }

    #[test]
    fn put_marks_input_encrypted_false_after_fresh_encrypt() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);

            let input = put_from_cwd(temp_dir, "out.bin", b"plain", "");
            assert_eq!(
                xattr::get(&input, "user.ark_local.encrypted").unwrap().as_deref(),
                Some(b"false".as_slice())
            );
        });
    }

    #[test]
    fn put_encryption_none_sends_raw_body() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = temp_dir.join("raw.bin");
            fs::write(&input, b"plain bytes").unwrap();
            let mut m = create_metadata(&ctx.identity.address, None);
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut m, Some(b"plain bytes")).unwrap();
            write_metadata_attributes(&ctx, "/raw.bin", &m, None).unwrap();

            put(&ctx, "raw.bin", &Permissions::default(), None, false).unwrap();

            let server_path = temp_dir.join("ark/gyan/raw.bin");
            assert_eq!(fs::read(&server_path).unwrap(), b"plain bytes");
            assert_eq!(xattr::get(&server_path, "user.ark.encryption_algorithm").unwrap(), None);
            assert_eq!(xattr::get(&input, "user.ark.member_0_key_value").unwrap(), None);
        });
    }

    #[test]
    fn put_dir_input_creates_dir_with_metadata() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::create_dir_all(temp_dir.join("shared")).unwrap();
            put(&ctx, "shared", &Permissions::default(), None, false).unwrap();

            let dir = temp_dir.join("ark/gyan/shared");
            assert!(dir.is_dir());
            let (server_ctx, server_dir) = account_context(&dir);
            let meta = read_metadata_attributes(&server_ctx, &server_dir).unwrap();
            assert_eq!(meta.modified_by, address);
            assert_eq!(meta.encryption_algorithm, None);
            assert!(meta.members[0].key.is_none());
        });
    }

    #[test]
    fn put_dir_input_rejects_encryption_algorithm_no_body() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::create_dir_all(temp_dir.join("shared")).unwrap();
            let err = put(&ctx, "shared", &Permissions::default(), Some(DEFAULT_ENCRYPTION_ALGORITHM), false).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn put_encryption_none_arg_sends_raw_body() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = temp_dir.join("raw.bin");
            fs::write(&input, b"plain bytes").unwrap();
            put(&ctx, "raw.bin", &Permissions::default(), Some("none"), false).unwrap();

            let server_path = temp_dir.join("ark/gyan/raw.bin");
            assert_eq!(fs::read(&server_path).unwrap(), b"plain bytes");
            assert_eq!(xattr::get(&server_path, "user.ark.encryption_algorithm").unwrap(), None);
        });
    }

    #[test]
    fn put_missing_local_copy_errors() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let err = put(&ctx, "notes.txt", &Permissions::default(), None, false).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::NotFound);
        });
    }

    #[test]
    fn put_dir_input_rejects_encryption_algorithm() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            fs::create_dir_all(temp_dir.join("shared")).unwrap();
            let err = put(&ctx, "shared", &Permissions::default(), Some(DEFAULT_ENCRYPTION_ALGORITHM), false).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn put_missing_identity_errors() {
        in_test_dir("ark_put_test", |_temp_dir| {
            let err = create_client_context().err().expect("expected error");
            let msg = format!("{}", err);
            assert!(msg.contains("no .ark"), "msg was {}", msg);
        });
    }

    #[test]
    fn put_metadata_only_adds_reader() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            put_plain(&ctx, temp_dir, "notes.txt", b"hello");

            put(&ctx, "notes.txt", &reader("john@example.com"), None, true).unwrap();

            let m = read_metadata_attributes(&ctx, "notes.txt").unwrap();
            let john = m.members.iter().find(|m| m.address == "john@example.com").unwrap();
            assert_eq!(john.permission, Permission::Reader);
            assert!(m.members.iter().any(|m| m.address == address && m.permission == Permission::Owner));
        });
    }

    #[test]
    fn put_metadata_only_adds_public_reader_when_unencrypted() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            put_plain(&ctx, temp_dir, "public.txt", b"open");

            put(&ctx, "public.txt", &reader("public"), None, true).unwrap();

            let m = read_metadata_attributes(&ctx, "public.txt").unwrap();
            let pub_member = m.members.iter().find(|m| m.address == "*").unwrap();
            assert_eq!(pub_member.permission, Permission::Reader);
            assert!(pub_member.key.is_none());
        });
    }

    #[test]
    fn put_metadata_only_rejects_public_on_encrypted_file() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            put_encrypted(&ctx, temp_dir, "enc.bin", b"plaintext");

            let err = put(&ctx, "enc.bin", &reader("public"), None, true).unwrap_err();
            assert!(err.to_string().contains("public member to encrypted"), "msg was {}", err);
        });
    }

    #[test]
    fn put_metadata_only_wraps_key_for_new_member_on_encrypted_file() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let (bob_identity, bob_secret_key) = create_identity("bob@example.com", None).unwrap();
            cache_identity(&ctx, &bob_identity);

            put_encrypted(&ctx, temp_dir, "enc.bin", b"plaintext");

            let owner_wrapped = read_metadata_attributes(&ctx, "enc.bin").unwrap().members[0].key.clone().unwrap();
            let owner_secret = ctx.identity_key.clone().unwrap();
            let file_key = decrypt_bytes(
                &Key { algorithm: owner_wrapped.algorithm.clone(), value: owner_secret.value.clone() },
                &owner_wrapped.value,
            ).unwrap();

            put(&ctx, "enc.bin", &reader("bob@example.com"), None, true).unwrap();

            let m = read_metadata_attributes(&ctx, "enc.bin").unwrap();
            let bob = m.members.iter().find(|m| m.address == "bob@example.com").unwrap();
            assert_eq!(bob.permission, Permission::Reader);
            let bob_wrapped = bob.key.as_ref().expect("bob's wrapped key");
            let recovered = decrypt_bytes(
                &Key { algorithm: bob_wrapped.algorithm.clone(), value: bob_secret_key.value.clone() },
                &bob_wrapped.value,
            ).unwrap();
            assert_eq!(recovered, file_key, "bob unwraps to same file key");
        });
    }

    #[test]
    fn put_metadata_only_upgrades_existing_member_permission() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let (sam_identity, _sam_secret_key) = create_identity("sam@example.com", None).unwrap();
            cache_identity(&ctx, &sam_identity);

            let path = temp_dir.join("doc.txt");
            fs::write(&path, b"body").unwrap();
            put(&ctx, "doc.txt", &reader("sam@example.com"), Some("none"), false).unwrap();

            put(&ctx, "doc.txt", &writer("sam@example.com"), None, true).unwrap();

            let m = read_metadata_attributes(&ctx, "doc.txt").unwrap();
            let sam = m.members.iter().find(|m| m.address == "sam@example.com").unwrap();
            assert_eq!(sam.permission, Permission::Writer);
        });
    }

    #[test]
    fn put_metadata_only_drops_member() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let (sam_identity, _sam_secret_key) = create_identity("sam@example.com", None).unwrap();
            cache_identity(&ctx, &sam_identity);

            let path = temp_dir.join("doc.txt");
            fs::write(&path, b"body").unwrap();
            put(&ctx, "doc.txt", &reader("sam@example.com"), Some("none"), false).unwrap();

            put(&ctx, "doc.txt", &drop("sam@example.com"), None, true).unwrap();

            let m = read_metadata_attributes(&ctx, "doc.txt").unwrap();
            assert!(!m.members.iter().any(|m| m.address == "sam@example.com"));
        });
    }

    #[test]
    fn put_metadata_only_rejects_dropping_last_owner() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            put_plain(&ctx, temp_dir, "doc.txt", b"body");

            let err = put(&ctx, "doc.txt", &drop(&address), None, true).unwrap_err();
            assert!(err.to_string().contains("at least one owner"), "msg was {}", err);
        });
    }

    #[test]
    fn put_permissions_ark_absolute_path_resolves_local_input() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let path = temp_dir.join("notes.txt");
            fs::write(&path, b"hello").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            put_permissions(&ctx, "/notes.txt", &reader("john@example.com")).unwrap();

            let m = read_metadata_attributes(&ctx, "/notes.txt").unwrap();
            assert!(m.members.iter().any(|m| m.address == "john@example.com"));
        });
    }

    #[test]
    fn put_metadata_only_preserves_body_hash_signature() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let path = put_plain(&ctx, temp_dir, "doc.txt", b"body");

            put(&ctx, "doc.txt", &reader("john@example.com"), None, true).unwrap();

            let m = read_metadata_attributes(&ctx, "doc.txt").unwrap();
            let body = fs::read(&path).unwrap();
            verify_metadata(&ctx.identity.public_key, &m, Some(&body)).unwrap();
        });
    }
}
