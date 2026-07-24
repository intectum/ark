use std::fs;
use std::io;
use std::io::Read;
use std::path::PathBuf;

use super::encrypt::encrypt as encrypt_body;
use crate::client::request;
use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, DEFAULT_HASH_ALGORITHM, create_secret_key};
use crate::types::{Hash, IdentityContext, LocalMetadata, Metadata};
use crate::metadata::{apply_key_to_metadata, create_metadata, get_member, has_metadata_attributes, read_local_metadata_attributes, read_metadata_attributes, sign_metadata, write_local_metadata_attributes, write_metadata_attributes, write_metadata_headers};
use crate::util::{io_err, io_invalid_input, now_iso, resolve_client_url, sha256};

/// Upload a body (or create a directory) at `path`.
///
/// - `body = None` produces a directory PUT (empty body).
/// - `encryption_algorithm`: `None` reuses the existing metadata's algorithm
///   (or defaults to AES-256-GCM). `Some("none")` uploads raw plaintext.
///   Directories reject any algorithm.
/// - `existing_metadata` / `existing_local`: when present, update in place
///   rather than minting a new [`Metadata`]. Used by [`put_io`] when the input
///   file already has ark xattrs.
///
/// A fresh file key is generated on every encrypted put and wrapped for every
/// member. If `existing_local.encrypted == Some(true)`, the body is uploaded
/// as-is without re-encryption. Writes are relayed to co-members.
pub fn put(
    ctx: &IdentityContext,
    path: &str,
    body: Option<&mut dyn Read>,
    encryption_algorithm: Option<&str>,
    existing_metadata: Option<Metadata>,
    existing_local_metadata: Option<LocalMetadata>,
) -> io::Result<(Metadata, LocalMetadata)> {
    let url = resolve_client_url(ctx, path)?;

    let is_dir = body.is_none();

    if is_dir && encryption_algorithm.is_some() {
        return Err(io_invalid_input("--encryption-algorithm not supported for directories"));
    }

    let body_bytes = if let Some(r) = body {
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)?;
        buf
    } else {
        Vec::new()
    };

    let mut metadata = match existing_metadata {
        Some(mut m) => {
            if let Some(a) = encryption_algorithm {
                m.encryption_algorithm = Some(a.to_string());
            }
            m
        }
        None => create_metadata(&ctx.identity.address, Some(encryption_algorithm.unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM))),
    };

    if get_member(&metadata.members, &ctx.identity.address).is_none() {
        return Err(io_err("no member entry for current account"));
    }

    if is_dir || encryption_algorithm == Some("none") {
        metadata.encryption_algorithm = None;
    }

    let mut local_metadata = existing_local_metadata.unwrap_or_default();

    let skip_encrypt = metadata.encryption_algorithm.is_none();
    let already_encrypted = local_metadata.encrypted == Some(true);

    local_metadata.sync_body_hash = if !is_dir && !already_encrypted {
        Some(Hash { algorithm: DEFAULT_HASH_ALGORITHM.to_string(), value: sha256(&body_bytes) })
    } else {
        None
    };

    let final_body = if already_encrypted || skip_encrypt {
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
        encrypt_body(ctx, &metadata, &mut body_bytes.as_slice(), &mut ciphertext)?;
        local_metadata.encrypted = Some(false);
        ciphertext
    };

    metadata.modified = now_iso();
    metadata.modified_by = ctx.identity.address.clone();

    let sign_body = if is_dir { None } else { Some(final_body.as_slice()) };
    sign_metadata(ctx.identity_key.as_ref().expect("client context missing identity_key"), &mut metadata, sign_body)?;

    local_metadata.sync_modified = Some(metadata.modified.clone());

    let metadata_headers = write_metadata_headers(&metadata);
    let mut headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    headers.push(("X-Ark-Relay", "full"));

    let (response_code, _, response_body) = request(Some(ctx), "PUT", &url, &headers, &final_body)?;
    if response_code != 201 && response_code != 204 {
        return Err(io_err(&format!("HTTP {}: {}", response_code, String::from_utf8_lossy(&response_body))));
    }

    Ok((metadata, local_metadata))
}

/// CLI-shaped [`put`]. Reads the body from `input` (or stdin when `None`). If
/// the input file already has ark metadata, it is reused for the upload. On
/// success, the updated metadata is written back to the input file.
pub fn put_io(ctx: &IdentityContext, path: &str, input: Option<&str>, encryption_algorithm: Option<&str>) -> io::Result<()> {
    let input_path: Option<PathBuf> = input.map(PathBuf::from);
    if let Some(i) = input_path.as_deref() {
        if !fs::exists(i)? {
            return Err(io_invalid_input("input does not exist"));
        }
    }

    let is_dir = input_path.as_deref().map(|p| p.is_dir()).unwrap_or(false);

    let existing_metadata = match input_path.as_deref() {
        Some(p) if has_metadata_attributes(p)? => Some(read_metadata_attributes(p)?),
        _ => None,
    };
    let existing_local_metadata = match input_path.as_deref() {
        Some(p) => Some(read_local_metadata_attributes(p)?),
        None => None,
    };

    let (metadata, local_metadata) = if is_dir {
        put(ctx, path, None, encryption_algorithm, existing_metadata, existing_local_metadata)?
    } else if let Some(p) = input_path.as_deref() {
        let mut f = fs::File::open(p)?;
        put(ctx, path, Some(&mut f), encryption_algorithm, existing_metadata, existing_local_metadata)?
    } else {
        let stdin = io::stdin();
        let mut lock = stdin.lock();
        put(ctx, path, Some(&mut lock), encryption_algorithm, existing_metadata, existing_local_metadata)?
    };

    if let Some(i) = input_path.as_deref() {
        write_metadata_attributes(i, &metadata)?;
        write_local_metadata_attributes(i, &local_metadata)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, decrypt_bytes, encrypt_bytes};
    use crate::context::create_client_context;
    use crate::server::start_test_server;
    use crate::types::Key;
    use crate::util::test::{in_test_dir, init_with_server, write_plain_test_file};

    fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        decrypt_bytes(&Key { algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(), value: key.to_vec() }, ciphertext)
    }

    fn put_via_io(temp_dir: &Path, arg: &str, plaintext: &[u8], cwd_subpath: &str) -> PathBuf {
        let input = temp_dir.join("input.bin");
        fs::write(&input, plaintext).unwrap();
        let cwd = temp_dir.join(cwd_subpath);
        fs::create_dir_all(&cwd).unwrap();
        std::env::set_current_dir(&cwd).unwrap();
        let ctx = create_client_context().unwrap();
        put_io(&ctx, arg, Some(input.to_str().unwrap()), None).unwrap();
        input
    }

    fn unwrap_first_member_key(path: &Path, identity_seed: &[u8]) -> Vec<u8> {
        let m = read_metadata_attributes(path).unwrap();
        let key = m.members[0].key.as_ref().expect("key set");
        decrypt_bytes(&Key { algorithm: key.algorithm.clone(), value: identity_seed.to_vec() }, &key.value).expect("unwrap")
    }

    #[test]
    fn put_io_encrypts_body_and_stores_meta_xattr() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            put_via_io(temp_dir, "notes.txt", b"plaintext", "");

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
    fn put_io_writes_metadata_back_to_input_file() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = put_via_io(temp_dir, "out.bin", b"hello", "");
            assert_eq!(
                xattr::get(&input, "user.ark.encryption_algorithm").unwrap().as_deref(),
                Some(DEFAULT_ENCRYPTION_ALGORITHM.as_bytes())
            );
            let _file_key = unwrap_first_member_key(&input, &ctx.identity_key.as_ref().unwrap().value);
        });
    }

    #[test]
    fn put_io_rotates_filekey_over_existing_metadata() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = temp_dir.join("input.bin");
            write_plain_test_file(&input, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"hello");
            let mut preset_meta = create_metadata(&ctx.identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            let preset_file_key = create_secret_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
            apply_key_to_metadata(&ctx, &mut preset_meta, &preset_file_key).unwrap();
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut preset_meta, Some(b"hello")).unwrap();
            write_metadata_attributes(&input, &preset_meta).unwrap();

            put_io(&ctx, "notes.txt", Some(input.to_str().unwrap()), None).unwrap();

            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let server_key = unwrap_first_member_key(&server_path, &ctx.identity_key.as_ref().unwrap().value);
            assert_ne!(server_key, preset_file_key.value);

            let ciphertext = fs::read(&server_path).unwrap();
            let plaintext = aes_decrypt(&server_key, &ciphertext).unwrap();
            assert_eq!(plaintext, b"hello");
        });
    }

    #[test]
    fn put_io_rotates_filekey_on_every_put() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let account_key = ctx.identity_key.as_ref().unwrap().value.clone();

            let input = temp_dir.join("input.bin");
            fs::write(&input, b"v1").unwrap();
            put_io(&ctx, "notes.txt", Some(input.to_str().unwrap()), None).unwrap();
            let key1 = unwrap_first_member_key(&input, &account_key);

            fs::write(&input, b"v2").unwrap();
            put_io(&ctx, "notes.txt", Some(input.to_str().unwrap()), None).unwrap();
            let key2 = unwrap_first_member_key(&input, &account_key);

            assert_ne!(key1, key2);

            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let ciphertext = fs::read(&server_path).unwrap();
            let plaintext = aes_decrypt(&key2, &ciphertext).unwrap();
            assert_eq!(plaintext, b"v2");
        });
    }

    #[test]
    fn put_io_creates_at_relative_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);

            put_via_io(temp_dir, "notes.txt", b"hello", "");

            assert!(temp_dir.join("ark/gyan/notes.txt").exists());
        });
    }

    #[test]
    fn put_io_overwrites_existing_file() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = temp_dir.join("input.bin");
            fs::write(&input, b"old").unwrap();
            put_io(&ctx, "x.txt", Some(input.to_str().unwrap()), None).unwrap();
            fs::write(&input, b"new plaintext").unwrap();
            put_io(&ctx, "x.txt", Some(input.to_str().unwrap()), None).unwrap();

            let on_disk = fs::read(temp_dir.join("ark/gyan/x.txt")).unwrap();
            assert_ne!(on_disk, b"old");
            assert_ne!(on_disk, b"new plaintext");
        });
    }

    #[test]
    fn put_io_from_subdir_uses_relative_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);
            let server_notes = temp_dir.join("ark/gyan/notes");
            fs::create_dir_all(&server_notes).unwrap();

            put_via_io(temp_dir, "todo.txt", b"buy milk", "notes");

            assert!(temp_dir.join("ark/gyan/notes/todo.txt").exists());
        });
    }

    #[test]
    fn put_io_absolute_url_path() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);

            put_via_io(temp_dir, "/sub/file.txt", b"absolute", "");

            assert!(temp_dir.join("ark/gyan/sub/file.txt").exists());
        });
    }

    #[test]
    fn put_io_via_explicit_address_form() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);

            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            put_via_io(temp_dir, &arg, b"via address", "");

            assert!(temp_dir.join("ark/gyan/explicit.txt").exists());
        });
    }

    #[test]
    fn put_io_sends_already_encrypted_body_unchanged() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let file_key = create_secret_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
            let ciphertext = encrypt_bytes(&file_key, b"hidden").unwrap().1;
            let input = temp_dir.join("input.bin");
            fs::write(&input, &ciphertext).unwrap();
            let mut m = create_metadata(&ctx.identity.address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            apply_key_to_metadata(&ctx, &mut m, &file_key).unwrap();
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut m, Some(&ciphertext)).unwrap();
            write_metadata_attributes(&input, &m).unwrap();
            write_local_metadata_attributes(&input, &LocalMetadata { encrypted: Some(true), sync_body_hash: None, sync_modified: None }).unwrap();

            put_io(&ctx, "file.bin", Some(input.to_str().unwrap()), None).unwrap();

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
    fn put_io_marks_input_encrypted_false_after_fresh_encrypt() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            init_with_server(temp_dir, &address);

            let input = put_via_io(temp_dir, "out.bin", b"plain", "");
            assert_eq!(
                xattr::get(&input, "user.ark_local.encrypted").unwrap().as_deref(),
                Some(b"false".as_slice())
            );
        });
    }

    #[test]
    fn put_io_encryption_none_sends_raw_body() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = temp_dir.join("input.bin");
            fs::write(&input, b"plain bytes").unwrap();
            let mut m = create_metadata(&ctx.identity.address, None);
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut m, Some(b"plain bytes")).unwrap();
            write_metadata_attributes(&input, &m).unwrap();

            put_io(&ctx, "raw.bin", Some(input.to_str().unwrap()), None).unwrap();

            let server_path = temp_dir.join("ark/gyan/raw.bin");
            assert_eq!(fs::read(&server_path).unwrap(), b"plain bytes");
            assert_eq!(xattr::get(&server_path, "user.ark.encryption_algorithm").unwrap(), None);
            assert_eq!(xattr::get(&input, "user.ark.member_0_key_value").unwrap(), None);
        });
    }

    #[test]
    fn put_io_dir_input_creates_dir_with_metadata() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input_dir = temp_dir.join("shared_input");
            fs::create_dir_all(&input_dir).unwrap();
            put_io(&ctx, "shared", Some(input_dir.to_str().unwrap()), None).unwrap();

            let dir = temp_dir.join("ark/gyan/shared");
            assert!(dir.is_dir());
            let meta = read_metadata_attributes(&dir).unwrap();
            assert_eq!(meta.modified_by, address);
            assert_eq!(meta.encryption_algorithm, None);
            assert!(meta.members[0].key.is_none());
        });
    }

    #[test]
    fn put_io_dir_input_rejects_encryption_algorithm_no_body() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input_dir = temp_dir.join("shared_input");
            fs::create_dir_all(&input_dir).unwrap();
            let err = put_io(&ctx, "shared", Some(input_dir.to_str().unwrap()), Some(DEFAULT_ENCRYPTION_ALGORITHM)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn put_io_encryption_none_arg_sends_raw_body() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input = temp_dir.join("input.bin");
            fs::write(&input, b"plain bytes").unwrap();
            put_io(&ctx, "raw.bin", Some(input.to_str().unwrap()), Some("none")).unwrap();

            let server_path = temp_dir.join("ark/gyan/raw.bin");
            assert_eq!(fs::read(&server_path).unwrap(), b"plain bytes");
            assert_eq!(xattr::get(&server_path, "user.ark.encryption_algorithm").unwrap(), None);
        });
    }

    #[test]
    fn put_io_missing_input_errors() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let missing = temp_dir.join("does_not_exist.bin");
            let err = put_io(&ctx, "notes.txt", Some(missing.to_str().unwrap()), None).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(format!("{}", err).contains("input does not exist"));
        });
    }

    #[test]
    fn put_io_dir_input_rejects_encryption_algorithm() {
        in_test_dir("ark_put_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let input_dir = temp_dir.join("input_dir");
            fs::create_dir_all(&input_dir).unwrap();
            let err = put_io(&ctx, "shared", Some(input_dir.to_str().unwrap()), Some(DEFAULT_ENCRYPTION_ALGORITHM)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn put_io_missing_identity_errors() {
        in_test_dir("ark_put_test", |_temp_dir| {
            let err = create_client_context().err().expect("expected error");
            let msg = format!("{}", err);
            assert!(msg.contains("no .ark"), "msg was {}", msg);
        });
    }
}
