use std::io;
use std::io::Write;

use super::{decrypt_stream, request};

use crate::crypto::DEFAULT_HASH_ALGORITHM;
use crate::http::check_response_code;
use crate::identity::resolve_identity;
use crate::metadata::{has_metadata_headers, read_metadata_attributes, read_metadata_headers, write_local_metadata_attributes, write_metadata_attributes};
use crate::storage::{Body, create_dir_all, parent_path, write_atomic_with_metadata};
use crate::types::{Context, Hash, LocalMetadata, Metadata};
use crate::util::{resolve_client_url, sha256, validate_update};

/// Download the body of a file at `path` (decrypting when encrypted).
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). The local file is written to the account root at
/// the path portion; for address form the address selects the download source
/// while the local file is still written under the account root.
pub fn get_content(ctx: &Context, path: &str) -> io::Result<()> {
    get(ctx, path, true)
}

/// Download a file body (and metadata) at `path`, with decryption control.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). The body is written to the account's own copy of
/// `path`; for address form the address selects the download source while the
/// local file is still written under the account root.
///
/// Verifies the metadata against the modifier's identity, and against the
/// account's own copy where it has one — the download must continue that copy
/// rather than replace it with an unrelated or older file. When `decrypt` is
/// true, unwraps the file key using `ctx.identity_key` and decrypts the body
/// before writing.
///
/// A directory is created where it is missing and takes the metadata alone;
/// its listing is the server's view of it, not a body the local copy holds.
///
/// Stores signed metadata as `user.ark.*` xattrs plus local metadata as
/// `user.ark_local.*` xattrs on the written file.
pub fn get(ctx: &Context, path: &str, decrypt: bool) -> io::Result<()> {
    let existing_metadata = read_metadata_attributes(ctx, path).ok();

    let mut buf: Vec<u8> = Vec::new();
    let (metadata, local_metadata) = get_stream(ctx, path, &mut buf, decrypt, existing_metadata.as_ref())?;

    if metadata.body_hash.is_none() {
        create_dir_all(ctx, path)?;
        write_metadata_attributes(ctx, path, &metadata)?;
        write_local_metadata_attributes(ctx, path, &local_metadata)?;
    } else {
        if let Some(parent) = parent_path(path) {
            create_dir_all(ctx, parent)?;
        }

        write_atomic_with_metadata(ctx, path, Body::Bytes(&buf), &metadata, Some(&local_metadata))?;
    }

    Ok(())
}

/// Download a file body (and metadata) at `path`, writing the body to
/// `output`. Returns the signed metadata pair.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). Writes the body to `output`.
///
/// Verifies the metadata signature against the modifier's identity. When
/// `decrypt` is true, unwraps the file key using `ctx.identity_key` and
/// decrypts the body before writing.
///
/// `existing_metadata`: the metadata of the copy this download replaces, when
/// it replaces one. The download is then also checked to continue that copy
/// rather than replace it with an unrelated or older file.
///
/// The returned [`LocalMetadata`] reflects whether the written body is
/// ciphertext (`encrypted=Some(true)`) or plaintext, and includes a
/// `sync_body_hash` when a plaintext body is written. A directory carries
/// neither: the listing written to `output` is not a body it holds.
pub fn get_stream(
    ctx: &Context,
    path: &str,
    output: &mut dyn Write,
    decrypt: bool,
    existing_metadata: Option<&Metadata>,
) -> io::Result<(Metadata, LocalMetadata)> {
    let url = resolve_client_url(ctx, path)?;

    let (code, headers, body) = request(Some(ctx), "GET", &url, &[], &[])?;
    check_response_code(code, &body)?;
    if !has_metadata_headers(&headers) {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no metadata: {}", path)));
    }

    let metadata = read_metadata_headers(&headers)?;

    // An unresolvable modifier is a verification failure, not a missing
    // target, and must not read as one to callers matching on the kind.
    let modifier_identity = resolve_identity(ctx, &metadata.modified_by)
        .map_err(|e| io::Error::other(format!("modifier {}: {}", metadata.modified_by, e)))?;
    let is_dir = metadata.body_hash.is_none();
    let update_body = if is_dir { None } else { Some(body.as_slice()) };
    validate_update(&modifier_identity.public_key, &metadata, existing_metadata, update_body)?;

    let final_body = if decrypt && metadata.encryption_algorithm.is_some() {
        let mut buf = Vec::new();
        decrypt_stream(ctx, &metadata, &mut body.as_slice(), &mut buf)?;
        buf
    } else {
        body
    };

    let local_metadata = LocalMetadata {
        encrypted: if is_dir { None } else { Some(!decrypt) },
        sync_body_hash: if !is_dir && (decrypt || metadata.encryption_algorithm.is_none()) {
            Some(Hash { algorithm: DEFAULT_HASH_ALGORITHM.to_string(), value: sha256(&final_body) })
        } else {
            None
        },
        sync_modified: Some(metadata.modified),
    };

    output.write_all(&final_body)?;

    Ok((metadata, local_metadata))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::env;

    use time::Duration;

    use super::*;

    use crate::client::put;
    use crate::context::create_client_context;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_secret_key, encrypt_bytes};
    use crate::identity::{create_identity, write_identity};
    use crate::metadata::{create_metadata, read_local_metadata_attributes, read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::testing::fs::{account_context, in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};
    use crate::testing::http::start_test_server;
    use crate::types::{Key, Permissions};

    #[test]
    fn get_writes_body_to_account_tree() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/hello.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"hi from server");

            get(&ctx, "hello.txt", false).unwrap();

            assert_eq!(fs::read(temp_dir.join("hello.txt")).unwrap(), b"hi from server");
        });
    }

    #[test]
    fn get_dir_returns_metadata_without_body_hash_error() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let server_dir = temp_dir.join("ark/gyan/shared");
            fs::create_dir_all(&server_dir).unwrap();
            let mut m = create_metadata(&ctx.identity.address, None);
            m.members[0].key = None;
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut m, None).unwrap();
            let (server_ctx, server_account_dir) = account_context(&server_dir);
            write_metadata_attributes(&server_ctx, &server_account_dir, &m).unwrap();

            let mut buf = Vec::new();
            let (metadata, _) = get_stream(&ctx, "shared", &mut buf, false, None).unwrap();
            assert!(metadata.body_hash.is_none(), "dir metadata should have no body_hash");
            assert!(!buf.is_empty(), "dir listing body should be returned");
        });
    }

    #[test]
    fn get_dir_creates_local_dir_with_metadata() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let server_dir = temp_dir.join("ark/gyan/shared");
            fs::create_dir_all(&server_dir).unwrap();
            let mut m = create_metadata(&ctx.identity.address, None);
            m.members[0].key = None;
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut m, None).unwrap();
            let (server_ctx, server_account_dir) = account_context(&server_dir);
            write_metadata_attributes(&server_ctx, &server_account_dir, &m).unwrap();

            get(&ctx, "shared", false).unwrap();

            let local_dir = temp_dir.join("shared");
            assert!(local_dir.is_dir(), "get should create the dir locally");
            assert_eq!(read_metadata_attributes(&ctx, "shared").unwrap().id, m.id);

            let local = read_local_metadata_attributes(&ctx, "shared").unwrap();
            assert_eq!(local.sync_modified, Some(m.modified));
            assert!(local.sync_body_hash.is_none(), "a dir holds no body to hash");
        });
    }

    #[test]
    fn get_from_subdir_uses_relative_path() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let server_notes = temp_dir.join("ark/gyan/notes");
            fs::create_dir_all(&server_notes).unwrap();
            write_plain_test_file(&server_notes.join("todo.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"buy milk");

            let client_notes = temp_dir.join("notes");
            fs::create_dir_all(&client_notes).unwrap();
            env::set_current_dir(&client_notes).unwrap();
            get(&ctx, "todo.txt", false).unwrap();
            assert_eq!(fs::read(client_notes.join("todo.txt")).unwrap(), b"buy milk");
        });
    }

    #[test]
    fn get_absolute_url_path() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let subdir = temp_dir.join("ark/gyan/sub");
            fs::create_dir_all(&subdir).unwrap();
            write_plain_test_file(&subdir.join("file.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"absolute");

            get(&ctx, "/sub/file.txt", false).unwrap();
            assert_eq!(fs::read(temp_dir.join("sub/file.txt")).unwrap(), b"absolute");
        });
    }

    #[test]
    fn get_via_explicit_address_form() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/explicit.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"via address");

            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            get(&ctx, &arg, false).unwrap();
            assert_eq!(fs::read(temp_dir.join("explicit.txt")).unwrap(), b"via address");
        });
    }

    #[test]
    fn get_writes_metadata_xattrs_from_response_headers() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let server_file = temp_dir.join("ark/gyan/secret");
            write_encrypted_test_file(&server_file, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"plaintext");
            let expected_ciphertext = fs::read(&server_file).unwrap();
            let (server_ctx, server_account_file) = account_context(&server_file);
            let expected_key_value = read_metadata_attributes(&server_ctx, &server_account_file).unwrap()
                .members[0].key.as_ref().unwrap().value.clone();

            let out = temp_dir.join("secret");
            get(&ctx, "secret", false).unwrap();

            assert_eq!(fs::read(&out).unwrap(), expected_ciphertext);
            let m = read_metadata_attributes(&ctx, "secret").unwrap();
            assert_eq!(m.encryption_algorithm.as_deref(), Some(DEFAULT_ENCRYPTION_ALGORITHM));
            assert_eq!(m.members.first().unwrap().key.as_ref().unwrap().value, expected_key_value);
        });
    }

    #[test]
    fn get_with_decrypt_returns_plaintext() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let file_key = create_secret_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
            let (_, ct) = encrypt_bytes(&file_key, b"clear text").unwrap();
            let server_file = temp_dir.join("ark/gyan/secret");
            let mut m = create_metadata(&address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            let (wrap_alg, wrapped) = encrypt_bytes(&ctx.identity.public_key, &file_key.value).unwrap();
            m.members[0].key = Some(Key {
                algorithm: wrap_alg,
                value: wrapped,
            });
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut m, Some(&ct)).unwrap();
            let (server_ctx, server_account_file) = account_context(&server_file);
            write_atomic_with_metadata(&server_ctx, &server_account_file, Body::Bytes(&ct), &m, None).unwrap();

            let out = temp_dir.join("secret");
            get(&ctx, "secret", true).unwrap();

            assert_eq!(fs::read(&out).unwrap(), b"clear text");
            assert_eq!(
                xattr::get(&out, "user.ark_local.encrypted").unwrap().as_deref(),
                Some(b"false".as_slice())
            );
        });
    }

    #[test]
    fn get_with_decrypt_errors_when_no_key_in_response() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let (other_identity, other_key) = create_identity("other@example.com", None).unwrap();
            write_encrypted_test_file(&temp_dir.join("ark/gyan/secret"), &other_identity, &other_key, b"raw");

            create_dir_all(&ctx, "/.ark/identities").unwrap();
            write_identity(&ctx, "/.ark/identities/other@example.com.json", &other_identity).unwrap();

            let err = get(&ctx, "secret", true).unwrap_err();
            assert!(err.to_string().contains("no member entry"), "msg was {}", err);
        });
    }

    #[test]
    fn get_stream_writes_body_without_touching_account_tree() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/piped.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"to stdout");

            let mut buf = Vec::new();
            get_stream(&ctx, "piped.txt", &mut buf, false, None).unwrap();

            assert_eq!(buf, b"to stdout");
            assert!(!temp_dir.join("piped.txt").exists());
        });
    }

    #[test]
    fn get_rejects_a_rollback_of_the_account_copy() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local_path = temp_dir.join("notes.txt");
            fs::write(&local_path, b"current").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            // A server handing back a correctly signed but earlier version of
            // the file it holds.
            let server_path = temp_dir.join("ark/gyan/notes.txt");
            let (server_ctx, server_account_path) = account_context(&server_path);
            let mut rolled_back = read_metadata_attributes(&server_ctx, &server_account_path).unwrap();
            rolled_back.modified -= Duration::hours(1);
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut rolled_back, Some(b"old")).unwrap();
            write_atomic_with_metadata(&server_ctx, &server_account_path, Body::Bytes(b"old"), &rolled_back, None).unwrap();

            let err = get(&ctx, "notes.txt", false).unwrap_err();
            assert!(err.to_string().contains("modified is older than existing"), "msg was {}", err);
            assert_eq!(fs::read(&local_path).unwrap(), b"current");
        });
    }

    #[test]
    fn get_rejects_an_unrelated_file_at_the_path_of_the_account_copy() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local_path = temp_dir.join("notes.txt");
            fs::write(&local_path, b"current").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            // A different file, correctly signed, standing where the account's
            // own file was.
            write_plain_test_file(&temp_dir.join("ark/gyan/notes.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"substitute");

            let err = get(&ctx, "notes.txt", false).unwrap_err();
            assert!(err.to_string().contains("id is wrong"), "msg was {}", err);
            assert_eq!(fs::read(&local_path).unwrap(), b"current");
        });
    }

    #[test]
    fn get_missing_identity_errors() {
        in_test_dir("ark_get_test", |_temp_dir| {
            let err = create_client_context().err().expect("expected error");
            let msg = format!("{}", err);
            assert!(msg.contains("no .ark"), "msg was {}", msg);
        });
    }
}
