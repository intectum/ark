use std::io;
use std::io::Write;

use super::{decrypt_stream, is_modified, remove_sidecars, request, write_conflict};

use crate::crypto::DEFAULT_HASH_ALGORITHM;
use crate::http::check_response_code;
use crate::metadata::{has_metadata_headers, read_local_metadata_attributes, read_metadata_attributes, read_metadata_headers, write_metadata_attributes_atomic};
use crate::paths::{parent_path, to_url};
use crate::storage::{create_dir_all, exists, write_atomic_with_metadata};
use crate::types::{Context, Hash, LocalMetadata, Metadata};
use crate::util::sha256;
use crate::validate::validate_entry;
use crate::versions::{is_versioned, write_version};

/// Download the body of a file at `path` (decrypting when encrypted).
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). The local file is written to the account root at
/// the path portion; for address form the address selects the download source
/// while the local file is still written under the account root.
///
/// Where the local file changed since it was last synced, records a conflict
/// rather than overwriting it, as [`get`] does. Returns whether it did.
pub fn get_content(ctx: &Context, path: &str) -> io::Result<bool> {
    get(ctx, path, true, false)
}

/// Download a file body (and metadata) at `path`, with decryption control.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). The body is written to the account's own copy of
/// `path`; for address form the address selects the download source while the
/// local file is still written under the account root.
///
/// Where the account's own copy of a file changed since it was last synced,
/// the copy is kept: a conflict is recorded with [`write_conflict`] where the
/// server's body differs from the one the copy was synced from, and the
/// metadata alone is taken where it does not. Returns whether a conflict was
/// recorded. With `force`, the server's copy is written over the account's
/// own regardless. Writing the server's copy drops the sidecars of any
/// conflict recorded on `path`.
///
/// Verifies the metadata against the author's identity, and against the
/// account's own copy where it has one — the download must continue that copy
/// rather than replace it with an unrelated or older file. Its author must
/// also have been allowed to make it (see [`validate_entry`]). When `decrypt`
/// is true, unwraps the file key using `ctx.identity_key` and decrypts the
/// body before writing.
///
/// A directory is created where it is missing and takes the metadata alone;
/// its listing is the server's view of it, not a body the local copy holds.
///
/// Stores signed metadata as `user.ark.*` xattrs plus local metadata as
/// `user.ark_local.*` xattrs on the written file.
pub fn get(ctx: &Context, path: &str, decrypt: bool, force: bool) -> io::Result<bool> {
    let mut buf: Vec<u8> = Vec::new();
    let (metadata, local_metadata) = get_stream(ctx, path, &mut buf, decrypt, None)?;

    if metadata.body_hash.is_none() {
        create_dir_all(ctx, path)?;
        write_metadata_attributes_atomic(ctx, path, &metadata, Some(&local_metadata))?;
        return Ok(false);
    }

    if !force && exists(ctx, path) && is_modified(ctx, path)? == Some(true) {
        let existing_metadata = read_metadata_attributes(ctx, path)?;
        // Only the members changed where the body did not, so the local edit is kept.
        if existing_metadata.body_hash.as_ref().map(|h| &h.value) == metadata.body_hash.as_ref().map(|h| &h.value) {
            let local_metadata = LocalMetadata { sync_author_date: Some(metadata.author_date), ..read_local_metadata_attributes(ctx, path)? };
            write_metadata_attributes_atomic(ctx, path, &metadata, Some(&local_metadata))?;
            return Ok(false);
        }

        write_conflict(ctx, path, &buf, &metadata, decrypt)?;
        return Ok(true);
    }

    if let Some(parent) = parent_path(path) {
        create_dir_all(ctx, parent)?;
    }

    write_atomic_with_metadata(ctx, path, &buf, &metadata, Some(&local_metadata))?;

    remove_sidecars(ctx, path, &[])?;

    Ok(false)
}

/// Download a file body (and metadata) at `path`, writing the body to
/// `output`. Returns the signed metadata pair.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). Writes the body to `output`.
///
/// What arrives is checked by [`validate_entry`]. When `decrypt` is true,
/// unwraps the file key using `ctx.identity_key` and decrypts the body before
/// writing.
///
/// `version`: the id of a past version of `path` to download in place of what
/// it holds now (see [`list_versions`](super::list_versions)).
///
/// What arrives is stored as a version in the account's own version store, as
/// the server sent it, so it can be read back without the server (see
/// [`get_version`](super::get_version)). Entries of the version store and of
/// the request log are not stored.
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
    version: Option<&str>,
) -> io::Result<(Metadata, LocalMetadata)> {
    let mut url = to_url(ctx, path)?;
    if let Some(id) = version {
        url.query_pairs_mut().append_pair("version", id);
    }

    let (code, headers, body) = request(Some(ctx), "GET", &url, &[], &[])?;
    check_response_code(code, &body)?;
    if !has_metadata_headers(&headers) {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no metadata: {}", path)));
    }

    let metadata = read_metadata_headers(&headers)?;
    let is_dir = metadata.body_hash.is_none();

    validate_entry(ctx, path, &metadata, if is_dir { None } else { Some(body.as_slice()) }, version, None)?;

    if is_versioned(ctx, path)? {
        write_version(ctx, path, if is_dir { &[] } else { &body }, &metadata)?;
    }

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
        sync_author_date: Some(metadata.author_date),
    };

    output.write_all(&final_body)?;

    Ok((metadata, local_metadata))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::env;
    use std::path::Path;

    use time::Duration;

    use super::*;

    use crate::client::put;
    use crate::context::create_client_context;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_secret_key, encrypt_bytes};
    use crate::identity::{create_identity, identity_cache_path, write_identity};
    use crate::metadata::{create_metadata, read_local_metadata_attributes, read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::testing::fs::{account_context, in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};
    use crate::testing::http::{seed_shared_dir, start_test_server};
    use crate::types::{Key, Member, Permission, Permissions};
    use crate::versions::{create_dir_version, read_versions, to_version, write_versioned_with_metadata};

    #[test]
    fn get_writes_body_to_account_tree() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/hello.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"hi from server");

            get(&ctx, "hello.txt", false, false).unwrap();

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
            write_metadata_attributes(&server_ctx, &server_account_dir, &m, None).unwrap();

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
            write_metadata_attributes(&server_ctx, &server_account_dir, &m, None).unwrap();

            get(&ctx, "shared", false, false).unwrap();

            let local_dir = temp_dir.join("shared");
            assert!(local_dir.is_dir(), "get should create the dir locally");
            assert_eq!(read_metadata_attributes(&ctx, "shared").unwrap().id, m.id);

            let local = read_local_metadata_attributes(&ctx, "shared").unwrap();
            assert_eq!(local.sync_author_date, Some(m.author_date));
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
            get(&ctx, "todo.txt", false, false).unwrap();
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

            get(&ctx, "/sub/file.txt", false, false).unwrap();
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
            get(&ctx, &arg, false, false).unwrap();
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
            get(&ctx, "secret", false, false).unwrap();

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
            write_atomic_with_metadata(&server_ctx, &server_account_file, &ct, &m, None).unwrap();

            let out = temp_dir.join("secret");
            get(&ctx, "secret", true, false).unwrap();

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

            // The account lets the author write here, so only the key is
            // missing.
            seed_shared_dir(temp_dir, &ctx.identity, ctx.identity_key.as_ref().unwrap(), "ark/gyan/sub", vec![
                Member { address: other_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            write_encrypted_test_file(&temp_dir.join("ark/gyan/sub/secret"), &other_identity, &other_key, b"raw");

            create_dir_all(&ctx, "/.ark/identities").unwrap();
            write_identity(&ctx, &identity_cache_path("other@example.com"), &other_identity).unwrap();

            let err = get(&ctx, "sub/secret", true, false).unwrap_err();
            assert!(err.to_string().contains("no member entry"), "msg was {}", err);
        });
    }

    #[test]
    fn get_takes_a_file_its_author_wrote_before_being_removed_from_the_directory() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let (other_identity, other_key) = create_identity("other@example.com", None).unwrap();
            create_dir_all(&ctx, "/.ark/identities").unwrap();
            write_identity(&ctx, &identity_cache_path("other@example.com"), &other_identity).unwrap();

            let dir = seed_shared_dir(temp_dir, &ctx.identity, ctx.identity_key.as_ref().unwrap(), "ark/gyan/shared", vec![
                Member { address: other_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);
            write_plain_test_file(&temp_dir.join("ark/gyan/shared/notes.txt"), &other_identity, &other_key, b"by other");

            // Removed from the directory after writing the file.
            let (server_ctx, server_path) = account_context(&dir);
            let written = read_metadata_attributes(&server_ctx, "/shared/notes.txt").unwrap();
            let mut removed = read_metadata_attributes(&server_ctx, &server_path).unwrap();
            removed.parent_version = Some(to_version(&removed));
            removed.author_date = written.author_date + Duration::seconds(1);
            removed.members.retain(|member| member.address != other_identity.address);
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut removed, None).unwrap();
            create_dir_version(&server_ctx, &server_path, &removed).unwrap();
            write_metadata_attributes(&server_ctx, &server_path, &removed, None).unwrap();

            // Holding the directory as it is now does not change who could
            // write there then.
            get(&ctx, "shared/", false, false).unwrap();
            get(&ctx, "shared/notes.txt", false, false).unwrap();
            assert_eq!(fs::read(temp_dir.join("shared/notes.txt")).unwrap(), b"by other");
        });
    }

    #[test]
    fn get_refuses_a_file_the_account_never_let_its_author_write() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            // Signed by its author, but written straight into the account by
            // the server rather than through anything the account allowed.
            let (other_identity, other_key) = create_identity("other@example.com", None).unwrap();
            write_plain_test_file(&temp_dir.join("ark/gyan/planted.txt"), &other_identity, &other_key, b"planted");
            create_dir_all(&ctx, "/.ark/identities").unwrap();
            write_identity(&ctx, &identity_cache_path("other@example.com"), &other_identity).unwrap();

            let err = get(&ctx, "planted.txt", false, false).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "msg was {}", err);
            assert!(!temp_dir.join("planted.txt").exists());
        });
    }

    #[test]
    fn get_refuses_a_version_the_account_never_allowed_made_on_a_history_it_does_not_hold() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            for body in [b"one", b"two"] {
                fs::write(temp_dir.join("notes.txt"), body).unwrap();
                put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            }

            // As a device that holds nothing of it yet.
            fs::remove_file(temp_dir.join("notes.txt")).unwrap();
            fs::remove_dir_all(temp_dir.join(".ark/versions")).unwrap();

            // Written by the server on top of what the account wrote, signed by
            // someone the account never allowed.
            let (other_identity, other_key) = create_identity("other@example.com", None).unwrap();
            let (server_ctx, _) = account_context(&temp_dir.join("ark/gyan/notes.txt"));
            let two = read_metadata_attributes(&server_ctx, "/notes.txt").unwrap();
            let mut planted = two.clone();
            planted.author = other_identity.address.clone();
            planted.author_date = two.author_date + Duration::seconds(1);
            planted.parent_version = Some(to_version(&two));
            sign_metadata(&other_key, &mut planted, Some(b"planted")).unwrap();
            write_atomic_with_metadata(&server_ctx, "/notes.txt", b"planted", &planted, None).unwrap();
            create_dir_all(&ctx, "/.ark/identities").unwrap();
            write_identity(&ctx, &identity_cache_path("other@example.com"), &other_identity).unwrap();

            let err = get(&ctx, "notes.txt", false, false).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "msg was {}", err);
            assert!(!temp_dir.join("notes.txt").exists());
            // What it was made against is taken in back to the first version.
            assert_eq!(read_versions(&ctx, "notes.txt").unwrap().len(), 2);
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
            rolled_back.author_date -= Duration::hours(1);
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut rolled_back, Some(b"old")).unwrap();
            write_atomic_with_metadata(&server_ctx, &server_account_path, b"old", &rolled_back, None).unwrap();

            let err = get(&ctx, "notes.txt", false, false).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "msg was {}", err);
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

            let err = get(&ctx, "notes.txt", false, false).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "msg was {}", err);
            assert_eq!(fs::read(&local_path).unwrap(), b"current");
        });
    }

    // Stand a version made on the account's copy of `notes.txt` on the
    // server, as another device of the account would.
    fn put_newer_server_version(ctx: &Context, temp_dir: &Path, body: &[u8]) -> Metadata {
        let (server_ctx, server_path) = account_context(&temp_dir.join("ark/gyan/notes.txt"));
        let mut newer = read_metadata_attributes(&server_ctx, &server_path).unwrap();
        newer.parent_version = Some(to_version(&newer));
        newer.author_date += Duration::seconds(1);
        sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut newer, Some(body)).unwrap();
        write_versioned_with_metadata(&server_ctx, &server_path, body, &newer).unwrap();
        newer
    }

    fn sidecar_names(temp_dir: &Path) -> Vec<String> {
        fs::read_dir(temp_dir).unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("notes.txt."))
            .collect()
    }

    #[test]
    fn get_records_a_conflict_rather_than_overwrite_a_local_edit() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local_path = temp_dir.join("notes.txt");
            fs::write(&local_path, b"base").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();
            let base_id = to_version(&read_metadata_attributes(&ctx, "notes.txt").unwrap());

            put_newer_server_version(&ctx, temp_dir, b"remote");
            fs::write(&local_path, b"local").unwrap();

            assert!(get(&ctx, "notes.txt", false, false).unwrap(), "conflict reported");

            assert_eq!(fs::read(&local_path).unwrap(), b"local", "local edit kept");
            assert_eq!(fs::read(temp_dir.join(format!("notes.txt.base-{}", base_id))).unwrap(), b"base");
            let remote_sidecar = sidecar_names(temp_dir).into_iter().find(|name| name.starts_with("notes.txt.remote-")).expect("remote sidecar");
            assert_eq!(fs::read(temp_dir.join(remote_sidecar)).unwrap(), b"remote");
        });
    }

    #[test]
    fn get_keeps_a_local_edit_when_only_the_metadata_changed() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local_path = temp_dir.join("notes.txt");
            fs::write(&local_path, b"base").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            let newer = put_newer_server_version(&ctx, temp_dir, b"base");
            fs::write(&local_path, b"local").unwrap();

            assert!(!get(&ctx, "notes.txt", false, false).unwrap());

            assert_eq!(fs::read(&local_path).unwrap(), b"local", "local edit kept");
            assert_eq!(read_metadata_attributes(&ctx, "notes.txt").unwrap().author_date, newer.author_date, "server metadata taken");
            assert!(sidecar_names(temp_dir).is_empty());
        });
    }

    #[test]
    fn get_with_force_overwrites_a_local_edit_and_drops_its_conflict() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let local_path = temp_dir.join("notes.txt");
            fs::write(&local_path, b"base").unwrap();
            put(&ctx, "notes.txt", &Permissions::default(), Some("none"), false).unwrap();

            put_newer_server_version(&ctx, temp_dir, b"remote");
            fs::write(&local_path, b"local").unwrap();
            get(&ctx, "notes.txt", false, false).unwrap();

            assert!(!get(&ctx, "notes.txt", false, true).unwrap());

            assert_eq!(fs::read(&local_path).unwrap(), b"remote");
            assert!(sidecar_names(temp_dir).is_empty(), "sidecars dropped: {:?}", sidecar_names(temp_dir));
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
