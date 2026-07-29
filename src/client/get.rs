use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;

use super::{decrypt_stream, request};
use crate::crypto::DEFAULT_HASH_ALGORITHM;
use crate::types::{Hash, IdentityContext, LocalMetadata, Metadata};
use crate::identity::resolve_identity;
use crate::metadata::{read_metadata_headers, verify_metadata, write_local_metadata_attributes, write_metadata_attributes};
use crate::util::{io_err, resolve_client_url, resolve_local_path, sha256};

/// Download the body of a file at `path` (decrypting when encrypted).
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). The local file is written to the account root at
/// the path portion; for address form the address selects the download source
/// while the local file is still written under the account root.
pub fn get_content(ctx: &IdentityContext, path: &str) -> io::Result<()> {
    let output = resolve_local_path(ctx, path)?;
    get(ctx, path, output.to_str(), true)
}

/// Download a file body (and metadata) at `path`, writing the body to a file
/// or stdout.
///
/// `path` accepts relative, absolute account (leading `/`), or address form
/// (`<name>@<host>/...`). Writes the body to `output` (or stdout when `None`).
///
/// Verifies the metadata signature against the modifier's identity. When
/// `decrypt` is true, unwraps the file key using `ctx.identity_key` and
/// decrypts the body before writing.
///
/// When `output` is `Some`, stores signed metadata as `user.ark.*` xattrs
/// plus local metadata as `user.ark_local.*` xattrs on the written file.
pub fn get(ctx: &IdentityContext, path: &str, output: Option<&str>, decrypt: bool) -> io::Result<()> {
    match output {
        Some(o) => {
            let mut buf: Vec<u8> = Vec::new();
            let (metadata, local_metadata) = get_stream(ctx, path, &mut buf, decrypt)?;

            let output_path = Path::new(o);
            if let Some(parent) = output_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(output_path, &buf)?;

            write_metadata_attributes(output_path, &metadata)?;
            write_local_metadata_attributes(output_path, &local_metadata)?;
        }
        None => {
            let mut stdout = io::stdout().lock();
            get_stream(ctx, path, &mut stdout, decrypt)?;
        }
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
/// The returned [`LocalMetadata`] reflects whether the written body is
/// ciphertext (`encrypted=Some(true)`) or plaintext, and includes a
/// `sync_body_hash` when a plaintext body is written.
pub fn get_stream(
    ctx: &IdentityContext,
    path: &str,
    output: &mut dyn Write,
    decrypt: bool,
) -> io::Result<(Metadata, LocalMetadata)> {
    let url = resolve_client_url(ctx, path)?;

    let (code, headers, body) = request(Some(ctx), "GET", &url, &[], &[])?;
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    let metadata = read_metadata_headers(&headers)?;

    let modifier_identity = resolve_identity(ctx, &metadata.modified_by)?;
    let verify_body = if metadata.body_hash.is_some() { Some(body.as_slice()) } else { None };
    verify_metadata(&modifier_identity.public_key, &metadata, verify_body)?;

    let final_body = if decrypt && metadata.encryption_algorithm.is_some() {
        let mut buf = Vec::new();
        decrypt_stream(ctx, &metadata, &mut body.as_slice(), &mut buf)?;
        buf
    } else {
        body
    };

    let local_metadata = LocalMetadata {
        encrypted: Some(!decrypt),
        sync_body_hash: if decrypt || metadata.encryption_algorithm.is_none() {
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
    use std::env;

    use super::*;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_secret_key, encrypt_bytes};
    use crate::context::create_client_context;
    use crate::identity::{create_identity, write_identity};
    use crate::metadata::{create_metadata, read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::server::start_test_server;
    use crate::types::Key;
    use crate::util::test::{in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};

    #[test]
    fn get_file_via_get_writes_to_output() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/hello.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"hi from server");

            let out = temp_dir.join("out.bin");
            get(&ctx, "hello.txt", Some(out.to_str().unwrap()), false).unwrap();

            assert_eq!(fs::read(&out).unwrap(), b"hi from server");
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
            write_metadata_attributes(&server_dir, &m).unwrap();

            let mut buf = Vec::new();
            let (metadata, _) = get_stream(&ctx, "shared", &mut buf, false).unwrap();
            assert!(metadata.body_hash.is_none(), "dir metadata should have no body_hash");
            assert!(!buf.is_empty(), "dir listing body should be returned");
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
            let out = temp_dir.join("out.bin");
            env::set_current_dir(&client_notes).unwrap();
            get(&ctx, "todo.txt", Some(out.to_str().unwrap()), false).unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"buy milk");
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

            let out = temp_dir.join("out.bin");
            get(&ctx, "/sub/file.txt", Some(out.to_str().unwrap()), false).unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"absolute");
        });
    }

    #[test]
    fn get_via_explicit_address_form() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/explicit.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"via address");

            let out = temp_dir.join("out.bin");
            let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
            get(&ctx, &arg, Some(out.to_str().unwrap()), false).unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"via address");
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
            let expected_key_value = read_metadata_attributes(&server_file).unwrap()
                .members[0].key.as_ref().unwrap().value.clone();

            let out = temp_dir.join("out.bin");
            get(&ctx, "secret", Some(out.to_str().unwrap()), false).unwrap();

            assert_eq!(fs::read(&out).unwrap(), expected_ciphertext);
            let m = read_metadata_attributes(&out).unwrap();
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
            fs::write(&server_file, &ct).unwrap();
            let mut m = create_metadata(&address, Some(DEFAULT_ENCRYPTION_ALGORITHM));
            let (wrap_alg, wrapped) = encrypt_bytes(&ctx.identity.public_key, &file_key.value).unwrap();
            m.members[0].key = Some(Key {
                algorithm: wrap_alg,
                value: wrapped,
            });
            sign_metadata(ctx.identity_key.as_ref().unwrap(), &mut m, Some(&ct)).unwrap();
            write_metadata_attributes(&server_file, &m).unwrap();

            let out = temp_dir.join("out.bin");
            get(&ctx, "secret", Some(out.to_str().unwrap()), true).unwrap();

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
            let (other_identity, other_key) = create_identity("other@example.com").unwrap();
            write_encrypted_test_file(&temp_dir.join("ark/gyan/secret"), &other_identity, &other_key, b"raw");

            let identities_dir = temp_dir.join(".ark").join("identities");
            fs::create_dir_all(&identities_dir).unwrap();
            write_identity(&identities_dir.join("other@example.com.json"), &other_identity).unwrap();

            let out = temp_dir.join("out.bin");
            let err = get(&ctx, "secret", Some(out.to_str().unwrap()), true).unwrap_err();
            assert!(err.to_string().contains("no member entry"), "msg was {}", err);
        });
    }

    #[test]
    fn get_to_stdout_succeeds() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/stdout.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"to stdout");

            get(&ctx, "stdout.txt", None, false).unwrap();
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
