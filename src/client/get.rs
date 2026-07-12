use std::fs;
use std::io::Write;
use std::path::Path;

use crate::client::ark_request;
use crate::crypto::decrypt_bytes;
use crate::types::{IdentityContext, LocalMetadata};
use crate::identity::resolve_identity;
use crate::metadata::{get_member, read_metadata_headers, verify_metadata, write_local_metadata_attributes, write_metadata_attributes};
use crate::types::Key;
use crate::util::{io_err, resolve_client_url, sha256};

pub fn cmd_get(ctx: &IdentityContext, path: &str, output: Option<&str>, decrypt: bool) -> std::io::Result<()> {
    let url = resolve_client_url(ctx, path)?;

    let (code, headers, body) = ark_request(Some(ctx), "GET", &url, &[], &[])?;
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }

    let metadata = read_metadata_headers(&headers)?;

    let modifier_identity = resolve_identity(ctx, &metadata.modified_by)?;
    verify_metadata(&modifier_identity.public_key, &metadata, Some(&body))?;

    let final_body = if decrypt {
        let member = match get_member(&metadata.members, &ctx.identity.address) {
            Some(m) => m,
            None => return Err(io_err("no member entry for current account"))
        };
        let encrypted_file_key = member.key.as_ref()
            .ok_or_else(|| io_err("no file key for current account"))?;
        let file_key = decrypt_bytes(
            &Key {
                algorithm: encrypted_file_key.algorithm.clone(),
                value: ctx.identity_key.as_ref().expect("client context missing identity_key").value.clone()
            },
            &encrypted_file_key.value,
        )?;

        let encryption_algorithm = metadata.encryption_algorithm.clone()
            .ok_or_else(|| io_err("file is not encrypted"))?;
        decrypt_bytes(&Key { algorithm: encryption_algorithm, value: file_key }, &body).map_err(|e| {
            io_err(&format!(
                "{} — server data may not be encrypted or the key may be wrong",
                e
            ))
        })?
    } else {
        body
    };

    match output {
        Some(file) => {
            fs::write(file, &final_body)?;

            let path = Path::new(file);
            write_metadata_attributes(path, &metadata)?;
            write_local_metadata_attributes(path, &LocalMetadata {
                encrypted: Some(!decrypt),
                sync_hash: if decrypt || metadata.encryption_algorithm.is_none() {
                    Some(sha256(&final_body))
                } else {
                    None
                },
            })?;
        }
        None => std::io::stdout().write_all(&final_body)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::crypto::{DEFAULT_ENCRYPTION_ALGORITHM, create_key, encrypt_bytes};
    use crate::context::create_client_context;
    use crate::identity::{create_identity, write_identity};
    use crate::metadata::{create_metadata, read_metadata_attributes, sign_metadata, write_metadata_attributes};
    use crate::server::start_test_server;
    use crate::types::Key;
    use crate::util::test::{in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};

    #[test]
    fn get_file_via_cmd_get_writes_to_output() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/hello.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"hi from server");

            let out = temp_dir.join("out.bin");
            cmd_get(&ctx, "hello.txt", Some(out.to_str().unwrap()), false).unwrap();

            assert_eq!(fs::read(&out).unwrap(), b"hi from server");
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
            cmd_get(&ctx, "todo.txt", Some(out.to_str().unwrap()), false).unwrap();
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
            cmd_get(&ctx, "/sub/file.txt", Some(out.to_str().unwrap()), false).unwrap();
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
            cmd_get(&ctx, &arg, Some(out.to_str().unwrap()), false).unwrap();
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
            cmd_get(&ctx, "secret", Some(out.to_str().unwrap()), false).unwrap();

            assert_eq!(fs::read(&out).unwrap(), expected_ciphertext);
            let m = read_metadata_attributes(&out).unwrap();
            assert_eq!(m.encryption_algorithm.as_deref(), Some("aes-256-gcm"));
            assert_eq!(m.members.iter().next().unwrap().key.as_ref().unwrap().value, expected_key_value);
        });
    }

    #[test]
    fn get_with_decrypt_returns_plaintext() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let file_key = create_key(DEFAULT_ENCRYPTION_ALGORITHM).unwrap();
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
            cmd_get(&ctx, "secret", Some(out.to_str().unwrap()), true).unwrap();

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
            write_plain_test_file(&temp_dir.join("ark/gyan/plain"), &other_identity, &other_key, b"raw");

            let identities_dir = temp_dir.join(".ark").join("identities");
            fs::create_dir_all(&identities_dir).unwrap();
            write_identity(&identities_dir.join("other@example.com.json"), &other_identity).unwrap();

            let out = temp_dir.join("out.bin");
            let err = cmd_get(&ctx, "plain", Some(out.to_str().unwrap()), true).unwrap_err();
            assert!(err.to_string().contains("no member entry"), "msg was {}", err);
        });
    }

    #[test]
    fn cmd_get_to_stdout_succeeds() {
        in_test_dir("ark_get_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/stdout.txt"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"to stdout");

            cmd_get(&ctx, "stdout.txt", None, false).unwrap();
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
