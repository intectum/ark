use std::io;

use crate::client::request;
use crate::http::check_response_code;
use crate::identity::resolve_identity;
use crate::metadata::{has_metadata_headers, read_metadata_headers, verify_metadata_signature};
use crate::types::{IdentityContext, Metadata};
use crate::util::resolve_client_url;

/// Fetch response headers and signed metadata for `path` without downloading
/// the body. Verifies the metadata signature against the modifier's identity.
///
/// `path` accepts relative, absolute account, or address form. See the
/// [module documentation](../index.html) for path resolution details.
pub fn head(ctx: &IdentityContext, path: &str) -> io::Result<(Vec<(String, String)>, Metadata)> {
    let url = resolve_client_url(ctx, path)?;

    let (code, headers, body) = request(Some(ctx), "HEAD", &url, &[], &[])?;
    check_response_code(code, &body)?;
    if !has_metadata_headers(&headers) {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no metadata: {}", path)));
    }

    let metadata = read_metadata_headers(&headers)?;

    // An unresolvable modifier is a verification failure, not a missing
    // target, and must not read as one to callers matching on the kind.
    let modifier_identity = resolve_identity(ctx, &metadata.modified_by)
        .map_err(|e| io::Error::other(format!("modifier {}: {}", metadata.modified_by, e)))?;
    verify_metadata_signature(&modifier_identity.public_key, &metadata)?;

    Ok((headers, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::DEFAULT_ENCRYPTION_ALGORITHM;
    use crate::identity::read_identity;
    use crate::metadata::read_metadata_attributes;
    use crate::testing::fs::{in_test_dir, init_with_server, write_encrypted_test_file, write_plain_test_file};
    use crate::testing::http::start_test_server;
    use crate::util::{encode_base64url, resolve_client_url_raw};

    #[test]
    fn head_returns_headers_without_body() {
        in_test_dir("ark_head_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            write_plain_test_file(&temp_dir.join("ark/gyan/file.bin"), &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"hello world");

            let identity = read_identity(&temp_dir.join(".ark").join("identity.json")).unwrap();
            let url = resolve_client_url_raw(temp_dir, "file.bin", &identity.address).unwrap();
            let (code, headers, body) = request(Some(&ctx), "HEAD", &url, &[], &[]).unwrap();
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert!(
                headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-length") && v == "11"),
                "headers: {:?}", headers
            );
        });
    }

    #[test]
    fn head_returns_metadata_headers() {
        in_test_dir("ark_head_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);
            let f = temp_dir.join("ark/gyan/secret");
            write_encrypted_test_file(&f, &ctx.identity, ctx.identity_key.as_ref().unwrap(), b"plaintext");
            let expected_key_b64 = encode_base64url(&read_metadata_attributes(&f).unwrap()
                .members[0].key.as_ref().unwrap().value);

            let identity = read_identity(&temp_dir.join(".ark").join("identity.json")).unwrap();
            let url = resolve_client_url_raw(temp_dir, "secret", &identity.address).unwrap();
            let (code, headers, body) = request(Some(&ctx), "HEAD", &url, &[], &[]).unwrap();
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-encryption-algorithm") && v == DEFAULT_ENCRYPTION_ALGORITHM));
            assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-member-0-permission") && v == "owner"));
            assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-ark-meta-member-0-key-value") && v == &expected_key_b64));
        });
    }

    #[test]
    fn head_missing_file_errors() {
        in_test_dir("ark_head_test", |temp_dir| {
            let port = start_test_server(temp_dir.to_path_buf());
            let address = format!("gyan@127.0.0.1:{}", port);
            let ctx = init_with_server(temp_dir, &address);

            let err = match head(&ctx, "nope") {
                Ok(_) => panic!("expected error"),
                Err(e) => e,
            };
            assert!(err.to_string().contains("HTTP 404"), "msg was {}", err);
        });
    }
}
