use std::fs;
use std::io::Write;
use std::path::Path;

use crate::http::{write_response, write_text};
use crate::metadata::{read_metadata_attributes, write_metadata_headers};
use crate::types::{DirectoryEntry, DirectoryEntryKind};
use crate::util::io_err;

pub fn serve_get(fs_path: &Path, stream: &mut dyn Write, send_body: bool) -> std::io::Result<()> {
    let fs_metadata = match fs::metadata(fs_path) {
        Ok(m) => m,
        Err(_) => return write_text(stream, 404, b"not found"),
    };

    if fs_metadata.is_dir() {
        let body = list_dir(fs_path)?;
        let content_length = body.len().to_string();
        let metadata_headers = read_metadata_attributes(fs_path).ok()
            .map(|m| write_metadata_headers(&m))
            .unwrap_or_default();
        let mut headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        headers.push(("Content-Type", "application/json"));
        headers.push(("Content-Length", content_length.as_str()));
        headers.push(("Connection", "close"));
        return write_response(stream, 200, &headers, if send_body { body.as_bytes() } else { &[] });
    }

    let metadata = match read_metadata_attributes(fs_path) {
        Ok(m) => m,
        Err(e) => return write_text(stream, 500, e.to_string().as_bytes()),
    };

    let metadata_headers = write_metadata_headers(&metadata);
    let content_length = fs_metadata.len().to_string();
    let mut headers: Vec<(&str, &str)> = metadata_headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    headers.push(("Content-Type", content_type(fs_path)));
    headers.push(("Content-Length", &content_length));
    headers.push(("Connection", "close"));

    write_response(stream, 200, &headers, &[])?;
    if send_body {
        let mut file = fs::File::open(fs_path)?;
        std::io::copy(&mut file, stream)?;
    }

    Ok(())
}

fn list_dir(path: &Path) -> std::io::Result<String> {
    let mut entries: Vec<_> = fs::read_dir(path)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    let items: Vec<DirectoryEntry> = entries
        .into_iter()
        .map(|e| {
            let meta = e.metadata()?;
            let kind = if meta.is_dir() { DirectoryEntryKind::Dir }
                else if meta.is_symlink() { DirectoryEntryKind::Symlink }
                else { DirectoryEntryKind::File };
            Ok(DirectoryEntry {
                kind,
                name: e.file_name().to_string_lossy().into_owned(),
            })
        })
        .collect::<std::io::Result<_>>()?;
    serde_json::to_string(&items).map_err(|e| io_err(&e.to_string()))
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" | "md" => "text/plain; charset=utf-8",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::super::start_test_server;
    use super::super::test_helpers::*;
    use crate::crypto::DEFAULT_ENCRYPTION_ALGORITHM;
    use crate::types::{DirectoryEntry, DirectoryEntryKind, Member, Permission};
    use crate::util::test::{TEST_ADDRESS, create_test_account, in_test_dir, write_encrypted_test_file, write_plain_test_file};
    use std::fs;

    #[test]
    fn get_file_returns_content() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            write_plain_test_file(&account_dir.join("hello.txt"), &identity, &secret_key, b"hi there");
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/hello.txt", &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"hi there");
            assert_eq!(header(&headers, "content-length"), Some("8"));
        });
    }

    #[test]
    fn get_missing_file_404() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/nope.txt", &[]);
            assert_eq!(code, 404);
        });
    }

    #[test]
    fn get_dir_returns_json_listing() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            fs::write(account_dir.join("a.txt"), b"hello").unwrap();
            fs::create_dir(account_dir.join("sub")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "content-type"), Some("application/json"));

            let entries: Vec<DirectoryEntry> = serde_json::from_slice(&body).unwrap();
            let file = entries.iter().find(|e| e.name == "a.txt").unwrap();
            assert!(matches!(file.kind, DirectoryEntryKind::File));
            let dir = entries.iter().find(|e| e.name == "sub").unwrap();
            assert!(matches!(dir.kind, DirectoryEntryKind::Dir));
        });
    }

    #[test]
    fn get_dir_empty_returns_empty_array() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            fs::create_dir(account_dir.join("empty")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/empty/", &[]);
            assert_eq!(code, 200);
            let entries: Vec<DirectoryEntry> = serde_json::from_slice(&body).unwrap();
            assert!(entries.is_empty());
        });
    }

    #[cfg(unix)]
    #[test]
    fn get_dir_lists_symlink_as_symlink_kind() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            fs::write(&target, b"hi").unwrap();
            std::os::unix::fs::symlink(&target, account_dir.join("link")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/", &[]);
            assert_eq!(code, 200);
            let entries: Vec<DirectoryEntry> = serde_json::from_slice(&body).unwrap();
            let link = entries.iter().find(|e| e.name == "link").unwrap();
            assert!(matches!(link.kind, DirectoryEntryKind::Symlink));
        });
    }

    #[test]
    fn head_file_no_body_with_length() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            write_plain_test_file(&account_dir.join("x"), &identity, &secret_key, b"abcde");
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "HEAD", "/ark/test/x", &[]);
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert_eq!(header(&headers, "content-length"), Some("5"));
        });
    }

    #[test]
    fn get_dir_returns_metadata_headers_when_present() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            seed_shared_dir(temp_dir, &identity, &secret_key, "ark/test/shared", vec![
                Member { address: "friend@example.com".to_string(), permission: Permission::Write, key: None },
            ]);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/shared/", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "x-ark-meta-member-0-address"), Some(TEST_ADDRESS));
            assert_eq!(header(&headers, "x-ark-meta-member-1-address"), Some("friend@example.com"));
        });
    }

    #[test]
    fn get_dir_no_metadata_headers_when_absent() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            fs::create_dir(account_dir.join("bare")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/bare/", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "x-ark-meta-id"), None);
        });
    }

    #[test]
    fn head_dir_no_body_with_json_type() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = signed_request(port, &identity, &secret_key, "HEAD", "/ark/test/", &[]);
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert_eq!(header(&headers, "content-type"), Some("application/json"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_get_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            write_plain_test_file(&target, &identity, &secret_key, b"secret");
            std::os::unix::fs::symlink(&target, account_dir.join("link")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/link", &[]);
            assert_eq!(code, 403);
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_head_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            write_plain_test_file(&target, &identity, &secret_key, b"secret");
            std::os::unix::fs::symlink(&target, account_dir.join("link")).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "HEAD", "/ark/test/link", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn get_returns_metadata_headers_from_xattr() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("secret");
            write_encrypted_test_file(&file, &identity, &secret_key, b"plaintext");
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _body, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/secret", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "x-ark-meta-encryption-algorithm"), Some(DEFAULT_ENCRYPTION_ALGORITHM));
            assert_eq!(header(&headers, "x-ark-meta-member-0-address"), Some(TEST_ADDRESS));
        });
    }

    #[test]
    fn get_ignores_unknown_user_ark_xattrs() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let file = account_dir.join("file");
            write_plain_test_file(&file, &identity, &secret_key, b"data");
            xattr::set(&file, "user.ark.foo", b"bar").unwrap();
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, headers) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/file", &[]);
            assert_eq!(code, 200);
            assert_eq!(header(&headers, "x-ark-meta-foo"), None);
        });
    }

    #[test]
    fn get_file_without_xattr_returns_500() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            fs::write(account_dir.join("plain"), b"raw").unwrap();
            let port = start_test_server(temp_dir.to_path_buf());

            let (code, _, _) = signed_request(port, &identity, &secret_key, "GET", "/ark/test/plain", &[]);
            assert_eq!(code, 500);
        });
    }

    #[test]
    fn get_by_read_only_member_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"secret", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Read, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = signed_request(port, &reader_identity, &reader_key, "GET", "/ark/owner/file.txt", &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"secret");
        });
    }

    #[test]
    fn get_by_non_member_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (stranger_identity, stranger_key, _) = create_test_account(temp_dir, "stranger@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"secret", vec![]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &stranger_identity, &stranger_key, "GET", "/ark/owner/file.txt", &[]);
            assert_eq!(code, 403);
        });
    }

    #[test]
    fn get_public_file_no_auth_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Read, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, _) = request(port, "GET", "/ark/owner/public.txt", &[], &[]);
            assert_eq!(code, 200);
            assert_eq!(body, b"open");
        });
    }

    #[test]
    fn head_public_file_no_auth_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Read, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, body, headers) = request(port, "HEAD", "/ark/owner/public.txt", &[], &[]);
            assert_eq!(code, 200);
            assert!(body.is_empty());
            assert_eq!(header(&headers, "content-length"), Some("4"));
        });
    }

    #[test]
    fn get_public_file_ignores_bad_auth() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Read, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let auth = build_auth("nobody@x", 0, "AAAA");
            let (code, body, _) = request(port, "GET", "/ark/owner/public.txt", &[], &[
                ("Authorization", &auth),
            ]);
            assert_eq!(code, 200);
            assert_eq!(body, b"open");
        });
    }
}
