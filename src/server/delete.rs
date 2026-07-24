use std::fs;
use std::io::Write;
use std::path::Path;

use crate::http::write_text;

pub fn serve_delete(fs_path: &Path, stream: &mut dyn Write) -> std::io::Result<()> {
    let fs_metadata = match fs::metadata(fs_path) {
        Ok(m) => m,
        Err(_) => return write_text(stream, 404, b"not found"),
    };

    let result = if fs_metadata.is_dir() {
        fs::remove_dir_all(fs_path)
    } else {
        fs::remove_file(fs_path)
    };

    match result {
        Ok(_) => write_text(stream, 204, &[]),
        Err(e) => write_text(stream, 500, e.to_string().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::start_test_server;
    use super::super::test_helpers::*;
    use crate::types::{Member, Permission};
    use crate::util::test::{TEST_ADDRESS, create_test_account, in_test_dir, write_plain_test_file};
    use std::fs;

    #[test]
    fn delete_file_removes_and_returns_204() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let p = account_dir.join("d.txt");
            write_plain_test_file(&p, &identity, &secret_key, b"bye");
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", "/ark/test/d.txt", &[]);
            assert_eq!(code, 204);
            assert!(!p.exists());
        });
    }

    #[test]
    fn delete_dir_recursively_removes_and_returns_204() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let d = account_dir.join("sub");
            fs::create_dir(&d).unwrap();
            fs::write(d.join("inner"), b"x").unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", "/ark/test/sub", &[]);
            assert_eq!(code, 204);
            assert!(!d.exists());
        });
    }

    #[test]
    fn delete_missing_404() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", "/ark/test/nope", &[]);
            assert_eq!(code, 404);
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_delete_blocked_403() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
            let target = account_dir.join("real.txt");
            write_plain_test_file(&target, &identity, &secret_key, b"keep");
            let link = account_dir.join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", "/ark/test/link", &[]);
            assert_eq!(code, 403);
            assert!(link.exists());
            assert!(target.exists());
        });
    }

    #[test]
    fn delete_at_ark_root_405() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (identity, secret_key, _) = create_test_account(temp_dir, TEST_ADDRESS);
            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &identity, &secret_key, "DELETE", "/ark/test", &[]);
            assert_eq!(code, 405);
            assert!(temp_dir.join("ark/test").exists());
        });
    }

    #[test]
    fn delete_by_write_member_succeeds() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (writer_identity, writer_key, _) = create_test_account(temp_dir, "writer@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: writer_identity.address.clone(), permission: Permission::Writer, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &writer_identity, &writer_key, "DELETE", "/ark/owner/file.txt", &[]);
            assert_eq!(code, 204);
            assert!(!file.exists());
        });
    }

    #[test]
    fn delete_by_read_only_member_forbidden() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");
            let (reader_identity, reader_key, _) = create_test_account(temp_dir, "reader@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/file.txt", b"v1", vec![
                Member { address: reader_identity.address.clone(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = signed_request(port, &reader_identity, &reader_key, "DELETE", "/ark/owner/file.txt", &[]);
            assert_eq!(code, 403);
            assert!(file.exists());
        });
    }

    #[test]
    fn delete_public_file_no_auth_still_unauthorized() {
        in_test_dir("ark_server_test", |temp_dir| {
            let (owner_identity, owner_key, _) = create_test_account(temp_dir, "owner@example.com");

            let file = seed_shared_file(temp_dir, &owner_identity, &owner_key, "ark/owner/public.txt", b"open", vec![
                Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            ]);

            let port = start_test_server(temp_dir.to_path_buf());
            let (code, _, _) = request(port, "DELETE", "/ark/owner/public.txt", &[], &[]);
            assert_eq!(code, 401);
            assert!(file.exists());
        });
    }
}
