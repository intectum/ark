use std::env::current_dir;
use std::path::Path;

use crate::identity::{read_identity, read_identity_key, resolve_identity_client};
use crate::metadata::{get_member, read_metadata_attributes, sign_metadata, verify_metadata_signature, write_metadata_attributes};
use crate::types::Member;
use crate::util::{find_root, io_err, io_invalid_input, now_iso};

const PUBLIC_CLI: &str = "public";
const PUBLIC_WIRE: &str = "*";

pub fn cmd_chmod(
    file: &str,
    owners: &[String],
    writers: &[String],
    readers: &[String],
    drops: &[String],
) -> std::io::Result<()> {
    let root = find_root(&current_dir()?)?;
    let identity = read_identity(&root.join(".ark").join("identity.json"))?;

    let path = Path::new(file);
    let mut metadata = read_metadata_attributes(path)?;

    let modifier_identity = resolve_identity_client(&root, &identity, &metadata.modified_by)?;
    verify_metadata_signature(&modifier_identity.public_key.value, &metadata)?;

    match get_member(&metadata.members, &identity.address) {
        Some(m) if m.permission == "owner" => {}
        _ => return Err(io_err("only an owner can change permissions")),
    }

    let template_wrapped_key = metadata
        .members
        .iter()
        .find(|m| !m.wrapped_key.is_empty())
        .map(|m| m.wrapped_key.clone())
        .unwrap_or_default();

    let encrypted = metadata.encryption != "none";

    apply_changes(&mut metadata.members, owners, "owner", &template_wrapped_key, encrypted)?;
    apply_changes(&mut metadata.members, writers, "write", &template_wrapped_key, encrypted)?;
    apply_changes(&mut metadata.members, readers, "read", &template_wrapped_key, encrypted)?;

    for addr in drops {
        let wire = cli_address_to_wire(addr);
        metadata.members.retain(|m| m.address != wire);
    }

    if !metadata.members.iter().any(|m| m.permission == "owner") {
        return Err(io_invalid_input("at least one owner must remain"));
    }

    metadata.modified = now_iso();
    metadata.modified_by = identity.address.clone();

    let body = std::fs::read(path)?;
    let signing_key = read_identity_key(&root.join(".ark").join("identity.key"))?;
    sign_metadata(&signing_key, &mut metadata, &body);

    write_metadata_attributes(path, &metadata)?;

    Ok(())
}

fn apply_changes(
    members: &mut Vec<Member>,
    addresses: &[String],
    permission: &str,
    template_wrapped_key: &[u8],
    encrypted: bool,
) -> std::io::Result<()> {
    for addr in addresses {
        let wire = cli_address_to_wire(addr);
        if wire == PUBLIC_WIRE && encrypted {
            return Err(io_invalid_input("cannot add public member to encrypted file"));
        }

        let wrapped_key = if wire == PUBLIC_WIRE {
            Vec::new()
        } else {
            template_wrapped_key.to_vec()
        };

        match members.iter_mut().find(|m| m.address == wire) {
            Some(existing) => existing.permission = permission.to_string(),
            None => members.push(Member {
                address: wire,
                permission: permission.to_string(),
                wrapped_key,
            }),
        }
    }
    Ok(())
}

fn cli_address_to_wire(addr: &str) -> String {
    if addr == PUBLIC_CLI { PUBLIC_WIRE.to_string() } else { addr.to_string() }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::create_account::create_account_with_key;
    use crate::metadata::{sign_metadata, write_metadata_attributes};
    use crate::util::test::{TempDir, get_default_test_metadata, with_cwd};

    fn seed_local_file(td: &TempDir, address: &str, key: &[u8; 32], name: &str, body: &[u8], encryption: &str) -> std::path::PathBuf {
        let path = td.0.join(format!("ark/gyan/{}", name));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        let mut m = get_default_test_metadata(key, address, body);
        m.encryption = encryption.to_string();
        sign_metadata(key, &mut m, body);
        write_metadata_attributes(&path, &m).unwrap();
        path
    }

    #[test]
    fn adds_reader_to_local_file() {
        let td = TempDir::new("ark_chmod_test");
        let address = "gyan@127.0.0.1:8080".to_string();
        let key = [90u8; 32];
        create_account_with_key(&td.0, &address, &key).unwrap();
        let path = seed_local_file(&td, &address, &key, "notes.txt", b"hello", "none");

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_chmod(path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[]).unwrap();
        });

        let m = read_metadata_attributes(&path).unwrap();
        let john = m.members.iter().find(|m| m.address == "john@example.com").unwrap();
        assert_eq!(john.permission, "read");
        assert!(m.members.iter().any(|m| m.address == address && m.permission == "owner"));
    }

    #[test]
    fn adds_public_reader_when_unencrypted() {
        let td = TempDir::new("ark_chmod_test");
        let address = "gyan@127.0.0.1:8080".to_string();
        let key = [91u8; 32];
        create_account_with_key(&td.0, &address, &key).unwrap();
        let path = seed_local_file(&td, &address, &key, "public.txt", b"open", "none");

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_chmod(path.to_str().unwrap(), &[], &[], &["public".to_string()], &[]).unwrap();
        });

        let m = read_metadata_attributes(&path).unwrap();
        let pub_member = m.members.iter().find(|m| m.address == "*").unwrap();
        assert_eq!(pub_member.permission, "read");
        assert!(pub_member.wrapped_key.is_empty());
    }

    #[test]
    fn rejects_public_on_encrypted_file() {
        let td = TempDir::new("ark_chmod_test");
        let address = "gyan@127.0.0.1:8080".to_string();
        let key = [92u8; 32];
        create_account_with_key(&td.0, &address, &key).unwrap();
        let path = seed_local_file(&td, &address, &key, "enc.bin", b"ciphertext", "aes-256-gcm");

        let account_dir = td.0.join("ark/gyan");
        let err = with_cwd(&account_dir, || {
            cmd_chmod(path.to_str().unwrap(), &[], &[], &["public".to_string()], &[]).unwrap_err()
        });
        assert!(err.to_string().contains("public member to encrypted"), "msg was {}", err);
    }

    #[test]
    fn upgrades_existing_member_permission() {
        let td = TempDir::new("ark_chmod_test");
        let address = "gyan@127.0.0.1:8080".to_string();
        let key = [93u8; 32];
        create_account_with_key(&td.0, &address, &key).unwrap();

        let path = td.0.join("ark/gyan/doc.txt");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"body").unwrap();
        let mut m = get_default_test_metadata(&key, &address, b"body");
        m.encryption = "none".to_string();
        m.members.push(Member {
            address: "sam@example.com".to_string(),
            permission: "read".to_string(),
            wrapped_key: m.members[0].wrapped_key.clone(),
        });
        sign_metadata(&key, &mut m, b"body");
        write_metadata_attributes(&path, &m).unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_chmod(path.to_str().unwrap(), &[], &["sam@example.com".to_string()], &[], &[]).unwrap();
        });

        let m2 = read_metadata_attributes(&path).unwrap();
        let sam = m2.members.iter().find(|m| m.address == "sam@example.com").unwrap();
        assert_eq!(sam.permission, "write");
    }

    #[test]
    fn drops_member() {
        let td = TempDir::new("ark_chmod_test");
        let address = "gyan@127.0.0.1:8080".to_string();
        let key = [94u8; 32];
        create_account_with_key(&td.0, &address, &key).unwrap();

        let path = td.0.join("ark/gyan/doc.txt");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"body").unwrap();
        let mut m = get_default_test_metadata(&key, &address, b"body");
        m.encryption = "none".to_string();
        m.members.push(Member {
            address: "sam@example.com".to_string(),
            permission: "read".to_string(),
            wrapped_key: m.members[0].wrapped_key.clone(),
        });
        sign_metadata(&key, &mut m, b"body");
        write_metadata_attributes(&path, &m).unwrap();

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_chmod(path.to_str().unwrap(), &[], &[], &[], &["sam@example.com".to_string()]).unwrap();
        });

        let m2 = read_metadata_attributes(&path).unwrap();
        assert!(!m2.members.iter().any(|m| m.address == "sam@example.com"));
    }

    #[test]
    fn rejects_dropping_last_owner() {
        let td = TempDir::new("ark_chmod_test");
        let address = "gyan@127.0.0.1:8080".to_string();
        let key = [95u8; 32];
        create_account_with_key(&td.0, &address, &key).unwrap();
        let path = seed_local_file(&td, &address, &key, "doc.txt", b"body", "none");

        let account_dir = td.0.join("ark/gyan");
        let err = with_cwd(&account_dir, || {
            cmd_chmod(path.to_str().unwrap(), &[], &[], &[], &[address.clone()]).unwrap_err()
        });
        assert!(err.to_string().contains("at least one owner"), "msg was {}", err);
    }

    #[test]
    fn rejects_non_owner_caller() {
        let td = TempDir::new("ark_chmod_test");
        let address = "gyan@127.0.0.1:8080".to_string();
        let key = [96u8; 32];
        create_account_with_key(&td.0, &address, &key).unwrap();

        let path = td.0.join("ark/gyan/doc.txt");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"body").unwrap();
        let mut m = get_default_test_metadata(&key, &address, b"body");
        m.encryption = "none".to_string();
        m.members[0].permission = "write".to_string();
        m.members.push(Member {
            address: "boss@example.com".to_string(),
            permission: "owner".to_string(),
            wrapped_key: m.members[0].wrapped_key.clone(),
        });
        sign_metadata(&key, &mut m, b"body");
        write_metadata_attributes(&path, &m).unwrap();

        let account_dir = td.0.join("ark/gyan");
        let err = with_cwd(&account_dir, || {
            cmd_chmod(path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[]).unwrap_err()
        });
        assert!(err.to_string().contains("only an owner"), "msg was {}", err);
    }

    #[test]
    fn re_signs_metadata_so_body_hash_matches() {
        let td = TempDir::new("ark_chmod_test");
        let address = "gyan@127.0.0.1:8080".to_string();
        let key = [97u8; 32];
        create_account_with_key(&td.0, &address, &key).unwrap();
        let path = seed_local_file(&td, &address, &key, "doc.txt", b"body", "none");

        let account_dir = td.0.join("ark/gyan");
        with_cwd(&account_dir, || {
            cmd_chmod(path.to_str().unwrap(), &[], &[], &["john@example.com".to_string()], &[]).unwrap();
        });

        let m = read_metadata_attributes(&path).unwrap();
        let body = fs::read(&path).unwrap();
        let identity_key = read_identity_key(&td.0.join("ark/gyan/.ark/identity.key")).unwrap();
        let public_key = crate::crypto::to_public_key(&identity_key);
        crate::metadata::verify_metadata(&public_key, &m, &body).unwrap();
    }
}
