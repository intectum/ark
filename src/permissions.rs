use crate::types::{Member, Permission, Permissions};

pub fn owner(address: impl Into<String>) -> Permissions {
    owners([address])
}

pub fn writer(address: impl Into<String>) -> Permissions {
    writers([address])
}

pub fn reader(address: impl Into<String>) -> Permissions {
    readers([address])
}

pub fn drop(address: impl Into<String>) -> Permissions {
    drops([address])
}

pub fn owners(addresses: impl IntoIterator<Item = impl Into<String>>) -> Permissions {
    Permissions {
        owners: addresses.into_iter().map(Into::into).collect(),
        ..Default::default()
    }
}

pub fn writers(addresses: impl IntoIterator<Item = impl Into<String>>) -> Permissions {
    Permissions {
        writers: addresses.into_iter().map(Into::into).collect(),
        ..Default::default()
    }
}

pub fn readers(addresses: impl IntoIterator<Item = impl Into<String>>) -> Permissions {
    Permissions {
        readers: addresses.into_iter().map(Into::into).collect(),
        ..Default::default()
    }
}

pub fn drops(addresses: impl IntoIterator<Item = impl Into<String>>) -> Permissions {
    Permissions {
        drops: addresses.into_iter().map(Into::into).collect(),
        ..Default::default()
    }
}

pub fn without(members: &[Member], address: &str) -> Vec<Member> {
    let wire = cli_address_to_wire(address);
    members.iter().filter(|member| member.address != wire).cloned().collect()
}

pub fn assign(members: &[Member], permission: Permission) -> Permissions {
    let addresses = members.iter().map(|member| member.address.clone());

    match permission {
        Permission::Owner => owners(addresses),
        Permission::Writer => writers(addresses),
        Permission::Reader => readers(addresses),
    }
}

pub fn map(members: &[Member], f: impl Fn(Permission) -> Permission) -> Permissions {
    let mut permissions = Permissions::default();

    for member in members {
        match f(member.permission) {
            Permission::Owner => permissions.owners.push(member.address.clone()),
            Permission::Writer => permissions.writers.push(member.address.clone()),
            Permission::Reader => permissions.readers.push(member.address.clone()),
        }
    }

    permissions
}

pub fn cli_address_to_wire(addr: &str) -> String {
    if addr == "public" { "*".to_string() } else { addr.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_removes_matching_address() {
        let members = [
            Member { address: "a@x".to_string(), permission: Permission::Owner, key: None },
            Member { address: "b@y".to_string(), permission: Permission::Writer, key: None },
        ];
        let got = without(&members, "a@x");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].address, "b@y");
    }

    #[test]
    fn without_translates_public_alias() {
        let members = [
            Member { address: "*".to_string(), permission: Permission::Reader, key: None },
            Member { address: "a@x".to_string(), permission: Permission::Owner, key: None },
        ];
        let got = without(&members, "public");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].address, "a@x");
    }

    #[test]
    fn assign_collects_all_into_one_role() {
        let members = [
            Member { address: "a@x".to_string(), permission: Permission::Owner, key: None },
            Member { address: "b@y".to_string(), permission: Permission::Writer, key: None },
        ];
        let perms = assign(&members, Permission::Reader);
        assert_eq!(perms.readers, vec!["a@x".to_string(), "b@y".to_string()]);
        assert!(perms.owners.is_empty());
        assert!(perms.writers.is_empty());
        assert!(perms.drops.is_empty());
    }

    #[test]
    fn map_remaps_per_member_permission() {
        let members = [
            Member { address: "a@x".to_string(), permission: Permission::Owner, key: None },
            Member { address: "b@y".to_string(), permission: Permission::Writer, key: None },
            Member { address: "c@z".to_string(), permission: Permission::Reader, key: None },
        ];
        let perms = map(&members, |p| match p {
            Permission::Owner => Permission::Owner,
            _ => Permission::Reader,
        });
        assert_eq!(perms.owners, vec!["a@x".to_string()]);
        assert_eq!(perms.readers, vec!["b@y".to_string(), "c@z".to_string()]);
        assert!(perms.writers.is_empty());
    }

    #[test]
    fn plural_helpers_collect_addresses() {
        let perms = readers(["a@x", "b@y"]);
        assert_eq!(perms.readers, vec!["a@x".to_string(), "b@y".to_string()]);
        assert!(perms.owners.is_empty());

        let perms = writers(vec!["a@x".to_string(), "b@y".to_string()]);
        assert_eq!(perms.writers, vec!["a@x".to_string(), "b@y".to_string()]);

        let perms = owners(["a@x"]);
        assert_eq!(perms.owners, vec!["a@x".to_string()]);

        let perms = drops(["a@x", "b@y"]);
        assert_eq!(perms.drops, vec!["a@x".to_string(), "b@y".to_string()]);
    }

    #[test]
    fn singular_helpers_match_one_element_plurals() {
        assert_eq!(reader("a@x").readers, readers(["a@x"]).readers);
        assert_eq!(writer("a@x").writers, writers(["a@x"]).writers);
        assert_eq!(owner("a@x").owners, owners(["a@x"]).owners);
        assert_eq!(drop("a@x").drops, drops(["a@x"]).drops);
    }
}
