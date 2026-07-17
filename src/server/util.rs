use std::fs;
use std::io::{Result, Write};
use std::path::Path;

use crate::metadata::{read_metadata_attributes, write_metadata_attributes};
use crate::types::{Member, Metadata, Permission};

pub fn write_target(fs_path: &Path, body: &[u8], metadata: &Metadata, target_is_dir: bool) -> Result<()> {
    if target_is_dir {
        fs::create_dir_all(fs_path)?;
    } else {
        if let Some(parent) = fs_path.parent() { fs::create_dir_all(parent)?; }
        let mut file = fs::File::create(fs_path)?;
        file.write_all(body)?;
    }

    write_metadata_attributes(fs_path, metadata)?;

    Ok(())
}

pub fn find_ancestor_members(fs_path: &Path, fs_account_path: &Path) -> Option<Vec<Member>> {
    let mut current = fs_path.parent()?;
    while current.starts_with(fs_account_path) {
        if let Ok(m) = read_metadata_attributes(current) {
            return Some(m.members);
        }
        current = current.parent()?;
    }
    None
}

pub fn members_changed(old: &[Member], new: &[Member]) -> bool {
    if old.len() != new.len() { return true; }
    let mut old_set: Vec<(&str, Permission)> = old.iter().map(|m| (m.address.as_str(), m.permission)).collect();
    let mut new_set: Vec<(&str, Permission)> = new.iter().map(|m| (m.address.as_str(), m.permission)).collect();
    old_set.sort_by(|a, b| a.0.cmp(b.0));
    new_set.sort_by(|a, b| a.0.cmp(b.0));
    old_set != new_set
}
