use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use ergo_ser::address::NetworkPrefix;
use ergo_wallet::address::pubkey_to_p2pk_address;
use ergo_wallet_service::{TrackedPubkeyMeta, WalletStore, WalletStoreError};
use serde::Deserialize;
use thiserror::Error;

const MAX_DESCRIPTOR_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum DescriptorError {
    #[error("descriptor file is invalid: {0}")]
    Invalid(String),
    #[error("descriptor store failure: {0}")]
    Store(#[from] WalletStoreError),
    #[error("descriptor file I/O failure: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorEntry {
    pub path: Vec<u32>,
    pub public_key: [u8; 33],
    pub label: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub added: usize,
    pub unchanged: usize,
}

impl ImportReport {
    pub fn changed(&self) -> bool {
        self.added != 0
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    #[serde(alias = "publicKey", alias = "pubkey", alias = "pubkey_hex")]
    public_key: Option<String>,
    #[serde(alias = "derivationPath", alias = "derivation_path")]
    path: Option<String>,
    label: Option<String>,
    curve: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawFile {
    version: Option<u32>,
    #[serde(alias = "entries")]
    descriptors: Option<Vec<RawEntry>>,
    keys: Option<Vec<RawEntry>>,
}

pub fn parse_file(path: &Path) -> Result<Vec<DescriptorEntry>, DescriptorError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(DescriptorError::Invalid(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_DESCRIPTOR_FILE_BYTES {
        return Err(DescriptorError::Invalid("file is too large".to_string()));
    }
    let bytes = fs::read(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| DescriptorError::Invalid("file is not UTF-8".to_string()))?;
    parse_text(text)
}

pub fn parse_text(text: &str) -> Result<Vec<DescriptorEntry>, DescriptorError> {
    let raw_entries = if let Ok(file) = serde_json::from_str::<RawFile>(text) {
        entries_from_file(file)?
    } else if let Ok(entries) = serde_json::from_str::<Vec<RawEntry>>(text) {
        entries
    } else {
        let file: RawFile =
            toml::from_str(text).map_err(|error| DescriptorError::Invalid(error.to_string()))?;
        entries_from_file(file)?
    };
    validate_entries(raw_entries)
}

fn entries_from_file(file: RawFile) -> Result<Vec<RawEntry>, DescriptorError> {
    if file.version.is_some_and(|version| version != 1) {
        return Err(DescriptorError::Invalid(
            "descriptor file version must be 1".to_string(),
        ));
    }
    match (file.descriptors, file.keys) {
        (Some(descriptors), None) => Ok(descriptors),
        (None, Some(keys)) => Ok(keys),
        (None, None) => Err(DescriptorError::Invalid(
            "descriptor file must contain descriptors or keys".to_string(),
        )),
        (Some(_), Some(_)) => Err(DescriptorError::Invalid(
            "descriptor file must not contain both descriptors and keys".to_string(),
        )),
    }
}

fn validate_entries(entries: Vec<RawEntry>) -> Result<Vec<DescriptorEntry>, DescriptorError> {
    if entries.is_empty() {
        return Err(DescriptorError::Invalid(
            "descriptor file must contain at least one key".to_string(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut result = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let path_text = entry
            .path
            .ok_or_else(|| DescriptorError::Invalid(format!("entry {index} is missing path")))?;
        let key_text = entry.public_key.ok_or_else(|| {
            DescriptorError::Invalid(format!("entry {index} is missing public_key"))
        })?;
        if let Some(curve) = entry.curve {
            if curve != "secp256k1" {
                return Err(DescriptorError::Invalid(format!(
                    "entry {index} uses an unsupported curve"
                )));
            }
        }
        let path = parse_path(&path_text)?;
        let public_key = parse_public_key(&key_text)?;
        pubkey_to_p2pk_address(&public_key, NetworkPrefix::Mainnet).map_err(|_| {
            DescriptorError::Invalid(format!("entry {index} is not a valid curve point"))
        })?;
        if !paths.insert(path.clone()) {
            return Err(DescriptorError::Invalid(format!(
                "entry {index} duplicates a derivation path"
            )));
        }
        if !keys.insert(public_key) {
            return Err(DescriptorError::Invalid(format!(
                "entry {index} duplicates a public key"
            )));
        }
        let label = entry.label.unwrap_or_default();
        if label.len() > 256 {
            return Err(DescriptorError::Invalid(format!(
                "entry {index} label is too long"
            )));
        }
        result.push(DescriptorEntry {
            path,
            public_key,
            label,
        });
    }
    Ok(result)
}

fn parse_public_key(value: &str) -> Result<[u8; 33], DescriptorError> {
    if value.len() != 66
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DescriptorError::Invalid(
            "public_key must be 66 lowercase hexadecimal characters".to_string(),
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| DescriptorError::Invalid("public_key is not hexadecimal".to_string()))?;
    let public_key: [u8; 33] = bytes
        .try_into()
        .map_err(|_| DescriptorError::Invalid("public_key must be 33 bytes".to_string()))?;
    if !matches!(public_key[0], 2 | 3) {
        return Err(DescriptorError::Invalid(
            "public_key must use a compressed SEC1 prefix".to_string(),
        ));
    }
    Ok(public_key)
}

fn parse_path(value: &str) -> Result<Vec<u32>, DescriptorError> {
    if value.is_empty() || value.len() > 512 {
        return Err(DescriptorError::Invalid(
            "path is empty or too long".to_string(),
        ));
    }
    let mut components = value.split('/');
    if matches!(components.next(), Some("m" | "M")) {
    } else {
        return Err(DescriptorError::Invalid(
            "path must start with m/".to_string(),
        ));
    }
    let mut result = Vec::new();
    for component in components {
        if component.is_empty() {
            return Err(DescriptorError::Invalid(String::from(
                "path contains an empty component",
            )));
        }
        let (digits, hardened) = if let Some(value) = component.strip_suffix('\'') {
            (value, true)
        } else if let Some(value) = component.strip_suffix('h') {
            (value, true)
        } else if let Some(value) = component.strip_suffix('H') {
            (value, true)
        } else {
            (component, false)
        };
        if digits.is_empty()
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return Err(DescriptorError::Invalid(format!(
                "invalid path component {component}"
            )));
        }
        let value: u32 = digits.parse().map_err(|_| {
            DescriptorError::Invalid(String::from("path component is out of range"))
        })?;
        if value > 0x7fff_ffff {
            return Err(DescriptorError::Invalid(String::from(
                "path component is out of range",
            )));
        }
        result.push(if hardened { value | 0x8000_0000 } else { value });
        if result.len() > 255 {
            return Err(DescriptorError::Invalid(String::from("path is too long")));
        }
    }
    Ok(result)
}

pub fn import(
    store: &dyn WalletStore,
    entries: &[DescriptorEntry],
) -> Result<ImportReport, DescriptorError> {
    if entries.is_empty() {
        return Err(DescriptorError::Invalid(String::from(
            "at least one descriptor is required",
        )));
    }
    let existing = store.read()?.tracked_addresses_with_meta()?;
    let existing_max = existing.iter().map(|item| item.path_idx).max();
    let mut by_path = BTreeMap::new();
    let mut by_key = BTreeMap::new();
    for item in existing {
        by_path.insert(item.derivation_path.clone(), item.pubkey);
        by_key.insert(item.pubkey, item.derivation_path.clone());
    }
    let mut additions = Vec::new();
    let mut unchanged = 0;
    for entry in entries {
        if let Some(existing_key) = by_path.get(&entry.path) {
            if *existing_key != entry.public_key {
                return Err(DescriptorError::Invalid(String::from(
                    "descriptor path is already assigned to another public key",
                )));
            }
            unchanged += 1;
            continue;
        }
        if let Some(existing_path) = by_key.get(&entry.public_key) {
            if existing_path != &entry.path {
                return Err(DescriptorError::Invalid(String::from(
                    "descriptor public key is already assigned to another path",
                )));
            }
            unchanged += 1;
            continue;
        }
        by_path.insert(entry.path.clone(), entry.public_key);
        by_key.insert(entry.public_key, entry.path.clone());
        additions.push(entry);
    }
    if additions.is_empty() {
        return Ok(ImportReport {
            added: 0,
            unchanged,
        });
    }
    let mut next_index = existing_max
        .map(|index| index.saturating_add(1))
        .unwrap_or(0);
    let mut write = store.begin_write()?;
    let added = additions.len();
    for entry in &additions {
        write.insert_tracked_pubkey(
            next_index,
            entry.public_key,
            &TrackedPubkeyMeta {
                derivation_path: entry.path.clone(),
                derivation_path_label: entry.label.clone(),
                added_at_height: 0,
            },
        )?;
        next_index = next_index.saturating_add(1);
    }
    write.rebuild_visible_addresses()?;
    write.commit()?;
    Ok(ImportReport { added, unchanged })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_service::RedbWalletStore;

    const KEY: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

    #[test]
    fn accepts_public_descriptor_records_and_rejects_secrets() {
        let text = format!(
            r#"version = 1
[[keys]]
path = "m/44'/429'/0'/0/0"
public_key = "{KEY}"
"#
        );
        let entries = parse_text(&text).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(parse_text(&format!(
            r#"version=1
[[keys]]
path="m/0"
public_key="{KEY}"
private_key="secret"
"#
        ))
        .is_err());
        assert!(parse_text(&format!(
            r#"version=1
[[keys]]
path="m/0"
public_key="{KEY}"
curve="ed25519"
"#
        ))
        .is_err());
    }

    #[test]
    fn rejects_duplicate_and_invalid_paths_and_keys() {
        let duplicate = format!(
            r#"[[keys]]
path="m/0"
public_key="{KEY}"
[[keys]]
path="m/0"
public_key="{KEY}"
"#
        );
        assert!(parse_text(&duplicate).is_err());
        assert!(parse_text(&format!(
            r#"keys=[{{path="m/0",public_key="{KEY}"}},{{path="m/1",public_key="{KEY}"}}]"#
        ))
        .is_err());
        assert!(parse_text(&format!(r#"keys=[{{path="m/0/01",public_key="{KEY}"}}]"#)).is_err());
        assert!(parse_text(&format!(
            r#"keys=[{{path="m/0",public_key="{}"}}]"#,
            "04".repeat(33)
        ))
        .is_err());
    }

    #[test]
    fn import_is_idempotent_and_reopenable() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap();
        let entries = parse_text(&format!(
            r#"keys=[{{path="m/44'/429'/0'/0/0",public_key="{KEY}"}}]"#
        ))
        .unwrap();
        let report = import(&store, &entries).unwrap();
        assert_eq!(report.added, 1);
        assert_eq!(import(&store, &entries).unwrap().added, 0);
        drop(store);
        let reopened = RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap();
        let read = reopened.read().unwrap();
        assert_eq!(read.tracked_addresses_with_meta().unwrap().len(), 1);
        assert_eq!(read.tracked_addresses_with_meta().unwrap()[0].path_idx, 0);
    }
}
