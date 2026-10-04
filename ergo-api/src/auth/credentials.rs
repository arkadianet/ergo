//! Named API credentials and a small durable revocation ledger.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use utoipa::ToSchema;

use super::ApiSecurity;

const MAX_REVOCATIONS: usize = 4096;
// A full ledger of 64-byte identifiers must remain readable after restart.
const MAX_LEDGER_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialScope {
    Mining,
    Wallet,
    Operator,
    Admin,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedCredentialConfig {
    pub id: String,
    pub hash: String,
    pub scopes: Vec<CredentialScope>,
}

impl std::fmt::Debug for ScopedCredentialConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedCredentialConfig")
            .field("id", &self.id)
            .field("hash", &"[redacted]")
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CredentialInfo {
    pub id: String,
    pub scopes: Vec<CredentialScope>,
    pub revoked: bool,
}

#[derive(Debug)]
pub(super) struct CredentialRegistry {
    keys: Vec<ScopedCredentialConfig>,
    revoked: RwLock<BTreeSet<String>>,
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u8,
    revoked: BTreeSet<String>,
}

pub fn validate_credentials(
    keys: &[ScopedCredentialConfig],
    master: Option<&str>,
) -> Result<(), String> {
    if keys.len() > 128 {
        return Err("at most 128 scoped API credentials may be configured".into());
    }
    if !keys.is_empty() && master.is_none() {
        return Err("scoped credentials require a master api_key_hash".into());
    }
    let mut ids = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for key in keys {
        if key.id.is_empty()
            || key.id.len() > 64
            || !key
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("credential id must be 1..64 ASCII letters, digits, '-' or '_'".into());
        }
        if !ids.insert(&key.id) {
            return Err("duplicate credential id".into());
        }
        ApiSecurity::new(key.hash.clone()).map_err(|e| e.to_string())?;
        if Some(key.hash.as_str()) == master || !hashes.insert(&key.hash) {
            return Err("credential hashes must be distinct from each other and the master".into());
        }
        if key.scopes.is_empty() {
            return Err("credential scopes cannot be empty".into());
        }
        if key.scopes.iter().collect::<BTreeSet<_>>().len() != key.scopes.len() {
            return Err("credential scopes cannot contain duplicates".into());
        }
    }
    Ok(())
}

impl CredentialRegistry {
    pub(super) fn load(keys: Vec<ScopedCredentialConfig>, path: PathBuf) -> Result<Self, String> {
        let revoked = match std::fs::metadata(&path) {
            Ok(meta) => {
                if !meta.is_file() || meta.len() > MAX_LEDGER_BYTES {
                    return Err("invalid credential revocation ledger".into());
                }
                let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
                let ledger: Ledger = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                if ledger.version != 1 || ledger.revoked.len() > MAX_REVOCATIONS {
                    return Err("unsupported or oversized credential revocation ledger".into());
                }
                ledger.revoked
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(e) => return Err(e.to_string()),
        };
        Ok(Self {
            keys,
            revoked: RwLock::new(revoked),
            path,
        })
    }

    pub(super) fn authorize(&self, hash: &str, required: CredentialScope) -> bool {
        let revoked = self
            .revoked
            .read()
            .expect("credential revocations poisoned");
        // Walk every configured digest rather than selecting by an untrusted id.
        let mut allowed = false;
        for key in &self.keys {
            let matches = bool::from(hash.as_bytes().ct_eq(key.hash.as_bytes()));
            allowed |= matches
                && !revoked.contains(&key.id)
                && (key.scopes.contains(&CredentialScope::Admin) || key.scopes.contains(&required));
        }
        allowed
    }

    pub(super) fn list(&self) -> Vec<CredentialInfo> {
        let revoked = self
            .revoked
            .read()
            .expect("credential revocations poisoned");
        self.keys
            .iter()
            .map(|key| CredentialInfo {
                id: key.id.clone(),
                scopes: key.scopes.clone(),
                revoked: revoked.contains(&key.id),
            })
            .collect()
    }

    pub(super) fn revoke(
        &self,
        id: &str,
    ) -> Result<(), crate::operator_control::OperatorControlError> {
        use crate::operator_control::OperatorControlError as Error;
        if !self.keys.iter().any(|key| key.id == id) {
            return Err(Error::NotFound("credential id is not configured".into()));
        }
        let mut revoked = self
            .revoked
            .write()
            .expect("credential revocations poisoned");
        if !revoked.contains(id) && revoked.len() >= MAX_REVOCATIONS {
            return Err(Error::Conflict("revocation ledger is full".into()));
        }
        // Fail closed in this process even if persistence fails. A failure is
        // never acknowledged as a durable revocation; retries persist the same set.
        revoked.insert(id.to_owned());
        let bytes = serde_json::to_vec(&Ledger {
            version: 1,
            revoked: revoked.clone(),
        })
        .map_err(|e| Error::Storage(e.to_string()))?;
        persist(&self.path, &bytes).map_err(|e| {
            Error::Storage(format!(
                "credential revoked in memory; ledger persistence failed: {e}"
            ))
        })
    }
}

fn persist(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(".credentials-{}-{nonce}.tmp", std::process::id()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&temp);
    result
}

/// All private routes default to operator scope unless they belong to a
/// more privileged subsystem. Admin-scoped credentials may use every group.
pub(super) fn required_scope(path: &str, admin: bool) -> CredentialScope {
    if admin
        || path == "/wallet/getPrivateKey"
        || path == "/api/v1/accounts/private-key"
        || path == "/node/shutdown"
        || path == "/api/v1/node/shutdown"
        || path.starts_with("/api/v1/node/credentials")
    {
        return CredentialScope::Admin;
    }
    if path == "/api/v1/mining/policy"
        || path.starts_with("/api/v1/mining/private-transactions")
    {
        return CredentialScope::Operator;
    }
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    if path.starts_with("/wallet")
        || path.starts_with("/scan")
        || path.starts_with("/accounts")
        || path.starts_with("/psbt")
        || path.starts_with("/transactions-psbt")
    {
        CredentialScope::Wallet
    } else if path.starts_with("/mining") || path.starts_with("/voting") || path == "/votes" {
        CredentialScope::Mining
    } else {
        CredentialScope::Operator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mining_credential_is_scoped_and_revocation_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoked.json");
        let master = ApiSecurity::hash_key(b"master");
        let keys = vec![ScopedCredentialConfig {
            id: "pool".into(),
            hash: ApiSecurity::hash_key(b"pool-key"),
            scopes: vec![CredentialScope::Mining],
        }];
        let security = ApiSecurity::new(master.clone())
            .unwrap()
            .with_credentials(keys.clone(), path.clone())
            .unwrap();
        assert!(security.authorize(b"pool-key", "/mining/candidate", false));
        assert!(security.authorize(b"pool-key", "/api/v1/mining/candidate", false));
        assert!(security.authorize(b"pool-key", "/api/v1/mining/template", false));
        assert!(security.authorize(b"pool-key", "/api/v1/mining/candidate-with-txs", false));
        assert!(!security.authorize(b"pool-key", "/api/v1/webhooks", false));
        assert!(!security.authorize(b"pool-key", "/wallet/unlock", false));
        assert!(!security.authorize(b"pool-key", "/api/v1/node/config", true));
        security.revoke_credential("pool").unwrap();
        assert!(!security.authorize(b"pool-key", "/mining/candidate", false));
        let restarted = ApiSecurity::new(master)
            .unwrap()
            .with_credentials(keys, path)
            .unwrap();
        assert!(!restarted.authorize(b"pool-key", "/mining/candidate", false));
        assert!(restarted.authorize(b"master", "/wallet/unlock", true));
        assert!(restarted.credentials()[0].revoked);
    }

    #[test]
    fn invalid_keys_and_duplicate_ids_fail_before_boot() {
        let mut key = ScopedCredentialConfig {
            id: "pool".into(),
            hash: ApiSecurity::hash_key(b"pool-key"),
            scopes: vec![CredentialScope::Mining],
        };
        assert!(validate_credentials(&[key.clone()], None).is_err());
        assert!(validate_credentials(&[key.clone(), key.clone()], Some("master")).is_err());
        key.scopes.clear();
        assert!(validate_credentials(&[key], Some("master")).is_err());
    }

    #[test]
    fn failed_revocation_persistence_denies_the_key_and_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("ledger");
        std::fs::create_dir(&parent).unwrap();
        let key = ScopedCredentialConfig {
            id: "pool".into(),
            hash: ApiSecurity::hash_key(b"pool-key"),
            scopes: vec![CredentialScope::Mining],
        };
        let security = ApiSecurity::new(ApiSecurity::hash_key(b"master"))
            .unwrap()
            .with_credentials(vec![key], parent.join("revoked.json"))
            .unwrap();
        std::fs::remove_dir(&parent).unwrap();
        std::fs::write(&parent, b"not a directory").unwrap();
        assert!(security.revoke_credential("pool").is_err());
        assert!(!security.authorize(b"pool-key", "/mining/candidate", false));
        std::fs::remove_file(&parent).unwrap();
        std::fs::create_dir(&parent).unwrap();
        security.revoke_credential("pool").unwrap();
        assert!(parent.join("revoked.json").is_file());
    }

    #[test]
    fn full_length_identifier_ledger_remains_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoked.json");
        let revoked = (0..MAX_REVOCATIONS).map(|id| format!("{id:064}")).collect();
        let bytes = serde_json::to_vec(&Ledger {
            version: 1,
            revoked,
        })
        .unwrap();
        assert!(bytes.len() > 65_536);
        assert!(bytes.len() as u64 <= MAX_LEDGER_BYTES);
        persist(&path, &bytes).unwrap();
        let registry = CredentialRegistry::load(Vec::new(), path).unwrap();
        assert_eq!(registry.revoked.read().unwrap().len(), MAX_REVOCATIONS);
    }
}
