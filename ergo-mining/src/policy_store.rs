//! Durable miner policy, separate from boot configuration and private bytes.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::{policy::BlockPolicy, MiningError};

pub(crate) fn load(path: &Path) -> Result<Option<BlockPolicy>, MiningError> {
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(store_error(error)),
    };
    if metadata.len() > 512 * 1024 {
        return Err(MiningError::InvalidConfig(
            "mining policy file exceeds 512 KiB".into(),
        ));
    }
    let bytes = std::fs::read(path).map_err(store_error)?;
    let policy: BlockPolicy = serde_json::from_slice(&bytes).map_err(|error| {
        MiningError::InvalidConfig(format!("invalid saved mining policy: {error}"))
    })?;
    policy.validate()?;
    Ok(Some(policy))
}

pub(crate) fn save(path: &Path, policy: &BlockPolicy) -> Result<(), MiningError> {
    let directory = path.parent().ok_or_else(|| {
        MiningError::InvalidConfig("mining policy file must have a parent directory".into())
    })?;
    std::fs::create_dir_all(directory).map_err(store_error)?;
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(store_error)?;
        let bytes = serde_json::to_vec_pretty(policy)
            .map_err(|error| MiningError::InvalidConfig(error.to_string()))?;
        file.write_all(&bytes).map_err(store_error)?;
        file.sync_all().map_err(store_error)?;
        std::fs::rename(&temporary, path).map_err(store_error)?;
        #[cfg(unix)]
        std::fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(store_error)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn store_error(error: std::io::Error) -> MiningError {
    MiningError::StateRead {
        op: "mining_policy_store",
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn saved_policy_survives_reopen_and_atomic_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        assert!(load(&path).unwrap().is_none());
        let mut policy = BlockPolicy {
            required_tx_ids: vec!["ab".repeat(32)],
            ..Default::default()
        };
        save(&path, &policy).unwrap();
        assert_eq!(load(&path).unwrap(), Some(policy.clone()));
        policy.required_tx_ids.clear();
        save(&path, &policy).unwrap();
        assert_eq!(load(&path).unwrap(), Some(policy));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    // ----- error paths -----

    #[test]
    fn corrupt_saved_policy_refuses_a_silent_default() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(&path, "{}").unwrap();
        assert!(load(&path).is_ok());
        std::fs::write(&path, "{broken").unwrap();
        assert!(load(&path).is_err());
    }
}
