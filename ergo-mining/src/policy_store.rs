//! Durable miner policy, separate from boot configuration and private bytes.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{policy::BlockPolicy, MiningError};

pub(crate) fn load(path: &Path) -> Result<Option<BlockPolicy>, MiningError> {
    remove_stale_temporaries(path);
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

/// Atomically replace the saved policy. Every error is a storage error and
/// leaves the saved file unchanged. `Ok(Some(warning))`: the new file did
/// replace the old one, but its directory entry could not be synced. That
/// replacement is visible and treated as committed; only its durability
/// across a power loss is uncertain.
pub(crate) fn save(path: &Path, policy: &BlockPolicy) -> Result<Option<String>, MiningError> {
    let directory = path
        .parent()
        .ok_or_else(|| store_error(std::io::Error::other("the path has no parent directory")))?;
    std::fs::create_dir_all(directory).map_err(store_error)?;
    let bytes = serde_json::to_vec_pretty(policy)
        .map_err(|error| store_error(std::io::Error::other(error)))?;
    let temporary = temporary_path(path);
    let replaced = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        #[cfg(test)]
        hooks::before_replace();
        std::fs::rename(&temporary, path)
    })();
    if let Err(error) = replaced {
        let _ = std::fs::remove_file(&temporary);
        return Err(store_error(error));
    }
    Ok(sync_directory(directory).err().map(|error| {
        format!(
            "{} replaced, but its directory entry was not synced: {error}",
            path.display()
        )
    }))
}

fn sync_directory(directory: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    hooks::directory_sync()?;
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

/// `<stem>.<pid>-<nanos>.tmp` beside `path`. The nonce keeps a restarted
/// process that reuses the PID (PID 1 in a container) from colliding with a
/// temporary a crash left behind; [`load`] removes such leftovers.
fn temporary_path(path: &Path) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_extension(format!("{}-{nonce}.tmp", std::process::id()))
}

/// Best-effort removal of temporaries a crash left beside `path`, including
/// the PID-only `<stem>.<pid>.tmp` names of earlier builds.
fn remove_stale_temporaries(path: &Path) {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (Some(stem), Ok(entries)) = (
        path.file_stem().and_then(|stem| stem.to_str()),
        std::fs::read_dir(directory),
    ) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let leftover = name
            .to_str()
            .and_then(|name| name.strip_prefix(stem)?.strip_prefix('.'))
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .is_some_and(|middle| {
                !middle.is_empty() && middle.bytes().all(|b| b.is_ascii_digit() || b == b'-')
            });
        if leftover {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn store_error(error: std::io::Error) -> MiningError {
    MiningError::StateRead {
        op: "mining_policy_store",
        reason: error.to_string(),
    }
}

/// Test seams inside [`save`], set per thread.
#[cfg(test)]
pub(crate) mod hooks {
    use std::cell::{Cell, RefCell};

    thread_local! {
        /// Runs after the new policy is written, before it replaces the old.
        pub(crate) static BEFORE_REPLACE: RefCell<Option<Box<dyn FnMut()>>> =
            const { RefCell::new(None) };
        /// Fails the directory sync that follows a replacement.
        pub(crate) static FAIL_DIRECTORY_SYNC: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn before_replace() {
        BEFORE_REPLACE.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
    }

    pub(super) fn directory_sync() -> std::io::Result<()> {
        if FAIL_DIRECTORY_SYNC.with(Cell::get) {
            return Err(std::io::Error::other("injected directory sync failure"));
        }
        Ok(())
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

    #[test]
    fn a_crash_leftover_with_this_pid_does_not_block_saving_and_is_removed_on_load() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mining-policy.json");
        // What a crash mid-save leaves, as the earlier PID-only name and as
        // the current PID-and-nonce name.
        let legacy = path.with_extension(format!("{}.tmp", std::process::id()));
        let current = temporary_path(&path);
        let unrelated = directory.path().join("mining-policy.json.tmp");
        for leftover in [&legacy, &current, &unrelated] {
            std::fs::write(leftover, "{partial").unwrap();
        }
        let policy = BlockPolicy {
            required_tx_ids: vec!["cd".repeat(32)],
            ..Default::default()
        };
        assert_eq!(save(&path, &policy).unwrap(), None);
        assert_eq!(load(&path).unwrap(), Some(policy));
        assert!(!legacy.exists());
        assert!(!current.exists());
        assert!(
            unrelated.exists(),
            "only this store's temporaries are removed"
        );
    }

    #[test]
    fn a_failed_directory_sync_after_the_replacement_still_commits() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mining-policy.json");
        save(&path, &BlockPolicy::default()).unwrap();
        let policy = BlockPolicy {
            rent_max_cost_basis_points: 0,
            ..Default::default()
        };
        hooks::FAIL_DIRECTORY_SYNC.with(|fail| fail.set(true));
        let saved = save(&path, &policy);
        hooks::FAIL_DIRECTORY_SYNC.with(|fail| fail.set(false));
        assert!(saved.unwrap().unwrap().contains("not synced"));
        assert_eq!(load(&path).unwrap(), Some(policy));
    }

    // ----- error paths -----

    #[test]
    fn storage_failures_are_storage_errors_and_keep_the_saved_policy() {
        let directory = tempfile::tempdir().unwrap();
        let blocker = directory.path().join("not-a-directory");
        std::fs::write(&blocker, "").unwrap();
        assert!(matches!(
            save(&blocker.join("mining-policy.json"), &BlockPolicy::default()),
            Err(MiningError::StateRead { .. })
        ));
    }

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
