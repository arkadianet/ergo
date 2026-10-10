//! Persist mode ownership before opening the wallet database. An unmarked
//! Phase 2 database is watch-only; migration to seed ownership is explicit
//! future work, never an interpretation of existing public keys as seed keys.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::config::{ConfigError, Network, WalletMode};

const MARKER: &str = "wallet-mode";

/// Persist network identity separately from address rendering. Offline chain
/// adapters use this marker without loading a daemon config or any secret.
pub(crate) fn claim_network(data_dir: &Path, network: Network) -> Result<(), ConfigError> {
    let path = data_dir.join("wallet-network");
    let expected = format!("{}\n", network.as_str());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(expected.as_bytes())?;
            file.sync_all()?;
            #[cfg(unix)]
            fs::File::open(data_dir)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_contents(&path, &expected)
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn claim(data_dir: &Path, mode: WalletMode) -> Result<(), ConfigError> {
    create_data_directory(data_dir, mode)?;
    if mode == WalletMode::WatchOnly && data_dir.join("wallet").try_exists()? {
        return Err(ConfigError::Invalid(
            "watch_only data_dir contains a secret store; use a separate data_dir".into(),
        ));
    }
    let marker = data_dir.join(MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => validate(&marker, mode)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if mode == WalletMode::Seed {
                // An unmarked embedded directory can have secrets plus
                // state.redb without any standalone wallet.redb. Its node
                // and daemon would not share a database lock, so adopting
                // the secrets here would silently create a second owner.
                for existing in [
                    "wallet",
                    "wallet.redb",
                    "state.redb",
                    crate::seal::WATCH_KEY_FILE,
                ] {
                    match fs::symlink_metadata(data_dir.join(existing)) {
                        Ok(_) => {
                            return Err(ConfigError::Invalid(
                                "seed mode requires a fresh data_dir; wallet data migration is not enabled"
                                    .into(),
                            ));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            protect_seed_directory(data_dir, mode)?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&marker) {
                Ok(mut file) => {
                    writeln!(file, "{}", mode.as_str())?;
                    file.sync_all()?;
                    #[cfg(unix)]
                    fs::File::open(data_dir)?.sync_all()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    validate(&marker, mode)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    protect_seed_directory(data_dir, mode)
}

/// Persist each newly created directory name before opening a wallet there.
/// A later secret-store creation only knows that `data_dir` already exists,
/// so it cannot supply these ancestor durability barriers retroactively.
fn create_data_directory(data_dir: &Path, mode: WalletMode) -> Result<(), ConfigError> {
    #[cfg(unix)]
    let missing: Vec<_> = data_dir
        .ancestors()
        .take_while(|ancestor| !ancestor.as_os_str().is_empty() && !ancestor.exists())
        .map(Path::to_path_buf)
        .collect();
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    // Watch-only data is as private as a seed wallet's: both are owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    let _ = mode;
    builder.create(data_dir)?;
    #[cfg(unix)]
    for created in missing.iter().rev() {
        fs::File::open(created)?.sync_all()?;
        let parent = created
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn protect_seed_directory(data_dir: &Path, mode: WalletMode) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))?;
        fs::File::open(data_dir)?.sync_all()?;
    }
    let _ = mode;
    #[cfg(not(unix))]
    let _ = data_dir;
    Ok(())
}

fn validate(marker: &Path, mode: WalletMode) -> Result<(), ConfigError> {
    validate_contents(marker, &format!("{}\n", mode.as_str()))
}

fn validate_contents(marker: &Path, expected: &str) -> Result<(), ConfigError> {
    let invalid = || {
        ConfigError::Invalid(
            "data_dir wallet ownership or network does not match configuration; use a separate data_dir"
                .into(),
        )
    };
    if !fs::symlink_metadata(marker)?.is_file() {
        return Err(invalid());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options.open(marker)?;
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut contents = String::new();
    file.take(32).read_to_string(&mut contents)?;
    if contents != expected {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_persists_and_prevents_mode_changes() {
        for mode in [WalletMode::WatchOnly, WalletMode::Seed] {
            let dir = tempfile::tempdir().unwrap();
            claim(dir.path(), mode).unwrap();
            claim(dir.path(), mode).unwrap();
            let other = match mode {
                WalletMode::WatchOnly => WalletMode::Seed,
                WalletMode::Seed => WalletMode::WatchOnly,
            };
            assert!(claim(dir.path(), other).is_err());
            assert_eq!(
                fs::read_to_string(dir.path().join(MARKER)).unwrap(),
                format!("{}\n", mode.as_str())
            );
        }
    }

    #[test]
    fn legacy_watch_database_cannot_be_claimed_as_seed() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("wallet.redb");
        fs::write(&database, b"existing public wallet").unwrap();
        assert!(claim(dir.path(), WalletMode::Seed).is_err());
        assert!(!dir.path().join(MARKER).exists());
        assert_eq!(fs::read(&database).unwrap(), b"existing public wallet");
        claim(dir.path(), WalletMode::WatchOnly).unwrap();
    }

    #[test]
    fn unmarked_embedded_secrets_and_state_are_never_adopted_or_modified() {
        for (has_secrets, has_state) in [(true, false), (false, true), (true, true)] {
            let dir = tempfile::tempdir().unwrap();
            let secret = dir.path().join("wallet/existing.json");
            let state = dir.path().join("state.redb");
            if has_secrets {
                fs::create_dir(dir.path().join("wallet")).unwrap();
                fs::write(&secret, b"existing encrypted seed").unwrap();
            }
            if has_state {
                fs::write(&state, b"existing embedded state").unwrap();
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
            }
            assert!(claim(dir.path(), WalletMode::Seed).is_err());
            assert!(!dir.path().join(MARKER).exists());
            assert!(!dir.path().join("wallet.redb").exists());
            if has_secrets {
                assert_eq!(fs::read(secret).unwrap(), b"existing encrypted seed");
            }
            if has_state {
                assert_eq!(fs::read(state).unwrap(), b"existing embedded state");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
                    0o755
                );
            }
        }
    }

    #[test]
    fn corrupt_markers_and_seed_stores_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(MARKER), b"seed\ntrailing data").unwrap();
        assert!(claim(dir.path(), WalletMode::Seed).is_err());
        fs::remove_file(dir.path().join(MARKER)).unwrap();
        fs::create_dir(dir.path().join("wallet")).unwrap();
        assert!(claim(dir.path(), WalletMode::WatchOnly).is_err());
        assert!(!dir.path().join(MARKER).exists());
    }

    #[cfg(unix)]
    #[test]
    fn seed_directory_is_private_and_marker_symlinks_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        claim(dir.path(), WalletMode::Seed).unwrap();
        assert_eq!(
            fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let other = tempfile::tempdir().unwrap();
        symlink(dir.path().join(MARKER), other.path().join(MARKER)).unwrap();
        assert!(claim(other.path(), WalletMode::Seed).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn new_seed_directory_ancestors_are_private_and_ownership_reopens() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("new-parent");
        let data_dir = parent.join("wallet-data");
        claim(&data_dir, WalletMode::Seed).unwrap();
        for created in [&parent, &data_dir] {
            assert_eq!(
                fs::metadata(created).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::metadata(data_dir.join(MARKER))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        claim(&data_dir, WalletMode::Seed).unwrap();
        assert!(claim(&data_dir, WalletMode::WatchOnly).is_err());
    }
}
