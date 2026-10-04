use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::Mode;
use rustix::process::umask;

use thiserror::Error;
use tokio::net::UnixListener;

const OWNER_MAGIC: &str = "ergo-walletd-socket:";
// umask belongs to the process, so concurrent daemon binds must not restore
// each other's mask while one is still creating its socket.
static SOCKET_BIND_MASK: Mutex<()> = Mutex::new(());

struct RestoreUmask(Mode);
impl Drop for RestoreUmask {
    fn drop(&mut self) {
        umask(self.0);
    }
}

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("socket I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("configured socket path is not a Unix socket: {0}")]
    NotSocket(PathBuf),
    #[error("socket path has no daemon ownership marker: {0}")]
    Unowned(PathBuf),
    #[error("socket path is already served by a live process: {0}")]
    Live(PathBuf),
    #[error("socket ownership marker is invalid: {0}")]
    InvalidMarker(PathBuf),
}

pub struct UnixSocketGuard {
    path: PathBuf,
    owner_path: PathBuf,
    token: String,
    armed: bool,
}

impl UnixSocketGuard {
    pub fn claim(path: &Path) -> Result<Self, SocketError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        clean_stale_socket(path)?;
        let owner_path = owner_path(path);
        let token = format!(
            "{OWNER_MAGIC}{}:{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&owner_path)?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&owner_path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            path: path.to_path_buf(),
            owner_path,
            token,
            armed: false,
        })
    }

    pub fn cleanup(&mut self) {
        self.cleanup_inner();
        self.armed = false;
    }

    pub fn discard(&mut self) {
        if fs::read(&self.owner_path).ok().as_deref() == Some(self.token.as_bytes()) {
            let _ = fs::remove_file(&self.owner_path);
        }
        self.armed = false;
    }

    fn cleanup_inner(&self) {
        let Ok(marker) = fs::read(&self.owner_path) else {
            return;
        };
        if marker != self.token.as_bytes() {
            return;
        }
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(&self.owner_path);
    }
}

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if self.armed {
            self.cleanup_inner();
        }
    }
}

pub fn bind_restricted(path: &Path) -> Result<(UnixListener, UnixSocketGuard), SocketError> {
    let mut guard = UnixSocketGuard::claim(path)?;
    let listener = {
        let _lock = SOCKET_BIND_MASK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _restore = RestoreUmask(umask(Mode::from_bits_truncate(0o077)));
        // The socket is owner-only at creation, before the final chmod.
        UnixListener::bind(path)
    };
    let listener = match listener {
        Ok(listener) => listener,
        Err(error) => {
            guard.discard();
            return Err(error.into());
        }
    };
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(path);
        guard.cleanup();
        return Err(error.into());
    }
    guard.armed = true;
    Ok((listener, guard))
}

fn valid_owner_marker(marker: &[u8]) -> bool {
    let Some(value) = marker.strip_prefix(OWNER_MAGIC.as_bytes()) else {
        return false;
    };
    let Some(value) = std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.split_once(':'))
    else {
        return false;
    };
    value.0.parse::<u32>().is_ok() && value.1.parse::<u128>().is_ok()
}

fn owner_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".owner");
    PathBuf::from(value)
}

fn clean_stale_socket(path: &Path) -> Result<(), SocketError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_file(owner_path(path));
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket() {
        return Err(SocketError::NotSocket(path.to_path_buf()));
    }
    let owner = owner_path(path);
    let marker = fs::read(&owner).map_err(|_| SocketError::Unowned(path.to_path_buf()))?;
    if !valid_owner_marker(&marker) {
        return Err(SocketError::InvalidMarker(path.to_path_buf()));
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(SocketError::Live(path.to_path_buf())),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            fs::remove_file(path)?;
            let _ = fs::remove_file(owner);
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener as StdUnixListener;

    fn owner_for(path: &Path) -> PathBuf {
        owner_path(path)
    }

    fn make_stale_socket(path: &Path) {
        let listener = StdUnixListener::bind(path).unwrap();
        drop(listener);
        let error = UnixStream::connect(path).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::CONNREFUSED.raw_os_error())
        );
    }

    #[test]
    fn stale_owned_socket_is_removed_but_live_socket_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale.sock");
        make_stale_socket(&stale);
        fs::write(owner_for(&stale), b"ergo-walletd-socket:1:1").unwrap();
        let mut guard = UnixSocketGuard::claim(&stale).unwrap();
        assert!(!stale.exists());
        assert!(owner_for(&stale).exists());
        guard.cleanup();
        assert!(!stale.exists());
        assert!(!owner_for(&stale).exists());

        let live = dir.path().join("live.sock");
        let _listener = StdUnixListener::bind(&live).unwrap();
        let error = StdUnixListener::bind(&live).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::ADDRINUSE.raw_os_error())
        );
        fs::write(owner_for(&live), b"ergo-walletd-socket:1:1").unwrap();
        assert!(matches!(
            UnixSocketGuard::claim(&live),
            Err(SocketError::Live(_))
        ));
        assert!(live.exists());
    }

    #[test]
    fn unowned_and_non_socket_paths_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("regular");
        fs::write(&regular, b"x").unwrap();
        assert!(matches!(
            UnixSocketGuard::claim(&regular),
            Err(SocketError::NotSocket(_))
        ));
        let unowned = dir.path().join("unowned.sock");
        let _listener = StdUnixListener::bind(&unowned).unwrap();
        assert!(matches!(
            UnixSocketGuard::claim(&unowned),
            Err(SocketError::Unowned(_))
        ));
    }

    #[tokio::test]
    async fn bind_restricted_sets_owner_only_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let (listener, mut guard) = bind_restricted(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(listener);
        guard.cleanup();
        assert!(!path.exists());
    }
}
