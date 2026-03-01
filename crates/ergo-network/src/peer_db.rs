use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::warn;

const WRITE_DEBOUNCE: Duration = Duration::from_secs(60);

/// A file-based peer database for persistence across restarts.
///
/// Stores known peer addresses as a JSON file at `{data_dir}/peers.json`.
pub struct PeerDb {
    path: PathBuf,
    peers: HashSet<SocketAddr>,
    dirty: bool,
    last_write: Option<Instant>,
}

impl PeerDb {
    /// Create a new `PeerDb`, loading from disk if the file exists.
    pub fn new(data_dir: &Path) -> Self {
        let path = data_dir.join("peers.json");
        let peers = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => match serde_json::from_str::<Vec<String>>(&contents) {
                    Ok(addrs) => {
                        let mut set = HashSet::new();
                        for s in addrs {
                            match s.parse::<SocketAddr>() {
                                Ok(addr) => {
                                    set.insert(addr);
                                }
                                Err(e) => {
                                    warn!("PeerDb: invalid address '{}': {}", s, e);
                                }
                            }
                        }
                        set
                    }
                    Err(e) => {
                        warn!("PeerDb: corrupt peers.json, ignoring: {}", e);
                        HashSet::new()
                    }
                },
                Err(e) => {
                    warn!("PeerDb: failed to read peers.json: {}", e);
                    HashSet::new()
                }
            }
        } else {
            HashSet::new()
        };

        PeerDb {
            path,
            peers,
            dirty: false,
            last_write: None,
        }
    }

    /// Add a peer address. Returns `true` if the address was new.
    pub fn add(&mut self, addr: SocketAddr) -> bool {
        let new = self.peers.insert(addr);
        if new {
            self.dirty = true;
        }
        new
    }

    /// Remove a peer address. Returns `true` if the address existed.
    pub fn remove(&mut self, addr: &SocketAddr) -> bool {
        let existed = self.peers.remove(addr);
        if existed {
            self.dirty = true;
        }
        existed
    }

    /// Return a reference to the set of known peers.
    pub fn peers(&self) -> &HashSet<SocketAddr> {
        &self.peers
    }

    /// Return the number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Return whether the peer set is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Flush to disk if dirty AND more than 60 seconds since last write (debounce).
    pub fn maybe_flush(&mut self) {
        if !self.dirty {
            return;
        }
        if let Some(last) = self.last_write {
            if last.elapsed() < WRITE_DEBOUNCE {
                return;
            }
        }
        self.flush();
    }

    /// Force write to disk immediately.
    pub fn flush(&mut self) {
        let addrs: Vec<String> = self.peers.iter().map(|a| a.to_string()).collect();
        match serde_json::to_string_pretty(&addrs) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.path, json) {
                    warn!("PeerDb: failed to write peers.json: {}", e);
                    return;
                }
            }
            Err(e) => {
                warn!("PeerDb: failed to serialize peers: {}", e);
                return;
            }
        }
        self.dirty = false;
        self.last_write = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn new_empty_dir_creates_empty_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = PeerDb::new(dir.path());
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
    }

    #[test]
    fn add_returns_true_for_new() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = PeerDb::new(dir.path());
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        assert!(db.add(addr));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn add_returns_false_for_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = PeerDb::new(dir.path());
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        assert!(db.add(addr));
        assert!(!db.add(addr));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn remove_returns_true_for_existing() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = PeerDb::new(dir.path());
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        db.add(addr);
        assert!(db.remove(&addr));
        assert!(db.is_empty());
        // Removing again should return false
        assert!(!db.remove(&addr));
    }

    #[test]
    fn flush_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.1:9030".parse().unwrap();

        {
            let mut db = PeerDb::new(dir.path());
            db.add(addr1);
            db.add(addr2);
            db.flush();
        }

        // Reload from same directory
        let db2 = PeerDb::new(dir.path());
        assert_eq!(db2.len(), 2);
        assert!(db2.peers().contains(&addr1));
        assert!(db2.peers().contains(&addr2));
    }

    #[test]
    fn maybe_flush_respects_debounce() {
        let dir = tempfile::tempdir().unwrap();
        let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.1:9030".parse().unwrap();

        let mut db = PeerDb::new(dir.path());
        db.add(addr1);
        db.flush(); // This sets last_write to now

        // Add another peer, then maybe_flush — should NOT write due to debounce
        db.add(addr2);
        db.maybe_flush();

        // Reload — should only see addr1 (addr2 was not flushed)
        let db2 = PeerDb::new(dir.path());
        assert_eq!(db2.len(), 1);
        assert!(db2.peers().contains(&addr1));
        assert!(!db2.peers().contains(&addr2));
    }

    #[test]
    fn corrupt_file_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        std::fs::write(&path, "this is not valid json!!!").unwrap();

        let db = PeerDb::new(dir.path());
        assert!(db.is_empty());
    }
}
