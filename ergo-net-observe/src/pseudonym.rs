//! Keyed pseudonymisation for peer addresses.
//!
//! The dataset must be publishable without exposing peer IPs. Addresses are
//! replaced by `hex(Blake2b256(key ‖ "ergo-observer-peer" ‖ addr)[..16])`.
//! The key is generated once (or supplied by the operator) and kept private;
//! without it the pseudonyms are not reversible, and two runs with different
//! keys do not join.
//!
//! This is a keyed PRF, not a signature. Blake2b-256 is not length-extendable,
//! so a length-prefixed domain separation is sufficient here; the key is
//! never written into the JSONL stream.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;

use ergo_primitives::digest::blake2b256;

const DOMAIN: &[u8] = b"ergo-observer-peer\0";

/// Holds the private key and whether pseudonymisation is enabled.
#[derive(Clone)]
pub struct Pseudonymizer {
    key: Arc<[u8; 32]>,
    enabled: bool,
}

impl std::fmt::Debug for Pseudonymizer {
    /// Never render the key: `Debug` output ends up in logs and test
    /// failures.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pseudonymizer")
            .field("key", &"<redacted>")
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl Pseudonymizer {
    /// Load a 64-hex-character key from `path`, creating a random one with
    /// owner-only permissions when the file does not exist.
    pub fn from_key_file(path: &Path, enabled: bool) -> io::Result<Self> {
        let key = match fs::read_to_string(path) {
            Ok(text) => parse_key(text.trim())?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let key: [u8; 32] = rand::random();
                write_key_file(path, &key)?;
                key
            }
            Err(e) => return Err(e),
        };
        Ok(Self {
            key: Arc::new(key),
            enabled,
        })
    }

    /// Deterministic key, used by tests and by operators who keep their own
    /// key material.
    pub fn from_key(key: [u8; 32], enabled: bool) -> Self {
        Self {
            key: Arc::new(key),
            enabled,
        }
    }

    /// `true` when records carry pseudonyms instead of raw addresses.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Pseudonymise one `addr` string. Deterministic for a fixed key.
    pub fn peer_id(&self, addr: &str) -> String {
        if !self.enabled {
            return addr.to_string();
        }
        let mut input = Vec::with_capacity(DOMAIN.len() + 32 + addr.len());
        input.extend_from_slice(DOMAIN);
        input.extend_from_slice(self.key.as_ref());
        input.extend_from_slice(addr.as_bytes());
        let digest = blake2b256(&input);
        hex::encode(&digest.as_bytes()[..16])
    }
}

fn parse_key(text: &str) -> io::Result<[u8; 32]> {
    let bytes = hex::decode(text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("key hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("key must be 32 bytes (64 hex chars), got {}", bytes.len()),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn write_key_file(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        writeln!(f, "{}", hex::encode(key))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, format!("{}\n", hex::encode(key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonym_is_deterministic_and_key_dependent() {
        let a = Pseudonymizer::from_key([1u8; 32], true);
        let b = Pseudonymizer::from_key([1u8; 32], true);
        let c = Pseudonymizer::from_key([2u8; 32], true);
        let id = a.peer_id("203.0.113.7:9030");
        assert_eq!(id, b.peer_id("203.0.113.7:9030"));
        assert_ne!(id, c.peer_id("203.0.113.7:9030"));
        assert_eq!(id.len(), 32);
        assert!(!id.contains("203.0.113.7"));
    }

    #[test]
    fn pseudonym_is_injective_for_distinct_addresses() {
        let a = Pseudonymizer::from_key([3u8; 32], true);
        assert_ne!(a.peer_id("a:1"), a.peer_id("a:2"));
    }

    #[test]
    fn disabled_pseudonym_returns_raw_address() {
        let a = Pseudonymizer::from_key([4u8; 32], false);
        assert_eq!(a.peer_id("127.0.0.1:9030"), "127.0.0.1:9030");
    }

    #[test]
    fn key_file_round_trips_and_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pseudonym.key");
        let a = Pseudonymizer::from_key_file(&path, true).unwrap();
        let b = Pseudonymizer::from_key_file(&path, true).unwrap();
        assert_eq!(a.peer_id("1.2.3.4:5"), b.peer_id("1.2.3.4:5"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
