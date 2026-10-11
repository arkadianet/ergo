//! In-memory custody of multisig signing nonces (`[security] multisig_nonces
//! = "daemon"`).
//!
//! Each nonce produced by `generateCommitments` is kept here under a random
//! single-use handle that is returned in its place. Handles expire after
//! [`NONCE_TTL`], the vault holds at most [`MAX_NONCES`] (oldest evicted
//! first), and locking or stopping the wallet wipes every nonce.
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use ergo_wallet_service::engine::{NonceCustody, NONCE_HANDLE_PREFIX};
use parking_lot::Mutex;
use zeroize::Zeroizing;

/// How long an unused commitment handle stays valid.
pub const NONCE_TTL: Duration = Duration::from_secs(3600);
/// Most nonces held at once.
pub const MAX_NONCES: usize = 4096;

/// A held nonce and when it was deposited.
type Entry = (Zeroizing<[u8; 32]>, Instant);

#[derive(Default)]
pub struct NonceVault {
    entries: Mutex<BTreeMap<String, Entry>>,
}

impl NonceVault {
    /// Wipe every held nonce.
    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    fn deposit_at(&self, nonce: Zeroizing<[u8; 32]>, now: Instant) -> String {
        let mut random = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
        let handle = format!("{NONCE_HANDLE_PREFIX}{}", hex::encode(random));
        let mut entries = self.entries.lock();
        entries.retain(|_, (_, created)| now.saturating_duration_since(*created) < NONCE_TTL);
        while entries.len() >= MAX_NONCES {
            let oldest = entries
                .iter()
                .min_by_key(|(_, (_, created))| *created)
                .map(|(handle, _)| handle.clone())
                .expect("a full vault has entries");
            entries.remove(&oldest);
        }
        entries.insert(handle.clone(), (nonce, now));
        handle
    }

    fn withdraw_at(&self, handle: &str, now: Instant) -> Option<Zeroizing<[u8; 32]>> {
        let (nonce, created) = self.entries.lock().remove(handle)?;
        (now.saturating_duration_since(created) < NONCE_TTL).then_some(nonce)
    }
}

impl NonceCustody for NonceVault {
    fn deposit(&self, nonce: Zeroizing<[u8; 32]>) -> String {
        self.deposit_at(nonce, Instant::now())
    }

    fn withdraw(&self, handle: &str) -> Option<Zeroizing<[u8; 32]>> {
        self.withdraw_at(handle, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_random_single_use_expiring_and_bounded() {
        let vault = NonceVault::default();
        let start = Instant::now();
        let first = vault.deposit_at(Zeroizing::new([1; 32]), start);
        let second = vault.deposit_at(Zeroizing::new([1; 32]), start);
        assert_ne!(first, second);
        assert!(first.starts_with(NONCE_HANDLE_PREFIX));
        assert_eq!(*vault.withdraw_at(&first, start).unwrap(), [1; 32]);
        assert!(vault.withdraw_at(&first, start).is_none(), "single use");
        assert!(
            vault.withdraw_at(&second, start + NONCE_TTL).is_none(),
            "expired"
        );
        for index in 0..MAX_NONCES + 10 {
            vault.deposit_at(
                Zeroizing::new([2; 32]),
                start + Duration::from_millis(index as u64),
            );
        }
        assert_eq!(vault.entries.lock().len(), MAX_NONCES);
        vault.clear();
        assert!(vault.entries.lock().is_empty());
    }
}
