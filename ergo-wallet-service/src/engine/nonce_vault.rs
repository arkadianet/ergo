//! In-memory custody of multisig signing nonces. This is the engine's default;
//! a host that wants the Scala wire form (`[security] multisig_nonces =
//! "caller"`) opts out with `WalletEngine::allow_caller_nonces`.
//!
//! Each nonce produced by `generateCommitments` is kept here under a random
//! single-use handle that is returned in its place. A handle is bound to the
//! input index and public commitment it was issued for and is removed by the
//! first withdrawal, whether or not that withdrawal matches. Handles expire
//! after [`NONCE_TTL`], the vault holds at most [`MAX_NONCES`] (oldest
//! evicted first), and locking or stopping the wallet wipes every nonce.
//! Nothing is written to disk, so a restarted daemon knows no handle.
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::nonce_custody::{NonceBinding, NonceCustody, NonceRefusal, NONCE_HANDLE_PREFIX};
use parking_lot::Mutex;
use zeroize::Zeroizing;

/// How long an unused commitment handle stays valid.
pub(crate) const NONCE_TTL: Duration = Duration::from_secs(3600);
/// Most nonces held at once.
pub(crate) const MAX_NONCES: usize = 4096;

/// A held nonce, the public data it was issued for, and when.
struct Entry {
    nonce: Zeroizing<[u8; 32]>,
    binding: NonceBinding,
    created: Instant,
}

#[derive(Default)]
pub(crate) struct NonceVault {
    entries: Mutex<BTreeMap<String, Entry>>,
}

impl NonceVault {
    fn deposit_at(
        &self,
        nonce: Zeroizing<[u8; 32]>,
        binding: NonceBinding,
        now: Instant,
    ) -> String {
        let mut random = [0u8; 16];
        rand::Rng::fill_bytes(
            &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
            &mut random,
        );
        let handle = format!("{NONCE_HANDLE_PREFIX}{}", hex::encode(random));
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| now.saturating_duration_since(entry.created) < NONCE_TTL);
        while entries.len() >= MAX_NONCES {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.created)
                .map(|(handle, _)| handle.clone())
                .expect("a full vault has entries");
            entries.remove(&oldest);
        }
        entries.insert(
            handle.clone(),
            Entry {
                nonce,
                binding,
                created: now,
            },
        );
        handle
    }

    fn withdraw_at(
        &self,
        handle: &str,
        binding: &NonceBinding,
        now: Instant,
    ) -> Result<Zeroizing<[u8; 32]>, NonceRefusal> {
        let entry = self
            .entries
            .lock()
            .remove(handle)
            .ok_or(NonceRefusal::Unavailable)?;
        if now.saturating_duration_since(entry.created) >= NONCE_TTL {
            return Err(NonceRefusal::Unavailable);
        }
        if entry.binding != *binding {
            return Err(NonceRefusal::WrongCommitment);
        }
        Ok(entry.nonce)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

impl NonceCustody for NonceVault {
    fn deposit(&self, nonce: Zeroizing<[u8; 32]>, binding: NonceBinding) -> String {
        self.deposit_at(nonce, binding, Instant::now())
    }

    fn withdraw(
        &self,
        handle: &str,
        binding: &NonceBinding,
    ) -> Result<Zeroizing<[u8; 32]>, NonceRefusal> {
        self.withdraw_at(handle, binding, Instant::now())
    }

    fn clear(&self) {
        self.entries.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::hints::{FirstProverMessage, RealCommitment};
    use ergo_wallet::proving::node_position::NodePosition;
    use std::sync::Arc;

    fn binding(input: u32, tag: u8) -> NonceBinding {
        NonceBinding {
            input,
            commitment: RealCommitment {
                image: SigmaBoolean::ProveDlog(GroupElement::from_bytes([2; 33])),
                commitment: FirstProverMessage::Schnorr([tag; 33]),
                position: NodePosition::crypto_tree_prefix(),
            },
        }
    }

    #[test]
    fn handles_are_random_and_single_use() {
        let vault = NonceVault::default();
        let start = Instant::now();
        let first = vault.deposit_at(Zeroizing::new([1; 32]), binding(0, 1), start);
        let second = vault.deposit_at(Zeroizing::new([1; 32]), binding(0, 1), start);
        assert_ne!(first, second);
        assert!(first.starts_with(NONCE_HANDLE_PREFIX));
        assert_eq!(
            *vault.withdraw_at(&first, &binding(0, 1), start).unwrap(),
            [1; 32]
        );
        assert_eq!(
            vault
                .withdraw_at(&first, &binding(0, 1), start)
                .unwrap_err(),
            NonceRefusal::Unavailable,
            "a handle works once"
        );
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn a_handle_is_bound_to_its_input_and_commitment_and_consumed_on_mismatch() {
        let vault = NonceVault::default();
        let start = Instant::now();
        let handle = vault.deposit_at(Zeroizing::new([3; 32]), binding(0, 1), start);
        assert_eq!(
            vault
                .withdraw_at(&handle, &binding(1, 1), start)
                .unwrap_err(),
            NonceRefusal::WrongCommitment
        );
        assert_eq!(
            vault
                .withdraw_at(&handle, &binding(0, 1), start)
                .unwrap_err(),
            NonceRefusal::Unavailable,
            "a refused attempt still consumes the handle"
        );
        let handle = vault.deposit_at(Zeroizing::new([3; 32]), binding(0, 1), start);
        assert_eq!(
            vault
                .withdraw_at(&handle, &binding(0, 2), start)
                .unwrap_err(),
            NonceRefusal::WrongCommitment
        );
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn handles_expire_are_bounded_and_wiped() {
        let vault = NonceVault::default();
        let start = Instant::now();
        let handle = vault.deposit_at(Zeroizing::new([4; 32]), binding(0, 1), start);
        assert_eq!(
            vault
                .withdraw_at(&handle, &binding(0, 1), start + NONCE_TTL)
                .unwrap_err(),
            NonceRefusal::Unavailable,
            "expired"
        );
        let oldest = vault.deposit_at(Zeroizing::new([5; 32]), binding(0, 1), start);
        for index in 0..MAX_NONCES + 10 {
            vault.deposit_at(
                Zeroizing::new([6; 32]),
                binding(0, 1),
                start + Duration::from_millis(1 + index as u64),
            );
        }
        assert_eq!(vault.len(), MAX_NONCES);
        assert_eq!(
            vault
                .withdraw_at(&oldest, &binding(0, 1), start)
                .unwrap_err(),
            NonceRefusal::Unavailable,
            "the oldest nonce is evicted first"
        );
        vault.clear();
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn a_restarted_vault_knows_no_earlier_handle() {
        let before = NonceVault::default();
        let handle = before.deposit(Zeroizing::new([7; 32]), binding(0, 1));
        drop(before);
        let after = NonceVault::default();
        assert_eq!(
            after.withdraw(&handle, &binding(0, 1)).unwrap_err(),
            NonceRefusal::Unavailable
        );
    }

    #[test]
    fn concurrent_withdrawals_of_one_handle_release_the_nonce_once() {
        for _ in 0..64 {
            let vault = Arc::new(NonceVault::default());
            let handle = vault.deposit(Zeroizing::new([8; 32]), binding(0, 1));
            let barrier = Arc::new(std::sync::Barrier::new(8));
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    let (vault, handle, barrier) = (vault.clone(), handle.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        vault.withdraw(&handle, &binding(0, 1)).is_ok()
                    })
                })
                .collect();
            let released = threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|released| *released)
                .count();
            assert_eq!(released, 1);
        }
    }
}
