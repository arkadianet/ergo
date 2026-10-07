//! Wallet lifecycle: status, init / restore, unlock / lock, the seed check
//! and the change-address update, plus the failed-attempt budget that guards
//! the password and seed oracles.

use tracing::{debug, info, warn};

use ergo_wallet_protocol::scala::types::WalletStatus;
use ergo_wallet_protocol::WalletAdminError;

use super::keys::WalletBootService;
use super::WalletEngine;

/// Failed-attempt budget for a sensitive wallet operation, enforced in the
/// engine so every surface (compat `/wallet/unlock`, native
/// `/api/v1/wallet/unlock`, future callers) shares one choke point.
///
/// Policy: at most [`Self::MAX_FAILURES`] failures inside
/// [`Self::WINDOW`]; exceeding the budget locks the operation for
/// [`Self::LOCKOUT`]. A success (or an unrelated error) resets the
/// window. Lockout trips produce [`WalletAdminError::RateLimited`] →
/// HTTP 429 — the variant existed for exactly this purpose but was never
/// constructed (audit finding M-4: unlimited online password guessing
/// against `/wallet/unlock`, each guess still costing a PBKDF2 run).
///
/// Instances live in the [`WalletEngine`] and change only through its
/// `&mut self` commands (`unlock`, `check`), so the borrow checker keeps
/// every update on the engine's single writer. Time is injected
/// (`*_at(now)`) so tests can drive the clock without sleeping.
#[derive(Default)]
pub(crate) struct AttemptLimiter {
    window_start: Option<std::time::Instant>,
    failures: u32,
    locked_until: Option<std::time::Instant>,
}

impl AttemptLimiter {
    pub(crate) const MAX_FAILURES: u32 = 5;
    pub(crate) const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
    pub(crate) const LOCKOUT: std::time::Duration = std::time::Duration::from_secs(300);

    pub(crate) const fn new() -> Self {
        Self {
            window_start: None,
            failures: 0,
            locked_until: None,
        }
    }

    /// `Ok(())` when the operation may proceed; `Err(())` while locked out.
    pub(crate) fn gate_at(&mut self, now: std::time::Instant) -> Result<(), ()> {
        if let Some(until) = self.locked_until {
            if now < until {
                return Err(());
            }
            // Lockout expired — start fresh.
            *self = Self::default();
        }
        Ok(())
    }

    pub(crate) fn record_failure_at(&mut self, now: std::time::Instant) {
        let in_window = match self.window_start {
            Some(start) => now.duration_since(start) <= Self::WINDOW,
            None => false,
        };
        if !in_window {
            self.window_start = Some(now);
            self.failures = 0;
        }
        self.failures += 1;
        if self.failures >= Self::MAX_FAILURES {
            self.locked_until = Some(now + Self::LOCKOUT);
        }
    }

    pub(crate) fn record_success(&mut self) {
        *self = Self::default();
    }
}

impl WalletEngine {
    pub fn status(&self) -> Result<WalletStatus, WalletAdminError> {
        let storage = self.storage.read();
        let state = self.state.read();
        let change_address = if state.is_unlocked() {
            state.change_address().unwrap_or("").to_string()
        } else {
            String::new()
        };
        let read = self
            .store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let invalidated = read
            .scan_invalidated()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let rescan_state = read
            .rescan_state()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        Ok(WalletStatus {
            is_initialized: !matches!(
                storage.lock_state(),
                ergo_wallet::storage::LockState::Uninitialized
            ),
            is_unlocked: state.is_unlocked(),
            change_address,
            wallet_height: self
                .chain
                .wallet_scan_height()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
            error: match rescan_state {
                crate::wallet::RescanState::Failed { reason, .. } => {
                    format!("rescan_failed: {reason}")
                }
                crate::wallet::RescanState::Running { .. } => "rescan_running".to_string(),
                crate::wallet::RescanState::Idle if invalidated => {
                    WalletAdminError::ScanInvalidated.to_string()
                }
                crate::wallet::RescanState::Idle => String::new(),
            },
        })
    }

    pub fn init(
        &mut self,
        pass: String,
        mnemonic_pass: String,
        strength: u8,
    ) -> Result<String, WalletAdminError> {
        let mut storage = self.storage.write();
        // Refuse to overwrite an existing wallet: `init` on an initialized
        // wallet would persist a second secret file. Return a typed `WalletExists`
        // (native 409 wallet_exists / compat 400) instead of clobbering the seed.
        if !matches!(
            storage.lock_state(),
            ergo_wallet::storage::LockState::Uninitialized
        ) {
            return Err(WalletAdminError::WalletExists);
        }
        let strength_enum = match strength {
            12 => ergo_wallet::mnemonic::MnemonicStrength::Words12,
            15 => ergo_wallet::mnemonic::MnemonicStrength::Words15,
            18 => ergo_wallet::mnemonic::MnemonicStrength::Words18,
            21 => ergo_wallet::mnemonic::MnemonicStrength::Words21,
            24 => ergo_wallet::mnemonic::MnemonicStrength::Words24,
            n => {
                return Err(WalletAdminError::Internal(format!(
                    "unsupported strength {n}"
                )));
            }
        };
        storage
            .init(strength_enum, &pass, &mnemonic_pass)
            .map_err(|e| match e {
                ergo_wallet::error::WalletError::WalletAlreadyInitialized => {
                    WalletAdminError::WalletExists
                }
                ergo_wallet::error::WalletError::InvalidMnemonic(_) => {
                    WalletAdminError::InvalidMnemonic
                }
                _ => WalletAdminError::Internal(e.to_string()),
            })
    }

    pub fn restore(
        &mut self,
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        let mut storage = self.storage.write();
        // Refuse to overwrite an existing wallet (same safety guard as `init`).
        if !matches!(
            storage.lock_state(),
            ergo_wallet::storage::LockState::Uninitialized
        ) {
            return Err(WalletAdminError::WalletExists);
        }
        // Persist incomplete history before publishing the seed so a crash
        // cannot leave a restored pruned wallet claiming a complete balance.
        if self.chain.is_pruned() {
            self.store
                .persist_scan_invalidation(true)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        }
        storage
            .restore(&mnemonic, &mnemonic_pass, &pass, use_pre_1627)
            .map_err(|e| match e {
                ergo_wallet::error::WalletError::WalletAlreadyInitialized => {
                    WalletAdminError::WalletExists
                }
                ergo_wallet::error::WalletError::InvalidMnemonic(_) => {
                    WalletAdminError::InvalidMnemonic
                }
                _ => WalletAdminError::Internal(e.to_string()),
            })
    }

    pub fn unlock(&mut self, pass: String) -> Result<(), WalletAdminError> {
        if self
            .unlock_limiter
            .gate_at(std::time::Instant::now())
            .is_err()
        {
            tracing::warn!("wallet unlock rejected: failed-attempt budget exhausted");
            return Err(WalletAdminError::RateLimited);
        }
        let mut storage = self.storage.write();
        let mut state = self.state.write();
        let result = WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            self.store.as_ref(),
            self.config.network,
            &pass,
        )
        .map_err(|e| match e {
            ergo_wallet::error::WalletError::WalletUninitialized => WalletAdminError::Uninitialized,
            ergo_wallet::error::WalletError::Decryption => WalletAdminError::WrongPassword,
            ergo_wallet::error::WalletError::ChangeAddressUntracked => {
                WalletAdminError::ChangeAddressUntracked
            }
            other => WalletAdminError::Internal(other.to_string()),
        });
        drop(storage);
        drop(state);
        match &result {
            Ok(()) => {
                self.unlock_limiter.record_success();
                info!("wallet unlocked");
            }
            Err(WalletAdminError::WrongPassword) => {
                self.unlock_limiter
                    .record_failure_at(std::time::Instant::now());
                warn!("wallet unlock failed: wrong password");
            }
            // Uninitialized / internal errors are not guess feedback — leave
            // the budget untouched.
            Err(_) => {}
        }
        result
    }

    pub fn lock(&mut self) -> Result<(), WalletAdminError> {
        let mut storage = self.storage.write();
        let mut state = self.state.write();
        storage.lock();
        state.set_unlocked(false);
        info!("wallet locked");
        Ok(())
    }

    pub fn check(
        &mut self,
        mnemonic: String,
        mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError> {
        // `check` is a yes/no oracle over the recovery phrase — the same
        // brute-force surface as unlock, so it shares the failed-attempt
        // budget (a mismatch counts as a failure; a match resets it).
        if self
            .check_limiter
            .gate_at(std::time::Instant::now())
            .is_err()
        {
            tracing::warn!("wallet check rejected: failed-attempt budget exhausted");
            return Err(WalletAdminError::RateLimited);
        }
        let storage = self.storage.read();
        let matched = storage.check_seed(&mnemonic, &mnemonic_pass);
        drop(storage);
        if matched {
            self.check_limiter.record_success();
        } else {
            self.check_limiter
                .record_failure_at(std::time::Instant::now());
        }
        debug!(matched, "wallet seed check completed");
        Ok(matched)
    }

    pub fn update_change_address(&mut self, address: String) -> Result<(), WalletAdminError> {
        if self.storage.read().unlocked().is_none() {
            return Err(WalletAdminError::Locked);
        }
        // Decode address → pubkey; reject if not a valid P2PK address for
        // this node's network (the same keys are tracked on every network,
        // so without the prefix check a testnet address would pass the
        // tracked-pubkey membership test on a mainnet node).
        let pubkey = match ergo_ser::address::decode_p2pk_address(&address, self.config.network) {
            Ok(pk) => pk,
            Err(_) => {
                return Err(WalletAdminError::ChangeAddressUntracked);
            }
        };
        // Tracking is not proof of ownership. Derive the recorded path with the
        // active master key and compare its public key before persisting anything.
        let owned = (|| -> Result<bool, WalletAdminError> {
            let storage = self.storage.read();
            let unlocked = storage.unlocked().ok_or(WalletAdminError::Locked)?;
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let tracked = read
                .tracked_pubkeys_with_paths()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            for (_, pk, path) in tracked {
                if pk == pubkey {
                    let path = ergo_wallet::derivation::DerivationPath::from_components(path);
                    let derived = unlocked
                        .master
                        .derive_pubkey_at_path(&path)
                        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                    if derived == pubkey {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })();
        match owned {
            Ok(true) => {}
            Ok(false) => {
                return Err(WalletAdminError::ChangeAddressUntracked);
            }
            Err(e) => {
                return Err(e);
            }
        }
        // Persist to WALLET_CHANGE_ADDRESS.
        let result: Result<(), WalletAdminError> = (|| -> Result<(), WalletAdminError> {
            let mut write = self
                .store
                .begin_write()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            write
                .set_change_address(pubkey)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            write
                .commit()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))
        })();
        if result.is_ok() {
            let mut s = self.state.write();
            s.set_change_address(address);
        }
        result
    }
}

#[cfg(test)]
mod attempt_limiter_tests {
    use super::AttemptLimiter;
    use std::time::{Duration, Instant};

    #[test]
    fn allows_below_budget_and_locks_at_max_failures() {
        let mut limiter = AttemptLimiter::new();
        let t0 = Instant::now();
        for i in 0..AttemptLimiter::MAX_FAILURES {
            assert!(
                limiter.gate_at(t0 + Duration::from_secs(i.into())).is_ok(),
                "attempt {i} inside budget must pass the gate"
            );
            limiter.record_failure_at(t0 + Duration::from_secs(i.into()));
        }
        // Budget exhausted → locked, even immediately.
        assert!(limiter.gate_at(t0 + Duration::from_secs(10)).is_err());
    }

    #[test]
    fn lockout_expires_and_state_resets() {
        let mut limiter = AttemptLimiter::new();
        let t0 = Instant::now();
        for i in 0..AttemptLimiter::MAX_FAILURES {
            limiter.record_failure_at(t0 + Duration::from_secs(i.into()));
        }
        // Lockout runs from the LAST failure (t0+4s), not the first.
        let last_failure = t0 + Duration::from_secs(AttemptLimiter::MAX_FAILURES as u64 - 1);
        assert!(limiter
            .gate_at(last_failure + Duration::from_secs(1))
            .is_err());
        let unlock_at = last_failure + AttemptLimiter::LOCKOUT + Duration::from_secs(1);
        assert!(limiter.gate_at(unlock_at).is_ok(), "lockout must expire");
        // Fresh window after expiry: a single new failure must not lock.
        limiter.record_failure_at(unlock_at);
        assert!(limiter.gate_at(unlock_at + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn success_resets_the_window() {
        let mut limiter = AttemptLimiter::new();
        let t0 = Instant::now();
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(t0 + Duration::from_secs(i.into()));
        }
        limiter.record_success();
        // Full fresh budget available again.
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(t0 + Duration::from_secs(30 + i as u64));
        }
        assert!(limiter.gate_at(t0 + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn failures_outside_the_window_do_not_accumulate() {
        let mut limiter = AttemptLimiter::new();
        let t0 = Instant::now();
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(t0 + Duration::from_secs(i.into()));
        }
        // Past WINDOW since the first failure: a new window starts, so
        // this failure is #1 of a fresh budget — no lockout.
        limiter.record_failure_at(t0 + AttemptLimiter::WINDOW + Duration::from_secs(1));
        assert!(limiter
            .gate_at(t0 + AttemptLimiter::WINDOW + Duration::from_secs(2))
            .is_ok());
    }
}
