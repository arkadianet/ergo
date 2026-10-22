//! Wallet lifecycle: status, init / restore, unlock / lock, the seed check
//! and the change-address update, plus the failed-attempt budget that guards
//! the password and seed oracles.

use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use ergo_wallet_protocol::scala::types::WalletStatus;
use ergo_wallet_protocol::WalletAdminError;

use super::keys::WalletBootService;
use super::WalletEngine;

/// Durable state of the engine's unlock failed-attempt budget, in seconds
/// since the Unix epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    /// Start of the current failure window.
    pub window_start: Option<u64>,
    /// Failures inside the current window.
    pub failures: u32,
    /// End of the current lockout.
    pub locked_until: Option<u64>,
    /// Lockouts since the last success; each doubles the next lockout.
    pub strikes: u32,
}

/// Where the unlock failed-attempt budget persists its [`AttemptRecord`], so that
/// restarting the host does not reset the guess budget.
pub trait AttemptJournal: Send + Sync {
    /// The stored record, or `None` when nothing has been stored.
    fn load(&self) -> Result<Option<AttemptRecord>, String>;
    /// Durably replace the stored record.
    fn save(&self, record: &AttemptRecord) -> Result<(), String>;
}

/// Failed-attempt budget for a sensitive wallet operation, enforced in the
/// engine so every surface (compat `/wallet/unlock`, native
/// `/api/v1/wallet/unlock`, future callers) shares one choke point.
///
/// Policy: at most [`Self::MAX_FAILURES`] failures inside
/// [`Self::WINDOW`]; exceeding the budget locks the operation for
/// [`Self::LOCKOUT`], doubled for every further lockout before a success
/// and capped at [`Self::MAX_LOCKOUT`]. A success resets everything.
/// Lockout trips produce [`WalletAdminError::RateLimited`] → HTTP 429.
///
/// With an [`AttemptJournal`] the record survives restarts. Times are wall
/// clock seconds so they remain meaningful across processes; a clock moved
/// backwards keeps a pending lockout rather than ending it.
///
/// Instances live in the [`WalletEngine`] and change only through its
/// `&mut self` commands (`unlock`, `check`), so the borrow checker keeps
/// every update on the engine's single writer. Time is injected
/// (`*_at(now)`) so tests can drive the clock without sleeping.
#[derive(Default)]
pub(crate) struct AttemptLimiter {
    record: AttemptRecord,
    journal: Option<std::sync::Arc<dyn AttemptJournal>>,
}

/// Seconds since the Unix epoch.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl AttemptLimiter {
    pub(crate) const MAX_FAILURES: u32 = 5;
    pub(crate) const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
    pub(crate) const LOCKOUT: std::time::Duration = std::time::Duration::from_secs(300);
    pub(crate) const MAX_LOCKOUT: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

    pub(crate) const fn new() -> Self {
        Self {
            record: AttemptRecord {
                window_start: None,
                failures: 0,
                locked_until: None,
                strikes: 0,
            },
            journal: None,
        }
    }

    /// Persist through `journal`, starting from its stored record. A record
    /// that cannot be read starts a lockout rather than a fresh budget.
    pub(crate) fn with_journal(journal: std::sync::Arc<dyn AttemptJournal>, now: u64) -> Self {
        let record = match journal.load() {
            Ok(record) => record.unwrap_or_default(),
            Err(error) => {
                warn!(%error, "unlock attempt record unreadable; starting with a lockout");
                AttemptRecord {
                    locked_until: Some(now + Self::LOCKOUT.as_secs()),
                    strikes: 1,
                    ..AttemptRecord::default()
                }
            }
        };
        let limiter = Self {
            record,
            journal: Some(journal),
        };
        limiter.persist();
        limiter
    }

    fn persist(&self) {
        if let Some(journal) = &self.journal {
            if let Err(error) = journal.save(&self.record) {
                warn!(%error, "unlock attempt record not persisted");
            }
        }
    }

    /// `Ok(())` when the operation may proceed; `Err(())` while locked out.
    pub(crate) fn gate_at(&mut self, now: u64) -> Result<(), ()> {
        if let Some(until) = self.record.locked_until {
            if now < until {
                return Err(());
            }
            // Lockout expired: a fresh window, but the strikes remain until
            // a success so the next lockout is longer.
            self.record.locked_until = None;
            self.record.window_start = None;
            self.record.failures = 0;
            self.persist();
        }
        Ok(())
    }

    pub(crate) fn record_failure_at(&mut self, now: u64) {
        let in_window = self
            .record
            .window_start
            .is_some_and(|start| now >= start && now - start <= Self::WINDOW.as_secs());
        if !in_window {
            self.record.window_start = Some(now);
            self.record.failures = 0;
        }
        self.record.failures += 1;
        if self.record.failures >= Self::MAX_FAILURES {
            let doubling = self.record.strikes.min(16);
            let lockout = Self::LOCKOUT
                .as_secs()
                .saturating_mul(1 << doubling)
                .min(Self::MAX_LOCKOUT.as_secs());
            self.record.locked_until = Some(now.saturating_add(lockout));
            self.record.strikes = self.record.strikes.saturating_add(1);
        }
        self.persist();
    }

    pub(crate) fn record_success(&mut self) {
        if self.record != AttemptRecord::default() {
            self.record = AttemptRecord::default();
            self.persist();
        }
    }
}

/// The unlock failed-attempt budget for a host that checks a wallet password
/// before its engine exists (a sealed daemon). It shares the engine's policy
/// and, through the same [`AttemptJournal`], its persisted state.
pub struct UnlockThrottle(AttemptLimiter);

impl UnlockThrottle {
    /// Load the budget from `journal`.
    pub fn new(journal: std::sync::Arc<dyn AttemptJournal>) -> Self {
        Self(AttemptLimiter::with_journal(journal, unix_now()))
    }

    /// Refuse while locked out ([`WalletAdminError::RateLimited`]).
    pub fn check(&mut self) -> Result<(), WalletAdminError> {
        self.0
            .gate_at(unix_now())
            .map_err(|()| WalletAdminError::RateLimited)
    }

    /// Record a wrong password.
    pub fn record_failure(&mut self) {
        self.0.record_failure_at(unix_now());
    }

    /// Record a correct password.
    pub fn record_success(&mut self) {
        self.0.record_success();
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
        // Owned secrets are wiped when this command returns.
        let (pass, mnemonic_pass) = (Zeroizing::new(pass), Zeroizing::new(mnemonic_pass));
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
        let phrase = storage
            .init(strength_enum, &pass, &mnemonic_pass)
            .map_err(|e| match e {
                ergo_wallet::error::WalletError::WalletAlreadyInitialized => {
                    WalletAdminError::WalletExists
                }
                ergo_wallet::error::WalletError::InvalidMnemonic(_) => {
                    WalletAdminError::InvalidMnemonic
                }
                _ => WalletAdminError::Internal(e.to_string()),
            })?;
        drop(storage);
        self.anchor_fresh_wallet();
        Ok(phrase)
    }

    /// A mnemonic `init` just generated cannot have history, so its wallet
    /// starts at the node's committed tip instead of block 1. Best effort: the
    /// seed is already saved and the caller is owed its phrase, so a node that
    /// cannot be reached leaves the wallet to replay from genesis at first
    /// unlock, as it always did.
    ///
    /// Every command, including a sync pass, takes the host's writer gate
    /// before it runs, so no pass is in flight while this rewrites the cursor.
    /// The rescan fence is checked as well: a cursor must never move under a
    /// running rescan.
    fn anchor_fresh_wallet(&self) {
        if !self.store.rebuilds_history_on_key_additions() || self.rescan.operations_fenced() {
            return;
        }
        // Registered scans have history of their own below the tip. Moving the
        // cursor would clear it and never rescan it, so such a wallet takes the
        // old path: the first unlock rebuilds from genesis for the scans too.
        match self
            .store
            .read()
            .and_then(|read| read.registered_scan_count())
        {
            Ok(0) => {}
            Ok(_) => return,
            Err(error) => {
                warn!(%error, "could not read the scan registry; the new wallet will replay from genesis");
                return;
            }
        }
        let tip = match self.chain.committed_tip() {
            Ok(Some(tip)) if tip.height > 0 => tip,
            Ok(_) => return,
            Err(error) => {
                warn!(%error, "node tip unavailable; the new wallet will replay from genesis");
                return;
            }
        };
        let anchored = self.store.begin_write().and_then(|mut write| {
            let recorded = write.begin_fresh_wallet(tip.height, &tip.header_id)?;
            write.commit()?;
            Ok(recorded)
        });
        match anchored {
            Ok(true) => info!(height = tip.height, "new wallet starts at the node tip"),
            Ok(false) => {}
            Err(error) => warn!(%error, "could not start the new wallet at the node tip"),
        }
    }

    pub fn restore(
        &mut self,
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        let (mnemonic, mnemonic_pass, pass) = (
            Zeroizing::new(mnemonic),
            Zeroizing::new(mnemonic_pass),
            Zeroizing::new(pass),
        );
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
        // A restored seed may have history: no fresh-wallet anchor left by an
        // earlier `init` (whose secret was since removed) may vouch for it.
        if self.store.rebuilds_history_on_key_additions() {
            self.store
                .begin_write()
                .and_then(|mut write| {
                    write.clear_fresh_anchor()?;
                    write.commit()
                })
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
        let pass = Zeroizing::new(pass);
        if self.unlock_limiter.gate_at(unix_now()).is_err() {
            tracing::warn!("wallet unlock rejected: failed-attempt budget exhausted");
            return Err(WalletAdminError::RateLimited);
        }
        // The first unlock of a wallet that `init` did not create is a
        // restore: its keys beyond the first are still to be found.
        let restoring = self.is_first_unlock_of_restored_wallet();
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
                if restoring {
                    self.discover_restored_keys();
                }
            }
            Err(WalletAdminError::WrongPassword) => {
                self.unlock_limiter.record_failure_at(unix_now());
                warn!("wallet unlock failed: wrong password");
            }
            // Uninitialized / internal errors are not guess feedback — leave
            // the budget untouched.
            Err(_) => {}
        }
        result
    }

    /// No key is tracked yet and `init` did not start this wallet: the next
    /// unlock derives its first keys from a seed that may have history.
    fn is_first_unlock_of_restored_wallet(&self) -> bool {
        let Ok(read) = self.store.read() else {
            return false;
        };
        matches!(read.tracked_pubkeys_with_paths(), Ok(rows) if rows.is_empty())
            && matches!(read.fresh_anchor(), Ok(None))
    }

    /// Find the used keys of a restored wallet through the node's address
    /// index, so restore does not stop at the first address. Derives the EIP-3
    /// external addresses in windows of [`GAP_LIMIT`], asks the index which
    /// were ever used, stops after a full window past the last used one, and
    /// tracks every key up to it. Best effort and silent when the node has no
    /// index: the wallet keeps the keys the unlock derived, as before.
    fn discover_restored_keys(&mut self) {
        let Some(service) = self.service.clone() else {
            return;
        };
        if !self.store.rebuilds_history_on_key_additions() {
            return;
        }
        match self.track_discovered_keys(&service) {
            Ok(0) => {}
            Ok(added) => info!(
                added,
                "restored wallet keys found through the address index"
            ),
            Err(error) => {
                warn!(%error, "address index key discovery failed; keeping the first keys")
            }
        }
    }

    fn track_discovered_keys(
        &mut self,
        service: &crate::runtime::WalletService,
    ) -> Result<usize, WalletAdminError> {
        use crate::address_index::{AddressIndexError, GAP_LIMIT, MAX_DISCOVERY_WINDOWS};
        use ergo_wallet::derivation::{DerivationPath, HARDENED_OFFSET};
        let network = self.config.network;
        let internal =
            |error: &dyn std::fmt::Display| WalletAdminError::Internal(error.to_string());
        let mut derived: Vec<(u32, [u8; 33])> = Vec::new();
        let mut last_used: Option<u32> = None;
        {
            let storage = self.storage.read();
            let unlocked = storage.unlocked().ok_or(WalletAdminError::Locked)?;
            for window in 0..MAX_DISCOVERY_WINDOWS {
                let start = window * GAP_LIMIT;
                let mut keys = Vec::with_capacity(GAP_LIMIT as usize);
                for index in start..start + GAP_LIMIT {
                    let path = DerivationPath::from_components(vec![
                        HARDENED_OFFSET | 44,
                        HARDENED_OFFSET | 429,
                        HARDENED_OFFSET,
                        0,
                        index,
                    ]);
                    let pubkey = unlocked
                        .master
                        .derive_pubkey_at_path(&path)
                        .map_err(|error| internal(&error))?;
                    keys.push((index, pubkey));
                }
                let pubkeys: Vec<[u8; 33]> = keys.iter().map(|(_, pubkey)| *pubkey).collect();
                let used = match service.indexed_key_usage(network, &pubkeys) {
                    Ok(Some(usage)) => usage.used,
                    Ok(None) | Err(AddressIndexError::Unavailable(_)) => return Ok(0),
                    Err(error) => return Err(internal(&error)),
                };
                // An address only counts while it is within the gap limit of
                // the last used one; a later hit past that is a different
                // wallet's business, as it would be for a full address scan.
                let horizon =
                    |last: Option<u32>| last.map_or(GAP_LIMIT - 1, |last| last + GAP_LIMIT);
                let mut exhausted = false;
                for ((index, _), used) in keys.iter().zip(used) {
                    if *index > horizon(last_used) {
                        exhausted = true;
                        break;
                    }
                    if used {
                        last_used = Some(*index);
                    }
                }
                derived.extend(keys);
                if exhausted || horizon(last_used) < start + GAP_LIMIT {
                    break;
                }
            }
        }
        let Some(last_used) = last_used else {
            return Ok(0);
        };
        let read = self.store.read().map_err(|error| internal(&error))?;
        let tracked = read
            .tracked_pubkeys_with_paths()
            .map_err(|error| internal(&error))?;
        drop(read);
        let mut next_index = tracked
            .iter()
            .map(|(index, _, _)| *index)
            .max()
            .map_or(0, |index| index + 1);
        let mut write = self.store.begin_write().map_err(|error| internal(&error))?;
        let mut added = 0;
        for (index, pubkey) in derived.into_iter().filter(|(index, _)| *index <= last_used) {
            let components = vec![
                HARDENED_OFFSET | 44,
                HARDENED_OFFSET | 429,
                HARDENED_OFFSET,
                0,
                index,
            ];
            if tracked.iter().any(|(_, _, path)| *path == components) {
                continue;
            }
            let meta = crate::wallet::types::TrackedPubkeyMeta {
                derivation_path: components,
                derivation_path_label: String::new(),
                added_at_height: 0,
            };
            write
                .insert_tracked_pubkey_keep_history(next_index, pubkey, &meta)
                .map_err(|error| internal(&error))?;
            next_index += 1;
            added += 1;
        }
        write
            .rebuild_visible_addresses()
            .map_err(|error| internal(&error))?;
        write.commit().map_err(|error| internal(&error))?;
        let read = self.store.read().map_err(|error| internal(&error))?;
        let hydration = crate::wallet::hydration::HydrationSnapshot::load(read.as_ref())
            .map_err(|error| internal(&error))?;
        self.state
            .write()
            .hydrate_from_reader(&hydration, network)
            .map_err(|error| internal(&error))?;
        Ok(added)
    }

    /// `POST /wallet/rescan` with `noActivityBefore`: the caller states the
    /// wallet had no activity before `from_height`, so an invalidated scan can
    /// restart there instead of at genesis. The stored history is cleared,
    /// the cursor is placed on the block before `from_height`, and the scan is
    /// valid again, with an incomplete-history record naming that block so
    /// status never claims history below it. Block following then resumes at
    /// `from_height`; there is no rescan job. An implicit partial rescan of an
    /// invalidated scan stays refused (see [`Self::prepare_rescan`]).
    pub fn declare_history_start(&mut self, from_height: u32) -> Result<(), WalletAdminError> {
        let internal =
            |error: &dyn std::fmt::Display| WalletAdminError::Internal(error.to_string());
        if from_height == 0 {
            return Err(WalletAdminError::BadRequest(
                "noActivityBefore needs a fromHeight above 0".to_string(),
            ));
        }
        let service = self.service.clone().ok_or_else(|| {
            WalletAdminError::RescanUnavailable("this wallet has no chain client".to_string())
        })?;
        if self.rescan.operations_fenced() {
            return Err(WalletAdminError::RescanUnavailable(
                "wallet rescan is running".to_string(),
            ));
        }
        let read = self.store.read().map_err(|error| internal(&error))?;
        if !read.scan_invalidated().map_err(|error| internal(&error))? {
            return Err(WalletAdminError::BadRequest(
                "noActivityBefore applies only to an invalidated scan; a valid wallet can rescan \
                 from any height without it"
                    .to_string(),
            ));
        }
        if read
            .registered_scan_count()
            .map_err(|error| internal(&error))?
            > 0
        {
            return Err(WalletAdminError::BadRequest(
                "noActivityBefore cannot restart a wallet that has registered scans".to_string(),
            ));
        }
        drop(read);
        let chain = service.chain();
        let mut tip = chain
            .committed_tip()
            .map_err(|error| WalletAdminError::NodeUnavailable(error.to_string()))?;
        if from_height > tip.height {
            return Err(WalletAdminError::BadRequest(format!(
                "fromHeight {from_height} is above the node tip {}",
                tip.height
            )));
        }
        let anchor = from_height - 1;
        let anchor_id = if anchor == 0 {
            crate::chain::GENESIS_CURSOR_ID
        } else {
            let mut attempts = 0;
            loop {
                match chain.block_at(anchor, tip.clone()) {
                    Ok(block) => break block.block_id,
                    Err(crate::chain::ChainClientError::StaleTip { actual, .. })
                        if attempts < 3 =>
                    {
                        attempts += 1;
                        tip = actual;
                    }
                    Err(error) => {
                        return Err(WalletAdminError::NodeUnavailable(error.to_string()));
                    }
                }
            }
        };
        let mut write = self.store.begin_write().map_err(|error| internal(&error))?;
        write
            .declare_history_start(anchor, &anchor_id)
            .map_err(|error| internal(&error))?;
        write.commit().map_err(|error| internal(&error))?;
        info!(
            from_height,
            "wallet history restarted at a declared block; earlier history is not reconstructed"
        );
        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), WalletAdminError> {
        let mut storage = self.storage.write();
        let mut state = self.state.write();
        storage.lock();
        state.set_unlocked(false);
        // Outstanding multisig commitments die with the unlocked session.
        if let Some(custody) = &self.nonce_custody {
            custody.clear();
        }
        info!("wallet locked");
        Ok(())
    }

    pub fn check(
        &mut self,
        mnemonic: String,
        mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError> {
        let (mnemonic, mnemonic_pass) = (Zeroizing::new(mnemonic), Zeroizing::new(mnemonic_pass));
        // `check` is a yes/no oracle over the recovery phrase — the same
        // brute-force surface as unlock, so it shares the failed-attempt
        // budget (a mismatch counts as a failure; a match resets it).
        if self.check_limiter.gate_at(unix_now()).is_err() {
            tracing::warn!("wallet check rejected: failed-attempt budget exhausted");
            return Err(WalletAdminError::RateLimited);
        }
        let storage = self.storage.read();
        let matched = storage.check_seed(&mnemonic, &mnemonic_pass);
        drop(storage);
        if matched {
            self.check_limiter.record_success();
        } else {
            self.check_limiter.record_failure_at(unix_now());
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
    use super::{AttemptJournal, AttemptLimiter, AttemptRecord};
    use std::sync::{Arc, Mutex};

    const T0: u64 = 1_800_000_000;
    const LOCKOUT: u64 = AttemptLimiter::LOCKOUT.as_secs();

    #[derive(Default)]
    struct MemoryJournal(Mutex<Option<AttemptRecord>>, Mutex<bool>);

    impl AttemptJournal for MemoryJournal {
        fn load(&self) -> Result<Option<AttemptRecord>, String> {
            if *self.1.lock().unwrap() {
                return Err("corrupt".into());
            }
            Ok(*self.0.lock().unwrap())
        }
        fn save(&self, record: &AttemptRecord) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(*record);
            Ok(())
        }
    }

    fn exhaust(limiter: &mut AttemptLimiter, start: u64) -> u64 {
        for i in 0..AttemptLimiter::MAX_FAILURES {
            assert!(limiter.gate_at(start + u64::from(i)).is_ok());
            limiter.record_failure_at(start + u64::from(i));
        }
        start + u64::from(AttemptLimiter::MAX_FAILURES) - 1
    }

    #[test]
    fn allows_below_budget_and_locks_at_max_failures() {
        let mut limiter = AttemptLimiter::new();
        exhaust(&mut limiter, T0);
        // Budget exhausted → locked, even immediately.
        assert!(limiter.gate_at(T0 + 10).is_err());
    }

    #[test]
    fn lockout_expires_and_repeated_lockouts_double_up_to_a_day() {
        let mut limiter = AttemptLimiter::new();
        let mut last = exhaust(&mut limiter, T0);
        let mut expected = LOCKOUT;
        for _ in 0..12 {
            // Lockout runs from the LAST failure.
            assert!(limiter.gate_at(last + expected - 1).is_err());
            assert!(
                limiter.gate_at(last + expected).is_ok(),
                "lockout must expire"
            );
            // A single new failure after expiry does not lock again...
            limiter.record_failure_at(last + expected);
            assert!(limiter.gate_at(last + expected + 1).is_ok());
            // ...but exhausting a later budget locks for twice as long.
            last = exhaust(
                &mut limiter,
                last + expected + AttemptLimiter::WINDOW.as_secs() + 2,
            );
            expected = (expected * 2).min(AttemptLimiter::MAX_LOCKOUT.as_secs());
        }
        assert_eq!(expected, AttemptLimiter::MAX_LOCKOUT.as_secs());
        limiter.record_success();
        let last = exhaust(&mut limiter, last + expected + 10);
        assert!(
            limiter.gate_at(last + LOCKOUT).is_ok(),
            "success resets escalation"
        );
    }

    #[test]
    fn success_resets_the_window() {
        let mut limiter = AttemptLimiter::new();
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(T0 + u64::from(i));
        }
        limiter.record_success();
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(T0 + 30 + u64::from(i));
        }
        assert!(limiter.gate_at(T0 + 60).is_ok());
    }

    #[test]
    fn failures_outside_the_window_do_not_accumulate() {
        let mut limiter = AttemptLimiter::new();
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(T0 + u64::from(i));
        }
        // Past WINDOW since the first failure: a new window starts.
        let later = T0 + AttemptLimiter::WINDOW.as_secs() + 1;
        limiter.record_failure_at(later);
        assert!(limiter.gate_at(later + 1).is_ok());
    }

    #[test]
    fn journal_carries_the_budget_and_lockout_across_restarts() {
        let journal = Arc::new(MemoryJournal::default());
        let mut first = AttemptLimiter::with_journal(journal.clone(), T0);
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            first.record_failure_at(T0 + u64::from(i));
        }
        drop(first);
        // A restart does not grant a fresh budget: one more failure locks.
        let mut second = AttemptLimiter::with_journal(journal.clone(), T0 + 10);
        second.record_failure_at(T0 + 10);
        drop(second);
        let mut third = AttemptLimiter::with_journal(journal.clone(), T0 + 11);
        assert!(third.gate_at(T0 + 11).is_err());
        assert!(third.gate_at(T0 + 10 + LOCKOUT).is_ok());
        third.record_success();
        assert_eq!(journal.0.lock().unwrap().unwrap(), AttemptRecord::default());
    }

    #[test]
    fn unreadable_journal_starts_locked() {
        let journal = Arc::new(MemoryJournal::default());
        *journal.1.lock().unwrap() = true;
        let mut limiter = AttemptLimiter::with_journal(journal, T0);
        assert!(limiter.gate_at(T0).is_err());
        assert!(limiter.gate_at(T0 + LOCKOUT).is_ok());
    }
}
