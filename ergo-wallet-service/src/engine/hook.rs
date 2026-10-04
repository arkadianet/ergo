//! The chain-apply hook: [`WalletStateHook`] feeds the wallet's tracked keys
//! and registered scans into block apply / rollback, and quiesces live
//! wallet apply while its [`RescanCoordinator`] reports a full rebuild.
//!
//! A hook for a wallet an engine runs comes only from
//! [`WalletEngine::state_hook`], which hands it the engine's own state, store
//! and rescan coordinator; [`WalletStateHook::standalone`] is the explicitly
//! engine-less path for test harnesses.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::state::WalletState;
use crate::wallet::WalletApplyHook;

use super::{RescanCoordinator, WalletEngine, WalletRescanGuard};

/// The production [`WalletApplyHook`] backed by the shared `Arc<RwLock<WalletState>>`
/// (synchronous `parking_lot::RwLock`).
///
/// Invoked from `StateStore::apply_block` and `rollback_to` on the chain-apply
/// path inside `handle_sync_tick`. The trait is synchronous because the apply
/// path is synchronous; the lock is synchronous because `WalletState` is plain
/// in-memory data. Both hook methods clone one collection and drop the guard.
///
/// Contention coupling: admin commands (`unlock`, `restore`, `derive_*`) take
/// the writer side across PBKDF2 / key-derivation work, so the hook can wait
/// briefly when one is in flight. Block-apply cadence (~120 s mainnet) is
/// much slower than even a slow PBKDF2 (sub-second), so the worst case is a
/// single delayed apply per admin operation.
pub struct WalletStateHook {
    wallet: Arc<RwLock<WalletState>>,
    /// Shared wallet store used for block-apply matching and invalidation.
    store: Arc<dyn crate::wallet::WalletStore>,
    /// The wallet's rollback guard; its coordinator also drives this hook's
    /// full-rescan quiesce gates.
    rescan_guard: WalletRescanGuard,
}

impl WalletStateHook {
    /// Crate-internal: a hook must share its wallet's rescan coordinator,
    /// which only [`WalletEngine::state_hook`] (and this crate's tests) can
    /// guarantee.
    pub(crate) fn new(
        wallet: Arc<RwLock<WalletState>>,
        store: Arc<dyn crate::wallet::WalletStore>,
        rescan: Arc<RescanCoordinator>,
    ) -> Self {
        Self {
            wallet,
            store,
            rescan_guard: WalletRescanGuard::new(rescan),
        }
    }

    /// A hook with a rescan coordinator of its own, for driving chain apply
    /// and rollback where no [`WalletEngine`] runs (test harnesses such as the
    /// embedded-vs-daemon shadow comparison). No engine shares its
    /// coordinator, so its quiesce gates and rollback guard never see an
    /// engine's rescan: a wallet an engine runs must use
    /// [`WalletEngine::state_hook`].
    pub fn standalone(
        wallet: Arc<RwLock<WalletState>>,
        store: Arc<dyn crate::wallet::WalletStore>,
    ) -> Self {
        Self::new(wallet, store, Arc::new(RescanCoordinator::new()))
    }

    /// The chain-rollback guard sharing this hook's rescan coordinator.
    pub fn rescan_guard(&self) -> &WalletRescanGuard {
        &self.rescan_guard
    }

    /// The hook + rollback guard pair threaded through chain apply/rollback.
    pub fn wiring(&self) -> crate::wallet::WalletWiring<'_> {
        crate::wallet::WalletWiring {
            hook: self,
            rescan_guard: &self.rescan_guard,
        }
    }

    fn rescan(&self) -> &RescanCoordinator {
        self.rescan_guard.coordinator()
    }
}

impl WalletEngine {
    /// The chain-apply hook for this engine's wallet: it reads the engine's
    /// in-memory state and wallet store and shares the engine's rescan
    /// coordinator, so its full-rebuild quiesce and its rollback guard act on
    /// the rescans this engine runs.
    pub fn state_hook(&self) -> WalletStateHook {
        WalletStateHook::new(self.state.clone(), self.store.clone(), self.rescan.clone())
    }
}

impl WalletApplyHook for WalletStateHook {
    fn tracked_p2pk_trees(&self) -> std::collections::BTreeSet<Vec<u8>> {
        // Full rescans and fail-closed recovery suppress wallet payloads;
        // partial rescans leave live wallet apply enabled.
        if self.rescan().scan_rebuild_in_progress() {
            return std::collections::BTreeSet::new();
        }
        let state = self.wallet.read();
        state.tracked_p2pk_trees().clone()
    }

    fn cached_pubkeys(&self) -> std::collections::BTreeMap<u64, [u8; 33]> {
        if self.rescan().scan_rebuild_in_progress() {
            return std::collections::BTreeMap::new();
        }
        let state = self.wallet.read();
        state.cached_pubkeys().clone()
    }

    fn wallet_state_snapshot(
        &self,
    ) -> (
        std::collections::BTreeSet<Vec<u8>>,
        std::collections::BTreeMap<u64, [u8; 33]>,
    ) {
        if self.rescan().scan_rebuild_in_progress() {
            return (Default::default(), Default::default());
        }
        let state = self.wallet.read();
        (
            state.tracked_p2pk_trees().clone(),
            state.cached_pubkeys().clone(),
        )
    }

    fn allow_non_contiguous_wallet_apply(&self) -> bool {
        self.rescan().in_progress() && !self.rescan().scan_rebuild_in_progress()
    }

    fn registered_scan_count(&self) -> usize {
        // Skip live scan apply while a full rescan is rebuilding the scan
        // tables: the rebuild clears and repopulates WALLET_SCAN_* block by
        // block, so a concurrent live write would race it (miss a spend
        // against the cleared reverse index, or stale that index). Mirrors
        // the full-rescan gate on the pubkey path. A PARTIAL
        // rescan does not set this flag, so live scan tracking continues
        // across it (scans have no range-rewind rebuild).
        if self.rescan().scan_rebuild_in_progress() {
            return 0;
        }
        // Cheap per-block gate: count rows in WALLET_SCANS. Scan tracking is
        // independent of the wallet-pubkey rescan, so (unlike the methods above)
        // it is NOT skipped while a *partial* rescan is in progress. A read error
        // skips scan work for this block (logged) rather than aborting chain apply.
        let count = self
            .store
            .read()
            .and_then(|read| read.registered_scan_count());
        match count {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(error = %e, "scan apply: wallet store scan count read failed; skipping this block");
                mark_scan_invalidated(self.store.as_ref(), self.rescan());
                0
            }
        }
    }

    fn match_boxes(&self, boxes: &[ergo_ser::ergo_box::ErgoBox]) -> Vec<Vec<u16>> {
        // Quiesced during a scan rebuild (see `registered_scan_count`). The
        // count gate already returns 0 then, so this is defense in depth —
        // mirrors the pubkey path gating both of its hook methods.
        if self.rescan().scan_rebuild_in_progress() {
            return vec![Vec::new(); boxes.len()];
        }
        // Load the registry once for the whole block, then match each box.
        match super::scan::load_registry_from_store(self.store.as_ref()) {
            Ok(registry) => boxes
                .iter()
                .map(|b| registry.matching_scan_ids(b))
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "scan apply: registry load failed; no matches this block");
                mark_scan_invalidated(self.store.as_ref(), self.rescan());
                vec![Vec::new(); boxes.len()]
            }
        }
    }
}

/// Flip `WALLET_SCAN_INVALIDATED` after a scan-registry read failure so
/// `/wallet/status` surfaces the condition and the operator can rescan. The
/// rescan guards are latched before the write attempt, regardless of whether
/// the durable flag write succeeds; the flag remains the recovery signal.
fn mark_scan_invalidated(store: &dyn crate::wallet::WalletStore, rescan: &RescanCoordinator) {
    const RETRIES: usize = 3;
    rescan.latch_fail_closed();
    let mut last_error = None;
    for attempt in 0..RETRIES {
        match try_mark_scan_invalidated(store) {
            Ok(()) => return,
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < RETRIES {
                    std::thread::yield_now();
                }
            }
        }
    }
    if let Some(error) = last_error {
        tracing::error!(error = %error, "scan apply: failed to set scan-invalidated flag after a registry read failure; continuing with in-memory invalidation");
    }
}

fn try_mark_scan_invalidated(
    store: &dyn crate::wallet::WalletStore,
) -> Result<(), crate::wallet::WalletStoreError> {
    store.persist_scan_invalidation(true)
}

#[cfg(test)]
mod invalidation_failure_tests {
    use super::*;
    use crate::wallet::{WalletRead, WalletStore, WalletStoreError, WalletWrite};

    struct FailingInvalidationStore;

    impl WalletStore for FailingInvalidationStore {
        fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
            panic!("read is not used by this test")
        }

        fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
            Err(WalletStoreError::Decode("injected".to_string()))
        }
    }

    #[test]
    fn invalidation_write_failure_latches_fail_closed_guards() {
        let coordinator = RescanCoordinator::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::mark_scan_invalidated(&FailingInvalidationStore, &coordinator)
        }));
        assert!(result.is_ok());
        assert!(coordinator.fail_closed());
        assert!(coordinator.in_progress());
        assert!(coordinator.scan_rebuild_in_progress());
    }
}

#[cfg(test)]
mod scan_invalidation_tests {
    use super::*;
    use crate::wallet::tables::{WALLET_SCANS, WALLET_SCAN_INVALIDATED};

    fn temp_db() -> (tempfile::TempDir, Arc<redb::Database>) {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        (dir, Arc::new(db))
    }

    fn flag_set(db: &redb::Database) -> bool {
        let r = db.begin_read().unwrap();
        match r.open_table(WALLET_SCAN_INVALIDATED) {
            Ok(t) => t.get(()).unwrap().map(|g| g.value()).unwrap_or(false),
            Err(_) => false,
        }
    }

    #[test]
    fn mark_scan_invalidated_sets_the_flag() {
        let coordinator = RescanCoordinator::new();
        let (_d, db) = temp_db();
        assert!(!flag_set(&db), "flag starts clear");
        let store: Arc<dyn crate::wallet::WalletStore> =
            Arc::new(crate::wallet::RedbWalletStore::new(db.clone()));
        mark_scan_invalidated(store.as_ref(), &coordinator);
        assert!(flag_set(&db), "flag set after mark");
        assert!(coordinator.fail_closed());
        assert!(coordinator.in_progress());
        assert!(coordinator.scan_rebuild_in_progress());
    }

    #[test]
    fn wallet_state_hook_snapshots_trees_and_pubkeys_together() {
        let state = Arc::new(RwLock::new(crate::state::WalletState::empty(false)));
        state
            .write()
            .insert_tracked_pubkey(0, [2; 33], ergo_ser::address::NetworkPrefix::Mainnet)
            .unwrap();
        let (_dir, db) = temp_db();
        let hook = WalletStateHook::new(
            state,
            Arc::new(crate::wallet::RedbWalletStore::new(db)),
            Arc::new(RescanCoordinator::new()),
        );
        let (trees, pubkeys) = crate::wallet::WalletApplyHook::wallet_state_snapshot(&hook);
        assert!(!trees.is_empty());
        assert!(!pubkeys.is_empty());
    }

    #[test]
    fn match_boxes_registry_load_failure_invalidates_for_rescan() {
        let (_d, db) = temp_db();
        // A corrupt WALLET_SCANS row (not valid Scan JSON) makes load_registry
        // fail when match_boxes loads it for the block.
        {
            let w = db.begin_write().unwrap();
            w.open_table(WALLET_SCANS)
                .unwrap()
                .insert(11u16, vec![0xFFu8, 0x00])
                .unwrap();
            w.commit().unwrap();
        }
        let store: Arc<dyn crate::wallet::WalletStore> =
            Arc::new(crate::wallet::RedbWalletStore::new(db.clone()));
        let hook = WalletStateHook::new(
            Arc::new(RwLock::new(crate::state::WalletState::empty(false))),
            store,
            Arc::new(RescanCoordinator::new()),
        );
        // match_boxes loads the registry first (regardless of the box slice), so
        // the corrupt row trips the Err branch even with no boxes.
        let out = crate::wallet::WalletApplyHook::match_boxes(&hook, &[]);
        assert!(out.is_empty());
        assert!(
            flag_set(&db),
            "a registry load failure must set WALLET_SCAN_INVALIDATED for rescan"
        );
    }
}
