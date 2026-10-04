//! Preserve the applied parent state when activating pruned UTXO downloads.
//!
//! This backend validates sequentially from its applied UTXO tip. A retention
//! floor computed only from a fresh header tip cannot supply the skipped parent
//! state. Fresh Mode3 nodes therefore replay full blocks from genesis and prune
//! after apply. Installed snapshots, applied NiPoPoW proofs and already-applied
//! pruned stores retain their durable download floor.

use ergo_state::chain::HeaderAvailability;
use ergo_state::ChainStateRead;
use ergo_sync::coordinator::SyncCoordinator;
use ergo_sync::executor::{HydrationError, SyncExecutor};
use tracing::{info, warn};

/// Repair a header-only floor left by older boot activation, then rebuild the
/// pending window from the actual applied tip. A fresh valid floor is a no-op.
pub(super) fn repair_unapplied_floor_and_rebuild_pending(
    store: &mut ergo_state::StateBackendKind,
    executor: &mut SyncExecutor,
    coordinator: &mut SyncCoordinator,
) -> Result<Option<u32>, HydrationError> {
    let Some(sentinel) = repair_unapplied_floor_after_header_sync(store, coordinator) else {
        return Ok(None);
    };
    executor.reset_recovery_done();
    let recovered = executor.recover_coordinator(store, coordinator)?;
    info!(
        sentinel,
        recovered, "fresh UTXO download window rebuilt from genesis"
    );
    Ok(Some(sentinel))
}

/// Header synchronization cannot advance a fresh UTXO download floor past the
/// first unapplied block. Reset the old header-only sentinel when present;
/// pruning after apply, snapshot installation and NiPoPoW proofs (whose
/// `PoPowSparse` store keeps the proof's `dense_from_height` floor) own all
/// other floors.
pub(super) fn repair_unapplied_floor_after_header_sync(
    store: &mut ergo_state::StateBackendKind,
    coordinator: &mut SyncCoordinator,
) -> Option<u32> {
    if !coordinator.sync_state().headers_chain_synced() {
        return None;
    }
    let meta = store.chain_state_meta();
    if meta.best_full_block_height != 0 || meta.header_availability != HeaderAvailability::Dense {
        return None;
    }
    let utxo = store.as_utxo_mut()?;
    let sentinel = match utxo.try_read_minimal_full_block_height_raw() {
        Ok(Some(sentinel)) if sentinel > 1 => sentinel,
        Ok(_) => return None,
        Err(error) => {
            warn!(%error, "cannot read fresh UTXO download floor; retrying next tick");
            return None;
        }
    };
    if let Err(error) = utxo.repair_unapplied_pruning_floor() {
        warn!(%error, sentinel, "cannot reset unapplied UTXO download floor; retrying next tick");
        return None;
    }
    coordinator.sync_state_mut().set_prune_sentinel(1);
    info!(
        old_floor = sentinel,
        "reset header-only UTXO floor; full replay requires the applied parent state"
    );
    Some(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::{serialize_header, Header};
    use ergo_state::chain::HeaderMeta;
    use ergo_state::store::StateStore;
    use ergo_sync::executor::SyncExecutor;
    use ergo_validation::context::ProtocolParams;

    // ----- helpers -----

    /// Header-chain tip the fixture seeds.
    const HEADER_TIP: u32 = 1200;
    /// Scala `updateBestFullBlock` output for `(current_min = 1,
    /// header_height = 1200, blocksToKeep = 250, votingLength = 1024)` —
    /// oracle vector `flip_h1200_keep250_mainnet`. `1200 - 250 + 1 = 951`.
    const EXPECTED_SENTINEL: u32 = 951;
    /// A bounded initial download window, beginning at the first unapplied block.
    const DOWNLOAD_WINDOW: usize = 384;

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_millis() as u64
    }

    fn synth_header(height: u32, parent: [u8; 32], timestamp_ms: u64) -> Header {
        let root = |seed: u8| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&height.to_be_bytes());
            b[4] = seed;
            b
        };
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes(parent),
            ad_proofs_root: Digest32::from_bytes(root(0xAD)),
            state_root: ADDigest::from_bytes([0u8; 33]),
            transactions_root: Digest32::from_bytes(root(0x77)),
            timestamp: timestamp_ms,
            n_bits: 0x1d00ffff,
            height,
            extension_root: Digest32::from_bytes(root(0xEE)),
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        }
    }

    /// A genesis-initialized store carrying a linear synthetic header
    /// chain `1..=HEADER_TIP` whose tip timestamp is `now` — the state a
    /// from-scratch UTXO node reaches at the headers-synced flip: header
    /// metadata stored as accepted, no full block applied, no sentinel row.
    /// This fixture bypasses header validation and does not prove PoW validity.
    ///
    /// The fresh tip timestamp is what makes `recover_coordinator` flip
    /// the latch with no peers connected (`check_headers_synced` is a pure
    /// function of the best header's timestamp).
    fn seeded_store() -> (ergo_state::StateBackendKind, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = StateStore::open(&dir.path().join("state.redb"))
            .expect("open store")
            .with_non_durable_commits_for_test();
        store.initialize_genesis(&[]).expect("init genesis");
        let base = now_ms() - u64::from(HEADER_TIP) * 120_000;
        let mut parent = store.chain_state_meta().best_header_id;
        for height in 1..=HEADER_TIP {
            let ts = base + u64::from(height) * 120_000;
            let header = synth_header(height, parent, ts);
            let (bytes, id) = serialize_header(&header).expect("serialize header");
            let id = *id.as_bytes();
            let meta = HeaderMeta {
                parent_id: parent,
                height,
                cumulative_score: u64::from(height).to_be_bytes().to_vec(),
                pow_validity: 1,
                timestamp: ts,
            };
            store
                .store_validated_header(
                    &id,
                    &bytes,
                    &meta,
                    Some((height, meta.cumulative_score.clone())),
                )
                .unwrap_or_else(|e| panic!("store header h={height}: {e:?}"));
            parent = id;
        }
        let cs = store.chain_state_meta();
        assert_eq!(cs.best_header_height, HEADER_TIP, "fixture header tip");
        assert_eq!(cs.best_full_block_height, 0, "fixture applies no blocks");
        (ergo_state::StateBackendKind::Utxo(store), dir)
    }

    /// Replay the boot sequence up to (but not including) the legacy floor
    /// repair: hydrate, build the header index, recover the coordinator.
    fn boot_before_floor_repair(
        store: &mut ergo_state::StateBackendKind,
    ) -> (SyncExecutor, SyncCoordinator) {
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            DifficultyParams::mainnet(),
        );
        let mut coordinator = SyncCoordinator::new_with_window(0, DOWNLOAD_WINDOW);
        coordinator.set_requires_proofs(true);
        executor.hydrate_from_store(store).expect("hydrate");
        executor
            .hydrate_block_context(store)
            .expect("hydrate block context");
        executor.load_header_index(store).expect("header index");
        executor
            .recover_coordinator(store, &mut coordinator)
            .expect("boot recovery");
        assert!(
            coordinator.sync_state().headers_chain_synced(),
            "fixture premise: the fresh tip must flip the headers-synced latch",
        );
        assert!(
            executor.recovery_done(),
            "fixture premise: boot recovery latches recovery_done before floor repair",
        );
        (executor, coordinator)
    }

    // ----- happy path -----

    #[test]
    fn fresh_pruned_utxo_downloads_preserve_the_first_unapplied_parent() {
        let (mut store, _dir) = seeded_store();
        let (mut executor, mut coordinator) = boot_before_floor_repair(&mut store);
        assert_eq!(
            repair_unapplied_floor_and_rebuild_pending(
                &mut store,
                &mut executor,
                &mut coordinator,
            )
            .unwrap(),
            None
        );
        assert_eq!(store.read_minimal_full_block_height().unwrap(), 1);
        let queued = coordinator.sync_state().blocks_to_download();
        assert_eq!(queued.first().map(|block| block.height), Some(1));
        assert_eq!(
            queued.last().map(|block| block.height),
            Some(DOWNLOAD_WINDOW as u32)
        );
    }

    #[test]
    fn older_unapplied_header_floor_is_reset_and_pending_window_is_rebuilt() {
        let (mut store, _dir) = seeded_store();
        store
            .as_utxo()
            .unwrap()
            .write_minimal_full_block_height(EXPECTED_SENTINEL)
            .unwrap();
        let (mut executor, mut coordinator) = boot_before_floor_repair(&mut store);
        coordinator
            .sync_state_mut()
            .set_prune_sentinel(EXPECTED_SENTINEL);
        assert_eq!(
            repair_unapplied_floor_and_rebuild_pending(
                &mut store,
                &mut executor,
                &mut coordinator,
            )
            .unwrap(),
            Some(1)
        );
        assert_eq!(store.read_minimal_full_block_height().unwrap(), 1);
        assert_eq!(
            coordinator
                .sync_state()
                .blocks_to_download()
                .first()
                .map(|block| block.height),
            Some(1)
        );
        assert_eq!(
            repair_unapplied_floor_and_rebuild_pending(
                &mut store,
                &mut executor,
                &mut coordinator,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn valid_fresh_utxo_floor_leaves_the_pending_range_intact() {
        // A valid fresh UTXO floor needs no repair. The helper must preserve
        // the genesis download range that boot recovery already built.
        let (mut store, _dir) = seeded_store();
        let (mut executor, mut coordinator) = boot_before_floor_repair(&mut store);
        let before: Vec<u32> = coordinator
            .sync_state()
            .blocks_to_download()
            .iter()
            .map(|b| b.height)
            .collect();
        assert_eq!(
            before.first().copied(),
            Some(1),
            "fresh floor premise: boot recovery starts from genesis",
        );

        let repaired =
            repair_unapplied_floor_and_rebuild_pending(&mut store, &mut executor, &mut coordinator)
                .expect("valid fresh floor repair is a no-op");
        assert_eq!(repaired, None, "a valid fresh floor needs no repair");

        let after: Vec<u32> = coordinator
            .sync_state()
            .blocks_to_download()
            .iter()
            .map(|b| b.height)
            .collect();
        assert_eq!(after, before, "valid download range must be untouched");
    }

    #[test]
    fn nipopow_proof_floor_survives_the_headers_synced_latch() {
        // A Mode 4 proof leaves the full tip at 0 with the proof's
        // `dense_from_height` floor and no snapshot marker. Forward header
        // sync can flip the latch before the snapshot install; the repair
        // must leave that bootstrap floor alone, quietly, on every tick.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tracing_subscriber::prelude::*;
        struct WarnCounter(Arc<AtomicUsize>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCounter {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if *event.metadata().level() == tracing::Level::WARN {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = StateStore::open(&dir.path().join("state.redb"))
            .expect("open store")
            .with_non_durable_commits_for_test();
        store.initialize_genesis(&[]).expect("init genesis");
        store
            .apply_popow_proof(&ergo_state::test_helpers::nipopow_proof_dense_from_2())
            .expect("apply popow proof");
        let mut store = ergo_state::StateBackendKind::Utxo(store);
        assert_eq!(store.read_minimal_full_block_height().unwrap(), 2);
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            DifficultyParams::mainnet(),
        );
        let mut coordinator = SyncCoordinator::new_with_window(0, DOWNLOAD_WINDOW);
        coordinator.sync_state_mut().set_prune_sentinel(2);
        coordinator.sync_state_mut().mark_headers_chain_synced();

        let warnings = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(WarnCounter(warnings.clone()));
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..2 {
                assert_eq!(
                    repair_unapplied_floor_and_rebuild_pending(
                        &mut store,
                        &mut executor,
                        &mut coordinator,
                    )
                    .unwrap(),
                    None
                );
            }
        });
        assert_eq!(
            warnings.load(Ordering::SeqCst),
            0,
            "no per-tick retry warning"
        );
        assert_eq!(store.read_minimal_full_block_height().unwrap(), 2);
        assert_eq!(coordinator.sync_state().prune_sentinel(), 2);
    }
}
