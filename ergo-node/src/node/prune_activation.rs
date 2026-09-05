//! Mode 3 prune-sentinel activation at the headers-synced flip.
//!
//! Scala seeds `minimalFullBlockHeight` the moment the headers chain
//! is declared synced, not on the first full-block apply:
//! `ToDownloadProcessor.toDownload` sees the first fresh header, calls
//! `FullBlockPruningProcessor.updateBestFullBlock(header)`
//! (`ToDownloadProcessor.scala:110-118` →
//! `FullBlockPruningProcessor.scala:48-69`), and from then on
//! `nextModifiersToDownload` starts its walk at
//! `minimalFullBlockHeight` for a node with no full blocks yet
//! (`ToDownloadProcessor.scala:99-102`).
//!
//! Rust's sentinel previously only advanced inside a full-block apply
//! (`ergo-state/src/store/mod.rs` eviction seam and its `persist.rs`
//! pipeline twin), so a fresh pruned node performed a full
//! genesis-onward IBD and only started evicting afterwards. This module
//! closes that gap with a one-shot seed driven from both flip
//! observation points — boot (`boot::sync_setup`, where
//! `recover_coordinator` may flip the latch off the best header's
//! timestamp) and the periodic tick (`sync_tick`, covering the
//! `on_header` freshness edge and the caught-up-to-peers fallback).
//!
//! The policy itself is
//! [`ergo_state::store::activation_minimal_full_block_height`], pinned
//! against the Scala oracle by
//! `ergo-state/tests/prune_activation_scala_oracle.rs`.
//!
//! **Seed height.** Scala seeds from the *flipping* header's own
//! height, inside `toDownload` at the moment it flips
//! (`ToDownloadProcessor.scala:110-112`). This module's `on_header`
//! observation point can run one or more headers after that edge —
//! `SyncState::check_headers_synced` flips the latch synchronously as
//! part of validating a specific header, but this helper is invoked
//! from the next `sync_tick`, and further headers may validate in
//! between. `SyncState::flip_seed_height` closes that gap: the
//! freshness edge records the flipping header's own height there, and
//! this module prefers it over the live `best_header_height` when
//! present. The two other observation points don't need it — boot's
//! `sync_setup` calls this immediately after `recover_coordinator`
//! detects the flip in the same synchronous step, and the
//! caught-up-to-peers fallback has no single flipping header to begin
//! with (its own current-tip height already **is** the value to seed
//! from). Net effect either way is benign even uncorrected: a
//! higher-than-Scala seed still leaves the retained suffix at least
//! `blocks_to_keep` deep relative to the (also higher) tip it was
//! computed against — it only ever seeds equal to or later than Scala.

use ergo_state::store::activation_minimal_full_block_height;
use ergo_state::ChainStateRead;
use ergo_sync::coordinator::SyncCoordinator;
use ergo_sync::executor::{HydrationError, SyncExecutor};
use tracing::{info, warn};

/// Boot-path arm: seed the sentinel at the flip, then rebuild the
/// coordinator's pending range against it.
///
/// Boot runs `recover_coordinator` *before* this seeding step (it is
/// what flips the headers-synced latch in the first place), so on a
/// from-scratch Mode 3 node that walk anchors at
/// `best_full_block_height = 0` and registers the bottom of the chain —
/// a range `SyncState::blocks_to_download` then discards wholesale,
/// because the seed that lands a moment later puts the sentinel far
/// above it. Recovery has already latched `recovery_done`, so no later
/// tick repeats the walk, and the seed helper is one-shot, so nothing
/// repopulates the queue either: section requests stop and full-block
/// sync stalls before it starts.
///
/// Re-running recovery after a fresh seed closes that window. The
/// second walk sees the sentinel in `SyncState` and anchors on the same
/// floor the download window uses. `reset_recovery_done` is safe here
/// because `recover_coordinator` is idempotent — `add_pending_block`
/// and `register_header` both de-duplicate by header id.
///
/// The periodic tick uses the same path: it seeds before its own
/// recovery call, so on the normal flip the single walk already sees
/// the sentinel and the rebuild here is what its step 3 would have done
/// anyway. The rebuild matters on the tick when a *retried* seed lands —
/// an earlier observation whose sentinel write failed has already
/// latched `recovery_done` over a range below the future sentinel.
///
/// Returns the seeded sentinel, or `None` when the flip must not move
/// it (every no-op condition of [`seed_prune_sentinel_at_flip`]).
pub(super) fn seed_prune_sentinel_and_rebuild_pending(
    store: &mut ergo_state::StateBackendKind,
    executor: &mut SyncExecutor,
    coordinator: &mut SyncCoordinator,
    blocks_to_keep: i32,
) -> Result<Option<u32>, HydrationError> {
    let Some(sentinel) = seed_prune_sentinel_at_flip(store, coordinator, blocks_to_keep) else {
        return Ok(None);
    };
    executor.reset_recovery_done();
    let recovered = executor.recover_coordinator(store, coordinator)?;
    info!(
        sentinel,
        recovered,
        pending = coordinator.sync_state().pending_blocks_len(),
        "Mode 3: pending download range rebuilt above the freshly seeded \
         prune sentinel",
    );
    Ok(Some(sentinel))
}

/// Seed the prune sentinel if the headers-synced flip has happened on a
/// pruned store that holds no full blocks yet. Persists the value and
/// mirrors it into `SyncState` so the coordinator's request-side gate
/// and download window both see it on the same tick.
///
/// Returns the seeded value, or `None` when the flip must not move the
/// sentinel. Idempotent: the seed materializes the sentinel row, and a
/// present row is one of the `None` conditions, so a second call is a
/// no-op. Cheap to call every tick — `blocks_to_keep <= 0` (archive /
/// Mode 6) and `best_full_block_height > 0` short-circuit before any
/// redb read.
pub(super) fn seed_prune_sentinel_at_flip(
    store: &mut ergo_state::StateBackendKind,
    coordinator: &mut SyncCoordinator,
    blocks_to_keep: i32,
) -> Option<u32> {
    if !coordinator.sync_state().headers_chain_synced() {
        return None;
    }
    if blocks_to_keep <= 0 {
        return None;
    }
    let meta = store.chain_state_meta();
    if meta.best_full_block_height > 0 {
        return None;
    }
    // Mode 3 pruning is UTXO-backend only: the digest backend's two
    // canonical configurations are Mode 5 (`blocks_to_keep = -1`) and
    // Mode 6 (`= 0`), both already excluded above. Bail rather than
    // widen the backend trait for a combination the runtime gate
    // refuses.
    let utxo = store.as_utxo()?;
    let voting_length = utxo.voting_settings().voting_length;
    let sentinel_row = match utxo.try_read_minimal_full_block_height_raw() {
        Ok(row) => row,
        Err(e) => {
            warn!(
                error = %e,
                "Mode 3: cannot read the prune sentinel row; \
                 activation seeding skipped this tick",
            );
            return None;
        }
    };
    // Seed from the height Scala actually flips on
    // (`ToDownloadProcessor.scala:110-112`) when we captured it: the
    // `on_header` freshness edge (`SyncState::check_headers_synced`)
    // records the flipping header's own height, but this helper may
    // observe the flip on a LATER tick than the one that flipped it —
    // any headers validated in between would otherwise inflate the
    // seed height above what Scala wrote. Falls back to the live
    // `best_header_height` when the flip has no single flipping header
    // (the caught-up-to-peers fallback) or when this is the boot-path
    // observation immediately following the flip it just detected,
    // where the two are identical anyway.
    let seed_height = coordinator
        .sync_state()
        .flip_seed_height()
        .unwrap_or(meta.best_header_height);
    let seeded = activation_minimal_full_block_height(
        sentinel_row,
        seed_height,
        meta.best_full_block_height,
        blocks_to_keep,
        voting_length,
    )?;
    if let Err(e) = utxo.write_minimal_full_block_height(seeded) {
        warn!(
            error = %e,
            sentinel = seeded,
            "Mode 3: prune sentinel activation write failed; \
             retrying on the next flip observation",
        );
        return None;
    }
    coordinator.sync_state_mut().set_prune_sentinel(seeded);
    info!(
        sentinel = seeded,
        seed_height,
        best_header_height = meta.best_header_height,
        blocks_to_keep,
        voting_length,
        "Mode 3: headers chain synced — prune sentinel seeded; \
         full-block download starts here (Scala \
         FullBlockPruningProcessor.updateBestFullBlock parity)",
    );
    Some(seeded)
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
    /// Smallest legal pruned window (`keep_versions 200 + SAFETY_MARGIN 50`).
    const BLOCKS_TO_KEEP: i32 = 250;
    /// Scala `updateBestFullBlock` output for `(current_min = 1,
    /// header_height = 1200, blocksToKeep = 250, votingLength = 1024)` —
    /// oracle vector `flip_h1200_keep250_mainnet`. `1200 - 250 + 1 = 951`.
    const EXPECTED_SENTINEL: u32 = 951;
    /// Deliberately smaller than `HEADER_TIP - EXPECTED_SENTINEL` would
    /// need to reach the sentinel from height 0: with this window a walk
    /// anchored at `best_full_block_height = 0` stops at 384, far below
    /// the sentinel, which is exactly the stall under test.
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
    /// from-scratch pruned node reaches at the headers-synced flip: every
    /// header validated, no full block applied, no sentinel row.
    ///
    /// The fresh tip timestamp is what makes `recover_coordinator` flip
    /// the latch with no peers connected (`check_headers_synced` is a pure
    /// function of the best header's timestamp).
    fn seeded_store() -> (ergo_state::StateBackendKind, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = StateStore::open(&dir.path().join("state.redb")).expect("open store");
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

    /// Replay the boot sequence up to (but not including) the activation
    /// seed: hydrate, build the header index, recover the coordinator.
    fn boot_up_to_the_seed(
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
            "fixture premise: boot recovery latches recovery_done before the seed",
        );
        (executor, coordinator)
    }

    // ----- happy path -----

    #[test]
    fn boot_seed_above_the_recovered_window_rebuilds_the_pending_range() {
        // Boot order is recover-then-seed, so the walk anchors at
        // `best_full_block_height = 0` and registers 1..=384 while the
        // seed lands at 951. `blocks_to_download` drops every entry below
        // the sentinel, `recovery_done` is already latched, and the seed
        // helper is one-shot — nothing would ever repopulate the queue.
        let (mut store, _dir) = seeded_store();
        let (mut executor, mut coordinator) = boot_up_to_the_seed(&mut store);

        let seeded = seed_prune_sentinel_and_rebuild_pending(
            &mut store,
            &mut executor,
            &mut coordinator,
            BLOCKS_TO_KEEP,
        )
        .expect("rebuild must not fail on an intact header chain");
        assert_eq!(seeded, Some(EXPECTED_SENTINEL), "Scala-parity seed value");

        let queued = coordinator.sync_state().blocks_to_download();
        assert!(
            !queued.is_empty(),
            "an empty download queue is the stall: no section request goes \
             out, so best_full_block_height never leaves 0",
        );
        assert_eq!(
            queued.first().map(|b| b.height),
            Some(EXPECTED_SENTINEL),
            "the rebuilt range must start at the sentinel — the first \
             block a pruned node is allowed to hold",
        );
        assert_eq!(
            queued.last().map(|b| b.height),
            Some(HEADER_TIP),
            "and run to the header tip, which is inside the window from \
             the sentinel floor",
        );
    }

    #[test]
    fn boot_seed_refused_for_an_archive_node_leaves_the_pending_range_intact() {
        // Same fixture with `blocks_to_keep = -1`. The seed is refused, so
        // the helper must not disturb the range boot recovery already
        // built: an archive node downloads from genesis onward.
        let (mut store, _dir) = seeded_store();
        let (mut executor, mut coordinator) = boot_up_to_the_seed(&mut store);
        let before: Vec<u32> = coordinator
            .sync_state()
            .blocks_to_download()
            .iter()
            .map(|b| b.height)
            .collect();
        assert_eq!(
            before.first().copied(),
            Some(1),
            "archive premise: boot recovery seeds from genesis onward",
        );

        let seeded = seed_prune_sentinel_and_rebuild_pending(
            &mut store,
            &mut executor,
            &mut coordinator,
            -1,
        )
        .expect("archive rebuild is a no-op, not a failure");
        assert_eq!(seeded, None, "an archive node must never arm the sentinel");

        let after: Vec<u32> = coordinator
            .sync_state()
            .blocks_to_download()
            .iter()
            .map(|b| b.height)
            .collect();
        assert_eq!(after, before, "archive download range must be untouched");
    }
}
