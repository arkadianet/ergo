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

use ergo_state::store::activation_minimal_full_block_height;
use ergo_state::ChainStateRead;
use ergo_sync::coordinator::SyncCoordinator;
use tracing::{info, warn};

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
    let seeded = activation_minimal_full_block_height(
        sentinel_row,
        meta.best_header_height,
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
        best_header_height = meta.best_header_height,
        blocks_to_keep,
        voting_length,
        "Mode 3: headers chain synced — prune sentinel seeded; \
         full-block download starts here (Scala \
         FullBlockPruningProcessor.updateBestFullBlock parity)",
    );
    Some(seeded)
}
