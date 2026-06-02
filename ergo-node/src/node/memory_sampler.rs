//! Periodic memory sampler for the action loop.
//!
//! Pure observability: reads point-in-time counters off `NodeState`,
//! formats them as one CSV row, appends to `path`. The file handle is
//! opened lazily on first call and cached in `file`. All errors log
//! once and otherwise swallow themselves — observability must never
//! affect node behavior. Synchronous `std::fs` is fine: the row is
//! O(few hundred bytes) and the cadence is 5 s.

use ergo_state::ChainStateRead;
use tracing::warn;

use super::NodeState;

pub(super) fn sample_memory(
    state: &NodeState,
    path: &std::path::Path,
    file: &mut Option<std::fs::File>,
) {
    if file.is_none() {
        match crate::mem_csv::open_or_init(path) {
            Ok(f) => *file = Some(f),
            Err(e) => {
                warn!(error = %e, path = %path.display(), "mem-csv open failed");
                return;
            }
        }
    }
    let f = match file.as_mut() {
        Some(f) => f,
        None => return,
    };

    let proc = crate::mem_probe::read_proc_status().unwrap_or_default();
    let smaps = crate::mem_smaps::read_smaps_rollup().unwrap_or_default();
    let chain = state.store.chain_state_meta();
    let bh = chain.best_header_height;
    let bf = chain.best_full_block_height;
    // The arena/batch/redb metrics below are UTXO-arena counters with
    // no digest-backend analogue; the memory sampler is gated off in
    // digest mode.
    let utxo = state
        .store
        .as_utxo()
        .expect("utxo-only: arena/batch memory metrics are gated off in digest mode");
    let sync_phase = if bh == 0 {
        "Bootstrap"
    } else if bf < bh {
        "Syncing"
    } else {
        "AtTip"
    };

    // Indexer status mirror: cheap (RwLock read + atomic). When the
    // indexer is disabled we record zeros + "Disabled" so the column
    // shape is stable across runs regardless of config.
    let (indexer_indexed_height, indexer_lag, indexer_status, redb_indexer_evictions) =
        match state.indexer_handle.as_ref() {
            Some(h) => {
                let height = ergo_indexer::IndexerQuery::indexed_height(h);
                let lag = (bf as u64).saturating_sub(height);
                let status = match ergo_indexer::IndexerQuery::status(h) {
                    ergo_indexer::IndexerStatus::Syncing => "Syncing",
                    ergo_indexer::IndexerStatus::CaughtUp => "CaughtUp",
                    ergo_indexer::IndexerStatus::Halted(_) => "Halted",
                };
                let evictions = h.store().map(|s| s.redb_cache_evictions()).unwrap_or(0);
                (height, lag, status, evictions)
            }
            None => (0, 0, "Disabled", 0),
        };

    let sample = crate::mem_csv::MemSample {
        ts_ms: crate::mem_csv::now_ms(),
        best_header: bh,
        best_full_block: bf,
        sync_phase,
        proc,
        avl_cache_clean_bytes: utxo.arena_cache_clean_bytes() as u64,
        avl_cache_capacity_bytes: utxo.arena_cache_capacity_bytes() as u64,
        avl_clean_len: utxo.arena_cache_clean_len() as u64,
        avl_dirty_len: utxo.arena_cache_dirty_len() as u64,
        avl_read_count: utxo.arena_read_count(),
        batch_headers_len: utxo.batch_headers_len() as u64,
        batch_headers_bytes: utxo.batch_headers_bytes() as u64,
        batch_meta_len: utxo.batch_meta_len() as u64,
        header_index_len: state.executor.header_index_len() as u64,
        header_index_est_bytes: state.executor.header_index_estimated_bytes() as u64,
        last_headers_len: state.executor.last_headers_len() as u64,
        last_headers_bytes: state.executor.last_headers_bytes() as u64,
        orphan_headers_len: state.executor.orphan_headers_len() as u64,
        orphan_headers_bytes: state.executor.orphan_headers_bytes() as u64,
        pending_blocks_len: state.coordinator.sync_state().pending_blocks_len() as u64,
        delivery_received_len: state.coordinator.delivery().received_set_len() as u64,
        delivery_inflight_total: state.coordinator.delivery().total_inflight() as u64,
        mempool_count: state.mempool.size() as u64,
        mempool_bytes: state.mempool.total_bytes() as u64,
        peer_count: state.peer_manager.peer_count() as u64,
        known_addresses_len: state.peer_manager.known_addresses_len() as u64,
        // ergo-state and ergo-p2p don't enable redb's `cache_metrics`
        // feature, so their `cache_stats().evictions()` returns 0. The
        // column is kept for wire-shape parity; only the indexer column
        // surfaces real numbers today.
        redb_state_evictions: utxo.redb_cache_evictions(),
        redb_indexer_evictions,
        redb_addrbook_evictions: 0,
        indexer_indexed_height,
        indexer_lag,
        indexer_status,
        smaps,
    };

    if let Err(e) = crate::mem_csv::append_row(f, &sample) {
        warn!(error = %e, "mem-csv append failed");
    }
}
