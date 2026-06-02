//! Per-call tip-context construction for mempool admission. Validates
//! at `tip + 1` height because that's where a candidate tx would land
//! if mined next; pre-header fields come from the current tip as a
//! best-effort proxy for the next pre-header.
//!
//! `OwnedTipContext` is the stack-owned wrapper: `MempoolTipContext`
//! holds references, so the caller builds the owned form once and
//! re-borrows it via `as_mempool_ctx` for each admission call (peer +
//! API paths share the same instance).

use ergo_mempool::admission::TipContext as MempoolTipContext;
use ergo_mempool::types::TipPointer;
use ergo_state::store::StateStore;
use ergo_state::ChainStateRead;

use super::NodeState;

pub(super) struct OwnedTipContext {
    pub(super) tip: TipPointer,
    pub(super) best_header_height: u32,
    pub(super) best_full_block_height: u32,
    pub(super) tx_context: ergo_validation::TransactionContext,
    pub(super) params: ergo_validation::ProtocolParams,
    pub(super) last_headers: Vec<ergo_ser::header::Header>,
}

impl OwnedTipContext {
    pub(super) fn as_mempool_ctx<'a>(&'a self, store: &'a StateStore) -> MempoolTipContext<'a> {
        MempoolTipContext {
            tip: self.tip,
            best_header_height: self.best_header_height,
            best_full_block_height: self.best_full_block_height,
            utxo: store,
            tx_context: &self.tx_context,
            params: &self.params,
            last_headers: &self.last_headers,
        }
    }
}

/// Returns `None` when the recent-headers window is cold (no full
/// block applied yet). Peer path drops on `None` (peer will re-Inv);
/// API path translates `None` to `RejectReason::TipUnready`.
pub(super) fn build_tip_context(state: &NodeState) -> Option<OwnedTipContext> {
    let ctx_headers = state.executor.block_context_headers();
    if ctx_headers.is_empty() {
        return None;
    }
    let tip_header = ctx_headers[0].header();
    let tip_header_id = *ctx_headers[0].header_id();
    let tip_height = state.store.chain_state_meta().best_full_block_height;
    let tip_height_next = tip_height.saturating_add(1);
    let tx_context = ergo_validation::TransactionContext {
        height: tip_height_next,
        miner_pubkey: *tip_header.solution.pk().as_bytes(),
        pre_header_timestamp: tip_header.timestamp,
        activated_script_version: tip_header.version.saturating_sub(1),
        pre_header_version: tip_header.version,
        pre_header_parent_id: *tip_header.parent_id.as_bytes(),
        pre_header_n_bits: tip_header.n_bits as u64,
        pre_header_votes: tip_header.votes,
    };
    let last_headers: Vec<ergo_ser::header::Header> =
        ctx_headers.iter().map(|ch| ch.header().clone()).collect();
    let best_header_height = state.store.chain_state_meta().best_header_height;
    // Mempool admission reads the active protocol parameters
    // (per-epoch voted set) instead of the network-wide defaults. The
    // cache is updated synchronously with chain_state in apply_block /
    // rollback_to / execute_reorg, so this read is consistent with the
    // tip we just observed above.
    let params = ergo_validation::ProtocolParams::from_active(state.store.active_params());
    Some(OwnedTipContext {
        tip: TipPointer {
            height: tip_height,
            header_id: ergo_primitives::digest::Digest32::from_bytes(tip_header_id),
        },
        best_header_height,
        best_full_block_height: tip_height,
        tx_context,
        params,
        last_headers,
    })
}
