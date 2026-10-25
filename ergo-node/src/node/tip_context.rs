//! Per-call tip-context construction for mempool admission. Validates
//! against the block after the tip as Scala's mempool predicts it
//! (`ErgoStateContext.simplifiedUpcoming`, see
//! [`ergo_validation::TransactionContext::mempool_upcoming`]): height
//! `tip + 1`, parent = the tip, timestamp `tip + 1`, the generator as miner,
//! no votes, and the newest nine headers.
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
    /// EIP-27 re-emission rule inputs (mainnet only), cloned from the
    /// executor's boot-time copy so admission enforces the same burning
    /// condition the block validator does. `None` on networks without EIP-27.
    pub(super) reemission: Option<ergo_validation::ReemissionRuleInputs>,
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
            reemission: self.reemission.as_ref(),
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
    // Mempool admission reads the active protocol parameters
    // (per-epoch voted set) instead of the network-wide defaults. The
    // cache is updated synchronously with chain_state in apply_block /
    // rollback_to / execute_reorg, so this read is consistent with the
    // tip we just observed above.
    let params = ergo_validation::ProtocolParams::from_active_with_settings(
        state.store.active_params(),
        state.store.validation_settings(),
    );
    // Scala's mempool context (`ErgoStateContext.simplifiedUpcoming`) takes
    // `blockVersion` from the active parameters and the pre-header version
    // from the last header; a mid-epoch header's version need not match.
    let mut tx_context = ergo_validation::TransactionContext::mempool_upcoming(
        tip_header,
        &tip_header_id,
        params.block_version,
    );
    // The applied full-block height, which the header window is aligned to.
    tx_context.height = tip_height.saturating_add(1);
    let last_headers: Vec<ergo_ser::header::Header> = ctx_headers
        .iter()
        .take(ergo_validation::UPCOMING_LAST_HEADERS)
        .map(|ch| ch.header().clone())
        .collect();
    let best_header_height = state.store.chain_state_meta().best_header_height;
    // Same EIP-27 rule inputs the block validator uses (installed on the
    // executor at boot); `None` on networks without re-emission.
    let reemission = state.executor.reemission_rules().cloned();
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
        reemission,
    })
}

#[cfg(test)]
mod tests {
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::{serialize_header, Header};
    use ergo_sigma::evaluator::PreHeaderVotes;
    use ergo_state::store::StateStore;

    // ----- oracle parity -----

    /// Scala's mempool validates with `stateContext.simplifiedUpcoming()`
    /// (`ErgoMemPool.scala:327`, `ErgoStateContext.scala:152-170`): parent
    /// = the tip, timestamp = tip + 1, the generator as miner, no votes, and
    /// `lastHeaders.take(9)`. The tip below votes and has a non-generator
    /// miner key, so none of these can come from the tip by accident.
    #[test]
    fn mempool_context_is_scala_simplified_upcoming() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&directory.path().join("state.redb"))
            .unwrap()
            .with_non_durable_commits_for_test();
        store.initialize_genesis(&[]).unwrap();
        let mut parent = ModifierId::from_bytes([0; 32]);
        let mut ids = Vec::new();
        for height in 1..=12u32 {
            let header = Header {
                version: 3,
                parent_id: parent,
                ad_proofs_root: Digest32::from_bytes([0; 32]),
                transactions_root: Digest32::from_bytes([0; 32]),
                state_root: ADDigest::from_bytes([0; 33]),
                // The unchecked helper's synthesized HEADER_META timestamp, so
                // block-context hydration passes its integrity check.
                timestamp: 1_700_000_000 + u64::from(height),
                extension_root: Digest32::from_bytes([0; 32]),
                n_bits: 16842752,
                height,
                votes: [1, 2, 3],
                unparsed_bytes: Vec::new(),
                solution: AutolykosSolution::V2 {
                    pk: ergo_primitives::group_element::GroupElement::from([3; 33]),
                    nonce: [0; 8],
                },
            };
            let (bytes, id) = serialize_header(&header).unwrap();
            store.store_header(id.as_bytes(), &bytes).unwrap();
            let root = store.root_digest();
            store
                .apply_block_unchecked_for_test(height, id.as_bytes(), &root, &[])
                .unwrap();
            ids.push(*id.as_bytes());
            parent = id;
        }
        let mut node = crate::node::tests::make_state_with_store(store);
        node.executor.hydrate_block_context(&node.store).unwrap();

        let owned = super::build_tip_context(&node).unwrap();
        let context = &owned.tx_context;
        let tip = &owned.last_headers[0];
        assert_eq!(tip.height, 12);
        assert_eq!(context.height, 13);
        assert_eq!(context.pre_header_parent_id, ids[11]);
        assert_eq!(context.pre_header_timestamp, tip.timestamp + 1);
        assert_eq!(
            context.miner_pubkey,
            ergo_ser::sigma_value::SECP256K1_GENERATOR
        );
        assert_eq!(context.pre_header_votes, PreHeaderVotes::Empty);
        assert_eq!(context.pre_header_n_bits, u64::from(tip.n_bits));
        assert_eq!(context.pre_header_version, tip.version);
        assert_eq!(
            owned
                .last_headers
                .iter()
                .map(|header| header.height)
                .collect::<Vec<_>>(),
            (4..=12).rev().collect::<Vec<_>>()
        );
    }
}
