//! Shared inventory / RequestModifier section eligibility.
use ergo_state::{ChainStateRead, StateBackendKind};
use tracing::warn;

pub(super) fn serving_sentinel(store: &StateBackendKind) -> Option<u32> {
    match store.read_minimal_full_block_height() {
        Ok(sentinel) => Some(sentinel),
        Err(error) => {
            warn!(%error, operation = "read_minimal_full_block_height", "cannot determine section serving eligibility");
            None
        }
    }
}

/// Byte availability decides whether proofs can be advertised: UTXO nodes
/// may retain regenerated/mined proofs. Gate on sentinel > 1, including
/// Mode 2 / NiPoPoW bootstrap; deny unindexed orphan ids so requests cannot
/// resurrect pruned bytes. Silent non-delivery without penalty mirrors Scala.
/// These reads never consume the apply pipeline's persistence results.
pub(super) fn servable_section(
    store: &StateBackendKind,
    id: &[u8; 32],
    sentinel: u32,
) -> Option<Vec<u8>> {
    match store.read_section_for_serving(id, sentinel) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(%error, section_id = %hex::encode(id), sentinel, operation = "read_section_for_serving", "cannot read section for serving or inventory");
            None
        }
    }
}
