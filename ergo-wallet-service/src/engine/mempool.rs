//! Mempool seam for the wallet engine.
//!
//! The engine never talks to a mempool directly; it reads a pool overlay
//! through [`MempoolOverlay`] for the unconfirmed-balance views, the
//! off-chain `/scan/unspentBoxes` overlay and the reward sweep's
//! pool-spend checks. The embedded node adapts its snapshot-backed API
//! mempool view; [`NoopMempoolOverlay`] is the empty-pool implementation.

use std::collections::HashMap;
use std::sync::Arc;

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;

/// Read-only view of the transaction pool, exactly the three reads the
/// wallet engine performs.
pub trait MempoolOverlay: Send + Sync {
    /// True if any pool tx spends the given committed-box id.
    fn is_spent_by_pool(&self, box_id: &Digest32) -> bool;

    /// Pool tx that spends `box_id`, or `None` if no pool tx does.
    fn pool_spending_tx(&self, box_id: &Digest32) -> Option<Digest32>;

    /// All pool-created output boxes indexed by box id. Returns one shared
    /// snapshot allocation, so a caller iterating it sees one coherent pool
    /// even if the pool is rebuilt mid-iteration.
    fn pool_outputs(&self) -> Arc<HashMap<Digest32, ErgoBox>>;
}

/// Empty pool: nothing is spent, no pool outputs exist. An engine built on
/// it behaves exactly like the confirmed-only path.
#[derive(Debug, Default, Clone)]
pub struct NoopMempoolOverlay {
    empty_outputs: Arc<HashMap<Digest32, ErgoBox>>,
}

impl NoopMempoolOverlay {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MempoolOverlay for NoopMempoolOverlay {
    fn is_spent_by_pool(&self, _box_id: &Digest32) -> bool {
        false
    }

    fn pool_spending_tx(&self, _box_id: &Digest32) -> Option<Digest32> {
        None
    }

    fn pool_outputs(&self) -> Arc<HashMap<Digest32, ErgoBox>> {
        self.empty_outputs.clone()
    }
}
