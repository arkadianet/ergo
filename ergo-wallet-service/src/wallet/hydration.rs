pub use crate::state::HydrationSource;

use std::collections::{BTreeMap, BTreeSet};

/// Hook the chain-apply pipeline calls inside the same redb write
/// transaction as chain state mutations. Provides snapshots of the
/// wallet's tracked-pubkey state so the wallet apply hook can
/// classify outputs.
///
/// Implementors wrap live wallet state and return snapshots. The
/// apply path uses primitive key and tree data only.
pub trait WalletApplyHook: Send + Sync {
    /// Snapshot of P2PK ErgoTree bytes for all currently-tracked
    /// pubkeys. The apply hook does `set.contains(output.ergo_tree_bytes)`.
    fn tracked_p2pk_trees(&self) -> BTreeSet<Vec<u8>>;

    /// Snapshot of `derivation_path_index → pubkey` for all tracked
    /// pubkeys. The apply hook uses this for miner-reward classification
    /// (extracts the embedded pubkey from a wrapper-script output and
    /// checks if it's in this map's values).
    fn cached_pubkeys(&self) -> BTreeMap<u64, [u8; 33]>;

    fn wallet_state_snapshot(&self) -> (BTreeSet<Vec<u8>>, BTreeMap<u64, [u8; 33]>) {
        (self.tracked_p2pk_trees(), self.cached_pubkeys())
    }

    fn allow_non_contiguous_wallet_apply(&self) -> bool {
        false
    }

    /// Number of registered `/scan/*` scans. The apply path skips ALL scan
    /// matching when this is 0 (the common case, especially during IBD before
    /// any scan exists), so it must be cheap. Defaults to 0 so non-scan hook
    /// impls (e.g. test stubs) need not override it.
    fn registered_scan_count(&self) -> usize {
        0
    }

    /// For each box in `boxes` (a block's outputs), the ids of registered scans
    /// whose tracking rule matches it — returned in the SAME order as `boxes`.
    /// Called once per block, ONLY when `registered_scan_count() > 0`. The
    /// implementor loads the scan registry once and runs the predicate matcher.
    /// Defaults to "nothing matches".
    fn match_boxes(&self, boxes: &[ergo_ser::ergo_box::ErgoBox]) -> Vec<Vec<u16>> {
        vec![Vec::new(); boxes.len()]
    }
}
