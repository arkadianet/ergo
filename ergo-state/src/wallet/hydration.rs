//! Trait defining the minimal hydration surface `WalletState` needs.
//!
//! Defined in `ergo-state` (not `ergo-wallet`) so the dep direction
//! is `ergo-wallet → ergo-state` (clean) instead of the other way
//! (which would create a cycle once `WalletState` types or the
//! `WalletError` type were referenced from inside ergo-state).
//!
//! Trait methods return only PRIMITIVE types (u32, u64, [u8; 33]) —
//! no `ergo-state::wallet` data-shape leakage. This keeps the
//! interface stable across schema changes inside ergo-state.

/// Minimal interface a wallet hydration source must provide.
/// Implemented in `ergo-state/src/wallet/reader.rs::WalletReader`.
pub trait HydrationSource {
    /// Iterate tracked pubkeys in `(derivation_path_index, pubkey)`
    /// ASC order — the BTreeMap order from `WALLET_TRACKED_PUBKEYS`.
    fn tracked_pubkeys(&self) -> Box<dyn Iterator<Item = (u64, [u8; 33])> + '_>;

    /// Iterate persisted visible-pubkeys in index-ASC order — the
    /// BTreeMap order from `WALLET_VISIBLE_ADDRESSES` (u32 → [u8; 33]).
    /// THIS is the source of truth for `/wallet/addresses` at boot.
    /// Returns the raw pubkey bytes — address rendering happens at
    /// REST read time (so we don't bake the network prefix into
    /// persistent state).
    fn visible_pubkeys(&self) -> Box<dyn Iterator<Item = (u32, [u8; 33])> + '_>;

    /// The persisted change-address pubkey from
    /// `WALLET_CHANGE_ADDRESS` (one row, value = `[u8; 33]`).
    /// Returns `None` if never set or table is empty.
    /// Rendered to a base58 address at REST read time.
    fn change_address_pubkey(&self) -> Option<[u8; 33]>;
}

use std::collections::{BTreeMap, BTreeSet};

/// Hook the chain-apply pipeline calls inside the SAME redb write
/// transaction as chain state mutations. Provides snapshots of the
/// wallet's tracked-pubkey state so the wallet apply hook can
/// classify outputs.
///
/// Implementor (in `ergo-node`): wraps `Arc<RwLock<WalletState>>`
/// and calls `.read()` inside each method to produce a snapshot.
/// Hot-path performance is not a concern: a typical wallet has
/// ≤ low-tens of tracked pubkeys.
pub trait WalletApplyHook: Send + Sync {
    /// Snapshot of P2PK ErgoTree bytes for all currently-tracked
    /// pubkeys. The apply hook does `set.contains(output.ergo_tree_bytes)`.
    fn tracked_p2pk_trees(&self) -> BTreeSet<Vec<u8>>;

    /// Snapshot of `derivation_path_index → pubkey` for all tracked
    /// pubkeys. The apply hook uses this for miner-reward classification
    /// (extracts the embedded pubkey from a wrapper-script output and
    /// checks if it's in this map's values).
    fn cached_pubkeys(&self) -> BTreeMap<u64, [u8; 33]>;

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
    /// implementor (ergo-node) loads the scan registry once and runs the
    /// `ergo-wallet` predicate matcher — which is why this lives behind the hook
    /// rather than in `ergo-state`. Defaults to "nothing matches".
    fn match_boxes(&self, boxes: &[ergo_ser::ergo_box::ErgoBox]) -> Vec<Vec<u16>> {
        vec![Vec::new(); boxes.len()]
    }
}
