//! redb table definitions for the wallet persistence layer.
//!
//! Key encoding rules:
//! - Single-row tables (scan_height, derivation_head, change_address)
//!   use `()` as the key so they hold exactly one value.
//! - Multi-row tables use simple tuple/array keys whose redb
//!   ordering matches the iteration order we need (see comments).
//!
//! Value encoding: structs serialized via `bincode` for compactness
//! and zero-copy reads where possible. Tag with schema version to
//! detect mismatches at boot.

use redb::TableDefinition;

/// Best block height the wallet has scanned to (one row). When the
/// wallet trails the chain (e.g., after restore-with-rescan), the
/// scanner advances this value block-by-block as it processes
/// historical blocks.
pub const WALLET_SCAN_HEIGHT: TableDefinition<(), u32> = TableDefinition::new("wallet_scan_height");

/// Unspent / spent / immature wallet boxes, keyed by box id.
/// Iterating this table gives all currently-known wallet boxes;
/// the value's `status` field discriminates lifecycle stage.
///
/// Key: 32-byte box id (`Digest32`).
/// Value: bincode-serialized `WalletBox` (see `types.rs`).
pub const WALLET_BOXES: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("wallet_boxes");

/// Index from `(tx_id, output_index)` to box id. Used by the
/// `apply` hook to mark a wallet box as spent when a later tx
/// references it as an input.
///
/// Key: `(tx_id: [u8; 32], output_index: u16)` packed as 34 bytes
/// (32 + 2 big-endian) so iteration order = tx-id then index.
/// Value: 32-byte box id (the same one used in `WALLET_BOXES`).
pub const WALLET_BOXES_BY_TX: TableDefinition<[u8; 34], [u8; 32]> =
    TableDefinition::new("wallet_boxes_by_tx");

/// Wallet transactions: the txs that touched a wallet box (either
/// produced an output to a tracked pubkey, or spent a tracked-pubkey
/// input). Key encoding `(block_height, tx_id)` lets iteration in
/// height-ASC order match the REST `/wallet/transactions` shape.
///
/// Key: `(block_height: u32 BE, tx_id: [u8; 32])` packed as 36 bytes.
/// Value: bincode-serialized `WalletTransaction` (see `types.rs`).
pub const WALLET_TXS: TableDefinition<[u8; 36], Vec<u8>> = TableDefinition::new("wallet_txs");

/// Next-available derivation-path index for new tracked pubkeys.
/// On boot, this should equal `MAX(WALLET_TRACKED_PUBKEYS.path_index) + 1`.
/// Stored as a single-row table for O(1) increment-and-fetch.
pub const WALLET_DERIVATION_HEAD: TableDefinition<(), u64> =
    TableDefinition::new("wallet_derivation_head");

/// Tracked HD pubkeys. Keyed by `(derivation_path_index, pubkey)` so
/// the BTree iteration order = derivation order across restarts
/// (spec §7.1 invariant). Value carries metadata (derivation path
/// Vec<u32>, optional label, height-added) per spec §7.1's
/// value-shape definition.
///
/// Key: `(derivation_path_index: u64 BE, pubkey: [u8; 33])` packed
/// as 41 bytes (8 + 33). Big-endian u64 ensures sort-by-index.
/// Value: bincode-serialized `TrackedPubkeyMeta` (see `types.rs`).
pub const WALLET_TRACKED_PUBKEYS: TableDefinition<[u8; 41], Vec<u8>> =
    TableDefinition::new("wallet_tracked_pubkeys");

/// Visible-address cache (the filtered list per
/// `WalletCache.publicKeyAddresses`). Rebuilt atomically with every
/// write to `WALLET_TRACKED_PUBKEYS`. Per spec §7.1 the value is
/// the pubkey bytes; address rendering happens at REST read time so
/// we don't bake the network prefix into persistent state.
///
/// Key: `index: u32` (matches spec's "filtered-view sequential
/// index"). Only entries for VISIBLE addresses appear here — hidden
/// master is absent.
/// Value: `pubkey: [u8; 33]`. The REST `/wallet/addresses` handler
/// renders to base58 at response-build time.
pub const WALLET_VISIBLE_ADDRESSES: TableDefinition<u32, [u8; 33]> =
    TableDefinition::new("wallet_visible_addresses");

/// Persisted change address (one row, value = 33-byte pubkey).
/// When `None`, the change address falls back to the first tracked
/// pubkey per spec §7.4. Stores the pubkey bytes, not the rendered
/// address string — REST handlers render at read time with the
/// current network prefix.
pub const WALLET_CHANGE_ADDRESS: TableDefinition<(), [u8; 33]> =
    TableDefinition::new("wallet_change_address");

/// Schema version constant for boot-time integrity check. Stored
/// in its own one-row table; bumped on any breaking change.
pub const WALLET_SCHEMA_VERSION_TABLE: TableDefinition<(), u32> =
    TableDefinition::new("wallet_schema_version");

/// Sticky "scan invalidated" flag. Set to `true` when a rescan is
/// aborted mid-way (e.g., by rollback during rescan). Cleared only
/// when a fresh rescan completes from height 0 (or equivalent
/// successful rebuild). Live chain-apply checks this flag and SKIPS
/// writing wallet tables while it's true — so a
/// partial-rescan-then-abort can't be silently papered over by
/// subsequent live blocks advancing scan_height past the gap.
/// `/wallet/status.error` reports "scan_invalidated" to surface
/// the broken state to operators.
pub const WALLET_SCAN_INVALIDATED: TableDefinition<(), bool> =
    TableDefinition::new("wallet_scan_invalidated");

/// Pack a `(derivation_path_index, pubkey)` pair into a 41-byte
/// `WALLET_TRACKED_PUBKEYS` key. Big-endian u64 prefix sorts
/// the table in derivation-order.
pub fn tracked_pubkey_key(derivation_path_index: u64, pubkey: &[u8; 33]) -> [u8; 41] {
    let mut k = [0u8; 41];
    k[..8].copy_from_slice(&derivation_path_index.to_be_bytes());
    k[8..].copy_from_slice(pubkey);
    k
}

/// Unpack a 41-byte `WALLET_TRACKED_PUBKEYS` key back into
/// `(derivation_path_index, pubkey)`.
pub fn parse_tracked_pubkey_key(k: &[u8; 41]) -> (u64, [u8; 33]) {
    let mut idx_bytes = [0u8; 8];
    idx_bytes.copy_from_slice(&k[..8]);
    let mut pk = [0u8; 33];
    pk.copy_from_slice(&k[8..]);
    (u64::from_be_bytes(idx_bytes), pk)
}

/// Pack `(tx_id, output_index)` for `WALLET_BOXES_BY_TX` key.
pub fn box_by_tx_key(tx_id: &[u8; 32], output_index: u16) -> [u8; 34] {
    let mut k = [0u8; 34];
    k[..32].copy_from_slice(tx_id);
    k[32..].copy_from_slice(&output_index.to_be_bytes());
    k
}

/// Pack `(block_height, tx_id)` for `WALLET_TXS` key.
pub fn wallet_tx_key(block_height: u32, tx_id: &[u8; 32]) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..4].copy_from_slice(&block_height.to_be_bytes());
    k[4..].copy_from_slice(tx_id);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn tracked_pubkey_key_round_trips() {
        let pubkey = [0xAB; 33];
        let k = tracked_pubkey_key(42, &pubkey);
        let (idx, pk) = parse_tracked_pubkey_key(&k);
        assert_eq!(idx, 42);
        assert_eq!(pk, pubkey);
    }

    #[test]
    fn tracked_pubkey_keys_sort_by_derivation_index() {
        // Critical invariant: redb iteration order = derivation order.
        // Sort a few keys by their byte ordering and confirm the
        // derivation_path_index ordering is preserved (BE prefix).
        let pk = [0u8; 33];
        let mut keys = [
            tracked_pubkey_key(100, &pk),
            tracked_pubkey_key(0, &pk),
            tracked_pubkey_key(42, &pk),
            tracked_pubkey_key(u64::MAX, &pk),
        ];
        keys.sort();
        let indices: Vec<u64> = keys.iter().map(|k| parse_tracked_pubkey_key(k).0).collect();
        assert_eq!(indices, [0, 42, 100, u64::MAX]);
    }

    #[test]
    fn box_by_tx_key_sorts_by_tx_then_index() {
        let tx_a = [0x01u8; 32];
        let tx_b = [0x02u8; 32];
        let mut keys = [
            box_by_tx_key(&tx_b, 0),
            box_by_tx_key(&tx_a, 5),
            box_by_tx_key(&tx_a, 1),
            box_by_tx_key(&tx_b, 99),
        ];
        keys.sort();
        // Expected: tx_a/1, tx_a/5, tx_b/0, tx_b/99
        assert_eq!(&keys[0][..32], &tx_a);
        assert_eq!(&keys[0][32..], &1u16.to_be_bytes());
        assert_eq!(&keys[1][..32], &tx_a);
        assert_eq!(&keys[1][32..], &5u16.to_be_bytes());
        assert_eq!(&keys[2][..32], &tx_b);
        assert_eq!(&keys[2][32..], &0u16.to_be_bytes());
        assert_eq!(&keys[3][..32], &tx_b);
        assert_eq!(&keys[3][32..], &99u16.to_be_bytes());
    }

    #[test]
    fn wallet_tx_key_sorts_by_height_then_tx_id() {
        let tx_a = [0x01u8; 32];
        let tx_b = [0x02u8; 32];
        let mut keys = [
            wallet_tx_key(100, &tx_a),
            wallet_tx_key(99, &tx_b),
            wallet_tx_key(100, &tx_b),
        ];
        keys.sort();
        // Expected: (99, tx_b), (100, tx_a), (100, tx_b)
        let extract_height = |k: &[u8; 36]| {
            let mut h = [0u8; 4];
            h.copy_from_slice(&k[..4]);
            u32::from_be_bytes(h)
        };
        assert_eq!(extract_height(&keys[0]), 99);
        assert_eq!(extract_height(&keys[1]), 100);
        assert_eq!(&keys[1][4..], &tx_a);
        assert_eq!(extract_height(&keys[2]), 100);
        assert_eq!(&keys[2][4..], &tx_b);
    }
}
