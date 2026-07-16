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

/// Full serialized box bytes for the wallet's own boxes, keyed by box id.
/// Companion to [`WALLET_BOXES`]: `WalletBox` keeps only the structured
/// fields (value/assets/status/provenance), not the box's ErgoTree or
/// registers, so the serialized form is stored here for the reserved-scan
/// reads (`/scan/{unspent,spent}Boxes/9|10`, which surface the wallet's
/// mining/payment boxes as `ScanBoxEntry` with full `bytes`).
///
/// Additive table — boxes created before this table existed simply have no
/// row (the read degrades to empty bytes until a `/wallet/rescan` backfills
/// them), so no schema bump / wipe is needed. A missing row is graceful; an
/// orphaned row (box removed but bytes left) is never read (reads iterate
/// `WALLET_BOXES` and join here), so it's a harmless reclaim-on-rescan leak.
///
/// Key: 32-byte box id. Value: `serialize_ergo_box` bytes (verbatim wire form).
pub const WALLET_BOX_BYTES: TableDefinition<[u8; 32], Vec<u8>> =
    TableDefinition::new("wallet_box_bytes");

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

/// Last-issued EIP-3 address index — the `i` in `m/44'/429'/0'/0/i`.
/// `deriveNextKey` reads this (default 0 when the row is absent; boot
/// auto-derive of index 0 never writes it) and issues `head + 1`.
/// Distinct from `WALLET_TRACKED_PUBKEYS`' key index, which is a
/// sequential insert counter over all tracked keys (root and custom
/// paths included), not an address index.
/// Stored as a single-row table for O(1) increment-and-fetch.
pub const WALLET_DERIVATION_HEAD: TableDefinition<(), u64> =
    TableDefinition::new("wallet_derivation_head");

/// Tracked HD pubkeys. Keyed by `(derivation_path_index, pubkey)` so
/// the BTree iteration order = derivation order across restarts.
/// Value carries metadata (derivation path Vec<u32>, optional label,
/// height-added).
///
/// Key: `(derivation_path_index: u64 BE, pubkey: [u8; 33])` packed
/// as 41 bytes (8 + 33). Big-endian u64 ensures sort-by-index.
/// Value: bincode-serialized `TrackedPubkeyMeta` (see `types.rs`).
pub const WALLET_TRACKED_PUBKEYS: TableDefinition<[u8; 41], Vec<u8>> =
    TableDefinition::new("wallet_tracked_pubkeys");

/// Visible-address cache (the filtered list per
/// `WalletCache.publicKeyAddresses`). Rebuilt atomically with every
/// write to `WALLET_TRACKED_PUBKEYS`. The value is the pubkey bytes;
/// address rendering happens at REST read time so we don't bake the
/// network prefix into persistent state.
///
/// Key: `index: u32` (a sequential index over the filtered view).
/// Only entries for VISIBLE addresses appear here — hidden master is
/// absent.
/// Value: `pubkey: [u8; 33]`. The REST `/wallet/addresses` handler
/// renders to base58 at response-build time.
pub const WALLET_VISIBLE_ADDRESSES: TableDefinition<u32, [u8; 33]> =
    TableDefinition::new("wallet_visible_addresses");

/// Persisted change address (one row, value = 33-byte pubkey).
/// When `None`, the change address falls back to the first tracked
/// pubkey. Stores the pubkey bytes, not the rendered
/// address string — REST handlers render at read time with the
/// current network prefix.
pub const WALLET_CHANGE_ADDRESS: TableDefinition<(), [u8; 33]> =
    TableDefinition::new("wallet_change_address");

/// Registered scans (`/scan/*` subsystem), keyed by scan id. Iterating the
/// table yields scans in ascending-id order (native `u16` redb ordering),
/// which is the `/scan/listAll` response order.
///
/// Key: `scan_id: u16` (>= 11 for user scans; see `ergo_wallet::scan`).
/// Value: `serde_json`-serialized `ergo_wallet::scan::Scan`. JSON (not
/// bincode) because the scan's `trackingRule` is an internally-tagged serde
/// enum, which bincode's non-self-describing format cannot represent.
pub const WALLET_SCANS: TableDefinition<u16, Vec<u8>> = TableDefinition::new("wallet_scans");

/// The monotonic `lastUsedScanId` counter (one row). Defaults to
/// `PaymentsScanId` (10) when absent, so the first user scan is id 11. Advanced
/// on every register and NEVER decremented on deregister — ids are never reused
/// (Scala `WalletStorage` parity).
pub const WALLET_LAST_USED_SCAN_ID: TableDefinition<(), u16> =
    TableDefinition::new("wallet_last_used_scan_id");

/// Boxes tracked by registered scans (`/scan/*` block-apply matcher), keyed by
/// `(scan_id, box_id)` packed as 34 bytes (`scan_id` big-endian first, so
/// iterating a `scan_id` prefix yields that scan's boxes in box-id order). The
/// value's `status` field discriminates unspent vs spent.
///
/// Key: `(scan_id: u16 BE, box_id: [u8; 32])` (see [`scan_box_key`]).
/// Value: bincode-serialized `ScanTrackedBox` (see `types.rs`).
pub const WALLET_SCAN_BOXES: TableDefinition<[u8; 34], Vec<u8>> =
    TableDefinition::new("wallet_scan_boxes");

/// Reverse index from a box id to the scan ids tracking it, so a spent input
/// can be marked across all its scans without a full-table scan. A row exists
/// while a box is tracked by at least one scan; it is removed on rollback of
/// the box's creation.
///
/// Key: 32-byte box id. Value: bincode-serialized `Vec<u16>` of scan ids.
pub const WALLET_SCAN_BOX_INDEX: TableDefinition<[u8; 32], Vec<u8>> =
    TableDefinition::new("wallet_scan_box_index");

/// Transactions associated with registered scans — one row per tx whose
/// created or spent boxes matched ≥1 scan, tagged with the union of those
/// scan ids (Scala `WalletScanLogic` stores `WalletTransaction(tx, height,
/// scanIds)` the same way; this build stores box-id references, not full tx
/// bytes, mirroring the wallet's lean `WALLET_TXS` shape). Backs
/// `/wallet/transactionsByScanId/{scanId}` for user scans.
///
/// Key: `(block_height: u32 BE, tx_id: [u8; 32])` (see [`wallet_tx_key`]) —
/// height-ascending iteration order. Value: bincode-serialized `ScanTxRecord`.
pub const WALLET_SCAN_TXS: TableDefinition<[u8; 36], Vec<u8>> =
    TableDefinition::new("wallet_scan_txs");

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

/// Pack `(scan_id, box_id)` for the `WALLET_SCAN_BOXES` key. Big-endian
/// `scan_id` prefix groups the table by scan, so a range scan over
/// `[scan_box_key(id, &[0;32]) ..= scan_box_key(id, &[0xff;32])]` yields exactly
/// that scan's tracked boxes.
pub fn scan_box_key(scan_id: u16, box_id: &[u8; 32]) -> [u8; 34] {
    let mut k = [0u8; 34];
    k[..2].copy_from_slice(&scan_id.to_be_bytes());
    k[2..].copy_from_slice(box_id);
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
    fn scan_box_keys_group_by_scan_then_box_id() {
        let box_a = [0x01u8; 32];
        let box_b = [0x02u8; 32];
        let mut keys = [
            scan_box_key(12, &box_a),
            scan_box_key(11, &box_b),
            scan_box_key(11, &box_a),
        ];
        keys.sort();
        // Expected: (11, box_a), (11, box_b), (12, box_a) — scan id first.
        let scan_of = |k: &[u8; 34]| u16::from_be_bytes([k[0], k[1]]);
        assert_eq!(scan_of(&keys[0]), 11);
        assert_eq!(&keys[0][2..], &box_a);
        assert_eq!(scan_of(&keys[1]), 11);
        assert_eq!(&keys[1][2..], &box_b);
        assert_eq!(scan_of(&keys[2]), 12);
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
