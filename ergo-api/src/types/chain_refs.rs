//! Chain-reference DTOs: tip pointers, header/full-block refs, the
//! recent-blocks list, and the difficulty / miner-stats series.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Tip pointers. During IBD `best_header` and `best_full_block` can
/// diverge by tens of thousands of blocks — they are reported separately
/// and the gap is precomputed for clients.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiTip {
    pub best_header: ApiHeaderRef,
    pub best_full_block: ApiFullBlockRef,
    pub headers_ahead_of_full_blocks: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiHeaderRef {
    pub height: u32,
    pub header_id: String,
    pub parent_id: String,
    pub timestamp_unix_ms: u64,
    /// Compact difficulty target (`nBits`) committed in this header.
    pub n_bits: u32,
    /// Network difficulty decoded from `n_bits`, as a decimal string —
    /// full precision, since difficulty exceeds `u64` at high mainnet
    /// difficulty. Hashrate is a client derivation (`difficulty /
    /// target_block_interval`), not a field here.
    pub difficulty: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiFullBlockRef {
    pub height: u32,
    pub header_id: String,
    pub parent_id: String,
    pub timestamp_unix_ms: u64,
    /// AVL+ authenticated UTXO-tree root digest committed in this full
    /// block's header — 33 bytes (`Digest32 || balance-byte`), hex-encoded
    /// (66 chars). Mirrors the on-chain `Header.stateRoot` field;
    /// distinct from the chain's cumulative-PoW score or any header hash.
    pub state_root_avl: String,
    /// Compact difficulty target (`nBits`) committed in this header.
    pub n_bits: u32,
    /// Network difficulty decoded from `n_bits`, as a decimal string.
    pub difficulty: String,
}

/// One recent full block for the dashboard cockpit's "recent blocks" list,
/// backing `GET /api/v1/blocks/recent` (newest-first). The list reflects the
/// committed full-block chain and may briefly trail `/api/v1/tip` during the
/// async-persist window (see the endpoint description). `size_bytes` sums the
/// on-disk section byte lengths — header + blockTransactions + extension,
/// plus adProofs when the node retains it (adProofs is optional in UTXO
/// mode). A block whose required sections are missing, or whose any section
/// read errors, is omitted from the list rather than reported with a
/// silently undercounted size.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiRecentBlock {
    pub height: u32,
    pub header_id: String,
    pub ts_unix_ms: u64,
    pub txs: u32,
    pub size_bytes: u64,
    /// Socket address (`ip:port`) of the FIRST peer that delivered this
    /// block's header to us — the peer whose `Modifier` carried the
    /// header bytes we accepted. A freshly-mined block is typically
    /// announced first by the miner/pool's node, so this attributes a
    /// block → peer (→ pool, with out-of-band peer↔pool knowledge).
    /// `None` when the deliverer is unknown: the block was synced before
    /// the bounded first-deliverer ring captured it, the entry has since
    /// been FIFO-evicted, or the block was applied locally (self-mined).
    /// Pure observability — never affects validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_by: Option<String>,
    /// Miner public key from the header's Autolykos solution (33-byte
    /// compressed secp256k1 point, hex) — present on both v1 and v2
    /// solutions. Identifies who mined the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miner_pk: Option<String>,
    /// P2PK base58 address derived from `miner_pk` with this node's
    /// network prefix — the conventional "miner" identity explorers
    /// show. `None` only if address encoding failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miner_address: Option<String>,
}

/// One sample in the difficulty time series returned by
/// `GET /api/v1/difficulty/history`: the network difficulty observed at a
/// block height, alongside that block's timestamp.
///
/// `difficulty` is the decoded decimal value as a string — at mainnet
/// scale it exceeds `u64`, so a JSON number would silently lose precision
/// in javascript consumers. `n_bits` is deliberately omitted: it is the
/// compact encoding of this same value, so it would be a lossy duplicate.
/// Consumers read `difficulty` directly.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiDifficultyPoint {
    pub height: u32,
    pub timestamp_unix_ms: u64,
    pub difficulty: String,
}

/// Ascending-by-height difficulty series for `GET
/// /api/v1/difficulty/history`. Oldest point first so a consumer can plot
/// it left-to-right without re-sorting.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiDifficultySeries {
    pub points: Vec<ApiDifficultyPoint>,
}

/// One miner's aggregate over the `minerStats` window.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMinerStat {
    /// Miner public key (33-byte compressed point, hex) from the folded
    /// headers' Autolykos solutions.
    pub pk: String,
    /// P2PK address derived from `pk` with this node's network prefix.
    /// Absent only when the stored pk bytes fail address encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Blocks this miner produced within the window.
    pub count: u32,
    /// Height of this miner's most recent block in the window.
    pub last_height: u32,
}

/// Response of `GET /api/v1/mining/minerStats` — the network mining
/// landscape over the last `window` headers of the canonical chain.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMinerStats {
    /// Best-header height at fold time (0 on an empty chain).
    pub tip_height: u32,
    /// Requested window after clamping to `[1, 16384]`.
    pub window: u32,
    /// Headers actually scanned — shorter than `window` near genesis.
    pub blocks: u32,
    /// Miners sorted by `count` descending, ties by `last_height`
    /// descending.
    pub miners: Vec<ApiMinerStat>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- ApiHeaderRef: difficulty fields round-trip -----

    /// `n_bits` (u32) and `difficulty` (decimal String) survive
    /// serialize → deserialize on the tip ref.
    #[test]
    fn api_header_ref_difficulty_fields_roundtrip() {
        let h = ApiHeaderRef {
            height: 5,
            header_id: "ab".to_string(),
            parent_id: "cd".to_string(),
            timestamp_unix_ms: 1,
            n_bits: 117_501_863,
            difficulty: "263500538576896".to_string(),
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: ApiHeaderRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.n_bits, 117_501_863);
        assert_eq!(back.difficulty, "263500538576896");
    }

    #[test]
    fn api_full_block_ref_uses_state_root_avl_not_state_digest() {
        // Pin the renamed wire key: the AVL+ UTXO-root field is named
        // state_root_avl on the wire, and the old state_digest name must
        // not appear (clients reading the old key get a missing field
        // and surface it instead of silently consuming wrong bytes).
        let f = ApiFullBlockRef {
            height: 1,
            header_id: String::new(),
            parent_id: String::new(),
            timestamp_unix_ms: 0,
            state_root_avl: "0123abcd".to_string(),
            n_bits: 0,
            difficulty: "0".to_string(),
        };
        let v = serde_json::to_value(&f).unwrap();
        let obj = v.as_object().expect("object");
        assert_eq!(
            obj.get("state_root_avl"),
            Some(&serde_json::Value::String("0123abcd".into())),
            "AVL root must wire under the new state_root_avl key"
        );
        assert!(
            !obj.contains_key("state_digest"),
            "old state_digest key must not appear on the wire"
        );
    }

    /// `ApiFullBlockRef` gained the same fields — round-trip them too.
    #[test]
    fn api_full_block_ref_difficulty_fields_roundtrip() {
        let f = ApiFullBlockRef {
            height: 5,
            header_id: "ab".to_string(),
            parent_id: "cd".to_string(),
            timestamp_unix_ms: 1,
            state_root_avl: "ef".to_string(),
            n_bits: 117_501_863,
            difficulty: "263500538576896".to_string(),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: ApiFullBlockRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.n_bits, 117_501_863);
        assert_eq!(back.difficulty, "263500538576896");
    }
}
