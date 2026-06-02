//! Wire-shaped DTOs for the Scala-compatible API surface.
//!
//! Field names match the Scala node's JSON output exactly via serde
//! `rename`. Numeric types are picked to fit observed mainnet values:
//! `u32` for heights/counts, `u64` for timestamps and difficulty, `u128`
//! for cumulative scores (mainnet score at h=1.77M is ~2.7e21, well within
//! u128 but past u64). Hex strings are unprefixed lowercase.
//!
//! Known divergence from Scala's `ErgoStatsCollector` encoder: several
//! chain-state fields are `Option`-typed in Scala and emit JSON `null`
//! when no header/full block exists yet (`headersHeight`, `fullHeight`,
//! `bestHeaderId`, `bestFullHeaderId`, `previousFullHeaderId`,
//! `difficulty`, `headersScore`, `fullBlocksScore`, `genesisBlockId`).
//! We currently emit defaults (empty string / 0) instead. The divergence
//! is observable only at startup before the first header is loaded.
//!
//! `restApiUrl` is intentionally omitted when None — Scala does the same
//! via `optionalFields = ni.restApiUrl.map(...).getOrElse(Map.empty)`.
//!
//! ## Block / transaction DTOs
//!
//! The block-half DTOs (`ScalaHeader`, `ScalaBlockTransactions`,
//! `ScalaTransaction`, `ScalaInput`, `ScalaOutput`,
//! `ScalaTransactionInput`, etc.) live in the shared `ergo-rest-json`
//! crate as a single source of truth pinned by the b4_* byte-parity
//! oracle. Re-exported below for source-compat with all existing
//! consumers.

use serde::{Deserialize, Serialize};

pub use ergo_rest_json::types::{
    ScalaAdProofs, ScalaAsset, ScalaBlockSection, ScalaBlockTransactions, ScalaDataInput,
    ScalaExtension, ScalaFullBlock, ScalaHeader, ScalaInput, ScalaOutput, ScalaOutputInput,
    ScalaPowSolutions, ScalaSpendingProof, ScalaTransaction, ScalaTransactionInput,
};

/// `/info` response. Field order matches the Scala node's emission so
/// hand-eyeballed diffs against captured fixtures stay readable; serde
/// preserves struct field order in JSON output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaInfo {
    #[serde(rename = "lastMemPoolUpdateTime")]
    pub last_mempool_update_time: u64,
    #[serde(rename = "currentTime")]
    pub current_time: u64,
    pub network: String,
    pub name: String,
    #[serde(rename = "stateType")]
    pub state_type: String,
    pub difficulty: u64,
    #[serde(rename = "bestFullHeaderId")]
    pub best_full_header_id: String,
    #[serde(rename = "bestHeaderId")]
    pub best_header_id: String,
    #[serde(rename = "peersCount")]
    pub peers_count: u32,
    #[serde(rename = "unconfirmedCount")]
    pub unconfirmed_count: u32,
    #[serde(rename = "appVersion")]
    pub app_version: String,
    #[serde(rename = "eip37Supported")]
    pub eip37_supported: bool,
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    #[serde(rename = "genesisBlockId")]
    pub genesis_block_id: String,
    #[serde(rename = "restApiUrl", skip_serializing_if = "Option::is_none")]
    pub rest_api_url: Option<String>,
    #[serde(rename = "previousFullHeaderId")]
    pub previous_full_header_id: String,
    #[serde(rename = "fullHeight")]
    pub full_height: u32,
    #[serde(rename = "headersHeight")]
    pub headers_height: u32,
    #[serde(rename = "stateVersion")]
    pub state_version: String,
    #[serde(rename = "fullBlocksScore")]
    pub full_blocks_score: u128,
    #[serde(rename = "maxPeerHeight")]
    pub max_peer_height: u32,
    #[serde(rename = "launchTime")]
    pub launch_time: u64,
    #[serde(rename = "isExplorer")]
    pub is_explorer: bool,
    #[serde(rename = "lastSeenMessageTime")]
    pub last_seen_message_time: u64,
    #[serde(rename = "eip27Supported")]
    pub eip27_supported: bool,
    #[serde(rename = "headersScore")]
    pub headers_score: u128,
    pub parameters: Parameters,
    #[serde(rename = "isMining")]
    pub is_mining: bool,
}

/// Voted protocol parameters at the current epoch. Until the rust node
/// parses voted parameters out of block extensions, the bridge fills this
/// from `ergo_validation::ProtocolParams::mainnet_default()` — correct in
/// shape and within an epoch of mainnet, but does not reflect live votes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Parameters {
    #[serde(rename = "outputCost")]
    pub output_cost: u64,
    #[serde(rename = "tokenAccessCost")]
    pub token_access_cost: u64,
    #[serde(rename = "maxBlockCost")]
    pub max_block_cost: u64,
    pub height: u32,
    #[serde(rename = "maxBlockSize")]
    pub max_block_size: u32,
    #[serde(rename = "dataInputCost")]
    pub data_input_cost: u64,
    #[serde(rename = "blockVersion")]
    pub block_version: u8,
    #[serde(rename = "inputCost")]
    pub input_cost: u64,
    #[serde(rename = "storageFeeFactor")]
    pub storage_fee_factor: i32,
    #[serde(rename = "subblocksPerBlock")]
    pub subblocks_per_block: u32,
    #[serde(rename = "minValuePerByte")]
    pub min_value_per_byte: u64,
}

/// `Peer` schema from the Scala API spec — used by `/peers/all` and
/// `/peers/connected`. Field order matches Scala's emission. Nullable
/// fields render as JSON `null` when absent (Scala uses `Option#asJson`,
/// not the conditional-fields pattern).
///
/// `connection_type` is `"Incoming"` / `"Outgoing"` (capital first letter)
/// `GET /peers/blacklisted` — Scala emits
/// `{"addresses": [...]}` where each entry is the result of
/// `InetAddress.toString()`. That Java method emits
/// `hostname/literal-ip` when a reverse-DNS hostname is set,
/// or `/literal-ip` (leading slash) when no hostname is bound —
/// NOT a bare IP. Bridges populating this list should call
/// `addr.toString()` semantics (or its Rust equivalent that
/// matches Java output) rather than emitting bare IPs, to keep
/// byte-parity with Scala's response on the same address.
/// Source: `ErgoPeersApiRoute.scala:98-102` +
/// `case class BlacklistedPeers`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaBlacklistedPeers {
    pub addresses: Vec<String>,
}

/// `GET /peers/status` — Scala emits
/// `{"lastIncomingMessage": <ms>, "currentSystemTime": <ms>}`.
/// Source: `ErgoPeersApiRoute.scala:76-82` +
/// `case class PeersStatusResponse`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaPeersStatus {
    #[serde(rename = "lastIncomingMessage")]
    pub last_incoming_message: u64,
    #[serde(rename = "currentSystemTime")]
    pub current_system_time: u64,
}

/// `GET /peers/syncInfo` — per-peer sync state. Each entry mirrors
/// what Scala's `syncTracker.fullInfo` exposes, narrowed to the
/// stable subset we can produce in Rust today:
/// - `address` — `host:port` of the peer
/// - `height` — peer's reported best height (V1) or inferred from
///   the newest peer-header that overlaps our chain (V2), 0 when
///   we have no overlap yet
/// - `status` — Scala chain-status string from `compare_sync_info`:
///   `"Equal"` / `"Younger"` / `"Older"` / `"Fork"` / `"Unknown"`
///   / `"Nonsense"` (Scala parity for `PeerChainStatus`)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaSyncInfoEntry {
    pub address: String,
    pub height: u32,
    pub status: String,
}

/// `GET /transactions/poolHistogram` element — `(nTxns, totalFee)`
/// pair for one wait-time bin. The histogram array always carries
/// `BINS + 1` entries; bin `i` (`0 <= i < BINS`) covers wait times
/// in `[i*maxtime/BINS, (i+1)*maxtime/BINS)`, and the last entry
/// covers `>= maxtime` (matches the OpenAPI description at
/// `web/openapi.yaml::getFeeHistogram`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScalaFeeHistogramBin {
    #[serde(rename = "nTxns")]
    pub n_txns: u32,
    #[serde(rename = "totalFee")]
    pub total_fee: u64,
}

/// `GET /peers/trackInfo` — aggregate delivery-tracker counters.
/// Mirrors Scala `deliveryTracker.fullInfo` at the field level:
/// - `numRequested` — modifiers currently in-flight
/// - `numReceived` — modifiers in the received-set dedupe ring
///   (capped at `MAX_RECEIVED_ENTRIES`)
/// - `numFailed` — modifiers that exhausted their retry budget
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaTrackInfo {
    #[serde(rename = "numRequested")]
    pub num_requested: u32,
    #[serde(rename = "numReceived")]
    pub num_received: u32,
    #[serde(rename = "numFailed")]
    pub num_failed: u32,
}

/// per the Scala enum, **not** the operator surface's `"inbound"` /
/// `"outbound"`. Don't share an encoder between the two surfaces.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaPeer {
    pub address: String,
    #[serde(rename = "restApiUrl")]
    pub rest_api_url: Option<String>,
    pub name: Option<String>,
    /// Unix-ms of last seen message (Scala emits `lastMessage` from
    /// `lastSeen.toMillis`). Renamed to `lastSeen` per the openapi
    /// `Peer` schema; both names appear in different Scala sources but
    /// the documented public schema is `lastSeen`.
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
    #[serde(rename = "connectionType")]
    pub connection_type: Option<String>,
}

/// `/blocks/{headerId}/proofFor/{txId}` response. Wire shape per
/// `ApiCodecs.scala:48-60`:
/// ```json
/// { "leafData": "<hex tx_id>", "levels": [["<hex sibling>", side_byte], ...] }
/// ```
/// `levels` is bottom-up, side byte `0 = LeftSide`, `1 = RightSide`.
/// Empty siblings (odd-paired with `EmptyNode`) serialize as `""` per
/// scrypto's `Base16.encode([])` — see `Node.scala:51-53`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaMerkleProof {
    #[serde(rename = "leafData")]
    pub leaf_data: String,
    pub levels: Vec<(String, u8)>,
}

/// Big-endian byte-encoded cumulative score → u128. Returns 0 if the
/// score length exceeds 16 bytes (would overflow u128) — mainnet score at
/// h=1.77M needs 9 bytes, so headroom is centuries.
pub fn score_to_u128(be_bytes: &[u8]) -> u128 {
    if be_bytes.is_empty() || be_bytes.len() > 16 {
        return 0;
    }
    let mut buf = [0u8; 16];
    buf[16 - be_bytes.len()..].copy_from_slice(be_bytes);
    u128::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn score_to_u128_pads_short_be_bytes() {
        // 9-byte BE input — same width as a real mainnet cumulative score —
        // must left-pad with zeros to fill the u128.
        let raw: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let s = score_to_u128(&raw);
        assert_eq!(s, 0x0001_0203_0405_0607_0809_u128);
    }

    #[test]
    fn score_to_u128_handles_full_width_input() {
        // Exactly 16 bytes — the maximum width that fits a u128 without clamp.
        let raw: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let s = score_to_u128(&raw);
        assert_eq!(s, 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128);
    }

    #[test]
    fn score_to_u128_clamps_oversize_to_zero() {
        let raw = vec![0xFFu8; 17];
        assert_eq!(score_to_u128(&raw), 0);
    }

    #[test]
    fn score_to_u128_handles_empty_score() {
        assert_eq!(score_to_u128(&[]), 0);
    }

    #[test]
    fn scala_info_serializes_with_camel_case_keys() {
        let info = ScalaInfo {
            last_mempool_update_time: 0,
            current_time: 1,
            network: "mainnet".into(),
            name: "ergo-rust-mainnet-0.1.0".into(),
            state_type: "utxo".into(),
            difficulty: 0,
            best_full_header_id: String::new(),
            best_header_id: String::new(),
            peers_count: 0,
            unconfirmed_count: 0,
            app_version: "0.1.0".into(),
            eip37_supported: true,
            state_root: String::new(),
            genesis_block_id: String::new(),
            rest_api_url: Some("http://127.0.0.1:9053".into()),
            previous_full_header_id: String::new(),
            full_height: 0,
            headers_height: 0,
            state_version: String::new(),
            full_blocks_score: 0,
            max_peer_height: 0,
            launch_time: 0,
            is_explorer: false,
            last_seen_message_time: 0,
            eip27_supported: true,
            headers_score: 0,
            parameters: Parameters {
                output_cost: 0,
                token_access_cost: 0,
                max_block_cost: 0,
                height: 0,
                max_block_size: 0,
                data_input_cost: 0,
                block_version: 0,
                input_cost: 0,
                storage_fee_factor: 0,
                subblocks_per_block: 0,
                min_value_per_byte: 0,
            },
            is_mining: false,
        };
        let v = serde_json::to_value(&info).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "lastMemPoolUpdateTime",
            "currentTime",
            "bestFullHeaderId",
            "bestHeaderId",
            "peersCount",
            "unconfirmedCount",
            "appVersion",
            "eip37Supported",
            "stateRoot",
            "genesisBlockId",
            "restApiUrl",
            "previousFullHeaderId",
            "fullHeight",
            "headersHeight",
            "stateVersion",
            "fullBlocksScore",
            "maxPeerHeight",
            "launchTime",
            "isExplorer",
            "lastSeenMessageTime",
            "eip27Supported",
            "headersScore",
            "isMining",
        ] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
        let p = obj.get("parameters").unwrap().as_object().unwrap();
        for key in [
            "outputCost",
            "tokenAccessCost",
            "maxBlockCost",
            "maxBlockSize",
            "dataInputCost",
            "blockVersion",
            "inputCost",
            "storageFeeFactor",
            "subblocksPerBlock",
            "minValuePerByte",
        ] {
            assert!(p.contains_key(key), "missing parameters.{key}");
        }
    }
}
