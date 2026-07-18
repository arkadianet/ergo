//! Operator event-feed DTOs: the flat per-event shape, the feed page,
//! and the diagnostics reorg-history ring.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One operator event for `GET /api/v1/events` — flat shape with optional
/// per-kind fields so the feed renders without a type registry. `kind` is
/// one of `blockApplied` / `reorg` / `peerConnected` / `peerDisconnected` /
/// `indexerStatus` / `syncWedged` / `shadowDivergence`. Reorg-only fields
/// (`depth`, `dropped_header_ids`, `returned_tx_ids`, `returned_txs_total`,
/// `delivered_by`) are best-effort from the node's 32-block committed tail
/// and the tip-change enrichment; deeper orphan ids are not fabricated.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiNodeEvent {
    /// Monotonic sequence number (gaps = ring eviction).
    pub seq: u64,
    pub unix_ms: u64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_header_ids: Option<Vec<String>>,
    /// Reorg-only: rolled-back tx ids returned to the mempool (capped 128).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub returned_tx_ids: Option<Vec<String>>,
    /// Reorg-only: uncapped returned-tx count.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub returned_txs_total: Option<u32>,
    /// Reorg-only: first deliverer of the winning tip header.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delivered_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Event-feed page for `GET /api/v1/events`: the retained tail (bounded by
/// the node-side ring) plus the newest sequence number for `?since=` polls.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiNodeEvents {
    pub latest_seq: u64,
    pub events: Vec<ApiNodeEvent>,
}

/// One retained reorg for `GET /api/v1/diagnostics/reorgs` — postmortem
/// ring (last 64 **or** 7 days), not the coarse glanceable event feed.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiReorgRecord {
    pub unix_ms: u64,
    pub height: u32,
    pub header_id: String,
    pub depth: u32,
    pub dropped_header_ids: Vec<String>,
    /// True when dropped ids hit the 32-block committed-tail cap.
    pub orphans_truncated: bool,
    /// Rolled-back tx ids returned to the mempool (first 128; see total).
    pub returned_tx_ids: Vec<String>,
    /// Uncapped rolled-back tx count.
    pub returned_txs_total: u32,
    /// Peer that first delivered the winning tip header, when known.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delivered_by: Option<String>,
}

/// Envelope for the diagnostics reorg history.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiReorgHistory {
    /// Session-total reorgs detected (not reset by age/count prune).
    pub total: u64,
    pub cap: u32,
    pub max_age_ms: u64,
    /// Newest-first retained entries.
    pub reorgs: Vec<ApiReorgRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_node_events_reorg_serializes_depth_and_dropped_header_ids() {
        let event = ApiNodeEvent {
            seq: 1,
            unix_ms: 1_700_000_000_000,
            kind: "reorg".to_string(),
            height: Some(100),
            header_id: Some("new-tip".to_string()),
            depth: Some(2),
            dropped_header_ids: Some(vec!["old-100".to_string(), "old-99".to_string()]),
            returned_tx_ids: None,
            returned_txs_total: None,
            delivered_by: None,
            txs: None,
            size_bytes: None,
            addr: None,
            detail: None,
        };

        let v = serde_json::to_value(event).unwrap();

        assert_eq!(
            v,
            serde_json::json!({
                "seq": 1,
                "unixMs": 1_700_000_000_000u64,
                "kind": "reorg",
                "height": 100,
                "headerId": "new-tip",
                "depth": 2,
                "droppedHeaderIds": ["old-100", "old-99"],
            })
        );
    }

    #[test]
    fn api_node_events_non_reorg_omits_reorg_fields() {
        let event = ApiNodeEvent {
            seq: 1,
            unix_ms: 1_700_000_000_000,
            kind: "peerConnected".to_string(),
            height: None,
            header_id: None,
            depth: None,
            dropped_header_ids: None,
            returned_tx_ids: None,
            returned_txs_total: None,
            delivered_by: None,
            txs: None,
            size_bytes: None,
            addr: Some("127.0.0.1:9030".to_string()),
            detail: None,
        };

        let v = serde_json::to_value(event).unwrap();
        let obj = v.as_object().expect("object");

        assert!(!obj.contains_key("depth"));
        assert!(!obj.contains_key("droppedHeaderIds"));
    }
}
