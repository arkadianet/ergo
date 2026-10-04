//! Bounded, operator-authorized diagnostic log history. Sequence values are
//! decimal strings so JavaScript clients never round a resume cursor.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiActivityRecord {
    pub seq: String,
    pub unix_ms: u64,
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields: std::collections::BTreeMap<String, serde_json::Value>,
    /// Oversized values/fields were omitted or shortened for this view.
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiActivityPage {
    /// Changes on process restart. Cursors are meaningful only in this session.
    pub session_id: String,
    pub oldest_seq: String,
    pub latest_seq: String,
    /// Resume from this cursor, not latestSeq, while hasMore is true.
    pub next_seq: String,
    pub has_more: bool,
    /// Some requested records have already been evicted.
    pub gap: bool,
    /// Session mismatch or a cursor beyond the current session; page starts over.
    pub reset: bool,
    pub capacity: usize,
    pub byte_capacity: usize,
    pub retained: usize,
    /// Capture never waits on a reader; contention losses are explicit.
    pub dropped_total: String,
    pub records: Vec<ApiActivityRecord>,
}
