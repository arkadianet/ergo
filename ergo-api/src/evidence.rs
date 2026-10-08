//! Read-only committed-journal DTOs. Transport authentication is supplied by
//! the configured API-key gate; these response fields are not node signatures.
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const MAX_EVIDENCE_EVENTS: usize = 16;
pub const MAX_EVIDENCE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EVIDENCE_SEQUENCE: u64 = (1u64 << 53) - 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceCursor {
    pub archive_id: String,
    pub sequence: u64,
    pub event_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceMeta {
    pub archive_id: String,
    pub anchor_id: String,
    pub cursor: EvidenceCursor,
    pub branch_generation: u64,
    pub tip_id: String,
    pub tip_height: u32,
    pub reconstruction_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRecord {
    /// Exact normative JournalEvent JSON UTF-8 string, including captured bytes
    /// and provenance. Hash this string using the documented journal framing;
    /// the outer HTTP JSON representation is not the journal hash preimage.
    pub event_json: String,
    pub event_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSource {
    pub kind: String,
    pub configured_genesis_anchor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommittedEvidencePage {
    pub schema: String,
    pub source: EvidenceSource,
    pub meta: EvidenceMeta,
    pub events: Vec<EvidenceRecord>,
    pub next_cursor: EvidenceCursor,
}

#[derive(Clone, Debug)]
pub enum EvidenceReadError {
    ReconstructionRequired(String),
    Unavailable(String),
    TooLarge,
}

/// Implemented by the node against its shared committed database. The API has
/// no writer/database dependency and must not manufacture a reader from flags.
pub trait CommittedEvidenceReader: Send + Sync {
    fn read_committed(
        &self,
        after: Option<&EvidenceCursor>,
        limit: usize,
    ) -> Result<CommittedEvidencePage, EvidenceReadError>;
}

pub type EvidenceReaderHandle = Arc<dyn CommittedEvidenceReader>;
