//! Production API reader of the existing shared committed database. No writer
//! handle, snapshot tip or queued PersistJob is consulted here.
use std::io::Write;
use std::sync::Arc;

use ergo_api::evidence::{
    CommittedEvidencePage, CommittedEvidenceReader, EvidenceCursor, EvidenceMeta,
    EvidenceReadError, EvidenceRecord, EvidenceSource, MAX_EVIDENCE_EVENTS,
    MAX_EVIDENCE_RESPONSE_BYTES,
};
use ergo_state::evidence::{read_committed, Cursor};
use ergo_state::store::StateError;

pub(super) struct CommittedEvidenceBridge {
    db: Arc<redb::Database>,
    configured_anchor: String,
}

impl CommittedEvidenceBridge {
    pub(super) fn new(db: Arc<redb::Database>, configured_anchor: [u8; 32]) -> Self {
        Self {
            db,
            configured_anchor: hex::encode(configured_anchor),
        }
    }
}

struct EventJson(Vec<u8>);
impl Write for EventJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_EVIDENCE_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "event exceeds evidence transport bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CommittedEvidenceReader for CommittedEvidenceBridge {
    fn read_committed(
        &self,
        after: Option<&EvidenceCursor>,
        limit: usize,
    ) -> Result<CommittedEvidencePage, EvidenceReadError> {
        if !(1..=MAX_EVIDENCE_EVENTS).contains(&limit) {
            return Err(EvidenceReadError::Unavailable(
                "invalid API page count".into(),
            ));
        }
        let cursor = after.map(|cursor| Cursor {
            archive_id: cursor.archive_id.clone(),
            sequence: cursor.sequence,
            event_hash: cursor.event_hash.clone(),
        });
        let page =
            read_committed(&self.db, cursor.as_ref(), limit).map_err(|error| match error {
                StateError::AppliedEvidence { detail } => {
                    EvidenceReadError::ReconstructionRequired(detail)
                }
                _ => EvidenceReadError::Unavailable("committed database read failed".into()),
            })?;
        if page.meta.anchor_id != self.configured_anchor {
            return Err(EvidenceReadError::ReconstructionRequired(
                "configured genesis anchor differs from committed journal".into(),
            ));
        }
        let meta: EvidenceMeta =
            serde_json::from_value(serde_json::to_value(&page.meta).map_err(|_| {
                EvidenceReadError::Unavailable("journal metadata encoding failed".into())
            })?)
            .map_err(|_| {
                EvidenceReadError::Unavailable("journal metadata transport failed".into())
            })?;
        let mut events = Vec::with_capacity(page.events.len());
        let mut total = 0usize;
        for stored in page.events {
            let mut bytes = EventJson(Vec::new());
            serde_json::to_writer(&mut bytes, &stored.event)
                .map_err(|_| EvidenceReadError::TooLarge)?;
            total = total
                .checked_add(bytes.0.len())
                .ok_or(EvidenceReadError::TooLarge)?;
            if total > MAX_EVIDENCE_RESPONSE_BYTES {
                return Err(EvidenceReadError::TooLarge);
            }
            events.push(EvidenceRecord {
                event_json: String::from_utf8(bytes.0).map_err(|_| {
                    EvidenceReadError::Unavailable("journal JSON was not UTF-8".into())
                })?,
                event_hash: stored.event_hash,
            });
        }
        Ok(CommittedEvidencePage {
            schema: "ergo-committed-evidence-page-v1".into(),
            source: EvidenceSource {
                kind: "committedRedbJournal".into(),
                configured_genesis_anchor: self.configured_anchor.clone(),
            },
            meta,
            events,
            next_cursor: EvidenceCursor {
                archive_id: page.next_cursor.archive_id,
                sequence: page.next_cursor.sequence,
                event_hash: page.next_cursor.event_hash,
            },
        })
    }
}

#[cfg(test)]
mod tests;
