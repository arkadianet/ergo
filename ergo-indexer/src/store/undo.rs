//! Per-block undo entry persistence.
//!
//! Wire format (own format, no Scala parity):
//! ```text
//!   1 byte:  0x00 if prev_indexed_header_id is None, 0x01 if Some
//!   32 bytes (only if Some): prev_indexed_header_id
//!   8 bytes:  prev_global_tx_index   (big-endian u64)
//!   8 bytes:  prev_global_box_index  (big-endian u64)
//! ```

use ergo_primitives::digest::Digest32;
use redb::WriteTransaction;

use crate::error::{IndexerError, UndoEntryMalformedReason};
use crate::store::tables::INDEXER_UNDO;
use crate::HeaderId;

/// `[indexed_height-1]` snapshot used by `rollback_one_block` to
/// restore meta when reverting block at `indexed_height`. Only the
/// previous-state pointers live here; the actual undo is re-derived
/// from block bytes plus current rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoEntry {
    /// `None` when the block being rolled back was block 1 (genesis
    /// case — no header preceded it).
    pub prev_indexed_header_id: Option<HeaderId>,
    pub prev_global_tx_index: u64,
    pub prev_global_box_index: u64,
}

impl UndoEntry {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49);
        match &self.prev_indexed_header_id {
            None => out.push(0x00),
            Some(id) => {
                out.push(0x01);
                out.extend_from_slice(id.as_bytes());
            }
        }
        out.extend_from_slice(&self.prev_global_tx_index.to_be_bytes());
        out.extend_from_slice(&self.prev_global_box_index.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IndexerError> {
        let mut cur = 0usize;
        let tag = *bytes.first().ok_or(IndexerError::UndoEntryMalformed {
            reason: UndoEntryMalformedReason::Empty,
        })?;
        cur += 1;

        let prev_indexed_header_id = match tag {
            0x00 => None,
            0x01 => {
                let end = cur + 32;
                if bytes.len() < end {
                    return Err(IndexerError::UndoEntryMalformed {
                        reason: UndoEntryMalformedReason::TruncatedHeaderId,
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes[cur..end]);
                cur = end;
                Some(Digest32::from_bytes(arr))
            }
            t => {
                return Err(IndexerError::UndoEntryMalformed {
                    reason: UndoEntryMalformedReason::UnknownTag(t),
                });
            }
        };

        let need = cur + 16;
        if bytes.len() < need {
            return Err(IndexerError::UndoEntryMalformed {
                reason: UndoEntryMalformedReason::TruncatedCounters,
            });
        }
        let mut tx_buf = [0u8; 8];
        tx_buf.copy_from_slice(&bytes[cur..cur + 8]);
        let mut box_buf = [0u8; 8];
        box_buf.copy_from_slice(&bytes[cur + 8..cur + 16]);
        let consumed = need;
        // Strict EOF — rollback removes the undo row after consuming it,
        // so a corrupted-then-rewritten row would never surface without
        // this guard.
        if bytes.len() != consumed {
            return Err(IndexerError::UndoEntryMalformed {
                reason: UndoEntryMalformedReason::TrailingBytes {
                    expected: consumed,
                    got: bytes.len(),
                },
            });
        }

        Ok(Self {
            prev_indexed_header_id,
            prev_global_tx_index: u64::from_be_bytes(tx_buf),
            prev_global_box_index: u64::from_be_bytes(box_buf),
        })
    }
}

pub(crate) fn write_undo(
    write_txn: &WriteTransaction,
    height: u64,
    entry: &UndoEntry,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXER_UNDO)?;
    let bytes = entry.encode();
    table.insert(height, bytes.as_slice())?;
    Ok(())
}

pub(crate) fn read_undo(
    read_txn: &redb::ReadTransaction,
    height: u64,
) -> Result<Option<UndoEntry>, IndexerError> {
    let table = read_txn.open_table(INDEXER_UNDO)?;
    let guard = table.get(height)?;
    match guard {
        None => Ok(None),
        Some(g) => UndoEntry::decode(g.value()).map(Some),
    }
}

/// Retention rule: prune `INDEXER_UNDO[k]` for all `k <
/// current_height - ROLLBACK_WINDOW`. Strictly less than — pruning at
/// `≤` would drop the deepest supported rollback target.
///
/// `ROLLBACK_WINDOW = 200` mirrors `ergo-state/src/store.rs:403`.
pub const ROLLBACK_WINDOW: u64 = 200;

pub(crate) fn prune_below_window(
    write_txn: &WriteTransaction,
    current_height: u64,
) -> Result<(), IndexerError> {
    if current_height <= ROLLBACK_WINDOW {
        return Ok(());
    }
    let cutoff = current_height - ROLLBACK_WINDOW;
    let mut table = write_txn.open_table(INDEXER_UNDO)?;
    table.retain(|k, _| k >= cutoff)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- error paths -----

    /// Rollback removes the undo row after consuming it, so a
    /// corrupted-then-rewritten row would never surface without the
    /// strict EOF guard.
    #[test]
    fn decode_rejects_trailing_bytes_after_valid_body() {
        let valid = UndoEntry {
            prev_indexed_header_id: None,
            prev_global_tx_index: 42,
            prev_global_box_index: 17,
        };
        let mut bytes = valid.encode();
        let consumed = bytes.len();
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let total = bytes.len();
        let err = UndoEntry::decode(&bytes).expect_err("must reject trailing bytes");
        assert!(
            matches!(
                err,
                IndexerError::UndoEntryMalformed {
                    reason: UndoEntryMalformedReason::TrailingBytes {
                        expected,
                        got,
                    }
                } if expected == consumed && got == total,
            ),
            "expected UndoEntryMalformed::TrailingBytes({consumed}, {total}), got {err:?}",
        );
    }

    #[test]
    fn decode_accepts_exact_body_with_header_id_present() {
        let valid = UndoEntry {
            prev_indexed_header_id: Some(Digest32::from_bytes([0xAA; 32])),
            prev_global_tx_index: 100,
            prev_global_box_index: 200,
        };
        let bytes = valid.encode();
        let parsed = UndoEntry::decode(&bytes).expect("happy path must succeed");
        assert_eq!(parsed.prev_indexed_header_id, valid.prev_indexed_header_id);
        assert_eq!(parsed.prev_global_tx_index, 100);
        assert_eq!(parsed.prev_global_box_index, 200);
    }
}
