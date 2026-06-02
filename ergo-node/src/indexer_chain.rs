//! Production [`IndexerChainSource`] adapter, wiring the indexer's
//! polling task against the real chain redb via [`ChainStoreReader`].
//!
//! The trait surface is minimal — three reads per poll iteration. The
//! adapter parses serialized header / block-transactions bytes the same
//! way `ergo-state::diff` already does. Failures translate to `None` per
//! the trait contract: missing tip → bypass forward apply this tick;
//! missing header_id at height → `IndexerPoll::Race`; missing block
//! section → `IndexerPoll::SectionRetry` (driver re-tries with bounded
//! backoff).

use std::sync::Arc;

use ergo_indexer::{ChainTip, HeaderId, IndexerChainSource, IndexerFullBlock};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_state::reader::ChainStoreReader;
use tracing::warn;

/// Adapter implementing [`IndexerChainSource`] over a [`ChainStoreReader`].
///
/// `Arc<Self>` is the form `IndexerTask` consumes (the task wants a
/// single shared chain handle for the lifetime of the polling loop).
/// Cloning is cheap — `ChainStoreReader` is itself `Arc`-shared.
pub struct ChainReaderAdapter {
    reader: ChainStoreReader,
}

impl ChainReaderAdapter {
    pub fn new(reader: ChainStoreReader) -> Arc<Self> {
        Arc::new(Self { reader })
    }
}

impl IndexerChainSource for ChainReaderAdapter {
    fn committed_tip(&self) -> ChainTip {
        // Pre-genesis (tables not materialized) reports height 0 with
        // an all-zero header_id — same shape as `ChainState::empty()`.
        // The polling task treats this as "nothing to apply yet" and
        // sleeps in `Idle`, which is the right behavior on first boot.
        match self.reader.committed_tip() {
            Ok(Some((height, header_id))) => ChainTip {
                height,
                header_id: Digest32::from_bytes(header_id),
            },
            Ok(None) => ChainTip {
                height: 0,
                header_id: Digest32::ZERO,
            },
            Err(e) => {
                warn!(error = %e, "committed_tip read failed");
                ChainTip {
                    height: 0,
                    header_id: Digest32::ZERO,
                }
            }
        }
    }

    fn header_id_at(&self, height: u32) -> Option<HeaderId> {
        match self.reader.get_header_id_at_height(height) {
            Ok(opt) => opt.map(Digest32::from_bytes),
            Err(e) => {
                warn!(height, error = %e, "get_header_id_at_height read failed");
                None
            }
        }
    }

    fn full_block(&self, header_id: &HeaderId) -> Option<IndexerFullBlock> {
        let header_id_bytes = header_id.as_bytes();
        let header_bytes = match self.reader.get_header(header_id_bytes) {
            Ok(Some(b)) => b,
            Ok(None) => return None,
            Err(e) => {
                warn!(
                    header_id = %hex::encode(header_id_bytes),
                    error = %e,
                    "get_header read failed",
                );
                return None;
            }
        };
        let header = match read_header(&mut VlqReader::new(&header_bytes)) {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    header_id = %hex::encode(header_id_bytes),
                    error = ?e,
                    "header parse failed",
                );
                return None;
            }
        };
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            header_id_bytes,
            header.transactions_root.as_bytes(),
        );
        let section_bytes = match self.reader.get_block_section(&section_id) {
            Ok(Some(b)) => b,
            Ok(None) => return None,
            Err(e) => {
                warn!(
                    section_id = %hex::encode(section_id),
                    error = %e,
                    "get_block_section read failed",
                );
                return None;
            }
        };
        let block_txs = match read_block_transactions(&mut VlqReader::new(&section_bytes)) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    header_id = %hex::encode(header_id_bytes),
                    error = ?e,
                    "block_transactions parse failed",
                );
                return None;
            }
        };
        let height = i32::try_from(header.height).ok()?;
        Some(IndexerFullBlock {
            height,
            header_id: *header_id,
            transactions: block_txs.transactions,
        })
    }
}
