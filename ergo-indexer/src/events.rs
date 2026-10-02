//! Optional observations derived from committed indexer rows.
//!
//! Observers run on the dedicated indexer thread, after a successful commit.
//! Implementations must finish promptly and never wait for a network consumer.
//! Uncommitted batches and failed rollbacks produce no observations.

use ergo_indexer_types::{BoxId, HeaderId, IndexedErgoBox, TxId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoxChangeKind {
    Created,
    Spent,
    Reverted,
    Unspent,
}

#[derive(Debug)]
pub struct BoxChange {
    pub kind: BoxChangeKind,
    pub box_id: BoxId,
    /// The transaction creating/spending the box (also on its reversal).
    pub tx_id: TxId,
    pub record: IndexedErgoBox,
}

#[derive(Debug)]
pub struct BlockChanges {
    pub header_id: HeaderId,
    pub height: u32,
    pub boxes: Vec<BoxChange>,
}

pub trait IndexerObserver: Send + Sync {
    fn on_committed(&self, changes: BlockChanges);
}
