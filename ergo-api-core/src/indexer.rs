#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexerStatus {
    Syncing,
    CaughtUp,
    Halted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexerRepair {
    pub pending: bool,
    pub next_gi: Option<u64>,
    pub skipped: u64,
    pub drift_skips: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexerTotals {
    pub boxes: u64,
    pub txs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexerStatusSnapshot {
    pub status: IndexerStatus,
    pub halt_reason: Option<String>,
    pub indexed_height: u64,
    pub repair: IndexerRepair,
    pub totals: IndexerTotals,
}

pub trait IndexerStatusSource: Send + Sync + 'static {
    fn snapshot(&self) -> IndexerStatusSnapshot;
}
