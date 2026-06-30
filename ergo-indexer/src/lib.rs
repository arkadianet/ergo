//! Opt-in extra-index parity with the Scala node's `extraIndex` feature.
//!
//! Sits on top of [`ergo_state`] (chain reader) and [`ergo_ser`]
//! (parsed wire types). Provides the writer-side store + apply
//! pipeline that mirrors the per-type indexed rows (boxes / txs /
//! addresses / templates / tokens / segments) into a private redb
//! database, plus the polling task that follows the chain tip.
//!
//! The reader-side surface (trait, DTOs, status enums, ID type aliases)
//! lives in [`ergo_indexer_types`] so `ergo-api` can consume it without
//! pulling in `redb` / `ergo-state`. Everything is re-exported here so
//! `ergo_indexer::*` remains the single import path for implementations
//! and node-side wiring.
//!
//! Module map:
//!
//! * [`store`] — redb tables + transaction helpers (`IndexerStore`).
//! * [`apply`] / [`rollback`] — per-block apply and rollback paths.
//! * [`segment`] / [`segment_buffer`] / [`segment_id`] — segmented
//!   indexes (address / template / token) with spill-on-overflow.
//! * [`address`] / [`template`] / [`token`] — per-type apply
//!   bookkeeping (balance maintenance, mint metadata, etc.).
//! * [`scratch`] — `BlockApplyScratch` reusable allocation arenas.
//! * [`ser`] — wire codecs for persisted indexed rows.
//! * [`handle`] — `IndexerHandle` boot + lifecycle.
//! * [`task`] — `IndexerTask` polling loop and chain-source trait.
//! * [`config`] / [`error`] — `IndexerConfig` and `IndexerError`.

pub mod address;
pub mod apply;
pub mod config;
pub mod error;
pub mod handle;
pub mod rollback;
pub mod scratch;
pub mod segment;
pub(crate) mod segment_buffer;
pub mod segment_id;
pub mod ser;
pub mod store;
pub mod task;
pub mod template;
pub mod token;

pub use apply::{apply_block, apply_block_with_scratch, IndexerBlock};
pub use config::IndexerConfig;
pub use error::IndexerError;
pub use handle::IndexerHandle;
pub use rollback::rollback_one_block;
pub use scratch::BlockApplyScratch;
pub use segment_buffer::secondary_index_drift_skips;
pub use store::{
    IndexerMeta, IndexerStore, OpenOutcome, UndoEntry, INDEXER_SCHEMA_VERSION, ROLLBACK_WINDOW,
};
pub use task::{
    ChainTip, IndexerChainSource, IndexerFullBlock, IndexerPoll, IndexerTask, MAX_SECTION_RETRIES,
};

pub use ergo_indexer_types::{
    BalanceDto, BoxId, HeaderId, IndexedBlockDto, IndexedBoxDto, IndexedErgoBox,
    IndexedErgoTransaction, IndexedTokenDto, IndexedTxDto, IndexerHaltReason, IndexerQuery,
    IndexerStatus, Page, SortDir, StorageRentEligibleDto, TemplateHash, TokenId, TreeHash, TxId,
};
