//! Indexer reader-side surface: trait, DTOs, status enums.
//!
//! Split out from `ergo-indexer` so `ergo-api` (and any other read-side
//! consumer) can depend on the trait + types without pulling in `redb`
//! or `ergo-state`. The `ergo-indexer` crate re-exports everything here
//! so internal callers continue to use a single `ergo_indexer::*` path.

pub mod protocol_genesis;
pub mod query;
pub mod status;
pub mod types;

pub use protocol_genesis::{is_protocol_genesis_box, PROTOCOL_GENESIS_BOX_IDS_MAINNET};
pub use query::{
    BalanceDto, IndexedBlockDto, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, Page,
    SortDir, StorageRentEligibleDto,
};
pub use status::{IndexerHaltReason, IndexerStatus};
pub use types::{IndexedErgoBox, IndexedErgoTransaction};

use ergo_primitives::digest::Digest32;

pub type BoxId = Digest32;
pub type TxId = Digest32;
pub type TokenId = Digest32;
pub type HeaderId = Digest32;
pub type TreeHash = Digest32;
pub type TemplateHash = Digest32;
