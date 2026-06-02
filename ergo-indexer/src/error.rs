use std::fmt;

use ergo_indexer_types::IndexerHaltReason;

/// Which apply / rollback step encountered a missing box. The
/// distinct contexts share a single `BoxMissing` variant so callers
/// can pattern-match the divergence shape without parsing message
/// text, while still seeing exactly which step tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxMissingContext {
    /// Rollback step 1 input-tokens recompute: an input box from the
    /// rolling-back block isn't in `INDEXED_BOX`.
    RollbackInputTokens,
    /// Rollback output reverse pass: a box created at this height
    /// isn't in `INDEXED_BOX`.
    RollbackOutput,
    /// Rollback step 2 input scan: an input box isn't in `INDEXED_BOX`
    /// at apply time.
    RollbackInput,
}

impl fmt::Display for BoxMissingContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RollbackInputTokens => f.write_str("rollback-input-tokens"),
            Self::RollbackOutput => f.write_str("rollback-output"),
            Self::RollbackInput => f.write_str("rollback-input"),
        }
    }
}

/// Which parent-record table's spill is missing on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpillParentKind {
    Address,
    Template,
    Token,
}

impl fmt::Display for SpillParentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address => f.write_str("address"),
            Self::Template => f.write_str("template"),
            Self::Token => f.write_str("token"),
        }
    }
}

/// Why `UndoEntry::decode` rejected stored bytes. UndoEntry has its
/// own framing format (not ergo-ser), so its decode failures get
/// their own typed shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoEntryMalformedReason {
    Empty,
    TruncatedHeaderId,
    UnknownTag(u8),
    TruncatedCounters,
    /// The body decoded fine but extra bytes remained at the end.
    /// Without this guard a corrupted undo row would be consumed and
    /// then removed by rollback, masking persistence corruption.
    TrailingBytes {
        expected: usize,
        got: usize,
    },
}

impl fmt::Display for UndoEntryMalformedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty body"),
            Self::TruncatedHeaderId => f.write_str("truncated header_id"),
            Self::UnknownTag(t) => write!(f, "unknown tag {t:#x}"),
            Self::TruncatedCounters => f.write_str("truncated counters"),
            Self::TrailingBytes { expected, got } => {
                write!(f, "trailing bytes: consumed {expected}, total {got}")
            }
        }
    }
}

/// Which boot-time height read overflowed `u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeightOverflowContext {
    /// `indexed_height` read from meta exceeded `u32::MAX`.
    Indexed,
    /// Next-height arithmetic (indexed + 1) exceeded `u32::MAX`.
    Next,
}

impl fmt::Display for HeightOverflowContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Indexed => f.write_str("indexed"),
            Self::Next => f.write_str("next"),
        }
    }
}

/// Internal indexer error type. Never crosses the API boundary — the
/// router middleware translates `IndexerStatus::Halted(reason)` into a
/// `503 indexer-halted` envelope.
#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    // ----- redb -----
    /// Any redb call returned an error (open, table-level, storage,
    /// iter, range, get/insert/remove). Boxed because `redb::Error`
    /// is ~160 bytes — clippy's `result_large_err` lint would
    /// otherwise penalise every `Result<_, IndexerError>` in the
    /// crate. The manual `From` impls below box on conversion so `?`
    /// works at every redb call site without an explicit boxing step.
    #[error("indexer db error: {0}")]
    Db(Box<redb::Error>),
    /// A redb write-transaction commit failed.
    #[error("indexer db commit failed: {0}")]
    DbCommit(Box<redb::CommitError>),

    // ----- row decode (redb body bytes → typed value) -----
    /// Bytes loaded from a redb row failed to decode via ergo-ser.
    /// `context` names the row type (e.g. `"indexed_box"`,
    /// `"indexed_tx"`).
    #[error("indexer db decode of {context}: {source}")]
    DbDecode {
        context: &'static str,
        #[source]
        source: ergo_primitives::reader::ReadError,
    },
    /// A persisted row's byte-length didn't match the fixed-width
    /// format. Distinct from `DbDecode` because the failure is at
    /// the framing-prefix length check, not inside ergo-ser.
    #[error("indexer db row length mismatch for {context}: expected {expected}, got {got}")]
    DbRowLength {
        context: &'static str,
        expected: usize,
        got: usize,
    },

    // ----- write-path (encode / hash / size cast) -----
    /// A persistence-write-path serializer call returned an error.
    /// `context` names the operation (e.g. `"indexed_box encode"`,
    /// `"serialize_ergo_box for storage_rent"`, `"tx serialize"`).
    #[error("indexer serialize {context}: {source}")]
    Serialize {
        context: &'static str,
        #[source]
        source: ergo_ser::WriteError,
    },
    /// A length the persistence layer must downcast to `i32`
    /// exceeded `i32::MAX`. Distinct from `Serialize` because the
    /// serializer succeeded — only the post-serialize cast failed.
    #[error("indexer {context} length {len} exceeds i32::MAX")]
    LengthExceedsI32 { context: &'static str, len: usize },
    /// `box_id_with` / `transaction_id_with` / `template_hash_for_box_bytes`
    /// returned an error. The body had already been validated, so a
    /// hash-derivation failure here implies a real serializer bug,
    /// not row corruption.
    #[error("indexer hash derivation {context} failed: {source}")]
    HashDerivation {
        context: &'static str,
        #[source]
        source: ergo_ser::WriteError,
    },

    // ----- schema / boot -----
    /// The `schema_version` key was absent from a populated database
    /// — implies on-disk corruption.
    #[error("indexer schema_version key missing")]
    SchemaCorruption,
    /// The `indexer_meta` table itself is missing from a populated
    /// database — the DB file is the wrong file (or has been
    /// truncated).
    #[error("indexer indexer_meta table missing")]
    SchemaTableMissing,
    /// Persisted schema version doesn't match the running code's.
    #[error("indexer schema version mismatch: persisted={persisted}, code={code}")]
    SchemaMismatch {
        /// Schema version the database was opened with.
        persisted: u32,
        /// Schema version the running code expects.
        code: u32,
    },
    /// Boot-time halt: the handle was called but no `IndexerStore`
    /// is attached. Reached when the API path queries a handle that
    /// failed open and was halted in place.
    #[error("indexer boot-time halt: no store attached")]
    BootStoreMissing,
    /// A height value read at boot-time exceeded `u32::MAX`. The
    /// indexer carries heights as `u32` per the chain's native
    /// representation; a `u64` row that won't fit is data corruption.
    #[error("indexer {context} height {height} exceeds u32::MAX")]
    HeightOverflowsU32 {
        height: u64,
        context: HeightOverflowContext,
    },

    // ----- filesystem (non-redb) -----
    /// `fs::create_dir_all` / `fs::remove_file` / similar failed
    /// during indexer-DB filesystem prep. Distinct from `Db` because
    /// the indexer-DB layer is not yet in scope when this fires.
    #[error("indexer filesystem {context}: {source}")]
    FsIo {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },

    // ----- existing typed domain variants -----
    /// Rollback requested past the deepest available undo entry.
    #[error("indexer undo entry missing for height {0}")]
    UndoMissing(u64),
    /// Chain store has lost block bytes the indexer needs to apply.
    #[error("chain section missing at height {0}")]
    SectionMissing(u64),
    /// An input box referenced by an applying block is not present
    /// in the indexer's box table — implies indexer/chain divergence
    /// on apply.
    #[error("indexer input box {box_id} missing at height {height}")]
    InputMissing {
        /// Hex-encoded missing `box_id`.
        box_id: String,
        /// Height of the applying block.
        height: u64,
    },

    // ----- new domain divergence variants (replacing stringified Db sites) -----
    /// Block apply or rollback expected a specific height, observed
    /// another. Indexer/chain divergence.
    #[error("indexer height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },
    /// Rollback at this height expected a specific `header_id`,
    /// observed another. Indexer/chain divergence.
    #[error("indexer header mismatch at height {height}: expected {expected}, got {got}")]
    HeaderMismatch {
        expected: String,
        got: String,
        height: u64,
    },
    /// Rollback was called for a height that has nothing indexed
    /// beneath it.
    #[error("indexer has nothing indexed at height {height} to rollback")]
    NothingToRollback { height: u64 },
    /// Indexer's box table is missing a row referenced by a rollback
    /// step. Same divergence family as `InputMissing` but covers the
    /// three rollback-side contexts.
    #[error("indexer box {box_id} missing at height {height} ({context})")]
    BoxMissing {
        box_id: String,
        height: u64,
        context: BoxMissingContext,
    },
    /// Indexer's tx table is missing a tx row referenced by rollback.
    /// Symmetric to `InputMissing` but on the tx side; rollback walks
    /// the per-tx reverse step.
    #[error("indexer tx {tx_id} missing at height {height}")]
    TxMissing { tx_id: String, height: u64 },
    /// `indexed_address` has no balance record at a step that
    /// requires one — apply post-output or rollback pre-output.
    /// Indicates an apply/rollback bookkeeping desync.
    #[error("indexer indexed_address for tree_hash {tree_hash} has no balance")]
    AddressBalanceMissing { tree_hash: String },
    /// Segment-bookkeeping topology assertion failed. The `detail`
    /// carries the specific assertion (double-flip, empty pop,
    /// missing-spill, segment-pop mismatch, etc.) — segment topology
    /// is deep enough that pinning the broader category at the
    /// variant level is the right granularity.
    #[error("indexer segment topology violated: {detail}")]
    SegmentTopologyError { detail: String },
    /// `unspent_by_creation_height` index is missing a row for a box
    /// that `INDEXED_BOX` says exists — desync between two indexer
    /// tables.
    #[error(
        "indexer storage_rent desync at creation_height {creation_height} for box {global_box_index}"
    )]
    StorageRentDesync {
        creation_height: u32,
        global_box_index: i64,
    },
    /// Parent record's spill count says spill N exists for this
    /// parent, but the spill row isn't on disk.
    #[error("indexer spill {seg_num} missing for {parent_kind} parent {parent_id}")]
    SpillMissingFromParent {
        parent_id: String,
        seg_num: i32,
        parent_kind: SpillParentKind,
    },
    /// `UndoEntry::decode` rejected stored bytes for a framing
    /// reason. Distinct from `DbDecode` because UndoEntry has its
    /// own framing format (not ergo-ser).
    #[error("indexer undo entry malformed: {reason}")]
    UndoEntryMalformed { reason: UndoEntryMalformedReason },
}

// Route every redb error type — the umbrella + the five subtypes,
// plus the already-boxed `Box<redb::Error>` returned by
// `tables::create_all` — through the `Db` variant so `?` works at
// every redb call site without an explicit `.map_err`/`.into()`.
impl From<redb::Error> for IndexerError {
    fn from(e: redb::Error) -> Self {
        Self::Db(Box::new(e))
    }
}
impl From<Box<redb::Error>> for IndexerError {
    fn from(e: Box<redb::Error>) -> Self {
        Self::Db(e)
    }
}
impl From<redb::DatabaseError> for IndexerError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Db(Box::new(e.into()))
    }
}
impl From<redb::TransactionError> for IndexerError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Db(Box::new(e.into()))
    }
}
impl From<redb::TableError> for IndexerError {
    fn from(e: redb::TableError) -> Self {
        Self::Db(Box::new(e.into()))
    }
}
impl From<redb::StorageError> for IndexerError {
    fn from(e: redb::StorageError) -> Self {
        Self::Db(Box::new(e.into()))
    }
}
impl From<redb::CommitError> for IndexerError {
    fn from(e: redb::CommitError) -> Self {
        Self::DbCommit(Box::new(e))
    }
}

impl IndexerError {
    /// Map an in-loop fatal error to the halt-reason classification
    /// used by the API gate.
    ///
    /// The typed structural variants (HeightMismatch, HeaderMismatch,
    /// NothingToRollback, BoxMissing, TxMissing, AddressBalanceMissing,
    /// SegmentTopologyError, StorageRentDesync, SpillMissingFromParent,
    /// UndoEntryMalformed, BootStoreMissing, HeightOverflowsU32, FsIo,
    /// SchemaTableMissing, DbCommit, DbDecode struct shape, DbRowLength,
    /// Serialize, LengthExceedsI32, HashDerivation) all halt as
    /// `DbCorruption` so operators get finer pattern-matching at the
    /// source-level enum without an API-visible status reclassification.
    pub fn halt_reason(&self) -> IndexerHaltReason {
        match self {
            Self::SchemaCorruption => IndexerHaltReason::SchemaCorruption,
            Self::UndoMissing(_) => IndexerHaltReason::UndoMissing,
            Self::SectionMissing(_) => IndexerHaltReason::SectionMissing,
            Self::InputMissing { .. } => IndexerHaltReason::InputMissing,
            Self::Db(_)
            | Self::DbCommit(_)
            | Self::DbDecode { .. }
            | Self::DbRowLength { .. }
            | Self::Serialize { .. }
            | Self::LengthExceedsI32 { .. }
            | Self::HashDerivation { .. }
            | Self::SchemaTableMissing
            | Self::SchemaMismatch { .. }
            | Self::BootStoreMissing
            | Self::HeightOverflowsU32 { .. }
            | Self::FsIo { .. }
            | Self::HeightMismatch { .. }
            | Self::HeaderMismatch { .. }
            | Self::NothingToRollback { .. }
            | Self::BoxMissing { .. }
            | Self::TxMissing { .. }
            | Self::AddressBalanceMissing { .. }
            | Self::SegmentTopologyError { .. }
            | Self::StorageRentDesync { .. }
            | Self::SpillMissingFromParent { .. }
            | Self::UndoEntryMalformed { .. } => IndexerHaltReason::DbCorruption,
        }
    }
}
