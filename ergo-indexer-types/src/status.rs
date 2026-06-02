use serde::{Deserialize, Serialize};

/// In-memory indexer status. Never persisted — persisting `CaughtUp`
/// would let a stale positive open routes before the indexer has
/// confirmed the canonical tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexerStatus {
    /// Initial state on successful boot; `indexed_height < committed_tip.height`.
    Syncing,
    /// Last poll observed `indexed_height >= committed_tip.height`.
    CaughtUp,
    /// Fatal error (boot-time or in-loop). Terminal — operator intervention only.
    Halted(IndexerHaltReason),
}

/// Concrete reason classifying a `Halted` indexer. The variant drives
/// the `503 indexer-halted` envelope's `detail` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndexerHaltReason {
    /// Unrecoverable schema/decode failure.
    DbCorruption,
    /// Reorg deeper than `ROLLBACK_WINDOW`.
    UndoMissing,
    /// Chain lost block bytes inside the crash window.
    SectionMissing,
    /// Indexer/chain divergence on apply.
    InputMissing,
    /// `schema_version` key missing from a populated DB.
    SchemaCorruption,
}

impl IndexerHaltReason {
    /// Kebab-case identifier — the literal `<reason>` substituted into
    /// the `503 indexer-halted` envelope's `detail` (e.g.
    /// `"indexer halted: db-corruption"`) and into `/indexedHeight`'s
    /// `haltReason` field. Matches the serde `rename_all = "kebab-case"`
    /// derivation but surfaced as a `&'static str` so the middleware can
    /// format envelopes without going through `serde_json::to_string`
    /// + quote-stripping.
    pub fn as_kebab_case(&self) -> &'static str {
        match self {
            Self::DbCorruption => "db-corruption",
            Self::UndoMissing => "undo-missing",
            Self::SectionMissing => "section-missing",
            Self::InputMissing => "input-missing",
            Self::SchemaCorruption => "schema-corruption",
        }
    }

    /// Human-readable detail text used in operator logs / metrics.
    /// Distinct from `as_kebab_case` — this is for humans, not the
    /// pinned envelope.
    pub fn detail(&self) -> &'static str {
        match self {
            Self::DbCorruption => "indexer DB corruption",
            Self::UndoMissing => "reorg deeper than rollback window",
            Self::SectionMissing => "chain section missing for backfill",
            Self::InputMissing => "indexer/chain divergence on apply",
            Self::SchemaCorruption => "indexer schema_version key missing",
        }
    }
}
