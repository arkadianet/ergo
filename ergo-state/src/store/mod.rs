//! Persistent state store backed by redb.
//!
//! Implements the spec's atomicity invariant: undo_log + AVL mutations +
//! chain_index + state_meta all in one redb write transaction.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use ergo_primitives::digest::{ADDigest, Digest32};
use ergo_validation::CheckedTransaction;
use redb::{Database, ReadableTable, TableDefinition};
use tracing::{debug, info, warn};

use crate::avl::node::AvlNode;
use crate::avl::tree::AvlTree;
use crate::chain::{ChainState, ChainStateMeta, HeaderAvailability, HeaderMeta, HeightLookup};

/// Difficulty-headers needed for the next recalculation after
/// `suffix_head_height`. Inlined mirror of Scala
/// `DifficultyAdjustment.heightsForNextRecalculation` + the
/// preceding helpers (`nextRecalculationHeight`,
/// `previousHeightsRequiredForRecalculation`). Pulled in here
/// because `prove_with_db` needs them for continuous-mode proof
/// construction; lives at module scope so it doesn't bloat the
/// `StateStore` impl block.
pub(crate) fn difficulty_headers_needed(
    suffix_head_height: u32,
    epoch_length: u32,
    use_last_epochs: u32,
) -> Vec<u32> {
    let next_recalc = if suffix_head_height.is_multiple_of(epoch_length) {
        suffix_head_height + 1
    } else {
        (suffix_head_height / epoch_length + 1) * epoch_length + 1
    };
    if (next_recalc - 1).is_multiple_of(epoch_length) && epoch_length > 1 {
        let mut out: Vec<u32> = (0..=use_last_epochs)
            .filter_map(|i| {
                let candidate = (next_recalc - 1) as i64 - (i as i64) * (epoch_length as i64);
                if candidate >= 0 {
                    Some(candidate as u32)
                } else {
                    None
                }
            })
            .collect();
        out.reverse();
        out
    } else if (next_recalc - 1).is_multiple_of(epoch_length)
        && next_recalc > epoch_length * use_last_epochs
    {
        let mut out: Vec<u32> = (0..=use_last_epochs)
            .map(|i| (next_recalc - 1) - i * epoch_length)
            .collect();
        out.reverse();
        out
    } else {
        vec![next_recalc - 1]
    }
}

// ---- redb table definitions ----

/// AVL+ tree nodes: node_id (u64) → serialized AvlNode.
/// Incremental strategy: only dirty (created/modified) nodes are written
/// on each commit, and deleted nodes are removed from the table.
pub(crate) const AVL_NODES: TableDefinition<u64, &[u8]> = TableDefinition::new("avl_nodes");

/// Undo log: (height, header_id) → serialized UndoEntry.
/// Keyed by both height and header_id so entries for different fork branches
/// at the same height can coexist (spec:355).
/// Composite key: 4 bytes height (BE) + 32 bytes header_id = 36 bytes.
pub(crate) const UNDO_LOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("undo_log");

/// State metadata: fixed key "root" → serialized StateMeta
pub(crate) const STATE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("state_meta");

/// Sentinel marking the *writer capability* of the last process to
/// commit to this DB — not the state of all historical AVL nodes.
/// Stamped by every `STATE_META` commit path that can emit v2 node
/// bytes; v1 bytes already on disk stay readable and upgrade lazily
/// as nodes get rewritten.
pub(crate) const NODE_FORMAT_VERSION_KEY: &str = "node_format_version";
pub(crate) const NODE_FORMAT_V2: &[u8] = b"v2";

/// Convert a `ReconstructedNode` (from the snapshot consume-side
/// codec) into a runtime [`AvlNode`] suitable for AVL_NODES
/// storage. Preserves separator keys (Internal) and v2-format
/// cached labels (left/right). Outer `label` is None — recomputed
/// lazily on first traversal.
fn reconstructed_to_avl(rec: &crate::avl::snapshot_codec::ReconstructedNode) -> AvlNode {
    use crate::avl::snapshot_codec::ReconstructedNode;
    match rec {
        ReconstructedNode::Leaf {
            key,
            value,
            next_key,
        } => AvlNode::Leaf {
            key: *key,
            value: value.clone(),
            next_key: *next_key,
            label: None,
        },
        ReconstructedNode::Internal {
            key,
            balance,
            left,
            right,
            left_label,
            right_label,
        } => AvlNode::Internal {
            key: *key,
            left: *left as crate::avl::node::NodeId,
            right: *right as crate::avl::node::NodeId,
            balance: *balance,
            left_label: Some(*left_label),
            right_label: Some(*right_label),
            label: None,
        },
    }
}

/// Sentinel set in `STATE_META` after a successful
/// `back_fill_modifier_type_index_with_progress` run. When present,
/// future calls short-circuit (emit `Skipped` and return `Ok(0)`) so
/// repeat-boots pay one `STATE_META.get` instead of a full HEADERS
/// scan + commit. Versioned via the `_v1` suffix so a future schema
/// rebuild can invalidate by bumping.
pub(crate) const MODIFIER_INDEX_BACKFILL_DONE_V1: &str = "modifier_index_backfill_done_v1";
pub(crate) const MODIFIER_INDEX_BACKFILL_DONE_VAL: &[u8] = b"1";

/// Sentinel set in `STATE_META` after a successful
/// `back_fill_headers_by_height_index` run. Same short-circuit
/// semantics as `MODIFIER_INDEX_BACKFILL_DONE_V1`: once present, future
/// calls return immediately without scanning `HEADER_META`.
pub(crate) const HEADERS_BY_HEIGHT_BACKFILL_DONE_V1: &str = "headers_by_height_backfill_done_v1";

/// Sentinel set in `STATE_META` after a successful
/// `back_fill_section_height_index` run. Phase 1a of Mode 3
/// (Pruned suffix window). Sub-sentinel section requests rely
/// on `SECTION_HEIGHT_INDEX` for the height lookup; legacy
/// archive DBs reopened in pruned mode MUST complete this
/// walk before the pruned-mode activation gate drops, so the
/// serve gate cannot misclassify "legacy un-indexed" as
/// "pruned/absent". Sentinel pattern mirrors
/// `MODIFIER_INDEX_BACKFILL_DONE_V1`.
pub(crate) const SECTION_HEIGHT_BACKFILL_DONE_V1: &str = "section_height_backfill_done_v1";
pub(crate) const SECTION_HEIGHT_BACKFILL_DONE_VAL: &[u8] = b"1";

/// `STATE_META` key for Mode 3's prune low-water mark. Holds a
/// 4-byte LE u32. Written by every forward apply that advances
/// the sentinel, in the same atomic `write_txn` as the eviction
/// step (see `advance_minimal_full_block_height_in_txn`). Absent
/// on archive / fresh / pre-Mode-3 DBs — `read_minimal_full_block_height`
/// returns `1` (GenesisHeight) in that case, the legitimate
/// archive default. Phase 1a deliberately does not seed the key
/// at open time so Phase 1b's bootstrap-aware seeding can write
/// the snapshot- or NiPoPoW-derived value without an undo
/// migration.
pub(crate) const MINIMAL_FULL_BLOCK_HEIGHT_KEY: &str = "minimal_full_block_height_v1";

/// Wallet-rollback safety margin. The wallet hook re-reads
/// `BlockTransactions` from `BLOCK_SECTIONS` during rollback; a
/// rollback that crosses the prune sentinel reads `None` and
/// the wallet desyncs silently. Config-load enforces
/// `blocks_to_keep >= ROLLBACK_WINDOW + SAFETY_MARGIN` so the
/// active rollback window can never fall into pruned territory.
/// Anchored to `persist::MAX_BATCH_BLOCKS` — the maximum number
/// of blocks the pipeline-batch worker commits between
/// sentinel reads, covering the worst-case "wallet sees old
/// sentinel while chain advanced N blocks" race window.
pub const SAFETY_MARGIN: u32 = crate::persist::MAX_BATCH_BLOCKS as u32;

/// Chain index: height → header_id (32 bytes). Best chain only (spec:339).
pub(crate) const CHAIN_INDEX: TableDefinition<u64, &[u8]> = TableDefinition::new("chain_index");

/// Headers: header_id (32 bytes) → serialized header bytes.
/// Written after PoW validation. Never deleted.
pub(crate) const HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers");

/// Block sections: modifier_id (32 bytes) → section bytes.
/// Keyed by the section's own computed ID (not header_id).
/// Section ID = blake2b256_prefixed(type_id, header_id, section_digest).
pub(crate) const BLOCK_SECTIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("block_sections");

/// Modifier type index: modifier_id (32 bytes) → type_byte (1 byte).
///
/// Lets `/blocks/modifier/{id}` dispatch from id alone without re-parsing
/// the value. Populated at section/header write time. Type bytes:
///
/// - 101 (`Header`)              → value lives in `HEADERS`
/// - 102 (`BlockTransactions`)   → value lives in `BLOCK_SECTIONS`
/// - 104 (`ADProofs`)            → value lives in `BLOCK_SECTIONS`
/// - 108 (`Extension`)           → value lives in `BLOCK_SECTIONS`
///
/// Pre-existing data (from before this index) is back-filled
/// deterministically by walking known headers and computing each header's
/// expected three section ids; sections whose id matches one of those
/// triples is tagged with the matching type byte. See
/// `back_fill_modifier_type_index`.
pub(crate) const MODIFIER_TYPE_INDEX: TableDefinition<&[u8], u8> =
    TableDefinition::new("modifier_type_index");

/// Section-height index: section modifier_id (32 bytes) → parent
/// header height (u32). Powers Mode 3 serve gating: a peer
/// requesting a section at height < `minimal_full_block_height`
/// gets a silent deny.
///
/// **Semantics — header-derived catalog, not a presence index.**
/// The row is written at `store_header` time (where height + the
/// 3 derived section ids are both known) so it lands atomically
/// with the header itself; the section *payload* may or may not
/// be present in `BLOCK_SECTIONS` yet. Queries that need
/// "section both indexed AND has bytes" must combine
/// `get_section_height` with a `BLOCK_SECTIONS.get` — the serve
/// gate in Phase 3a does exactly that: deny on missing height
/// row, deny on sub-sentinel height, otherwise serve only if
/// `BLOCK_SECTIONS` returns the bytes.
///
/// Eviction in Phase 2a/2b deletes the `BLOCK_SECTIONS` row but
/// retains the `SECTION_HEIGHT_INDEX` row as a tombstone so the
/// Phase 3a receive / storage / serve guards can resolve
/// resurrection-attempt section_ids back to their sub-sentinel
/// heights and reject them. The eviction step co-commits with
/// the chain-state advance so post-eviction the payload does not
/// exist at a pruned
/// height. Pre-eviction divergence (catalog row exists, payload
/// missing) is normal and harmless — the serve gate's
/// payload-presence check handles it.
///
/// Pre-existing data (archive DBs reopened in Mode 3) is
/// back-filled deterministically by `back_fill_section_height_index`,
/// gated by the `SECTION_HEIGHT_BACKFILL_DONE_V1` sentinel.
pub(crate) const SECTION_HEIGHT_INDEX: TableDefinition<&[u8], u32> =
    TableDefinition::new("section_height_index");

/// Header metadata: header_id (32 bytes) → serialized HeaderMeta.
/// Tracks parent, height, cumulative score, PoW validity, timestamp.
pub(crate) const HEADER_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("header_meta");

// (ModifierIndexBackfillEvent + chunk caps live in store/backfill.rs.)

/// Header chain index: height (u32 BE as u64) → header_id (32 bytes).
/// Persists the CURRENT BEST-HEADER CHAIN ONLY. Rewritten on fork flip.
/// Invariant: entry exists iff id is on the best-header chain at that height,
/// for heights in [1, CHAIN_STATE_META.best_header_height].
/// Atomicity: written in the same write txn as CHAIN_STATE_META updates.
pub(crate) const HEADER_CHAIN_INDEX: TableDefinition<u64, &[u8]> =
    TableDefinition::new("header_chain_index");

/// Multi-header height index: height (u32 as u64) → concatenated header_ids
/// (one 32-byte id per known header at that height). Mirrors Scala's
/// `heightIdsKey(h)` in `HeadersProcessor.scala:268-276` — `headerIdsAtHeight`
/// reads this row, splits into 32-byte chunks, and returns `Seq[ModifierId]`.
///
/// **Ordering invariant**: first 32 bytes are the best-header-chain id at
/// that height; subsequent ids are orphans (validated but not on the best
/// chain at this height). Scala's documented contract: "First id is always
/// from the best headers chain." (`HeadersProcessor.scala:272`).
///
/// Distinct from [`HEADER_CHAIN_INDEX`], which holds best-only and is
/// optimised for the `bestHeaderIdAtHeight` fast-path read. This index
/// drives `/blocks/at/{h}` and is the only Rust-side surface that returns
/// fork ids.
pub(crate) const HEADERS_BY_HEIGHT: TableDefinition<u64, &[u8]> =
    TableDefinition::new("headers_by_height");

/// Chain state: fixed key "chain_state" → serialized ChainStateMeta.
/// Tracks best_header and best_full_block pointers across restarts.
pub(crate) const CHAIN_STATE_META: TableDefinition<&str, &[u8]> =
    TableDefinition::new("chain_state_meta");

/// Key in `CHAIN_STATE_META` recording the on-disk schema the data
/// dir was initialized for. Written on first init (or first
/// verify-call on a legacy unsentinel DB); read on every subsequent
/// open. A mismatch between the recorded value and the value the
/// opening backend expects is a hard error — the schemas are not
/// interconvertible in place. Allowed values:
/// - `"utxo"` — `StateStore` with an AVL+ arena (Modes 1/2/3).
/// - `"digest"` — `StateStore` headers-only (Mode 6); same schema,
///   `apply_block` never runs.
/// - `"digest-verifier"` — `DigestStateStore` (Mode 5); a distinct
///   schema with no arena.
///
/// Mode 3 (pruning) and Mode 2 (bootstrap) stay under `"utxo"` since
/// they are operational modes on the same backend; the sentinel
/// tracks the on-disk schema, not the operational mode.
pub(crate) const DATA_DIR_STATE_TYPE_KEY: &str = "data_dir_state_type";

/// Key in `CHAIN_STATE_META` recording a pending Mode 2 install trust
/// claim. Set on snapshot install (a one-byte `0x01`), consumed by the
/// validator on the first post-install epoch boundary block, then
/// cleared. Persisted so a restart between install and the first
/// epoch-start application does not lose the claim — without it the
/// node would reject the next epoch boundary on
/// `exMatchValidationSettings`: the cache holds launch defaults while
/// the chained block carries the pre-snapshot cumulative
/// validation_settings (mainnet has activated rules 215 + 409 and
/// status updates for 1007/1008/1011 prior to this snapshot height).
pub(crate) const MODE2_TRUST_FIRST_EPOCH_KEY: &str = "mode2_trust_first_epoch";

/// Persistent UTXO-bootstrap provenance marker. Written exactly
/// once during `install_snapshot_state` and NEVER cleared. Distinct
/// from `MODE2_TRUST_FIRST_EPOCH_KEY` (which arms the first
/// post-install voting-epoch validation reconcile and is consumed
/// at that block). The marker survives every subsequent
/// reorg / reopen / archive-flag toggle so the `/api/v1/identity`
/// projection can distinguish a real UTXO-snapshot install from a
/// store that was archive-then-pruned and now happens to have
/// `sentinel > 1`. Without this marker, the BootstrapKind heuristic
/// `Dense + sentinel > 1` would label both shapes identically and
/// the operator-facing `post-prune archive` arm in
/// `mode_label_for_with_state` would be unreachable.
pub(crate) const UTXO_BOOTSTRAP_INSTALLED_V1_KEY: &str = "utxo_bootstrap_installed_v1";

/// Stamp / verify the `data_dir_state_type` sentinel against a
/// supplied `redb::Database`. Free-function form of
/// `StateStore::verify_or_init_state_type` so the
/// `crate::digest_store::DigestStateStore` sibling can share the
/// exact same stamp logic without instantiating a `StateStore`
/// first. Both backends must agree on what counts as a mismatch —
/// the extraction guarantees one source of truth.
///
/// Three accepted values, one per on-disk schema:
/// - `"utxo"` — `StateStore` with an active AVL+ arena (Modes 1/2/3).
/// - `"digest"` — `StateStore` in headers-only configuration
///   (Mode 6); same schema as `"utxo"` but `apply_block` never runs.
/// - `"digest-verifier"` — `DigestStateStore` (Mode 5); a distinct
///   schema (digest + chain-state history ledgers, no arena).
///
/// `"digest"` and `"digest-verifier"` are deliberately separate:
/// the headers-only `StateStore` and the `DigestStateStore` have
/// incompatible on-disk layouts, so a dir written by one must never
/// reopen as the other.
/// Outcome of [`check_state_type_inner`]: either the sentinel is
/// already correct, or it is absent and (after the caller validates
/// the dir's shape) should be stamped with the resolved value.
pub(crate) enum StateTypeResolution {
    /// Sentinel present and equal to the expected value. No write.
    AlreadyStamped,
    /// No sentinel; this value resolved from the on-disk shape and
    /// should be written by [`stamp_state_type_inner`] AFTER the
    /// caller confirms the dir is valid for it.
    NeedsStamp(String),
}

/// Read-only resolution of the `data_dir_state_type` sentinel. Never
/// writes. Returns [`StateTypeResolution`] or a `StateTypeMismatch` /
/// `DbCorruption` error. Splitting the read-only check from the write
/// ([`stamp_state_type_inner`]) lets a caller validate the directory
/// shape BEFORE the sentinel is persisted, so a failed mis-open never
/// poisons the on-disk classification.
///
/// Three accepted values, one per on-disk schema:
/// - `"utxo"` — `StateStore` with an active AVL+ arena (Modes 1/2/3).
/// - `"digest"` — `StateStore` headers-only (Mode 6); same schema as
///   `"utxo"` but `apply_block` never runs.
/// - `"digest-verifier"` — `DigestStateStore` (Mode 5); a distinct
///   schema (digest + chain-state history ledgers, no arena).
pub(crate) fn check_state_type_inner(
    db: &redb::Database,
    expected_state_type: &str,
) -> Result<StateTypeResolution, StateError> {
    if !matches!(expected_state_type, "utxo" | "digest" | "digest-verifier") {
        return Err(StateError::InvalidPrecondition {
            what: "verify_or_init_state_type: expected_state_type must be \
                   \"utxo\", \"digest\", or \"digest-verifier\"",
        });
    }
    let existing: Option<String> = {
        let read_txn = db.begin_read()?;
        match read_txn.open_table(CHAIN_STATE_META) {
            Ok(table) => table
                .get(DATA_DIR_STATE_TYPE_KEY)?
                .map(|g| String::from_utf8_lossy(g.value()).to_string()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(e.into()),
        }
    };
    if let Some(recorded) = existing {
        if recorded == expected_state_type {
            return Ok(StateTypeResolution::AlreadyStamped);
        }
        return Err(StateError::StateTypeMismatch {
            configured: expected_state_type.to_string(),
            recorded,
        });
    }
    // No sentinel. Infer the backend from the on-disk shape so a
    // dir whose sentinel was lost to partial corruption is not
    // silently re-stamped onto an INCOMPATIBLE schema:
    // - AVL+ arena rows ⇒ `"utxo"` (every pre-sentinel DB is an
    //   archive; legacy migration path).
    // - digest-verifier markers (its history ledger or the
    //   `root_digest` meta key) ⇒ `"digest-verifier"` — hard-
    //   protected because that schema is not interconvertible with
    //   the `StateStore` schema.
    // - neither ⇒ resolve to `expected`.
    //
    // The `"utxo"` vs `"digest"` (Mode 6 headers-only) distinction is
    // deliberately NOT inferred here: both share the `StateStore`
    // schema and differ only in whether `apply_block` runs (config),
    // and a `StateStore` mid-IBD (headers synced, no blocks applied)
    // is on-disk indistinguishable from a headers-only Mode 6 store.
    // For that same-schema pair the sentinel is authoritative and a
    // sentinel-less dir falls through to `expected` (the operator's
    // configured mode), which is safe precisely because the schema is
    // identical. The hard guarantee — incompatible schemas can never
    // be confused — rests on the AVL and digest-verifier checks plus
    // the caller's post-check shape validation.
    let has_avl_rows = {
        let read_txn = db.begin_read()?;
        match read_txn.open_table(AVL_NODES) {
            Ok(table) => table.first()?.is_some(),
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(e) => return Err(e.into()),
        }
    };
    let has_digest_verifier_markers = crate::digest_store::has_digest_verifier_markers(db)?;
    // Both marker sets present is a frankenstore — two incompatible
    // schemas in one dir. Never infer one over the other; hard-fail.
    if has_avl_rows && has_digest_verifier_markers {
        return Err(StateError::DbCorruption {
            table: "data_dir_state_type",
            key: "inference".into(),
            reason: "dir carries BOTH UTXO arena rows and digest-verifier markers \
                 with no state-type sentinel — incompatible schemas, refusing to \
                 infer a backend"
                .into(),
        });
    }
    let inferred = if has_avl_rows {
        "utxo"
    } else if has_digest_verifier_markers {
        "digest-verifier"
    } else {
        expected_state_type
    };
    if inferred != expected_state_type {
        return Err(StateError::StateTypeMismatch {
            configured: expected_state_type.to_string(),
            recorded: inferred.to_string(),
        });
    }
    Ok(StateTypeResolution::NeedsStamp(inferred.to_string()))
}

/// Write the `data_dir_state_type` sentinel. Call ONLY after
/// [`check_state_type_inner`] returns `NeedsStamp` AND the caller has
/// validated that the directory's contents are actually valid for
/// `value` — stamping a dir that later fails shape validation would
/// poison its on-disk classification.
pub(crate) fn stamp_state_type_inner(db: &redb::Database, value: &str) -> Result<(), StateError> {
    let write_txn = crate::begin_write_qr(db)?;
    {
        let mut table = write_txn.open_table(CHAIN_STATE_META)?;
        table.insert(DATA_DIR_STATE_TYPE_KEY, value.as_bytes())?;
    }
    write_txn.commit()?;
    Ok(())
}

/// Combined check-then-stamp, for callers (`StateStore`) that have
/// already validated the directory during their own `open` before
/// this runs, so stamping immediately is safe.
pub(crate) fn verify_or_init_state_type_inner(
    db: &redb::Database,
    expected_state_type: &str,
) -> Result<(), StateError> {
    match check_state_type_inner(db, expected_state_type)? {
        StateTypeResolution::AlreadyStamped => Ok(()),
        StateTypeResolution::NeedsStamp(value) => stamp_state_type_inner(db, &value),
    }
}

mod apply;
pub use apply::compute_minimal_full_block_height;
mod backfill;
mod dry_run;
/// Test-only re-export of the canonical proof producer, used by
/// the digest-mode apply seam's producer/consumer interop test and
/// the `test-helpers` ADProofs-derivation seam. Production code never
/// reaches `dry_run` cross-module.
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) use dry_run::apply_change_set_via_prover;
mod error;
mod height_index;
mod meta;
mod open;
mod popow_cache;
mod rebuild;
mod reorg;
mod snapshot;
mod undo;
mod votes;

pub use backfill::ModifierIndexBackfillEvent;
pub use error::{PopowByIdLookup, PopowMissingAt, StateError, VotedParamsWriteError};
pub(crate) use height_index::{
    append_orphan_to_height_index, promote_to_height_index_slot_0, read_height_index_ids,
    rewrite_best_chain_into_index, rewrite_height_index_for_new_best,
};
use meta::StateMeta;
pub use snapshot::{BaseDisposition, CommittedSnapshot, DryRunBase};
use undo::undo_log_key;
pub use undo::UndoEntry;
use votes::compute_epoch_votes_via_txn;

// (StateMeta lives in store/meta.rs.)

type UtxoRemoveMap = BTreeMap<[u8; 32], ()>;
type UtxoInsertMap = BTreeMap<[u8; 32], Vec<u8>>;
type UtxoChangeMaps = (UtxoRemoveMap, UtxoInsertMap);

struct UtxoMutation<'a> {
    height: u32,
    header_id: &'a [u8; 32],
    expected_state_root: &'a ADDigest,
    digest_before: ADDigest,
    to_remove: &'a UtxoRemoveMap,
    to_insert: &'a UtxoInsertMap,
    voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
    /// Wallet apply payload committed atomically with the chain
    /// mutation. Consumed by `persist_apply`'s synchronous path
    /// inside its write_txn; or queued on the `PersistJob` for the
    /// worker's `execute_batch` to apply inside the batch write_txn
    /// on the pipeline path. Either way, chain + wallet commit
    /// together.
    wallet_payload: Option<&'a WalletApplyPayload>,
}

/// Owned wallet-apply payload built at block-apply time on the main
/// thread. Carries everything needed to run `apply_block_to_wallet` +
/// `promote_matured_boxes` inside the chain's redb write_txn, so the
/// chain and wallet commit atomically in the same transaction.
///
/// Bundled as owned data (not references to live wallet state) so
/// the payload crosses the persist-pipeline thread boundary into
/// `PersistJob` without lifetime or Send/Sync friction.
#[derive(Clone)]
pub(crate) struct WalletApplyPayload {
    pub tracked_p2pk_trees: std::collections::BTreeSet<Vec<u8>>,
    pub cached_pubkeys: std::collections::BTreeMap<u64, [u8; 33]>,
    pub block_txs_owned: Vec<OwnedBlockTxData>,
    /// One record per block output box that matched ≥1 registered scan.
    /// Computed on the main thread (where the `ergo-wallet` matcher is reachable
    /// via the hook) and carried as owned data so it crosses the persist-worker
    /// boundary; `ergo-state` persists it atomically in the chain write-txn.
    /// Empty when no scans are registered — and ALSO empty for a block that only
    /// spends (no new matches), which is why the scan-apply gate uses
    /// `has_registered_scans` below, not `scan_matches.is_empty()`.
    pub scan_matches: Vec<ScanMatchRecord>,
    /// True iff ≥1 scan was registered at payload-build time
    /// (`registered_scan_count() > 0`). Gates `apply_block_to_scans`: when no
    /// scans exist the scan tables are never opened/created and the per-input
    /// spend-index probe is skipped — the `scan_count == 0` fast path, made
    /// complete at the apply site (not just at payload build). Must NOT be
    /// derived from `scan_matches.is_empty()`: a registered scan still needs
    /// phase-2 spend transitions on a block that produced no new matches.
    pub has_registered_scans: bool,
}

impl WalletApplyPayload {
    /// True when this payload carries wallet-key tracking (tracked P2PK
    /// trees or cached pubkeys), as opposed to existing solely to carry
    /// scan matches.
    ///
    /// The commit sites gate `apply_block_to_wallet` + `promote_matured_boxes`
    /// on this: a scan-only payload (built because scans are registered but the
    /// wallet currently has no keys/trees — e.g. keys not yet loaded, hydration
    /// failed, or a genuinely keyless node) must NOT run wallet apply, which
    /// would advance `WALLET_SCAN_HEIGHT` for blocks the wallet never
    /// classified. Nothing resumes scanning from that height today, so the
    /// concrete harm is `/wallet/status` + `/wallet/balances` reporting a
    /// `walletHeight` (and wallet-confirmations base) for work never done.
    /// Scan tracking (`apply_block_to_scans`) runs regardless.
    ///
    /// This reproduces the pre-scan-tracking payload-build gate exactly:
    /// before scans existed, a payload was built (and wallet apply run) only
    /// when `!trees.is_empty() || !pubkeys.is_empty()`.
    pub(crate) fn has_wallet_tracking(&self) -> bool {
        !self.tracked_p2pk_trees.is_empty() || !self.cached_pubkeys.is_empty()
    }
}

/// One scan-matched output box, produced at payload-build time. Carries the
/// serialized box so the matched box can be persisted (and rendered for
/// `/scan/spentBoxes` after it leaves the UTXO set).
#[derive(Clone)]
pub(crate) struct ScanMatchRecord {
    pub box_id: [u8; 32],
    /// Ids of every registered scan whose rule matched this box.
    pub scan_ids: Vec<u16>,
    /// Full serialized `ErgoBox` bytes.
    pub box_bytes: Vec<u8>,
    pub inclusion_height: u32,
    pub creation_out_index: u16,
}

// ---- Persistent state store ----

/// Persistent UTXO state backed by redb + in-memory AVL+ tree.
///
/// The AVL tree is maintained in memory for fast access. On each block
/// application, dirty nodes are flushed to the avl_nodes table within the
/// same write transaction that writes undo_log, chain_index, and state_meta.
///
/// On crash recovery: read state_meta → load tree from avl_nodes → resume.
/// DEFAULT rollback window: undo entries older than this are pruned on
/// forward apply, so it caps the deepest reorg the UTXO store can serve.
/// Mirrors the Scala reference node's `keepVersions` default (200).
/// Operator-configurable via `[node] keep_versions` -> the per-store
/// [`StateStore::set_rollback_window`]; this const is the open-time default
/// and the value every test that doesn't override sees.
pub const ROLLBACK_WINDOW: u32 = 200;

/// Point-in-time read-only instrumentation gauges for a [`StateStore`].
///
/// Grouped into one struct so the consensus-critical `StateStore` surface
/// isn't padded with a dozen individual metric getters. Every field is pure
/// observability — none is consensus state. Produced by [`StateStore::metrics`]
/// and consumed only by the heartbeat sampler in `ergo-node`. `Default` is the
/// all-zero reading used for backends without a UTXO arena (e.g. digest mode).
#[derive(Debug, Default, Clone, Copy)]
pub struct StateMetrics {
    /// Cumulative AVL arena node reads since the last `arena_reset_read_count`.
    pub arena_read_count: u64,
    /// Bytes currently held in the AVL arena's clean LRU cache (0 if unbudgeted).
    pub arena_cache_clean_bytes: usize,
    /// Configured byte budget for the AVL clean cache (0 if unbudgeted).
    pub arena_cache_capacity_bytes: usize,
    /// Number of nodes in the AVL clean cache.
    pub arena_cache_clean_len: usize,
    /// Structurally modified (dirty) AVL nodes pending commit. Sustained
    /// growth signals a stalled commit pipeline.
    pub arena_cache_dirty_len: usize,
    /// Headers buffered in `batch_headers` awaiting persist.
    pub batch_headers_len: usize,
    /// Sum of buffered header bytes in `batch_headers`.
    pub batch_headers_bytes: usize,
    /// `header_meta` entries buffered awaiting persist.
    pub batch_meta_len: usize,
    /// Cumulative redb page-cache evictions for the state DB. Only non-zero
    /// when redb's `cache_metrics` feature is enabled.
    pub redb_cache_evictions: u64,
}

pub struct StateStore {
    db: Arc<Database>,
    tree: AvlTree,
    height: u32,
    genesis_committed: bool,
    chain_state: ChainState,
    /// In-memory mirror of the active protocol parameter set at the
    /// current full-block tip. Kept consistent with `chain_state` by
    /// `apply_utxo_changes` (advances on epoch-start) and `rollback_to`
    /// (rebuilt after the rollback commit). Snapshot publisher reads
    /// via `StateStore::active_params()` — no DB round-trip, no
    /// pipeline flush, always in sync with the in-memory
    /// `best_full_block_height`.
    cached_active_params: ergo_validation::ActiveProtocolParameters,
    /// In-memory mirror of the cumulative `ErgoValidationSettings` at
    /// the current full-block tip. Folded from every `voted_params`
    /// row's `activated_update` in encounter order. Refreshed alongside
    /// `cached_active_params` and read by the validator and mempool to
    /// govern rule disabling.
    cached_validation_settings: ergo_validation::ErgoValidationSettings,
    /// Header + block-section tables with their buffered-write
    /// overlay. Shares the `db` handle; the best-header pointers stay
    /// in `chain_state`, passed in by reference at the write seams.
    headers: crate::header_store::HeaderSectionTables,
    /// IBD durability relaxation. When enabled, block commits use
    /// Durability::None except every `ibd_flush_interval` blocks which
    /// use Durability::Immediate (flushing all prior non-durable commits).
    /// On crash, up to ibd_flush_interval blocks of work may be lost.
    ibd_mode: bool,
    ibd_blocks_since_flush: u32,
    ibd_flush_interval: u32,
    /// Background persist pipeline. When Some, persist_apply sends jobs
    /// to a background thread instead of writing synchronously.
    persist_pipeline: Option<crate::persist::PersistPipeline>,
    /// In-memory mirror of `MODE2_TRUST_FIRST_EPOCH_KEY`. `true` after
    /// `install_snapshot_state` until the first post-install epoch
    /// boundary block consumes it via `take_mode2_trust_first_epoch`.
    /// Hydrated from disk on `open`.
    mode2_trust_first_epoch: bool,
    /// Network-specific launch parameters, used to seed the height-0
    /// row in `voted_params` and to replay the active-params state
    /// machine from genesis. Captured at `open` time from the caller
    /// (`scala_launch_for_network(chain_spec.network)` in production)
    /// so a testnet store can't accidentally seed mainnet defaults.
    init_launch_params: ergo_validation::ActiveProtocolParameters,
    /// Network-specific voting parameters (`voting_length`,
    /// `soft_fork_epochs`, `activation_epochs`, `version2_activation`).
    /// Captured at `open` time from the caller (`chain_spec.voting`
    /// in production). Consumed by the validator at every epoch
    /// boundary — `voting_length` gates the epoch-start branch in
    /// `block_proc::process_block`, and the soft-fork tally
    /// thresholds drive `compute_next_params`.
    voting_settings: ergo_chain_spec::VotingParams,
    /// Difficulty schedule for this network. Consumed by the NiPoPoW
    /// prover (`prove_with_db`) for continuous-mode difficulty-header
    /// selection and epoch-length resolution. Defaults to mainnet at
    /// `open`; boot overrides via [`Self::set_difficulty_params`] from
    /// `chain_spec.difficulty` (same wiring shape as
    /// `set_blocks_to_keep`), so a testnet store proves with testnet
    /// epochs instead of silently assuming mainnet.
    difficulty_params: ergo_chain_spec::DifficultyParams,
    /// Mode 3 retention window: `-1` = archive (no pruning, default),
    /// `0` = canonical Mode 6 headers-only (never prunes blocks
    /// because no full-block apply happens), `> 0` = suffix-window
    /// pruning. The forward-apply seam (`persist_apply`) reads
    /// this to decide whether to compute a new prune sentinel and
    /// delete sub-sentinel sections inside the same atomic
    /// write_txn. Boot wires this from `[node] blocks_to_keep` via
    /// `set_blocks_to_keep`; tests use the setter directly.
    blocks_to_keep: i32,
    /// Undo-retention window (max serviceable reorg depth). Defaults to
    /// [`ROLLBACK_WINDOW`] at `open`; boot overrides from
    /// `[node] keep_versions` via [`Self::set_rollback_window`] (same
    /// wiring shape as `set_blocks_to_keep`). Read by the forward-apply
    /// prune seams, the `rollback_to` depth guard, and the tx-diff LCA
    /// walk caps.
    rollback_window: u32,
}

impl StateStore {
    /// Default cache budget for the disk-backed AVL arena: 1 GB.
    /// Profiling at h=505k showed 128 MB undersized for IBD: redb page-cache
    /// reads + LRU evictions were ~3% of samples while DB had grown to 3.8 GB.
    /// 1 GB keeps the working set resident through typical IBD batches and
    /// shifts the bottleneck off cache misses. Configurable via
    /// `[store] cache_bytes` TOML or `--cache-bytes` CLI for memory-limited
    /// hosts; smaller test fixtures still call `open_with_cache` explicitly.
    pub const DEFAULT_CACHE_BYTES: usize = 1024 * 1024 * 1024;

    /// Reload `cached_active_params` from `voted_params` at the current
    /// `best_full_block_height`. Called after open's reconcile, after
    /// rollback, and after reorg. Returns `Err` only when used during
    /// `open` (where the rest of startup can still abort).
    fn refresh_cached_active_params(&mut self) -> Result<(), StateError> {
        let h = self.chain_state.best_full_block_height;
        match self.active_params_at(h)? {
            Some(p) => {
                self.cached_active_params = p;
            }
            None => {
                return Err(StateError::InternalInvariantAt {
                    what: "voted_params: cache refresh found no row \
                           (open's reconcile should have written the genesis row)",
                    height: h,
                });
            }
        }
        // Refresh validation_settings cache alongside active params.
        self.cached_validation_settings = self.compute_validation_settings_at(h)?;
        Ok(())
    }

    /// Refresh the cache after a successful rollback/reorg commit.
    ///
    /// The cache governs validation — `BlockValidationContext.params`
    /// and mempool admission both read it — so a stale cache after a
    /// successful commit would mean subsequent block validation runs
    /// against the wrong active set, a consensus divergence. We panic
    /// instead, surfacing the failure to the operator immediately
    /// rather than silently drifting from Scala.
    ///
    /// The only paths to a refresh failure post-commit are:
    /// - redb read error (db corruption / hardware)
    /// - missing genesis row (open()'s reconcile bug)
    /// - row-decode failure (codec bug or db corruption)
    ///
    /// All three are "stop the world" events. Continuing on best-effort
    /// is worse than crashing.
    fn refresh_cached_active_params_post_commit(&mut self) {
        let h = self.chain_state.best_full_block_height;
        match self.active_params_at(h) {
            Ok(Some(p)) => {
                self.cached_active_params = p;
            }
            Ok(None) => {
                panic!(
                    "[state] FATAL: voted_params cache refresh found no row <= h={h} \
                     post-commit. Validation cannot continue safely — open's reconcile \
                     should have written the genesis row. This is a bug or db corruption."
                );
            }
            Err(e) => {
                panic!(
                    "[state] FATAL: voted_params cache refresh failed at h={h}: {e}. \
                     Validation cannot continue safely — db read after a successful \
                     commit should not fail. This is a bug or db corruption."
                );
            }
        }
        // Validation settings refresh: same fatal posture. The only
        // currently load-bearing settings entry is rule 409, but the
        // mechanism is the same — stale settings would mean we run
        // rule 409 when it should be skipped or vice-versa.
        match self.compute_validation_settings_at(h) {
            Ok(s) => {
                self.cached_validation_settings = s;
            }
            Err(e) => {
                panic!(
                    "[state] FATAL: validation_settings cache refresh failed at h={h}: {e}. \
                     Validation cannot continue safely."
                );
            }
        }
    }

    /// Compute `ErgoValidationSettings` at `height` by folding every
    /// `voted_params` row's `activated_update` from key 0 up to the
    /// highest row with `key <= height`. Used internally by the cache
    /// refresh; external callers go through `validation_settings()`.
    fn compute_validation_settings_at(
        &self,
        height: u32,
    ) -> Result<ergo_validation::ErgoValidationSettings, StateError> {
        let r = self.db.begin_read()?;
        Ok(crate::active_params::compute_validation_settings_at(
            &r, height,
        )?)
    }

    /// Active protocol parameters at the current full-block tip.
    /// Read from in-memory cache; never touches redb. Always consistent
    /// with `chain_state().best_full_block_height`.
    pub fn active_params(&self) -> &ergo_validation::ActiveProtocolParameters {
        &self.cached_active_params
    }

    /// Network-specific voting parameters seeded at `open` time.
    /// Stable for the store's lifetime — `voting_length` and the
    /// soft-fork thresholds are network constants, not per-epoch
    /// state. Validator paths consume this so epoch-boundary logic
    /// uses the right cadence per network.
    pub fn voting_settings(&self) -> &ergo_chain_spec::VotingParams {
        &self.voting_settings
    }

    /// Cumulative `ErgoValidationSettings` at the current full-block
    /// tip. Read from in-memory cache; same consistency invariant as
    /// `active_params()`.
    pub fn validation_settings(&self) -> &ergo_validation::ErgoValidationSettings {
        &self.cached_validation_settings
    }

    /// Enable the background persist pipeline.
    ///
    /// After this call, `persist_apply` sends jobs to a background thread
    /// instead of writing synchronously. The main thread can immediately
    /// proceed to the next block.
    ///
    /// `queue_depth`: max in-flight jobs before backpressure (8-16 typical).
    pub fn enable_persist_pipeline(&mut self, queue_depth: usize) {
        self.persist_pipeline = Some(crate::persist::PersistPipeline::new(
            Arc::clone(&self.db),
            queue_depth,
            self.voting_settings.voting_length,
            self.blocks_to_keep,
        ));
    }

    fn drain_persist_results(&self) -> Result<(), StateError> {
        let Some(ref pipeline) = self.persist_pipeline else {
            return Ok(());
        };
        for result in pipeline.drain_all_results() {
            match result {
                crate::persist::PersistResult::Ok { .. } => {}
                crate::persist::PersistResult::Err { height, error } => {
                    return Err(StateError::PersistFailed { height, error });
                }
            }
        }
        Ok(())
    }

    /// Wait for all queued persist jobs to complete.
    /// Must be called before rollback/reorg or on shutdown.
    pub fn flush_persist_pipeline(&self) -> Result<(), StateError> {
        self.drain_persist_results()?;
        if let Some(ref pipeline) = self.persist_pipeline {
            if let Some(crate::persist::PersistResult::Err { height, error }) = pipeline.flush() {
                return Err(StateError::PersistFailed { height, error });
            }
        }
        Ok(())
    }

    /// Current committed height (0 = genesis, no blocks applied).
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Whether genesis state has been committed.
    pub fn genesis_committed(&self) -> bool {
        self.genesis_committed
    }

    /// Get the current root digest.
    pub fn root_digest(&mut self) -> ADDigest {
        self.tree.root_digest()
    }

    /// Cumulative count of arena node reads since the last reset.
    /// Observability surface — used by heartbeat metrics and by
    /// cold-restart read-count regression tests. Not consensus state.
    pub fn arena_read_count(&self) -> u64 {
        self.tree.arena_read_count()
    }

    /// Reset the arena read counter to zero. Observability-only;
    /// has no effect on consensus state or AVL tree contents.
    pub fn arena_reset_read_count(&self) {
        self.tree.arena_reset_read_count()
    }

    /// A cloned `Arc` handle to the underlying redb `Database`. Allows
    /// subsystems (e.g. the wallet writer task) to open their own read
    /// transactions against the same database file without going through
    /// the main action loop. The `Arc` clone is cheap; the database itself
    /// is shared via the arc.
    pub fn db_arc(&self) -> Arc<Database> {
        self.db.clone()
    }

    /// Point-in-time snapshot of the store's read-only instrumentation
    /// gauges (AVL arena cache, persist-batch buffers, redb eviction
    /// counter). Grouped behind one accessor — see [`StateMetrics`] — so the
    /// consensus-critical `StateStore` surface isn't padded with a dozen
    /// individual getters; the heartbeat sampler in `ergo-node` is the only
    /// consumer. Pure observability — none of these fields is consensus state.
    pub fn metrics(&self) -> StateMetrics {
        StateMetrics {
            arena_read_count: self.tree.arena_read_count(),
            arena_cache_clean_bytes: self.tree.arena_cache_clean_bytes(),
            arena_cache_capacity_bytes: self.tree.arena_cache_capacity_bytes(),
            arena_cache_clean_len: self.tree.arena_cache_clean_len(),
            arena_cache_dirty_len: self.tree.arena_cache_dirty_len(),
            batch_headers_len: self.headers.batch_headers_len(),
            batch_headers_bytes: self.headers.batch_headers_bytes(),
            batch_meta_len: self.headers.batch_meta_len(),
            redb_cache_evictions: self.db.cache_stats().evictions(),
        }
    }

    /// Insert a (key, value) directly into the AVL tree without running
    /// block validation or committing to disk. Exists only to exercise the
    /// tree-walk code path in cold-restart read-count regression tests.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn tree_insert_for_test(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.tree.insert(key, value);
    }

    /// Enable or disable IBD durability relaxation.
    ///
    /// When enabled, block commits use `Durability::None` except every
    /// `flush_interval` blocks. On disable, forces a durable flush of
    /// any pending non-durable commits.
    pub fn set_ibd_mode(&mut self, enabled: bool, flush_interval: u32) {
        if self.ibd_mode && !enabled {
            // Exiting IBD: force durable flush if there are pending non-durable commits
            if self.ibd_blocks_since_flush > 0 {
                if let Err(e) = self.force_durable_flush() {
                    warn!(error = %e, "durable flush on IBD exit failed");
                }
            }
        }
        self.ibd_mode = enabled;
        self.ibd_flush_interval = flush_interval;
        self.ibd_blocks_since_flush = 0;
    }

    /// Whether IBD durability mode is active.
    pub fn ibd_mode(&self) -> bool {
        self.ibd_mode
    }

    /// Force a durable (Immediate) empty write to flush all prior
    /// Durability::None commits to disk.
    fn force_durable_flush(&self) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        // Durability::Immediate is the default — just commit an empty txn.
        // This forces redb to fsync, persisting all prior non-durable writes.
        write_txn.commit()?;
        Ok(())
    }

    /// Drain background persistence and force a final durable commit.
    ///
    /// `StateStore` owns both the foreground `Arc<Database>` and the
    /// background persist pipeline. Relying on struct-field drop order makes
    /// shutdown hard to reason about: the database handle can be dropped while
    /// the persist thread still owns its clone, and no final durable write is
    /// issued after queued `Durability::None` IBD commits land. Ctrl+C uses
    /// this explicit path so redb sees a normal clean close on the next start.
    pub fn shutdown_cleanly(&mut self) -> Result<(), StateError> {
        if let Some(pipeline) = self.persist_pipeline.take() {
            drop(pipeline);
        }
        self.force_durable_flush()?;
        self.ibd_blocks_since_flush = 0;
        Ok(())
    }

    /// Initialize the genesis state: insert all genesis boxes and commit
    /// as height 0 in a single operation. Must be called before apply_block.
    ///
    /// This is the only way to set up the pre-block-1 UTXO state. The genesis
    /// state is persisted atomically so rebuild_from_committed() can restore
    /// it if the first block application fails.
    pub fn initialize_genesis(&mut self, boxes: &[([u8; 32], Vec<u8>)]) -> Result<(), StateError> {
        if self.genesis_committed {
            return Err(StateError::InvalidPrecondition {
                what: "initialize_genesis: store already has genesis committed",
            });
        }
        for (box_id, serialized) in boxes {
            self.tree.insert(*box_id, serialized.clone());
        }
        let digest = self.tree.root_digest();
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut avl_table = write_txn.open_table(AVL_NODES)?;
            for (node_id, node) in self.tree.all_nodes() {
                avl_table.insert(node_id, node_to_bytes(&node).as_slice())?;
            }
            let meta = StateMeta {
                height: 0,
                tree_height: self.tree.tree_height(),
                root_digest: *digest.as_bytes(),
                root_node_id: self.tree.root_id(),
            };
            let mut meta_table = write_txn.open_table(STATE_META)?;
            meta_table.insert("root", meta.serialize().as_slice())?;
            meta_table.insert(NODE_FORMAT_VERSION_KEY, NODE_FORMAT_V2)?;

            // Initialize chain state meta at genesis (height 0).
            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert(
                "chain_state",
                self.chain_state.to_persisted().serialize().as_slice(),
            )?;
        }
        write_txn.commit()?;
        self.tree.clear_dirty();
        self.tree.arena_commit();
        self.genesis_committed = true;
        Ok(())
    }

    /// Atomically install a UTXO snapshot at `snapshot_height`.
    ///
    /// Mode 2 consume-side terminal step: takes the
    /// `ReconstructedTree` produced by [`crate::avl::snapshot_codec::reconstruct_tree`]
    /// and bulk-writes it into `AVL_NODES`, sets `STATE_META`
    /// (`root_node_id=0`, `tree_height`, `root_digest=manifest_id`),
    /// and advances `chain_state.best_full_block_*` to
    /// (`snapshot_height`, `canonical_header_id`). Then rebuilds
    /// the in-memory `tree` so subsequent reads hit the new state.
    ///
    /// Pre-conditions enforced at runtime:
    /// 1. Store must not already have full-block state
    ///    (`best_full_block_height == 0`). Refuses overlay.
    /// 2. `snapshot_height != 0` (GenesisHeight install would
    ///    leave the store in a half-installed-fresh-looking state
    ///    that the reciprocal bootstrap guards cannot detect).
    /// 3. `snapshot_height <= best_header_height` — headers up
    ///    to the anchor must have been validated and indexed by
    ///    the caller's prior header-sync step (NiPoPoW prefix or
    ///    Mode 2's full header download).
    /// 4. Cross-check `canonical_header_id` against
    ///    `HEADERS_BY_HEIGHT[snapshot_height]` slot 0 (covers
    ///    BOTH the sparse prefix and the dense suffix that
    ///    `apply_popow_proof` writes; `HEADER_CHAIN_INDEX` would
    ///    miss the sparse prefix that real Mode 4 anchors fall
    ///    in).
    /// 5. The reconstructed tree's root_label must equal the
    ///    first 32 bytes of `expected_state_root` (defense-in-
    ///    depth — the 2g trust check already enforced this against
    ///    the header chain, but a fresh check here protects
    ///    against a state-machine bug between 2g and 2i).
    ///
    /// Caller invariant NOT runtime-enforced (deferred to Phase 5
    /// boot-consistency check): `snapshot_height` must be aligned
    /// to the active network's `voting_length` (1024 mainnet, 128
    /// testnet). Scala only generates snapshots at voting-epoch
    /// boundaries via the `SnapshotsInfo` scheduling logic; the
    /// orchestrator passes a guaranteed-aligned height. Adding a
    /// store-side `snapshot_height % voting_length == 0` guard
    /// would force every test fixture to use multi-thousand-
    /// height vectors and is a Phase 5 acceptance concern, not a
    /// Phase 1b store-correctness concern. A mid-epoch
    /// snapshot_height won't corrupt persistence (the AVL /
    /// chain_state / sentinel writes are well-defined for any
    /// value), but it would persist a `best_full_block_height`
    /// that doesn't sit on an epoch boundary — eviction's
    /// voting-epoch snap (Phase 2a) handles this by rounding the
    /// sentinel DOWN at eviction time.
    ///
    /// Atomicity: AVL_NODES bulk-write, STATE_META update,
    /// CHAIN_STATE_META update, Mode 2 trust sentinel arm, and
    /// Mode 3 prune sentinel co-commit all happen inside a single
    /// redb `write_txn`. A crash mid-install rolls back cleanly;
    /// the node restarts in pre-bootstrap state. `self.chain_state`
    /// is staged into a local `new_cs` and promoted only after
    /// `write_txn.commit()?` succeeds, so a failed install
    /// leaves in-memory state aligned with disk.
    pub fn install_snapshot_state(
        &mut self,
        reconstructed: crate::avl::snapshot_codec::ReconstructedTree,
        snapshot_height: u32,
        canonical_header_id: [u8; 32],
        expected_state_root: &ADDigest,
    ) -> Result<(), StateError> {
        // 1. Refuse if any full-block state is already applied —
        // bootstrap is meaningful only on a fresh data_dir.
        if self.chain_state.best_full_block_height > 0 {
            return Err(StateError::InstallSnapshotRefused {
                current_height: self.chain_state.best_full_block_height,
            });
        }

        // Voting-epoch alignment is a documented caller invariant
        // (`snapshot_height % voting_length == 0`), not a runtime
        // guard. See the docstring "Caller invariant NOT
        // runtime-enforced" section: enforcing it here would
        // conflict with the reopen-time voted-params reconcile
        // walk (which expects rows at every `voting_length`
        // multiple from `chain_floor` to `tip`). The Phase 5
        // boot-consistency check (with full chain_state +
        // chain_index context) is the right home.
        //
        // 1a. Refuse `snapshot_height == 0` — a snapshot at
        // GenesisHeight is meaningless (there's no pre-bootstrap
        // state to jump past) and the resulting in-memory state
        // would have `best_full_block_height == 0` while AVL /
        // CHAIN_STATE_META rows AND the Mode 2 trust sentinel
        // would be committed. Both bootstrap guards
        // (`install_snapshot_state`'s `best_full > 0` check and
        // `apply_popow_proof`'s reciprocal one) would still see
        // the store as fresh, so a misordered second writer could
        // overwrite the just-installed state. Scala never targets
        // a snapshot at height 0 (snapshots land on epoch
        // boundaries, the first being at 1024 testnet / 52224
        // mainnet), so this is a defensive guard that closes the
        // half-installed-fresh-DB hole the reciprocal guards alone
        // do not catch.
        if snapshot_height == 0 {
            return Err(StateError::InstallSnapshotAtGenesisRefused);
        }

        // 1b. Refuse if headers up to `snapshot_height` have not
        // been validated and indexed yet. Production Mode 4
        // always runs header sync (NiPoPoW prefix or Mode 2's
        // full header download) BEFORE install — this runtime
        // guard hardens what was previously a docstring-only
        // precondition and prevents an orchestration bug from
        // persisting `best_full_block_height > best_header_height`.
        if snapshot_height > self.chain_state.best_header_height {
            return Err(StateError::InstallSnapshotPreconditionUnmet {
                snapshot_height,
                best_header_height: self.chain_state.best_header_height,
            });
        }

        // 1c. Cross-check `canonical_header_id` against the
        // locally indexed canonical at `snapshot_height`. Use
        // `HEADERS_BY_HEIGHT` slot 0 (covers BOTH the sparse
        // prefix and the dense suffix written by
        // `apply_popow_proof`) rather than `HEADER_CHAIN_INDEX`
        // (dense-suffix only in PoPowSparse mode — see
        // `popow_cache.rs` where prefix headers go to
        // HEADERS_BY_HEIGHT but NOT to HEADER_CHAIN_INDEX). A
        // real Mode 4 anchor at the last epoch boundary is
        // typically deep enough to fall in the sparse prefix, so
        // cross-checking against HEADER_CHAIN_INDEX would falsely
        // reject valid bootstrap anchors.
        let indexed_ids = self.header_ids_at_height_all(snapshot_height)?;
        match indexed_ids.first() {
            Some(id) if *id == canonical_header_id => {}
            Some(id) => {
                return Err(StateError::InstallSnapshotHeaderIdMismatch {
                    snapshot_height,
                    caller_id: hex::encode(canonical_header_id),
                    indexed_id: hex::encode(id),
                });
            }
            None => {
                return Err(StateError::InstallSnapshotHeaderNotIndexed { snapshot_height });
            }
        }

        // 2. Defense-in-depth root check.
        let expected_root_prefix: [u8; 32] = expected_state_root.as_bytes()[..32]
            .try_into()
            .expect("ADDigest prefix is always 32 bytes");
        if reconstructed.root_label.as_bytes() != &expected_root_prefix {
            return Err(StateError::InstallSnapshotRootMismatch {
                computed: hex::encode(reconstructed.root_label.as_bytes()),
                expected: hex::encode(expected_root_prefix),
            });
        }

        // 3. Atomic write. Stage the new ChainStateMeta into a
        // local; do NOT mutate `self.chain_state` until after the
        // write_txn commits. If any fallible step inside the txn
        // returns Err, redb rolls back the disk state and we leave
        // RAM untouched — `self.chain_state` continues to reflect
        // the on-disk truth.
        let write_txn = crate::begin_write_qr(&self.db)?;
        let mut new_cs = self.chain_state.to_persisted();
        new_cs.best_full_block_id = canonical_header_id;
        new_cs.best_full_block_height = snapshot_height;
        {
            let mut avl_table = write_txn.open_table(AVL_NODES)?;
            for (idx, rec_node) in reconstructed.nodes.iter().enumerate() {
                let avl_node = reconstructed_to_avl(rec_node);
                avl_table.insert(idx as u64, node_to_bytes(&avl_node).as_slice())?;
            }

            // StateMeta.root_digest is the 33-byte ADDigest:
            // 32-byte root label + 1-byte tree-height suffix.
            // Reproduce that layout from the reconstructed root.
            let mut root_digest = [0u8; 33];
            root_digest[..32].copy_from_slice(reconstructed.root_label.as_bytes());
            root_digest[32] = reconstructed.tree_height;
            let meta = StateMeta {
                height: snapshot_height,
                tree_height: reconstructed.tree_height,
                root_digest,
                root_node_id: 0,
            };
            let mut meta_table = write_txn.open_table(STATE_META)?;
            meta_table.insert("root", meta.serialize().as_slice())?;
            meta_table.insert(NODE_FORMAT_VERSION_KEY, NODE_FORMAT_V2)?;
            // Persistent UTXO-bootstrap provenance marker. One
            // byte, never cleared. Distinguishes a true Mode 2
            // install from a Mode 3 archive-then-pruned restart
            // for /api/v1/identity projection downstream.
            meta_table.insert(UTXO_BOOTSTRAP_INSTALLED_V1_KEY, &[1u8][..])?;

            // Persist the staged chain_state. Headers up to
            // `snapshot_height` have already been validated and
            // indexed by the running node (2g's trust check
            // pre-condition), so only the full-block pointers move.
            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert("chain_state", new_cs.serialize().as_slice())?;
            // CHAIN_INDEX anchor at the snapshot height. Without
            // this, a later rollback whose target is the snapshot
            // height itself (legal under the Phase 4 sentinel
            // boundary: rollback to `sentinel - 1 = snapshot_height`
            // is the lowest permitted target since wallet replay
            // walks `target + 1 ..= from`) reads CHAIN_INDEX[H] as
            // None and fails with `NoCommittedState`. Installing
            // the anchor here makes CHAIN_INDEX coverage start at
            // the snapshot boundary so reorg-to-snapshot resolves
            // through the normal path instead of forcing
            // `rebuild_from_committed`. The header id matches the
            // `canonical_header_id` we just cross-checked against
            // `HEADERS_BY_HEIGHT` slot 0 in step 1c above.
            let mut chain_table = write_txn.open_table(CHAIN_INDEX)?;
            chain_table.insert(snapshot_height as u64, canonical_header_id.as_slice())?;
        }
        // Arm the one-shot Mode 2 install trust claim, co-committed
        // with the chain_state update above. Reuses the same
        // sentinel-write primitive the test-only `arm_*_for_test`
        // helper calls, so an encoding drift fails both paths.
        open::write_mode2_trust_sentinel(&write_txn)?;
        // Mode 3 Phase 1b — co-commit the prune low-water mark
        // at `snapshot_height + 1` (the first not-pre-bootstrap
        // height). Writing here is the only point in the DB's
        // lifetime where `snapshot_height` is unambiguously
        // available; deferring to a post-install derivation
        // would lie about the boundary once forward apply
        // advances `best_full_block_height`. Max-style via
        // `advance_minimal_full_block_height_in_txn`, so a prior
        // `apply_popow_proof` having seeded the sentinel higher
        // (e.g. higher `dense_from_height`) is a silent no-op
        // rather than a transaction abort.
        Self::advance_minimal_full_block_height_in_txn(
            &write_txn,
            snapshot_height.saturating_add(1),
        )?;
        write_txn.commit()?;
        // Only after the atomic commit succeeds may we promote
        // the staged in-memory state. A failure above leaves the
        // store observably unchanged.
        self.chain_state = ChainState::from_persisted(&new_cs);
        self.mode2_trust_first_epoch = true;

        // 4. Rebuild the in-memory tree so subsequent reads find
        // the new nodes via the arena. Cache capacity matches the
        // existing one — no reason to reset it.
        let cache_bytes = self.tree.arena_cache_capacity_bytes();
        let arena = Box::new(crate::avl::arena::CachedDiskArena::new(
            Arc::clone(&self.db),
            cache_bytes,
        ));
        let new_tree = AvlTree::new_with_arena(
            arena,
            0,
            reconstructed.tree_height,
            reconstructed.nodes.len() as u64,
            reconstructed.root_label,
        );
        self.tree = new_tree;

        Ok(())
    }

    /// Build a serve-ready snapshot at the current
    /// `best_full_block_height`. Returns a
    /// [`crate::avl::snapshot_codec::SnapshotServer`] holding the
    /// manifest, chunks, and the (height, manifest_id) pair to
    /// advertise via `SnapshotsInfo`.
    ///
    /// Walks the full AVL+ tree — `O(N)` in tree size — so callers
    /// should only invoke this when:
    /// 1. The tip is at a Scala-aligned snapshot boundary
    ///    (`best_full_block_height % SNAPSHOT_EVERY == 0`), AND
    /// 2. We don't already have a snapshot cached at this height.
    ///
    /// Mainnet uses `manifest_depth = 14`
    /// ([`crate::avl::snapshot_codec::MAINNET_MANIFEST_DEPTH`]).
    pub fn build_snapshot_at_tip(
        &self,
        manifest_depth: u8,
    ) -> Result<crate::avl::snapshot_codec::SnapshotServer, StateError> {
        let height = self.chain_state.best_full_block_height;
        crate::avl::snapshot_codec::SnapshotServer::build(&self.tree, height, manifest_depth)
    }

    /// Returns `(reachable_node_count, arena_size, tree_height)` for
    /// AVL-shape regression tests. Not consensus state. Gated behind
    /// `test-helpers` so production downstream consumers cannot reach
    /// it; integration tests under `<crate>/tests/*.rs` enable the
    /// feature explicitly.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn debug_tree_stats(&self) -> (usize, usize, u8) {
        (
            self.tree.reachable_node_count(),
            self.tree.arena_size(),
            self.tree.tree_height(),
        )
    }

    /// Lookup a box by box_id. Returns serialized box bytes.
    pub fn get_box_bytes(&self, box_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.tree.lookup(box_id)
    }

    /// Lookup a box by box_id and deserialize to ErgoBox.
    pub fn get_box(
        &self,
        box_id: &ergo_primitives::digest::Digest32,
    ) -> Option<ergo_ser::ergo_box::ErgoBox> {
        let bytes = self.tree.lookup(box_id.as_bytes())?;
        let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
        ergo_ser::ergo_box::read_ergo_box(&mut r).ok()
    }

    // ---- Chain-level storage ----

    /// Current chain state (best-header and best-full-block pointers).
    pub fn chain_state(&self) -> &ChainState {
        &self.chain_state
    }

    /// Peek the data_dir's recorded `state_type` sentinel without
    /// running migrations or recovery. Returns `Ok(None)` if the dir
    /// is fresh or pre-sentinel; `Ok(Some(s))` if a sentinel was
    /// written by a prior init.
    ///
    /// Intended for use as an *early* gate in node startup, called
    /// before `open_with_cache` so a mode mismatch refuses BEFORE
    /// any of the open-time migrations (`backfill_header_chain_index_if_needed`,
    /// `reconcile_voted_params`, codec migrations) get a chance to
    /// mutate an incompatible data dir.
    pub fn peek_state_type(path: &Path) -> Result<Option<String>, StateError> {
        // Open the DB read-only — no migrations, no recovery, just
        // a single read txn on CHAIN_STATE_META. The DB is dropped
        // before this function returns.
        let db = Database::builder().create(path)?;
        let read_txn = db.begin_read()?;
        let sentinel = match read_txn.open_table(CHAIN_STATE_META) {
            Ok(table) => table
                .get(DATA_DIR_STATE_TYPE_KEY)?
                .map(|g| String::from_utf8_lossy(g.value()).to_string()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(sentinel)
    }

    /// Verify the data directory's `state_type` sentinel matches
    /// `expected_state_type`, or stamp the sentinel on first init /
    /// legacy migration. Called by `ergo-node` *after* `open` /
    /// `open_with_cache` to write the sentinel for fresh dirs. The
    /// load-bearing refusal for mode mismatches happens in
    /// `peek_state_type` *before* open; this function is the
    /// post-open "stamp it" step.
    ///
    /// Accepted values (one per on-disk schema):
    /// - `"utxo"` — `StateStore` with UTXO storage in active use
    ///   (`apply_block` runs). Modes 1, 2, 3.
    /// - `"digest"` — same `StateStore` schema but headers-only
    ///   (Mode 6). `apply_block` is never invoked, no UTXO mutations,
    ///   `best_full_block_height` stays at 0.
    /// - `"digest-verifier"` — `DigestStateStore`, a distinct schema
    ///   (digest + chain-state history ledgers, no AVL+ arena).
    ///   Mode 5. Stamped by `DigestStateStore::open`, not this
    ///   method; named here so the value space is documented in one
    ///   place. Kept separate from `"digest"` because the two
    ///   schemas are not interconvertible in place.
    ///
    /// Semantics:
    /// - Fresh dir (no sentinel + no AVL+ rows) → stamp `expected`.
    /// - Legacy dir (no sentinel + has AVL+ rows) → infer `"utxo"`
    ///   (every pre-sentinel DB is an archive). Refuse if `expected`
    ///   isn't `"utxo"`.
    /// - Sentinel present → must equal `expected`; refuse otherwise.
    ///
    /// Mode 3 (pruning) and Mode 2 (UTXO snapshot bootstrap) both
    /// stay under `"utxo"` — the operator's *operational* mode
    /// (archive/pruned/bootstrap) is config-only; the sentinel tracks
    /// which on-disk schema is being maintained.
    pub fn verify_or_init_state_type(&self, expected_state_type: &str) -> Result<(), StateError> {
        verify_or_init_state_type_inner(&self.db, expected_state_type)
    }

    /// Cheap, cloneable read handle for concurrent readers (e.g. the API
    /// task). Reads do not see batch-buffered writes; see
    /// [`crate::reader::ChainStoreReader`] for the exact contract.
    pub fn reader_handle(&self) -> crate::reader::ChainStoreReader {
        crate::reader::ChainStoreReader::new(self.db.clone())
    }

    /// Resolve the wallet's EIP-3 first-address pubkey as the miner reward
    /// key. Narrow read seam for the mining subsystem (which holds `&StateStore`
    /// but should not touch redb / wallet-table plumbing directly). A failure
    /// to even open a read transaction maps to `Corrupt` — consistent with the
    /// resolver's rule that only true table absence/emptiness is `Pending`.
    /// See [`crate::wallet::reader::WalletReader::resolve_eip3_reward_key`].
    pub fn resolve_eip3_reward_key(&self) -> crate::wallet::reader::RewardKeyResolution {
        match self.db.begin_read() {
            Ok(read_txn) => {
                crate::wallet::reader::WalletReader::new(&read_txn).resolve_eip3_reward_key()
            }
            Err(_) => crate::wallet::reader::RewardKeyResolution::Corrupt,
        }
    }

    /// Active protocol parameters for the given height: the row in
    /// `voted_params` with `key <= height`. After `StateStore::open`'s
    /// reconcile path, the genesis row at key 0 is always present, so
    /// this returns `Ok(None)` only if the table is empty (which open
    /// disallows). Callers can therefore treat `Ok(None)` as a bug.
    ///
    /// Used by the snapshot builder to populate `/info.parameters`
    /// with the active set at the current full-block tip.
    pub fn active_params_at(
        &self,
        height: u32,
    ) -> Result<Option<ergo_validation::ActiveProtocolParameters>, StateError> {
        let r = self.db.begin_read()?;
        Ok(crate::active_params::read_latest_at(&r, height)?)
    }

    /// Store a validated header by its ID.
    ///
    /// Also tags `MODIFIER_TYPE_INDEX[header_id] = 101` (Scala
    /// `Header.modifierTypeId`) so `/blocks/modifier/{id}` can dispatch
    /// from id alone without re-parsing the value.
    ///
    /// Mode 3 wire-up: parses the header to derive its 3 expected
    /// section ids (`Blake2b256(type ++ headerId ++ root)` for
    /// ADProofs / BlockTransactions / Extension) and writes the
    /// matching `SECTION_HEIGHT_INDEX[section_id] = header.height`
    /// rows in the same write_txn. The serve gate in Phase 3a
    /// reads these heights to decide allow/deny against the
    /// prune sentinel. A malformed `header_bytes` skips the
    /// section-id derivation (the existing back-fill walk
    /// catches up legacy / failed-parse cases).
    pub fn store_header(
        &self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
    ) -> Result<(), StateError> {
        self.headers.store_header(header_id, header_bytes)
    }

    /// Mode 3 — whether the `SECTION_HEIGHT_BACKFILL_DONE_V1`
    /// sentinel is stamped. Boot uses this to fail-closed when
    /// `blocks_to_keep > 0` and the index is incomplete: serve
    /// gating then cannot distinguish "pruned" from "un-indexed
    /// legacy", and silent classification of valid archive data
    /// as "pruned" is the wrong behavior. Phase 4 wires the
    /// activation-time check; Phase 1a delivers the accessor +
    /// the error variant in `StateError::SectionHeightBackfillRequired`.
    pub fn section_height_backfill_complete(&self) -> Result<bool, StateError> {
        let r = self.db.begin_read()?;
        match r.open_table(STATE_META) {
            Ok(meta) => match meta.get(SECTION_HEIGHT_BACKFILL_DONE_V1)? {
                Some(guard) => Ok(guard.value() == SECTION_HEIGHT_BACKFILL_DONE_VAL),
                None => Ok(false),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Mode 3 — verify that the two derived indexes the Phase 3a
    /// gates depend on are actually complete, not just
    /// sentinel-stamped. The backfill sentinels prove "the walk
    /// finished" but cannot detect post-walk row deletion or
    /// data-dir tampering. Called from boot in sentinel-active
    /// mode so a partially-populated index fails loud instead of
    /// silently black-holing above-sentinel section traffic.
    ///
    /// Returns `Ok(())` when:
    ///   * HEADERS_BY_HEIGHT row count >= the count of distinct
    ///     heights in HEADER_META (the table holds one row per
    ///     height, possibly with multiple ids in the payload);
    ///   * SECTION_HEIGHT_INDEX row count >= 3 × number of headers
    ///     in HEADER_META (three section ids per header).
    ///
    /// Returns `DbCorruption` otherwise. Walks HEADER_META once
    /// (~60 MB scan on mainnet) — bounded one-time boot cost,
    /// not per-request.
    pub fn verify_height_indexes_completeness(&self) -> Result<(), StateError> {
        use ergo_ser::modifier_id::{
            compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
        };
        let r = self.db.begin_read()?;
        let header_meta = match r.open_table(HEADER_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                // Sentinel-active stores must have HEADER_META —
                // the sentinel-> 1 transition only happens after
                // a bootstrap writer or eviction, both of which
                // require at least one header. An empty
                // HEADER_META with `sentinel > 1` means
                // catastrophic corruption.
                let sentinel = self.read_minimal_full_block_height()?;
                if sentinel > 1 {
                    return Err(StateError::DbCorruption {
                        table: "header_meta",
                        key: String::new(),
                        reason: format!("HEADER_META table missing despite sentinel = {sentinel}"),
                    });
                }
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        let headers_table = r.open_table(HEADERS)?;
        let height_index = match r.open_table(HEADERS_BY_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Err(StateError::DbCorruption {
                    table: "headers_by_height",
                    key: String::new(),
                    reason: "HEADERS_BY_HEIGHT table missing despite sentinel-active boot".into(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        let section_index = match r.open_table(SECTION_HEIGHT_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Err(StateError::DbCorruption {
                    table: "section_height_index",
                    key: String::new(),
                    reason: "SECTION_HEIGHT_INDEX table missing despite sentinel-active boot"
                        .into(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        use crate::chain::HeaderMeta;
        // Per-height presence check: for each HEADER_META entry,
        // confirm HEADERS_BY_HEIGHT has a row at that height AND
        // the id is present in the row. Then derive the three
        // section ids from the header bytes and confirm each has
        // a SECTION_HEIGHT_INDEX row mapping to the expected
        // height. This catches "equal cardinality but wrong
        // coverage" corruption — a stale row at one height masks
        // a missing row at another, yet a per-id check still
        // fails.
        for entry in header_meta.iter()? {
            let (k, v) = entry?;
            let header_id_bytes = k.value();
            if header_id_bytes.len() != 32 {
                return Err(StateError::DbCorruption {
                    table: "header_meta",
                    key: hex::encode(header_id_bytes),
                    reason: format!(
                        "HEADER_META key has unexpected length {}",
                        header_id_bytes.len()
                    ),
                });
            }
            let mut header_id = [0u8; 32];
            header_id.copy_from_slice(header_id_bytes);
            let meta =
                HeaderMeta::deserialize(v.value()).map_err(|e| StateError::DbCorruption {
                    table: "header_meta",
                    key: hex::encode(header_id),
                    reason: format!("HeaderMeta decode failed: {e}"),
                })?;
            // HEADERS_BY_HEIGHT — the row for this height must
            // contain our id (concatenated 32-byte ids).
            let height_row =
                height_index
                    .get(meta.height as u64)?
                    .ok_or_else(|| StateError::DbCorruption {
                        table: "headers_by_height",
                        key: meta.height.to_string(),
                        reason: format!(
                            "HEADERS_BY_HEIGHT[{}] missing despite HEADER_META row for id {}",
                            meta.height,
                            hex::encode(header_id),
                        ),
                    })?;
            let bytes = height_row.value();
            // Row-length integrity: HEADERS_BY_HEIGHT rows are
            // concatenated 32-byte ids. A non-multiple-of-32
            // payload is a corruption that the eviction parser
            // would also reject — fail loud here so it surfaces
            // at boot rather than at the first prune.
            if !bytes.len().is_multiple_of(32) {
                return Err(StateError::DbCorruption {
                    table: "headers_by_height",
                    key: meta.height.to_string(),
                    reason: format!(
                        "HEADERS_BY_HEIGHT[{}] payload length {} is not a multiple of 32",
                        meta.height,
                        bytes.len(),
                    ),
                });
            }
            let mut found = false;
            for chunk in bytes.chunks_exact(32) {
                if chunk == header_id {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(StateError::DbCorruption {
                    table: "headers_by_height",
                    key: meta.height.to_string(),
                    reason: format!(
                        "HEADERS_BY_HEIGHT[{}] does not contain id {} present in HEADER_META",
                        meta.height,
                        hex::encode(header_id),
                    ),
                });
            }
            // SECTION_HEIGHT_INDEX — derive the three section
            // ids and confirm each is mapped to this header's
            // height. We need the header bytes to extract the
            // three roots.
            let header_bytes_opt = headers_table.get(header_id.as_slice())?;
            let Some(header_bytes_guard) = header_bytes_opt else {
                return Err(StateError::DbCorruption {
                    table: "headers",
                    key: hex::encode(header_id),
                    reason: "HEADERS row missing despite HEADER_META row".into(),
                });
            };
            let header_bytes = header_bytes_guard.value();
            let mut rdr = ergo_primitives::reader::VlqReader::new(header_bytes);
            let header =
                ergo_ser::header::read_header(&mut rdr).map_err(|e| StateError::DbCorruption {
                    table: "headers",
                    key: hex::encode(header_id),
                    reason: format!("header bytes failed to parse: {e:?}"),
                })?;
            for (type_byte, root) in [
                (TYPE_AD_PROOFS, header.ad_proofs_root.as_bytes()),
                (TYPE_BLOCK_TRANSACTIONS, header.transactions_root.as_bytes()),
                (TYPE_EXTENSION, header.extension_root.as_bytes()),
            ] {
                let section_id = compute_section_id(type_byte, &header_id, root);
                let recorded = section_index.get(section_id.as_slice())?.map(|g| g.value());
                match recorded {
                    Some(h) if h == meta.height => {}
                    Some(h) => {
                        return Err(StateError::DbCorruption {
                            table: "section_height_index",
                            key: hex::encode(section_id),
                            reason: format!(
                                "SECTION_HEIGHT_INDEX[section_id] = {h}, expected {} \
                                 (header_id={}, type=0x{type_byte:02x})",
                                meta.height,
                                hex::encode(header_id),
                            ),
                        });
                    }
                    None => {
                        return Err(StateError::DbCorruption {
                            table: "section_height_index",
                            key: hex::encode(section_id),
                            reason: format!(
                                "SECTION_HEIGHT_INDEX missing entry for section_id derived from \
                                 header_id={} at height {} (type=0x{type_byte:02x})",
                                hex::encode(header_id),
                                meta.height,
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Mode 3 — look up a section's parent-header height via the
    /// `SECTION_HEIGHT_INDEX`. Returns `None` for sections with no
    /// row (not-yet-indexed legacy + never-seen ids alike — the
    /// serve gate in Phase 3a treats both as fail-closed deny).
    ///
    /// Drains the persist pipeline first so async commit failures
    /// surface as `PersistFailed` rather than silently classifying
    /// the section as "unknown" — same shape `get_block_section`
    /// uses.
    pub fn get_section_height(&self, section_id: &[u8; 32]) -> Result<Option<u32>, StateError> {
        self.drain_persist_results()?;
        self.headers.get_section_height(section_id)
    }

    /// Set the Mode 3 retention window. Production boot wires this
    /// from `[node] blocks_to_keep` in `ergo-node/src/node/boot.rs`
    /// IMMEDIATELY after `StateStore::open_with_cache_launch_voting`
    /// and BEFORE `enable_persist_pipeline` (the pipeline worker
    /// captures the value at spawn time, so a later call wouldn't
    /// reach the pipeline path). Tests call it directly.
    ///
    /// Semantics: `-1` = archive (no pruning), `0` = canonical
    /// Mode 6 (headers-only; never prunes because there are no
    /// full-block applies to drive the sentinel), `> 0` = suffix
    /// window of N blocks. Phase 4's config-load gate enforces
    /// `>= ROLLBACK_WINDOW + SAFETY_MARGIN` so the rollback
    /// reorg-resolver can never need a pruned block.
    pub fn set_blocks_to_keep(&mut self, blocks_to_keep: i32) {
        self.blocks_to_keep = blocks_to_keep;
    }

    /// Override the undo-retention window captured at `open`
    /// ([`ROLLBACK_WINDOW`]). Boot wires this from `[node] keep_versions`
    /// BEFORE the persist pipeline spawns, mirroring `set_blocks_to_keep`;
    /// config load rejects `0` (a store that can never roll back), so the
    /// value here is always >= 1. Prospective only: undo entries already
    /// pruned by a smaller previous window stay gone.
    pub fn set_rollback_window(&mut self, window: u32) {
        self.rollback_window = window;
    }

    /// The undo-retention window (max serviceable reorg depth).
    pub fn rollback_window(&self) -> u32 {
        self.rollback_window
    }

    /// Override the difficulty schedule captured at `open` (mainnet
    /// default). Boot calls this with `chain_spec.difficulty` BEFORE
    /// any prove path runs, mirroring `set_blocks_to_keep`.
    pub fn set_difficulty_params(&mut self, params: ergo_chain_spec::DifficultyParams) {
        self.difficulty_params = params;
    }

    /// The difficulty schedule the NiPoPoW prover uses.
    pub fn difficulty_params(&self) -> &ergo_chain_spec::DifficultyParams {
        &self.difficulty_params
    }

    /// Read the current `blocks_to_keep` setting. Returns `-1`
    /// for stores that haven't had it set (the archive default).
    pub fn blocks_to_keep(&self) -> i32 {
        self.blocks_to_keep
    }

    /// Mode 3 prune low-water mark. Returns `1` (GenesisHeight)
    /// on archive / fresh / pre-init DBs; bootstrap writers and
    /// the apply / eviction seam advance it via
    /// `advance_minimal_full_block_height_in_txn`.
    pub fn read_minimal_full_block_height(&self) -> Result<u32, StateError> {
        Ok(self.try_read_minimal_full_block_height_raw()?.unwrap_or(1))
    }

    /// Distinguishing peek: `Ok(None)` when the row is absent
    /// (never written), `Ok(Some(v))` when the row is present at
    /// `v`. Operators and tests that need to differentiate
    /// "never written" from "written and at default" use this;
    /// the serve gate uses `read_minimal_full_block_height`,
    /// which collapses both to `1`.
    pub fn try_read_minimal_full_block_height_raw(&self) -> Result<Option<u32>, StateError> {
        let r = self.db.begin_read()?;
        match r.open_table(STATE_META) {
            Ok(meta) => match meta.get(MINIMAL_FULL_BLOCK_HEIGHT_KEY)? {
                Some(guard) => {
                    let bytes = guard.value();
                    if bytes.len() != 4 {
                        return Err(StateError::DbCorruption {
                            table: "state_meta",
                            key: hex::encode(MINIMAL_FULL_BLOCK_HEIGHT_KEY.as_bytes()),
                            reason: format!(
                                "minimal_full_block_height payload has unexpected length: {}",
                                bytes.len()
                            ),
                        });
                    }
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(bytes);
                    Ok(Some(u32::from_le_bytes(buf)))
                }
                None => Ok(None),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Mode 3 — walk `HEADERS_BY_HEIGHT[height]` (every header id
    /// at the height, not just the best-chain one), parse each
    /// header to recover its three section ids, and delete the
    /// matching rows from `BLOCK_SECTIONS` + `SECTION_HEIGHT_INDEX`.
    /// Returns the count of deleted section ids for logging /
    /// tests.
    ///
    /// Orphan-header coverage is deliberate: a sub-sentinel
    /// orphan whose section bytes still exist would let an `Inv`
    /// request return a hit, which a pruned node must not do.
    /// Walking every height-row is the same shape Scala's
    /// `pruneBlockDataAt` uses (lines 232-237 of
    /// `FullBlockPruningProcessor.scala`).
    ///
    /// A missing `HEADERS_BY_HEIGHT` row (no headers ever indexed
    /// at this height) is `Ok(0)` — the height was never tracked,
    /// so there's nothing to evict and no inconsistency to flag.
    ///
    /// A header_id present in `HEADERS_BY_HEIGHT` but missing
    /// from `HEADERS`, or with header bytes that fail to parse,
    /// returns `StateError::DbCorruption`. The two tables are
    /// jointly maintained by the apply / popow / store_header
    /// writers; an inconsistency here means the section bytes
    /// for this header_id cannot be reached for deletion, and
    /// advancing the sentinel while leaving the rows in place
    /// would let the serve gate lie about availability.
    /// Failing the whole eviction txn (and therefore the
    /// surrounding apply) is the right behavior — it aborts the
    /// chain advance until the operator investigates.
    pub(crate) fn delete_block_sections_at_height_in_txn(
        write_txn: &redb::WriteTransaction,
        height: u32,
    ) -> Result<u32, StateError> {
        use ergo_ser::modifier_id::{
            compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
        };
        // 1. Collect header ids at the height.
        let header_ids: Vec<[u8; 32]> = {
            let idx = match write_txn.open_table(HEADERS_BY_HEIGHT) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
                Err(e) => return Err(e.into()),
            };
            read_height_index_ids(&idx, height)?
        };
        if header_ids.is_empty() {
            return Ok(0);
        }
        // 2. For each header id, parse + derive 3 section ids.
        // Inconsistency between HEADERS_BY_HEIGHT and HEADERS is
        // a hard failure: we cannot compute the section ids to
        // delete, and advancing the sentinel without deleting
        // them would corrupt the serve gate.
        let mut section_ids: Vec<[u8; 32]> = Vec::with_capacity(header_ids.len() * 3);
        {
            let headers = write_txn.open_table(HEADERS)?;
            for id in &header_ids {
                let bytes_opt = headers.get(id.as_slice())?.map(|g| g.value().to_vec());
                let Some(bytes) = bytes_opt else {
                    return Err(StateError::DbCorruption {
                        table: "headers",
                        key: hex::encode(id.as_slice()),
                        reason: format!(
                            "delete_block_sections_at_height_in_txn(h={height}): \
                             header_id indexed in HEADERS_BY_HEIGHT but missing from HEADERS"
                        ),
                    });
                };
                let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
                let header = ergo_ser::header::read_header(&mut r).map_err(|e| {
                    StateError::DbCorruption {
                        table: "headers",
                        key: hex::encode(id.as_slice()),
                        reason: format!(
                            "delete_block_sections_at_height_in_txn(h={height}): \
                             header bytes failed to parse ({e:?})"
                        ),
                    }
                })?;
                for (type_byte, root) in [
                    (TYPE_AD_PROOFS, header.ad_proofs_root.as_bytes()),
                    (TYPE_BLOCK_TRANSACTIONS, header.transactions_root.as_bytes()),
                    (TYPE_EXTENSION, header.extension_root.as_bytes()),
                ] {
                    section_ids.push(compute_section_id(type_byte, id, root));
                }
            }
        }
        // 3. Delete the section bytes from BLOCK_SECTIONS but
        // KEEP the SECTION_HEIGHT_INDEX rows as tombstones. The
        // Phase 3a/3b guards (receive, storage, serve) look up
        // `get_section_height(id)` to decide whether a section is
        // sub-sentinel; if eviction deleted the index row, a late
        // / malicious re-delivery would resolve to `None` and
        // fail-OPEN past the storage guard, breaking monotonic
        // pruning. Retaining the height row (4 bytes per section
        // id, vs the kilobytes the section itself occupies)
        // converts "unknown height" into "known sub-sentinel
        // height" for the lifetime of the store. Count freed
        // bytes (BLOCK_SECTIONS removals) so eviction telemetry
        // tracks reclaimed storage, not stale index entries.
        let mut deleted = 0u32;
        {
            let mut sections = write_txn.open_table(BLOCK_SECTIONS)?;
            for id in &section_ids {
                if sections.remove(id.as_slice())?.is_some() {
                    deleted += 1;
                }
            }
        }
        Ok(deleted)
    }

    /// Mode 3 prune low-water-mark advance — in-txn variant for
    /// the apply / eviction seam in Phase 2a/2b and the bootstrap
    /// writers (`install_snapshot_state`, `apply_popow_proof`) in
    /// Phase 1b. Reads the current sentinel from the supplied
    /// `write_txn`, takes `max(current, height)`, and writes the
    /// result inside the SAME txn. The caller's
    /// `write_txn.commit()` lifts the new sentinel + AVL / undo /
    /// chain_index / state_meta + section deletions to durable
    /// storage atomically — a crash between any of those points
    /// rolls them back together.
    ///
    /// **Max-style, NOT strict.** A `height < current` advance is
    /// a no-op (returns Ok without modifying the row), not an
    /// error. This matters for bootstrap composition: if
    /// `install_snapshot_state` writes the sentinel first
    /// (snapshot_height + 1), a later `apply_popow_proof` with a
    /// lower `dense_from_height` must not abort its entire apply
    /// — it just skips its sentinel write because the higher
    /// install value already pins the boundary. The strict
    /// monotonicity guard lives in the standalone
    /// `write_minimal_full_block_height` for tests / defensive
    /// invariant enforcement; production writers want max-style.
    pub fn advance_minimal_full_block_height_in_txn(
        write_txn: &redb::WriteTransaction,
        height: u32,
    ) -> Result<(), StateError> {
        // Read phase — scope the table handle so it drops before
        // we re-open in write phase. Absent row is distinct from
        // value-equals-default: an absent row MUST be materialized
        // by this write, even if `height` equals the read-side
        // serve default (1, GenesisHeight). Without this, a
        // bootstrap writer with `dense_from_height == 1` or
        // `snapshot_height == 0` (= snapshot_height + 1 == 1)
        // would silently no-op on a fresh DB and leave the row
        // unstamped — semantically equivalent today, but a
        // landmine for future migrations that rely on row
        // presence.
        let current: Option<u32> = {
            let meta = write_txn.open_table(STATE_META)?;
            let bytes_opt = meta
                .get(MINIMAL_FULL_BLOCK_HEIGHT_KEY)?
                .map(|g| g.value().to_vec());
            drop(meta);
            match bytes_opt {
                Some(bytes) => {
                    if bytes.len() != 4 {
                        return Err(StateError::DbCorruption {
                            table: "state_meta",
                            key: hex::encode(MINIMAL_FULL_BLOCK_HEIGHT_KEY.as_bytes()),
                            reason: format!(
                                "minimal_full_block_height payload has unexpected length: {}",
                                bytes.len()
                            ),
                        });
                    }
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&bytes);
                    Some(u32::from_le_bytes(buf))
                }
                None => None,
            }
        };
        if let Some(c) = current {
            if height <= c {
                // No-op: higher value already pinned the boundary.
                // Phase 1b dual-bootstrap composition relies on
                // this — second writer with a lower candidate
                // skips silently rather than aborting the whole
                // txn. Emit a debug signal so operators
                // investigating a stuck-sentinel ticket can
                // confirm whether a no-op fired (legitimate
                // composition vs. an unexpected pre-existing
                // higher pin that may indicate stale DB state).
                debug!(
                    current = c,
                    attempted = height,
                    "prune-sentinel advance was a no-op (current >= attempted)",
                );
                return Ok(());
            }
        }
        // Write phase — either absent row (always write) or
        // present row with `height > current` (max-style advance).
        let mut meta = write_txn.open_table(STATE_META)?;
        meta.insert(
            MINIMAL_FULL_BLOCK_HEIGHT_KEY,
            height.to_le_bytes().as_slice(),
        )?;
        Ok(())
    }

    /// Strict-monotonic standalone variant — used by tests and
    /// any caller that wants to enforce "must advance forward"
    /// as a hard invariant rather than the silent-no-op semantics
    /// of `advance_minimal_full_block_height_in_txn`. Errors with
    /// `PruneSentinelMonotonicity { current, attempted }` on
    /// backward writes.
    ///
    /// The check-then-write happens inside ONE write_txn — opening
    /// the txn, reading the current sentinel, comparing, and
    /// writing the new value are all bound to the same redb
    /// transaction. A concurrent writer that advances the sentinel
    /// between the read and the write cannot exist; redb serializes
    /// writers at the txn boundary.
    ///
    /// Production apply/eviction/bootstrap code MUST use
    /// `advance_minimal_full_block_height_in_txn` so the
    /// sentinel write co-commits with the surrounding atomic
    /// write_txn AND so dual-bootstrap composition's
    /// lower-second-writer case is silently absorbed rather than
    /// aborting the whole txn.
    pub fn write_minimal_full_block_height(&self, height: u32) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        // Read + monotonicity check + write all inside the same
        // txn so a concurrent writer cannot interleave.
        let current: u32 = {
            let meta = write_txn.open_table(STATE_META)?;
            let bytes_opt = meta
                .get(MINIMAL_FULL_BLOCK_HEIGHT_KEY)?
                .map(|g| g.value().to_vec());
            drop(meta);
            match bytes_opt {
                Some(bytes) => {
                    if bytes.len() != 4 {
                        return Err(StateError::DbCorruption {
                            table: "state_meta",
                            key: hex::encode(MINIMAL_FULL_BLOCK_HEIGHT_KEY.as_bytes()),
                            reason: format!(
                                "minimal_full_block_height payload has unexpected length: {}",
                                bytes.len()
                            ),
                        });
                    }
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&bytes);
                    u32::from_le_bytes(buf)
                }
                None => 1,
            }
        };
        if height < current {
            return Err(StateError::PruneSentinelMonotonicity {
                current,
                attempted: height,
            });
        }
        {
            let mut meta = write_txn.open_table(STATE_META)?;
            meta.insert(
                MINIMAL_FULL_BLOCK_HEIGHT_KEY,
                height.to_le_bytes().as_slice(),
            )?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve a header by its ID. Checks the batch buffer first.
    pub fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        self.headers.get_header(header_id)
    }

    /// Store a block section by its computed modifier ID.
    ///
    /// Uses `Durability::None`: the section bytes land in the redb file
    /// (and pagecache) but the commit marker is not durably written until
    /// the next higher-durability commit — which the batched persist
    /// pipeline produces every `ibd_flush_interval` blocks. This avoids
    /// the 44 fsync/sec stall the main thread was incurring at sustained
    /// 22 b/s (2 sections × ~15ms fsync each).
    ///
    /// Crash recovery: lost-but-not-yet-durable sections re-download
    /// from peers, same path as the rest of in-flight IBD state. The
    /// per-block AVL state-root verification at apply time catches any
    /// drift, so there's no path for stale section data to silently
    /// corrupt downstream state.
    ///
    /// Mode 3 gating: this entry point bypasses the prune-sentinel
    /// resurrection guard that lives on `store_block_section_typed`.
    /// Production callers (sync, coordinator, mining) MUST use
    /// `store_block_section_typed`; this variant is gated behind
    /// `test-helpers` so it is unreachable from the production build
    /// and cannot become an escape hatch around the storage
    /// invariant once pruning is live.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn store_block_section(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
    ) -> Result<(), StateError> {
        self.headers.store_block_section(modifier_id, section_bytes)
    }

    /// Store a block section AND tag its modifier type in
    /// `MODIFIER_TYPE_INDEX`. Same durability semantics as
    /// `store_block_section`. Callers that know the section type
    /// (sync / coordinator) should prefer this variant so
    /// `/blocks/modifier/{id}` can dispatch immediately on the next
    /// read without waiting for a startup back-fill pass.
    ///
    /// Mode 3 Phase 3a defense-in-depth: rejects writes whose
    /// parent header is below the current prune sentinel. The
    /// receive-side gating in `ergo-sync::executor` silently
    /// drops these before they reach the store; the storage-side
    /// guard catches the case where the executor missed
    /// (resurrection attempt via a delayed peer delivery, a
    /// rogue peer pushing directly, or an executor bug that
    /// bypassed receive gating). `SECTION_HEIGHT_INDEX` provides
    /// the height lookup that was stamped at header-store time
    /// (Phase 1a wiring) — sections whose parent we never indexed
    /// are passed through (no height to compare against; the
    /// serve gate will catch them on read if needed).
    pub fn store_block_section_typed(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
        section_type: u8,
    ) -> Result<(), StateError> {
        self.headers
            .store_block_section_typed(modifier_id, section_bytes, section_type)
    }

    /// Read the persistent UTXO-bootstrap provenance marker. Returns
    /// `true` iff `install_snapshot_state` ever committed a snapshot
    /// to this store. Distinguishes a true Mode 2 install from a
    /// Mode 3 archive-then-pruned restart at boot — used to refine
    /// the `/api/v1/identity` mode label and nothing else (storage
    /// gates fire on the sentinel, not the marker).
    pub fn was_utxo_bootstrapped(&self) -> Result<bool, StateError> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(STATE_META) {
            Ok(t) => Ok(t.get(UTXO_BOOTSTRAP_INSTALLED_V1_KEY)?.is_some()),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Arm the persistent UTXO-bootstrap marker outside of
    /// `install_snapshot_state`, for tests that need to simulate
    /// "snapshot already installed" without driving a full
    /// reconstructed-tree install through the production seam.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_arm_utxo_bootstrap_marker(&self) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(STATE_META)?;
            t.insert(UTXO_BOOTSTRAP_INSTALLED_V1_KEY, &[1u8][..])?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Test-only helper that simulates a pre-upgrade data dir: clears
    /// every `HEADERS_BY_HEIGHT` row AND the
    /// `HEADERS_BY_HEIGHT_BACKFILL_DONE_V1` sentinel, leaving
    /// `HEADERS` + `HEADER_META` + `HEADER_CHAIN_INDEX` populated.
    /// The next `back_fill_headers_by_height_index` call then runs a
    /// real scan over the existing data.
    ///
    /// Mutation surface is too small to justify a normal public
    /// helper, but the legacy-backfill code path can only be
    /// exercised via this shape, so it's gated on the
    /// `test-helpers` feature to be reachable from integration tests
    /// in `ergo-state/tests/`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn clear_headers_by_height_state_for_test(&self) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            // Drop the table outright (re-created on next open_table).
            let _ = write_txn.delete_table(HEADERS_BY_HEIGHT);
            let mut t = write_txn.open_table(STATE_META)?;
            t.remove(HEADERS_BY_HEIGHT_BACKFILL_DONE_V1)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Wipe `SECTION_HEIGHT_INDEX` while leaving HEADER_META /
    /// HEADERS_BY_HEIGHT intact, simulating the "rows missing for
    /// ids that exist in HEADER_META" corruption shape. Pairs
    /// with `clear_headers_by_height_state_for_test` so the
    /// completeness checker has negative coverage on both
    /// downstream indexes.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn clear_section_height_index_for_test(&self) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let _ = write_txn.delete_table(SECTION_HEIGHT_INDEX);
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Overwrite the `HEADERS_BY_HEIGHT` row at the given height
    /// with a payload whose length is NOT a multiple of 32 —
    /// simulating the malformed-row corruption shape that the
    /// eviction parser at `read_height_index_ids` rejects but
    /// that an unverified boot would silently miss.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn write_malformed_headers_by_height_row_for_test(
        &self,
        height: u32,
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(HEADERS_BY_HEIGHT)?;
            // 35 bytes — 32 + 3 trailing garbage — fails the
            // multiple-of-32 row-length check.
            let payload = [0xCDu8; 35];
            t.insert(height as u64, payload.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Look up the modifier-type byte for a given id.
    ///
    /// Returns `Some(101 | 102 | 104 | 108)` for tagged ids, `None` for
    /// untagged ids. Untagged means either the id is unknown or the
    /// value pre-dates the type-index back-fill.
    pub fn get_modifier_type(&self, id: &[u8; 32]) -> Result<Option<u8>, StateError> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(MODIFIER_TYPE_INDEX) {
            Ok(table) => match table.get(id.as_slice())? {
                Some(g) => Ok(Some(g.value())),
                None => Ok(None),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Retrieve a block section by its computed modifier ID.
    pub fn get_block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        self.drain_persist_results()?;
        self.headers.get_block_section(modifier_id)
    }

    /// Store header metadata (parent, height, cumulative score, validity).
    pub fn store_header_meta(
        &self,
        header_id: &[u8; 32],
        meta: &HeaderMeta,
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut table = write_txn.open_table(HEADER_META)?;
            table.insert(header_id.as_slice(), meta.serialize().as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve header metadata by header ID. Checks the batch buffer first.
    pub fn get_header_meta(&self, header_id: &[u8; 32]) -> Result<Option<HeaderMeta>, StateError> {
        self.headers.get_header_meta(header_id)
    }

    /// Look up every header id known at a given height, including
    /// fork orphans. Backs the Scala-compat `/blocks/at/{h}` route
    /// (`headerIdsAtHeight` in `HeadersProcessor.scala:274`).
    ///
    /// Returns `Ok(vec![])` when no headers are indexed at `height`.
    /// First entry is always the best-header-chain id at `height`
    /// (the [`HEADERS_BY_HEIGHT`] invariant); subsequent entries are
    /// orphans (validated headers at this height that aren't on the
    /// current best chain). Order beyond slot 0 is insertion-order
    /// of the orphan arrivals.
    pub fn header_ids_at_height_all(&self, height: u32) -> Result<Vec<[u8; 32]>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADERS_BY_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        read_height_index_ids(&table, height)
    }

    /// Look up the header_id on the best-header chain at a given height.
    pub fn get_header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        self.headers.get_header_id_at_height(height)
    }

    /// Scan `HEADER_CHAIN_INDEX` for the canonical height of a given
    /// header id, asserting Dense-mode index invariants while
    /// scanning. Returns `Ok(None)` only after a clean, fully-
    /// validated scan that found nothing.
    ///
    /// Strict contract (distinct from `get_header_id_at_height`):
    /// - `HEADER_CHAIN_INDEX` missing entirely → `DbCorruption`.
    ///   Callers use this on the prove_with_db error path which is
    ///   Dense-mode-gated above, so a missing index is corruption,
    ///   not "anchor absent".
    /// - row with value of length != 32 → `DbCorruption`. Stops the
    ///   scan instead of silently skipping a malformed row.
    /// - height key that does not fit in `u32` → `DbCorruption`.
    ///
    /// `HEADER_CHAIN_INDEX` is keyed by height, so there is no fast
    /// id → height lookup; this is a linear scan. Acceptable on
    /// error paths only — used by `prove_with_db` to distinguish
    /// caller-supplied anchor misuse from cross-table corruption
    /// when a caller-supplied id is missing from `HEADERS`.
    fn find_canonical_height_for_id(&self, target: &[u8; 32]) -> Result<Option<u32>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADER_CHAIN_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Err(StateError::DbCorruption {
                    table: "header_chain_index",
                    key: String::new(),
                    reason: "find_canonical_height_for_id: \
                             HEADER_CHAIN_INDEX table absent (Dense-mode invariant violated)"
                        .to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        for entry in table.iter()? {
            let (height_guard, id_guard) = entry?;
            let raw_height = height_guard.value();
            let height = u32::try_from(raw_height).map_err(|_| StateError::DbCorruption {
                table: "header_chain_index",
                key: hex::encode(raw_height.to_be_bytes()),
                reason: format!(
                    "find_canonical_height_for_id: height key out of u32 range: {raw_height}"
                ),
            })?;
            let id_bytes = id_guard.value();
            if id_bytes.len() != 32 {
                return Err(StateError::DbCorruption {
                    table: "header_chain_index",
                    key: hex::encode(raw_height.to_be_bytes()),
                    reason: format!(
                        "find_canonical_height_for_id: row has len {} (expected 32)",
                        id_bytes.len()
                    ),
                });
            }
            if id_bytes == target.as_slice() {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    /// Sparse-aware variant of [`Self::get_header_id_at_height`] returning
    /// a [`HeightLookup`] that distinguishes the three semantically
    /// distinct "absent" cases:
    ///
    /// * [`HeightLookup::Dense`] — a row exists in
    ///   `HEADER_CHAIN_INDEX[height]`.
    /// * [`HeightLookup::SparseGap`] — no row, AND we are in
    ///   [`HeaderAvailability::PoPowSparse`] mode AND the height falls
    ///   below `dense_from_height`. The header is canonical (the proof
    ///   established that) but not locally indexed. Callers MUST treat
    ///   this as "wait, retry" rather than "fraud" or "out of range".
    /// * [`HeightLookup::AboveTip`] — height exceeds
    ///   `best_header_height` (either mode).
    ///
    /// Callers that only need the legacy `Option<[u8; 32]>` shape
    /// (treating both gap arms as `None`) can stay on
    /// [`Self::get_header_id_at_height`]; callers where losing the
    /// `SparseGap` distinction would be unsafe (Mode 2 manifest
    /// verification, snapshot-install re-fetch, executor
    /// `load_header_index`) MUST use this one or the signal is erased
    /// at the call site.
    pub fn lookup_header_at_height(&self, height: u32) -> Result<HeightLookup, StateError> {
        if let Some(id) = self.get_header_id_at_height(height)? {
            return Ok(HeightLookup::Dense(id));
        }
        // Map `None` per current mode + height position.
        let cs = self.chain_state();
        if height > cs.best_header_height {
            return Ok(HeightLookup::AboveTip);
        }
        match cs.header_availability {
            HeaderAvailability::Dense => {
                // Dense mode AND height ≤ best_header_height AND
                // index row missing → corruption. Defensively return
                // SparseGap and log; callers should treat this as an
                // unrecoverable inconsistency. We do not panic because
                // the read path is hot and a downstream caller can
                // surface the failure with more context.
                tracing::error!(
                    height,
                    best_header_height = cs.best_header_height,
                    "HEADER_CHAIN_INDEX missing row in Dense mode — store corruption",
                );
                Ok(HeightLookup::SparseGap)
            }
            HeaderAvailability::PoPowSparse {
                dense_from_height, ..
            } => {
                if height < dense_from_height {
                    // Expected sparse-prefix gap. Not fraud.
                    Ok(HeightLookup::SparseGap)
                } else {
                    // Inside the dense range but missing — same
                    // corruption signature as the Dense arm above.
                    tracing::error!(
                        height,
                        dense_from_height,
                        best_header_height = cs.best_header_height,
                        "HEADER_CHAIN_INDEX missing row inside dense range (PoPowSparse mode)",
                    );
                    Ok(HeightLookup::SparseGap)
                }
            }
        }
    }

    /// Range-scan the best-header chain index over [lo, hi] inclusive.
    /// Returns (height, header_id) pairs in ascending height order.
    pub fn scan_header_chain_range(
        &self,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<(u32, [u8; 32])>, StateError> {
        self.headers.scan_header_chain_range(lo, hi)
    }

    /// Read the sentinel that records whether HEADER_CHAIN_INDEX has been
    /// fully backfilled. Returns Some(1) if backfill has completed successfully,
    /// None if the key is absent (pre-upgrade DB or fresh DB).
    pub fn header_chain_index_version(&self) -> Result<Option<u8>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(STATE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get("hci_version")? {
            Some(guard) => {
                let bytes = guard.value();
                // Sentinel is exactly [1]. Anything else is a malformed value
                // that we should not silently treat as "backfill ran".
                match bytes {
                    [1u8] => Ok(Some(1)),
                    other => Err(StateError::DbCorruption {
                        table: "state_meta",
                        key: hex::encode(b"hci_version"),
                        reason: format!("sentinel has unexpected payload: {:?}", other),
                    }),
                }
            }
            None => Ok(None),
        }
    }

    /// Mark a header as permanently PoW-invalid (persisted, survives restart).
    /// Returns an error if header_meta does not exist — the caller must store
    /// header_meta before marking invalidity.
    pub fn mark_pow_invalid(&self, header_id: &[u8; 32]) -> Result<(), StateError> {
        let mut meta = self.get_header_meta(header_id)?.ok_or(
            // Documented precondition: caller must store header_meta
            // before mark_pow_invalid. Missing row here is caller
            // misuse (passed an unknown / unprepared header id), not
            // persisted-state corruption — DbCorruption would
            // overstate the failure for downstream triage. The
            // operator-visible header_id is carried in the
            // surrounding tracing span.
            StateError::InvalidPrecondition {
                what: "mark_pow_invalid: caller must store header_meta first",
            },
        )?;
        meta.pow_validity = 2;
        self.store_header_meta(header_id, &meta)
    }

    /// Mark a header as session-invalid (in-memory only, cleared on restart).
    pub fn mark_session_invalid(&mut self, header_id: [u8; 32]) {
        self.chain_state.session_invalids.insert(header_id);
    }

    /// Check if a header is invalid: persistent (PoW `== 2` or full-block
    /// validation `== 3`) or session-scoped. Mirrors Scala
    /// `ErgoHistoryReader.isSemanticallyValid` returning `Invalid` for any
    /// header carrying a `validityKey -> 0` row.
    pub fn is_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
        if self.chain_state.session_invalids.contains(header_id) {
            return Ok(true);
        }
        if let Some(meta) = self.get_header_meta(header_id)? {
            return Ok(meta.pow_validity == 2 || meta.pow_validity == 3);
        }
        Ok(false)
    }

    /// Durable-only invalidity: persistent PoW (`== 2`) or full-block
    /// validation (`== 3`) flags, **excluding** the session-scoped set.
    ///
    /// The hereditary parent-invalid guard in header processing must use this,
    /// not [`Self::is_invalid`]: a session mark is a transient/IO verdict (a
    /// block that may yet apply), so treating it as a permanent parent flag
    /// would let one transient failure block the entire descendant subtree for
    /// the session. Scala's parent check tests `isSemanticallyValid == Invalid`
    /// — the durable `validityKey -> 0` row — which corresponds to `2 | 3` here.
    pub fn is_durably_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
        if let Some(meta) = self.get_header_meta(header_id)? {
            return Ok(meta.pow_validity == 2 || meta.pow_validity == 3);
        }
        Ok(false)
    }

    /// Persistently invalidate a header that failed **full-block validation**
    /// and every stored descendant header, then re-anchor the best-header
    /// pointer down to the highest surviving header. Returns the full set of
    /// invalidated ids (inclusive of `header_id`) so the caller can evict them
    /// from any in-flight download queue.
    ///
    /// Scala parity: `ErgoHistory.reportModifierIsInvalid`
    /// (ErgoHistory.scala:122). Scala computes
    /// `continuationHeaderChains(invalidatedHeader, _ => true).flatten.distinct`
    /// — the invalidated header plus every header reachable forward from it —
    /// writes `validityKey(id) -> 0` for each (durable), and re-points
    /// `BestHeaderKey` via `loopHeightDown(headersHeight, !invalidatedIds.contains)`.
    /// A single rejection on live testnet invalidated ~3,100 descendant
    /// headers ("Going to invalidate <id> and Array(...)").
    ///
    /// This is the reject-valid-liveness half only: it does NOT roll UTXO
    /// state back, because on this failure path committed state already sits
    /// at the failing block's parent (the block never applied). `best_full_*`
    /// therefore already points at the branch point and is left untouched;
    /// only `best_header_*` re-anchors, which restores the mining gate's
    /// `headers == full` equality at the surviving tip.
    ///
    /// Reserved for definitive validation verdicts. Callers must NOT route
    /// transient/IO failures here (see `mark_session_invalid`).
    pub fn invalidate_validation_branch(
        &mut self,
        header_id: [u8; 32],
    ) -> Result<Vec<[u8; 32]>, StateError> {
        let start_meta = self.get_header_meta(&header_id)?.ok_or(
            // Same precondition as mark_pow_invalid: the header meta must
            // exist before we can flag it. A missing row is caller misuse,
            // not corruption.
            StateError::InvalidPrecondition {
                what: "invalidate_validation_branch: caller must store header_meta first",
            },
        )?;

        // Phase 1: collect the invalidated set = start header + every stored
        // descendant, walking height by height and following parent links.
        // `header_ids_at_height_all` returns canonical + orphan ids at each
        // height, so fork descendants are captured too (Scala's
        // continuationHeaderChains explores all forward branches).
        let mut invalid_set: HashSet<[u8; 32]> = HashSet::new();
        invalid_set.insert(header_id);
        let mut invalidated: Vec<[u8; 32]> = vec![header_id];
        let top = self.chain_state.best_header_height;
        let mut h = start_meta.height + 1;
        // Walk until a height yields no further descendants — NOT bounded by
        // `best_header_height`. A stored competing branch can extend above the
        // current best tip (more blocks, less work), and every stored
        // descendant of the failing header must be flagged or it could re-grow
        // best_header on restart. The `added_any` gap check is the terminator;
        // `header_ids_at_height_all` returns empty once heights run out, so the
        // loop always ends. `top` is retained only for `loop_best_header_down`.
        loop {
            let mut added_any = false;
            for id in self.header_ids_at_height_all(h)? {
                if invalid_set.contains(&id) {
                    continue;
                }
                if let Some(meta) = self.get_header_meta(&id)? {
                    if invalid_set.contains(&meta.parent_id) {
                        invalid_set.insert(id);
                        invalidated.push(id);
                        added_any = true;
                    }
                }
            }
            if !added_any {
                break;
            }
            h += 1;
        }

        // Phase 2: durably flag every invalidated header (pow_validity = 3),
        // then re-anchor best_header — both in one write transaction so a
        // crash mid-invalidation cannot leave a re-anchored pointer above a
        // header that was never flagged (which would re-wedge on restart).
        let new_best = self.loop_best_header_down(&invalid_set, top)?;
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut meta_table = write_txn.open_table(HEADER_META)?;
            for id in &invalidated {
                // Read the row from the already-open write-txn table rather
                // than `get_header_meta` (which opens a fresh read txn per id —
                // an N+1 pattern while this write txn is live). Only
                // pow_validity changes; the rest of the row is immutable once
                // stored. Copy the value out and drop the borrow before insert.
                let existing = match meta_table.get(id.as_slice())? {
                    Some(guard) => Some(HeaderMeta::deserialize(guard.value()).map_err(|e| {
                        StateError::DbCorruption {
                            table: "header_meta",
                            key: hex::encode(id),
                            reason: e.to_string(),
                        }
                    })?),
                    None => None,
                };
                if let Some(mut meta) = existing {
                    meta.pow_validity = 3;
                    meta_table.insert(id.as_slice(), meta.serialize().as_slice())?;
                }
            }
            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            let mut cs = self.chain_state.to_persisted();
            cs.best_header_id = new_best.0;
            cs.best_header_height = new_best.1;
            cs.best_header_score = new_best.2.clone();
            cs_table.insert("chain_state", cs.serialize().as_slice())?;
        }
        write_txn.commit()?;

        // Mirror the re-anchored best-header onto in-memory chain_state.
        self.chain_state.best_header_id = new_best.0;
        self.chain_state.best_header_height = new_best.1;
        self.chain_state.best_header_score = new_best.2;

        Ok(invalidated)
    }

    /// Walk the canonical best-header index down from `top`, returning the
    /// `(id, height, cumulative_score)` of the highest height whose canonical
    /// header id is NOT in `invalid_set`. Scala `loopHeightDown`. Falls back
    /// to the zeroed pre-genesis anchor if every height is invalidated.
    fn loop_best_header_down(
        &self,
        invalid_set: &HashSet<[u8; 32]>,
        top: u32,
    ) -> Result<([u8; 32], u32, Vec<u8>), StateError> {
        let mut h = top;
        loop {
            if let Some(id) = self.get_header_id_at_height(h)? {
                if !invalid_set.contains(&id) {
                    let score = self
                        .get_header_meta(&id)?
                        .map(|m| m.cumulative_score)
                        .unwrap_or_else(|| vec![0]);
                    return Ok((id, h, score));
                }
            }
            if h == 0 {
                // Entire chain invalidated — pre-genesis anchor.
                return Ok(([0u8; 32], 0, vec![0]));
            }
            h -= 1;
        }
    }

    /// Begin buffering header writes. Subsequent store_validated_header calls
    /// write to an in-memory overlay instead of redb. Call flush_header_batch
    /// to commit all buffered headers in a single write transaction.
    pub fn begin_header_batch(&mut self) {
        self.headers.begin_header_batch();
    }

    /// Flush all buffered header writes to redb in a single transaction.
    /// The in-memory chain_state was already updated during the batch;
    /// its projected persisted form is handed to the header tables so the
    /// CHAIN_STATE_META row and the best-chain index rewrite agree.
    pub fn flush_header_batch(&mut self) -> Result<(), StateError> {
        let cs_after = self.chain_state.to_persisted();
        self.headers.flush_header_batch(&cs_after)
    }

    /// Atomically persist header bytes + header_meta + optional best-header
    /// update. When batching is active, writes to in-memory buffer instead
    /// of redb (flushed by flush_header_batch). Otherwise writes directly.
    pub fn store_validated_header(
        &mut self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
        meta: &HeaderMeta,
        new_best: Option<(u32, Vec<u8>)>, // (height, cumulative_score) if new best
    ) -> Result<(), StateError> {
        let mut cs_meta = self.chain_state.to_persisted();
        let r = self.headers.store_validated_header(
            header_id,
            header_bytes,
            meta,
            new_best.clone(),
            &mut cs_meta,
        );
        // Mirror the committed best-header back onto the in-memory
        // chain_state. The component updated `cs_meta` in both the
        // batching and non-batching branches when `new_best` was
        // `Some`, so this single conditional covers both.
        if new_best.is_some() && r.is_ok() {
            self.chain_state.best_header_id = cs_meta.best_header_id;
            self.chain_state.best_header_height = cs_meta.best_header_height;
            self.chain_state.best_header_score = cs_meta.best_header_score.clone();
        }
        r
    }

    /// Apply a verified NiPoPoW proof to history. Atomically writes
    /// HEADERS + HEADER_META for every header in the proof's
    /// `headers_chain` (prefix + suffix), HEADER_CHAIN_INDEX rows
    /// for the **dense suffix range only**, the best-header pointers,
    /// and the `header_availability = PoPowSparse { .. }` mode tag.
    ///
    /// Caller is responsible for verifying the proof
    /// (`NipopowProof::is_valid` + quorum semantics in
    /// `ergo-validation::popow`) BEFORE invoking this method —
    /// `apply_popow_proof` accepts any structurally-typed proof; the
    /// security argument lives one layer up.
    ///
    /// Precondition: the store is in `HeaderAvailability::Dense` mode
    /// with `best_header_height == 0` (fresh node). Calling this on
    /// a node that already has chain state returns
    /// `StateError::ApplyPopowProofWrongMode` rather than
    /// overwriting; the re-bootstrap case is operator-driven (wipe
    /// data_dir).
    ///
    /// Does NOT touch `CHAIN_INDEX` (full-block index) or
    /// `best_full_block_*`. The Mode 2 snapshot bootstrap remains
    /// eligible to run after this, gated on `best_full_block_height == 0`.
    /// Sentinel key for the cached NiPoPoW serve-side proof bytes.
    /// Scala parity: `PopowProcessor.scala::NipopowSnapshotHeightKey`.
    /// Holds a single serialized `NipopowProof` blob updated when the
    /// chain crosses a snapshot epoch. Read on inbound
    /// `GetNipopowProof` requests from peers.
    const CACHED_POPOW_PROOF_KEY: &'static str = "cached_popow_proof";

    /// Advance best_full_block pointer without applying UTXO mutations.
    /// Used for genesis (height 1) whose state was bootstrapped by initialize_genesis.
    pub fn advance_best_full_block(
        &mut self,
        header_id: [u8; 32],
        height: u32,
    ) -> Result<(), StateError> {
        let mut cs = self.chain_state.to_persisted();
        cs.best_full_block_id = header_id;
        cs.best_full_block_height = height;
        self.persist_chain_state_meta(&cs)?;
        self.chain_state.best_full_block_id = header_id;
        self.chain_state.best_full_block_height = height;
        Ok(())
    }

    /// Test-only, unsafe: forcibly overwrite the best-header pointer without
    /// validating that the header exists in HEADERS/HEADER_META or that the
    /// chain below it is persisted.
    ///
    /// HAZARDS:
    /// - Does NOT write HEADER_CHAIN_INDEX. The function instead clears the
    ///   `hci_version` sentinel, so the next `StateStore::open` will re-run
    ///   the backfill walk. If the fake header has no HEADER_META, backfill
    ///   will return an error — which is the intended failure mode.
    /// - Leaves CHAIN_STATE_META and HEADER_CHAIN_INDEX intentionally out of
    ///   sync until the next open. Tests that exercise startup loading after
    ///   calling this must either also arrange HEADER_META for the full chain
    ///   OR accept that backfill will fail.
    ///
    /// Prefer `store_validated_header` in tests that exercise any startup/load
    /// logic. This helper exists only for tests that need to bypass validation
    /// to assert on storage-layer behavior (e.g. "does pointer survive restart?").
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_set_best_header_unsafe(
        &mut self,
        header_id: [u8; 32],
        height: u32,
        cumulative_score: Vec<u8>,
    ) -> Result<(), StateError> {
        let mut cs = self.chain_state.to_persisted();
        cs.best_header_id = header_id;
        cs.best_header_height = height;
        cs.best_header_score = cumulative_score.clone();

        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert("chain_state", cs.serialize().as_slice())?;
            // Clear the sentinel — backfill must re-run next open.
            let mut meta_table = write_txn.open_table(STATE_META)?;
            meta_table.remove("hci_version")?;
        }
        write_txn.commit()?;

        self.chain_state.best_header_id = header_id;
        self.chain_state.best_header_height = height;
        self.chain_state.best_header_score = cumulative_score;
        Ok(())
    }

    /// Insert a single HEADER_CHAIN_INDEX entry for tests that pre-seed a
    /// chain but bypass the normal persist path (which maintains the index).
    /// Without such an entry, a subsequent real persist_apply triggers
    /// `rewrite_best_chain_into_index` which walks back past the seeded
    /// range and hits a zero parent_id.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_put_header_chain_index(
        &self,
        height: u32,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut idx_table = write_txn.open_table(HEADER_CHAIN_INDEX)?;
            idx_table.insert(height as u64, header_id.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Insert a single `CHAIN_INDEX` (applied chain) entry. Companion to
    /// `test_force_put_header_chain_index`, used by tests that need to
    /// pin a divergence between the applied chain and the best-header
    /// chain — e.g. identity-aware "applied at height" tests.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_put_chain_index(
        &self,
        height: u32,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut chain_table = write_txn.open_table(CHAIN_INDEX)?;
            chain_table.insert(height as u64, header_id.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Read the applied-chain header id at a given height directly
    /// from `CHAIN_INDEX`. `None` if no row exists. Intended for
    /// tests that assert CHAIN_INDEX coverage independently of the
    /// in-memory chain_state mirror.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn chain_index_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(CHAIN_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(height as u64)? {
            Some(g) => {
                let bytes = g.value();
                if bytes.len() != 32 {
                    return Err(StateError::DbCorruption {
                        table: "chain_index",
                        key: height.to_string(),
                        reason: format!("payload length {} (expected 32)", bytes.len()),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(bytes);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Test helper: force-set `best_full_block_*` alongside `best_header_*`
    /// without running the normal apply path. Used by diff-module tests
    /// to pin a synthetic committed tip. Persists the full `ChainStateMeta`
    /// and mirrors into in-memory `chain_state`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_set_best_full_block_unsafe(
        &mut self,
        header_id: [u8; 32],
        height: u32,
    ) -> Result<(), StateError> {
        let mut cs = self.chain_state.to_persisted();
        cs.best_full_block_id = header_id;
        cs.best_full_block_height = height;
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert("chain_state", cs.serialize().as_slice())?;
        }
        write_txn.commit()?;
        self.chain_state.best_full_block_id = header_id;
        self.chain_state.best_full_block_height = height;
        Ok(())
    }

    /// Delete the persisted header bytes for a given id without touching
    /// `chain_state` or `header_meta`. Used by integrity tests to
    /// synthesize the "header row missing while DB key still in
    /// chain_index / chain_state" corruption shape that production
    /// hydration paths must reject.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_remove_header_row_unsafe(
        &mut self,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(HEADERS)?;
            t.remove(header_id.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Delete the persisted `header_meta` row for a given id without
    /// touching anything else. Companion to `test_remove_header_row_unsafe`
    /// for exercising the "meta missing while bytes still present"
    /// corruption shape.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_remove_header_meta_row_unsafe(
        &mut self,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(HEADER_META)?;
            t.remove(header_id.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Overwrite the persisted header bytes for a given id with
    /// arbitrary bytes, bypassing the canonical-hash invariant the
    /// production path enforces. Used to synthesize trailing-bytes
    /// and body/key drift corruption shapes — the hardened
    /// `CheckedHeader::from_persisted_parts` constructor is supposed
    /// to detect both.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_corrupt_header_bytes_unsafe(
        &mut self,
        header_id: &[u8; 32],
        new_bytes: &[u8],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(HEADERS)?;
            t.insert(header_id.as_slice(), new_bytes)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Persist a given chain state meta to the database.
    fn persist_chain_state_meta(&self, cs: &ChainStateMeta) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut table = write_txn.open_table(CHAIN_STATE_META)?;
            table.insert("chain_state", cs.serialize().as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }
}

impl ergo_validation::UtxoView for StateStore {
    fn get_box(
        &self,
        box_id: &ergo_primitives::digest::Digest32,
    ) -> Option<ergo_ser::ergo_box::ErgoBox> {
        StateStore::get_box(self, box_id)
    }
}

impl StateStore {
    /// Speculatively apply a checked-transaction batch to the current
    /// committed AVL+ state, returning `(new_state_root,
    /// raw_proof_bytes, snapshot_tip_id)` without persisting anything.
    ///
    /// Mining uses this to assemble a block candidate against the
    /// committed tip: build the candidate's tx list, run the dry-run
    /// to obtain the new state root and AD-proof bytes, fill them
    /// into the candidate header, and broadcast.
    ///
    /// Behavior:
    ///
    /// * Captures `chain_state().best_full_block_id` as the
    ///   `snapshot_tip_id` returned in the third tuple element. The
    ///   caller compares this against its frozen parent_id to detect
    ///   tip-flip races between candidate assembly and submission.
    /// * Builds the block-level remove/insert maps via the same
    ///   `build_utxo_changes_checked` path that real `apply_block`
    ///   uses, so intra-block create-then-spend cancellation is
    ///   identical.
    /// * Hydrates a plain `BatchAVLProver` (never the persistent
    ///   variant) from the in-memory AVL tree, applies the batch in
    ///   `apply_mutations` order (removes first, BTreeMap-ascending,
    ///   then inserts BTreeMap-ascending), captures the prover's
    ///   digest and proof bytes, drops the prover.
    /// * Never mutates `self.tree`, the redb file, or `chain_state`.
    ///
    /// The caller is responsible for computing `ad_proofs_root`
    /// from the returned `raw_proof_bytes`; it is
    /// `blake2b256(raw_proof_bytes)` — pinned against Scala via
    /// `tests/ad_proofs_root_oracle.rs`.
    pub fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        let snapshot_tip_id = self.chain_state.best_full_block_id;
        let parent_root = self.tree.root_digest();
        let (to_remove, to_insert) = Self::build_utxo_changes_checked(checked)?;
        let to_lookup = Self::build_data_input_lookups_checked(checked);
        let (new_root, proof_bytes) =
            dry_run::apply_change_set_via_prover(&self.tree, &to_lookup, &to_remove, &to_insert)?;
        // Pre-broadcast self-check: the generated proof must verifier-
        // replay from the parent root to the claimed post-root, or the
        // candidate is withheld (see self_check_candidate_proof).
        dry_run::self_check_candidate_proof(
            &parent_root,
            &to_lookup,
            &to_remove,
            &to_insert,
            &proof_bytes,
            &new_root,
        )?;
        Ok((new_root, proof_bytes, snapshot_tip_id))
    }

    /// Active protocol parameters + cumulative validation settings at the
    /// current best-full-block tip. Returns owned clones so the caller can
    /// pass them across thread boundaries (e.g. into a mining task).
    pub fn tip_snapshot_params(
        &self,
    ) -> (
        ergo_validation::ActiveProtocolParameters,
        ergo_validation::ErgoValidationSettings,
    ) {
        (
            self.cached_active_params.clone(),
            self.cached_validation_settings.clone(),
        )
    }

    /// Last 10 applied headers, tip-first (index 0 = best-full-block tip,
    /// index 9 = tip - 9). Reads `CHAIN_INDEX` (the applied chain) and
    /// `HEADERS`. Used by the mining candidate generator to construct
    /// `CONTEXT.headers` for script validation.
    ///
    /// Returns an error if fewer than 10 applied entries exist (only
    /// possible during early IBD). Mining is gated on synced(tip) so this
    /// case never reaches candidate generation; the error is informational
    /// for callers that may invoke this before sync completes.
    pub fn last_applied_chain_window_10(
        &self,
    ) -> Result<[ergo_ser::header::Header; 10], StateError> {
        let tip_h = self.chain_state.best_full_block_height;
        if tip_h < 10 {
            return Err(StateError::EarlyIBD {
                needed_min: 10,
                observed: tip_h,
            });
        }
        let read_txn = self.db.begin_read()?;
        let chain_table = read_txn.open_table(CHAIN_INDEX)?;
        let headers_table = read_txn.open_table(HEADERS)?;

        // Newest first.
        let mut headers: Vec<ergo_ser::header::Header> = Vec::with_capacity(10);
        for h in (tip_h - 9..=tip_h).rev() {
            let id_guard = chain_table
                .get(h as u64)?
                .ok_or(StateError::AppliedChainGap { at_height: h })?;
            let id_bytes = id_guard.value();
            if id_bytes.len() != 32 {
                return Err(StateError::DbCorruption {
                    table: "chain_index",
                    key: hex::encode((h as u64).to_be_bytes()),
                    reason: format!("row has len {} (expected 32)", id_bytes.len()),
                });
            }
            let hdr_guard =
                headers_table
                    .get(id_bytes)?
                    .ok_or_else(|| StateError::DbCorruption {
                        table: "headers",
                        key: hex::encode(id_bytes),
                        reason: format!("applied-chain header missing at h={h}"),
                    })?;
            let mut r = ergo_primitives::reader::VlqReader::new(hdr_guard.value());
            // The id came from CHAIN_INDEX and HEADERS confirmed the
            // row exists; a decode failure on that row is cross-table
            // corruption rather than a codec-edge error.
            let header =
                ergo_ser::header::read_header(&mut r).map_err(|e| StateError::DbCorruption {
                    table: "headers",
                    key: hex::encode(id_bytes),
                    reason: format!("last_applied_chain_window_10: header decode at h={h}: {e}"),
                })?;
            headers.push(header);
        }
        let arr: [ergo_ser::header::Header; 10] =
            headers
                .try_into()
                .map_err(|_| StateError::InternalInvariant {
                    what: "last_applied_chain_window_10: built window with size != 10",
                })?;
        Ok(arr)
    }

    /// If the hci_version sentinel is absent, rebuild HEADER_CHAIN_INDEX via
    /// a single sequential HEADER_META scan + backward walk from best_header_id.
    /// Sets the sentinel on success. Called once by `open_with_cache`.
    /// Open-time reconcile of the `voted_params` table.
    ///
    /// Computes `expected_keys = {0} ∪ {1024, 2048, ..., tip - tip%1024}`
    /// and compares against the table's actual key set:
    /// - Extras (keys outside `expected_keys`) → `VotedParamsExtraRows`.
    /// - Missing keys → fill in one write_txn (genesis row from
    ///   `scala_launch()`, others by walking chain_index → headers →
    ///   block_sections → parse_active_params).
    /// - Equal sets → no writes, fast no-op on every subsequent open.
    ///
    /// Failures during the chain-walk (missing chain_index entry,
    /// missing header, missing extension, parse failure) abort the
    /// txn — no partial reconcile lands.
    fn reconcile_voted_params(&mut self) -> Result<(), StateError> {
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::modifier_id::TYPE_EXTENSION;

        let tip = self.chain_state.best_full_block_height;

        // Mode 2 (UTXO snapshot bootstrap) gap: a snapshot-bootstrapped
        // node has no pre-snapshot block data — chain_index is empty
        // below snapshot_height. The full 0..tip:step(voting_length)
        // walk would fault at the first epoch boundary since the block
        // wasn't downloaded. Detect this by finding the lowest height
        // present in CHAIN_INDEX and starting `expected` from the next
        // voting_length-multiple at or above it.
        //
        // For Mode 1 (full archive) chain_index has every height from
        // genesis, so `min_chain_height = 1` and the floor is the
        // existing `0` row (seeded from `scala_launch()`).
        //
        // For Mode 2 at install time we still emit the height-0
        // genesis row (mock active params from `scala_launch()` — the
        // validator never queries those for post-snapshot block
        // application; this row is for table-shape consistency only).
        let chain_floor = {
            let read_txn = self.db.begin_read()?;
            match read_txn.open_table(CHAIN_INDEX) {
                Ok(table) => {
                    use redb::ReadableTable;
                    table
                        .iter()?
                        .next()
                        .and_then(|r| r.ok())
                        .map(|(k, _)| k.value())
                }
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(e.into()),
            }
        };
        // Effective floor for the reconcile walk:
        //   * If CHAIN_INDEX has entries: use the lowest height present.
        //   * If CHAIN_INDEX is empty but best_full_block_height > 0:
        //     Mode 2 install — install_snapshot_state advances
        //     chain_state.best_full_block_height but DOESN'T populate
        //     CHAIN_INDEX (there are no pre-snapshot blocks). Use
        //     best_full_block_height as the effective floor.
        //   * Otherwise (fresh node, no blocks applied): no floor.
        let effective_floor: Option<u64> = match chain_floor {
            Some(low) if low > 0 => Some(low),
            _ if tip > 0 => Some(tip as u64),
            _ => None,
        };
        let voting_length = self.voting_settings.voting_length as u64;
        let walk_start = effective_floor.map(|low| {
            // First voting_length-multiple at or above the lowest
            // available height. For snapshot_height=1,775,615 with
            // mainnet voting_length=1024 → ceil(1,775,615 / 1024) *
            // 1024 = 1,775,616.
            low.div_ceil(voting_length) * voting_length
        });
        let expected: std::collections::BTreeSet<u64> = std::iter::once(0u64)
            .chain(match walk_start {
                Some(start) => Box::new((start..=tip as u64).step_by(voting_length as usize))
                    as Box<dyn Iterator<Item = u64>>,
                None => Box::new((voting_length..=tip as u64).step_by(voting_length as usize))
                    as Box<dyn Iterator<Item = u64>>,
            })
            .collect();
        let present = {
            let read_txn = self.db.begin_read()?;
            crate::active_params::present_keys(&read_txn)?
        };

        let extras: Vec<u64> = present.difference(&expected).copied().collect();
        if !extras.is_empty() {
            return Err(StateError::VotedParamsExtraRows { extras });
        }

        // Decode every already-present row. A row at an expected key
        // whose bytes fail to deserialize (truncated, bit-flipped,
        // wrong block_version range, …) is db corruption — fail loud
        // here rather than at a future read site that would surface
        // the wrong active set or a confusing late error.
        {
            let read_txn = self.db.begin_read()?;
            for &k in &present {
                if crate::active_params::read_latest_at(&read_txn, k as u32)?.is_none() {
                    // present_keys reported the key, so this can only
                    // hit on a truly empty / mid-write race; surface as
                    // missing-row at this height for fail-loud behavior.
                    return Err(StateError::VotedParamsMissingChainIndex { height: k as u32 });
                }
            }
        }

        let missing: Vec<u64> = expected.difference(&present).copied().collect();
        if missing.is_empty() {
            return Ok(());
        }

        let t0 = std::time::Instant::now();
        let write_txn = crate::begin_write_qr(&self.db)?;
        for &k in &missing {
            if k == 0 {
                // Genesis reconcile uses the same VotedParamsWriteFailed
                // family as the non-genesis loop below so all reconcile
                // write failures pattern-match through one variant
                // (op="reconcile", height=0 for genesis).
                crate::active_params::insert(&write_txn, &self.init_launch_params).map_err(
                    |e| StateError::VotedParamsWriteFailed {
                        op: "reconcile",
                        height: 0,
                        source: Box::new(e),
                    },
                )?;
                continue;
            }
            let h = k as u32;

            let header_id: [u8; 32] = {
                let chain_table = write_txn.open_table(CHAIN_INDEX)?;
                let guard = chain_table
                    .get(h as u64)?
                    .ok_or(StateError::VotedParamsMissingChainIndex { height: h })?;
                let mut id = [0u8; 32];
                id.copy_from_slice(guard.value());
                id
            };

            let header_bytes: Vec<u8> = {
                let headers_table = write_txn.open_table(HEADERS)?;
                let guard = headers_table.get(header_id.as_slice())?.ok_or(
                    StateError::VotedParamsMissingHeader {
                        height: h,
                        header_id: hex::encode(header_id),
                    },
                )?;
                guard.value().to_vec()
            };
            let header = {
                let mut r = VlqReader::new(&header_bytes);
                ergo_ser::header::read_header(&mut r).map_err(|e| StateError::DbCorruption {
                    table: "headers",
                    key: hex::encode(header_id),
                    reason: format!("decode failed during voted_params reconcile h={h}: {e:?}"),
                })?
            };

            let section_id = ergo_ser::modifier_id::compute_section_id(
                TYPE_EXTENSION,
                &header_id,
                header.extension_root.as_bytes(),
            );

            let extension_bytes: Vec<u8> = {
                let sec_table = write_txn.open_table(BLOCK_SECTIONS)?;
                let guard = sec_table.get(section_id.as_slice())?.ok_or(
                    StateError::VotedParamsMissingExtension {
                        height: h,
                        section_id: hex::encode(section_id),
                    },
                )?;
                guard.value().to_vec()
            };
            let extension = {
                let mut r = VlqReader::new(&extension_bytes);
                ergo_ser::extension::read_extension(&mut r).map_err(|e| {
                    StateError::DbCorruption {
                        table: "block_sections",
                        key: hex::encode(section_id),
                        reason: format!(
                            "extension decode failed during voted_params reconcile h={h}: {e:?}"
                        ),
                    }
                })?
            };

            let params = ergo_validation::parse_active_params(&extension, h)
                .map_err(|source| StateError::VotedParamsParseFailed { height: h, source })?;

            // Wrap into VotedParamsWriteFailed so the (op, height)
            // context survives at the error boundary along with the
            // typed VotedParamsWriteError source.
            crate::active_params::insert(&write_txn, &params).map_err(|e| {
                StateError::VotedParamsWriteFailed {
                    op: "reconcile",
                    height: h,
                    source: Box::new(e),
                }
            })?;
        }
        write_txn.commit()?;
        info!(
            keys_filled = missing.len(),
            elapsed_secs = t0.elapsed().as_secs_f64(),
            tip,
            "voted_params reconcile",
        );
        Ok(())
    }

    // (helper for the migration below)
    /// Codec v1→v2 migration sweep on open.
    ///
    /// An earlier writer emitted `voted_params` rows in v1 format
    /// (no `proposed_update` / `activated_update` blobs). The current
    /// codec auto-detects v1 on read but produces empty updates for
    /// those fields. That's correct for the genesis row but **wrong**
    /// for any epoch where a soft-fork activated (e.g. EIP-37 at
    /// h=843_776 should have `activated_update` containing rule 409
    /// disabled).
    ///
    /// To correct existing stores: walk every voted_params row in
    /// ascending order, replay the soft-fork state machine from
    /// `scala_launch()` up to that height (using each row's
    /// `proposed_update` recovered from the block's extension blob
    /// via chain_index → headers → block_sections), and rewrite the
    /// row in v2 format with the correct `activated_update`.
    ///
    /// Single redb txn, all-or-nothing. Sentinel
    /// `voted_params_codec_v2` in `state_meta` skips the sweep on
    /// subsequent opens.
    fn migrate_voted_params_codec_v2_if_needed(&mut self) -> Result<(), StateError> {
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::modifier_id::TYPE_EXTENSION;
        use ergo_validation::voting::compute_next_params;

        const SENTINEL_KEY: &str = "voted_params_codec_v2";

        // Sentinel check: skip if migration already ran.
        {
            let read_txn = self.db.begin_read()?;
            if let Ok(t) = read_txn.open_table(STATE_META) {
                if t.get(SENTINEL_KEY)?.is_some() {
                    return Ok(());
                }
            }
        }

        // Collect every present key + its current row bytes. We need
        // to detect "is any row v1?" to decide whether to run the
        // sweep at all (v2-only stores skip).
        let keys: Vec<u64> = {
            let read_txn = self.db.begin_read()?;
            crate::active_params::present_keys(&read_txn)?
                .into_iter()
                .collect()
        };
        if keys.is_empty() {
            // Nothing to migrate (open's reconcile would have written
            // genesis row first; if we're here with an empty table,
            // reconcile must have skipped it — i.e., empty chain).
            // Set the sentinel so we don't keep checking.
            let write_txn = crate::begin_write_qr(&self.db)?;
            {
                let mut t = write_txn.open_table(STATE_META)?;
                t.insert(SENTINEL_KEY, [1u8].as_slice())?;
            }
            write_txn.commit()?;
            return Ok(());
        }

        let t0 = std::time::Instant::now();

        // Replay the soft-fork state machine from genesis through
        // tip, carrying the cumulative state forward. Fix up each
        // row's activated_update to match.
        let voting_settings = self.voting_settings;
        let voting_length = voting_settings.voting_length;
        let mut state_machine = self.init_launch_params.clone();
        // For h=0 (genesis row), activated_update = empty; that's
        // already what the launch params produce.

        let write_txn = crate::begin_write_qr(&self.db)?;
        let mut rewritten = 0usize;
        for &k in &keys {
            let new_row = if k == 0 {
                self.init_launch_params.clone()
            } else {
                let h = k as u32;

                let header_id: [u8; 32] = {
                    let chain_table = write_txn.open_table(CHAIN_INDEX)?;
                    let guard = chain_table
                        .get(h as u64)?
                        .ok_or(StateError::VotedParamsMissingChainIndex { height: h })?;
                    let mut id = [0u8; 32];
                    id.copy_from_slice(guard.value());
                    id
                };

                let header_bytes: Vec<u8> = {
                    let headers_table = write_txn.open_table(HEADERS)?;
                    let guard = headers_table.get(header_id.as_slice())?.ok_or(
                        StateError::VotedParamsMissingHeader {
                            height: h,
                            header_id: hex::encode(header_id),
                        },
                    )?;
                    guard.value().to_vec()
                };
                let header = {
                    let mut r = VlqReader::new(&header_bytes);
                    ergo_ser::header::read_header(&mut r).map_err(|e| StateError::DbCorruption {
                        table: "headers",
                        key: hex::encode(header_id),
                        reason: format!("decode failed during voted_params migrate h={h}: {e:?}"),
                    })?
                };

                let section_id = ergo_ser::modifier_id::compute_section_id(
                    TYPE_EXTENSION,
                    &header_id,
                    header.extension_root.as_bytes(),
                );
                let extension_bytes: Vec<u8> = {
                    let sec_table = write_txn.open_table(BLOCK_SECTIONS)?;
                    let guard = sec_table.get(section_id.as_slice())?.ok_or(
                        StateError::VotedParamsMissingExtension {
                            height: h,
                            section_id: hex::encode(section_id),
                        },
                    )?;
                    guard.value().to_vec()
                };
                let extension = {
                    let mut r = VlqReader::new(&extension_bytes);
                    ergo_ser::extension::read_extension(&mut r).map_err(|e| {
                        StateError::DbCorruption {
                            table: "block_sections",
                            key: hex::encode(section_id),
                            reason: format!(
                                "extension decode failed during voted_params migrate h={h}: {e:?}"
                            ),
                        }
                    })?
                };

                // Recover proposed_update from the extension. The
                // current parser preserves it; v1 stored rows did not.
                let parsed = ergo_validation::parse_active_params(&extension, h)
                    .map_err(|source| StateError::VotedParamsParseFailed { height: h, source })?;

                // Parse the cumulative validation_settings from the
                // extension (Scala's `parsedSettings`). Used by the
                // genesis-era bypass below to mirror Scala's
                // `calculatedSettings = parsedSettings` semantics.
                let parsed_settings_update =
                    ergo_validation::voting::validation_settings::parse_validation_settings_update(
                        &extension,
                    )
                    .map_err(|e| StateError::DbCorruption {
                        // Parsing the validation-settings entries
                        // out of an extension we already decoded:
                        // failure here means the on-disk extension
                        // bytes are malformed (writer-side bug or
                        // disk damage).
                        table: "block_sections",
                        key: hex::encode(section_id),
                        reason: format!(
                            "validation_settings parse failed during voted_params migrate h={h}: {e:?}"
                        ),
                    })?;

                // Compute fork_vote: this block's header.votes contains 120.
                let fork_vote = header.votes.iter().any(|&v| v as i8 == 120);

                // Mirror the genesis-era bypass (Scala
                // `currentParameters.height == 0`,
                // `ErgoStateContext.scala:198-199`): at the first
                // real boundary with state_machine still at genesis,
                // accept parsed as computed and use the cumulative
                // `parsed_settings_update` (not `proposed_update`) as
                // activated_update so the validation_settings fold
                // converges to the on-chain cumulative.
                let mut next_state = if state_machine.epoch_start_height == 0 {
                    let mut p = parsed.clone();
                    p.activated_update = parsed_settings_update.clone();
                    p
                } else {
                    let epoch_votes = compute_epoch_votes_via_txn(&write_txn, h, voting_length)
                        .map_err(|e| StateError::VotedParamsMigrateFailed {
                            op: "epoch_votes",
                            height: h,
                            detail: e.to_string(),
                        })?;
                    let (next_state, _activated) = compute_next_params(
                        &state_machine,
                        &epoch_votes,
                        fork_vote,
                        &parsed.proposed_update,
                        h,
                        &voting_settings,
                    )
                    .map_err(|e| StateError::VotedParamsRecomputeFailed {
                        height: h,
                        source: Box::new(e),
                    })?;
                    next_state
                };

                state_machine = next_state.clone();
                next_state.epoch_start_height = h;
                next_state
            };

            // Rewrite the row in v2 format. VotedParamsWriteFailed
            // preserves the (op, height) context and the typed
            // VotedParamsWriteError source at the boundary. `k` is
            // the row's u64 table key; cast to u32 since epoch-start
            // heights are u32 (the value of `k` is guaranteed to
            // fit by the writer that produced the row).
            crate::active_params::insert(&write_txn, &new_row).map_err(|e| {
                StateError::VotedParamsWriteFailed {
                    op: "migrate",
                    height: k as u32,
                    source: Box::new(e),
                }
            })?;
            rewritten += 1;
        }

        // Set sentinel.
        {
            let mut t = write_txn.open_table(STATE_META)?;
            t.insert(SENTINEL_KEY, [1u8].as_slice())?;
        }
        write_txn.commit()?;

        info!(
            rewritten,
            elapsed_secs = t0.elapsed().as_secs_f64(),
            "voted_params codec v1→v2 migration",
        );
        Ok(())
    }

    fn backfill_header_chain_index_if_needed(&mut self) -> Result<(), StateError> {
        if self.header_chain_index_version()? == Some(1) {
            return Ok(());
        }
        let cs = self.chain_state.to_persisted();
        // Under `PoPowSparse` the dense backfill walk would fail at
        // the first sparse-prefix gap (`height discontinuity` from
        // the strict-decrement walk below). The index is correct by
        // construction in sparse mode — `apply_popow_proof` writes
        // only the dense suffix range and the bounded forward
        // catchup fills the remainder. Mark the sentinel so
        // subsequent reopens skip the walk.
        if matches!(
            cs.header_availability,
            HeaderAvailability::PoPowSparse { .. }
        ) {
            let write_txn = crate::begin_write_qr(&self.db)?;
            {
                let mut state_meta_table = write_txn.open_table(STATE_META)?;
                state_meta_table.insert("hci_version", [1u8].as_slice())?;
            }
            write_txn.commit()?;
            info!(
                best_header_height = cs.best_header_height,
                "PoPowSparse mode: skipping HEADER_CHAIN_INDEX dense backfill walk",
            );
            return Ok(());
        }
        if cs.best_header_height == 0 {
            // Empty chain: nothing to backfill. Do NOT set the sentinel here.
            // The sentinel means "the index is fully populated for
            // [1, best_header_height]"; setting it with zero data would
            // make a subsequent header-write skip through the "already done"
            // path even though backfill has never actually inspected the DB.
            // Re-checking on every open while the chain is empty is cheap
            // (one key lookup). Backfill runs the first time we open with
            // best_header_height > 0.
            return Ok(());
        }

        let t0 = std::time::Instant::now();
        info!(
            best_header_height = cs.best_header_height,
            "backfilling HEADER_CHAIN_INDEX",
        );

        // Phase 1: sequential scan of HEADER_META into an in-memory
        // id → (parent_id, height) map. Sequential reads are orders of
        // magnitude faster than 1.5M random lookups.
        let meta_map = {
            let read_txn = self.db.begin_read()?;
            let meta_table = read_txn.open_table(HEADER_META)?;
            let mut map: HashMap<[u8; 32], ([u8; 32], u32)> =
                HashMap::with_capacity(cs.best_header_height as usize);
            for entry in meta_table.iter()? {
                let (k, v) = entry?;
                let key_bytes = k.value();
                if key_bytes.len() != 32 {
                    continue;
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(key_bytes);
                let m = crate::chain::HeaderMeta::deserialize(v.value()).map_err(|e| {
                    StateError::DbCorruption {
                        table: "header_meta",
                        key: hex::encode(id),
                        reason: e.to_string(),
                    }
                })?;
                map.insert(id, (m.parent_id, m.height));
            }
            map
        };
        debug!(
            rows = meta_map.len(),
            elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0,
            "backfill: loaded HEADER_META rows",
        );

        // Phase 2: walk best_header chain backward, requiring strict height
        // continuity — each step must decrement height by exactly 1, starting
        // at best_header_height and ending at height 1. A length-only check
        // could accept a chain with duplicate or skipped heights; the counter
        // below guarantees the walk yields entries for [1, best_header_height]
        // with no gaps.
        let mut walked: Vec<(u32, [u8; 32])> = Vec::with_capacity(cs.best_header_height as usize);
        let mut cur = cs.best_header_id;
        let mut expected_height = cs.best_header_height;
        loop {
            let (parent, h) = meta_map.get(&cur).copied().ok_or_else(|| {
                // Walk reached an id that header_meta doesn't know
                // about — cross-table inconsistency between chain
                // state (which advertises best_header_id) and
                // HEADER_META.
                StateError::DbCorruption {
                    table: "header_meta",
                    key: hex::encode(cur),
                    reason: format!("backfill: row missing at expected height {expected_height}"),
                }
            })?;
            if h != expected_height {
                // HEADER_META.height disagrees with the height
                // derived from the parent-walk — writer wrote an
                // inconsistent row.
                return Err(StateError::DbCorruption {
                    table: "header_meta",
                    key: hex::encode(cur),
                    reason: format!(
                        "backfill: height discontinuity (expected {expected_height}, meta says {h})"
                    ),
                });
            }
            walked.push((h, cur));
            if h == 1 {
                break;
            }
            cur = parent;
            expected_height -= 1;
        }
        if walked.len() != cs.best_header_height as usize {
            // The preceding loop enforces h == expected_height on
            // every hop and only breaks at h == 1, so the post-walk
            // length is effectively guaranteed equal to
            // best_header_height. Firing this branch means the
            // internal loop invariant slipped — defense-in-depth
            // guard, classify as our-bug not on-disk corruption.
            return Err(StateError::InternalInvariant {
                what: "backfill: walk length != best_header_height after height-checked walk",
            });
        }

        // Phase 3: drain any pre-existing entries, then bulk insert the walked
        // chain, then set the sentinel — all in ONE write txn.
        //
        // Draining first is critical: the sentinel might be absent because
        // `test_force_set_best_header_unsafe` cleared it, because an earlier
        // partial implementation wrote entries and aborted, or because a prior
        // backfill crashed mid-insert. Any of those can leave entries above
        // the current best_header_height or at heights with stale ids. Without
        // a drain, backfill would paper over invariant violations and then set
        // hci_version=1, promising consistency the table doesn't have.
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut idx_table = write_txn.open_table(HEADER_CHAIN_INDEX)?;
            let stale_keys: Vec<u64> = {
                let mut out = Vec::new();
                for entry in idx_table.iter()? {
                    let (k, _) = entry?;
                    out.push(k.value());
                }
                out
            };
            for k in stale_keys {
                idx_table.remove(k)?;
            }
            for &(h, id) in walked.iter().rev() {
                idx_table.insert(h as u64, id.as_slice())?;
            }
            let mut meta_table = write_txn.open_table(STATE_META)?;
            meta_table.insert("hci_version", [1u8].as_slice())?;
            // Writer-capability sentinel: any process running the backfill is
            // v2-capable, so restamp defensively (normally already present).
            meta_table.insert(NODE_FORMAT_VERSION_KEY, NODE_FORMAT_V2)?;
        }
        write_txn.commit()?;
        info!(
            elapsed_ms = t0.elapsed().as_millis() as u64,
            "backfill complete",
        );
        Ok(())
    }

    /// Internal: persist a block application.
    ///
    /// When the persist pipeline is active, this builds a PersistJob and sends
    /// it to the background thread (non-blocking unless the queue is full).
    /// Otherwise falls back to a synchronous write transaction.
    fn persist_apply(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        new_digest: &ADDigest,
        undo: &UndoEntry,
        voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
        wallet_payload: Option<&WalletApplyPayload>,
    ) -> Result<(), StateError> {
        // Defensive: voted_params_row should be `Some` iff this is an
        // epoch-start block. The caller (block_proc) is the gatekeeper;
        // we double-check here so a misuse fails loud at the storage
        // boundary rather than corrupting the table.
        if let Some(p) = &voted_params_row {
            let voting_length = self.voting_settings.voting_length;
            if !(height.is_multiple_of(voting_length) && height > 0) {
                return Err(StateError::InvalidPrecondition {
                    what: "voted_params_row supplied at non-epoch-start height",
                });
            }
            if p.epoch_start_height != height {
                return Err(StateError::InvalidPrecondition {
                    what: "voted_params_row.epoch_start_height != block height",
                });
            }
        }
        use crate::avl::changelog::NodeChange;

        // Discard label-dirty set (labels not persisted).
        let label_ids = self.tree.take_label_dirty();
        let avl_label_skipped = label_ids.len() as u32;

        // Build the AVL write/delete sets from the ChangeLog.
        let mut seen = std::collections::HashSet::new();
        let mut avl_writes = Vec::new();
        let mut avl_deletes = Vec::new();
        for change in undo.change_log.changes() {
            let id = match change {
                NodeChange::Created(id) | NodeChange::Modified(id, _) => *id,
            };
            if seen.insert(id) {
                if let Some(node) = self.tree.get_node(id) {
                    avl_writes.push((id, node_to_bytes(&node)));
                } else {
                    avl_deletes.push(id);
                }
            }
        }
        let avl_structural = avl_writes.len() as u32 + avl_deletes.len() as u32;

        // Serialize metadata.
        let undo_key = undo_log_key(height, header_id).to_vec();
        let undo_bytes = undo.serialize();
        let undo_size = undo_bytes.len();

        let state_meta_bytes = StateMeta {
            height,
            tree_height: self.tree.tree_height(),
            root_digest: *new_digest.as_bytes(),
            root_node_id: self.tree.root_id(),
        }
        .serialize();

        let alloc_meta_bytes = AllocMeta {
            next_id: self.tree.next_id(),
        }
        .serialize()
        .to_vec();

        let old_best_header_height = self.chain_state.best_header_height;
        let best_header_bumped = old_best_header_height < height;
        // Pre-apply `best_full_block_height` for the Phase 2a/2b
        // eviction-range computation. Captured here so both the
        // synchronous seam below AND the pipeline-batch seam (via
        // `PersistJob`) see the same source of truth — the
        // chain_state value at the moment this block entered
        // `persist_apply`. Steady-state forward apply has
        // `diff = 1`; the archive→pruned transition has
        // `diff = 1` for the first apply (so only the new
        // pruning frontier is evicted, archive prefix stays).
        let old_best_full_block_height = self.chain_state.best_full_block_height;
        // Capture pre-update parent header for the test-helpers synthesis
        // path inside execute_batch. Reading from chain_state BEFORE we
        // mutate `cs` below ensures we record the actual prior tip.
        let parent_header_id = self.chain_state.best_header_id;
        let mut cs = self.chain_state.to_persisted();
        cs.best_full_block_height = height;
        cs.best_full_block_id = *header_id;
        if best_header_bumped {
            cs.best_header_id = *header_id;
            cs.best_header_height = height;
        }
        let chain_state_bytes = cs.serialize();

        let durable_this_block = if self.ibd_mode && self.ibd_flush_interval > 0 {
            self.ibd_blocks_since_flush >= self.ibd_flush_interval
        } else {
            true
        };

        let prune_below = if height > self.rollback_window {
            Some(height - self.rollback_window)
        } else {
            None
        };
        let undo_kb = undo_size as f64 / 1024.0;

        // --- Pipeline path: send to background thread ---
        if let Some(ref pipeline) = self.persist_pipeline {
            self.drain_persist_results()?;

            // M5 final-slice atomicity: clone the wallet payload into
            // the job so the worker can apply wallet writes inside
            // its batch's write_txn. Payload is owned data
            // (BTreeSet/BTreeMap/Vec) — clone is cheap relative to
            // the chain mutation itself. Without this, `apply_block`
            // would still need to fire the wallet write on a
            // separate post-flush write_txn (two-commit) on the
            // pipeline path.
            let wallet_payload_owned = wallet_payload.cloned();
            let job = crate::persist::PersistJob {
                height,
                header_id: *header_id,
                avl_writes,
                avl_deletes,
                undo_key,
                undo_bytes,
                state_meta_bytes,
                alloc_meta_bytes,
                chain_state_bytes,
                best_header_bumped,
                old_best_header_height,
                old_best_full_block_height,
                durable: durable_this_block,
                prune_below,
                parent_header_id,
                voted_params_row,
                wallet_payload: wallet_payload_owned,
            };

            if height.is_multiple_of(1000) || height <= 5 {
                debug!(
                    height,
                    mode = "async",
                    avl_structural,
                    avl_label_skipped,
                    undo_kb,
                    "perf persist",
                );
            }

            pipeline.send(job)?;

            // Update IBD flush counter.
            if self.ibd_mode {
                if durable_this_block {
                    self.ibd_blocks_since_flush = 0;
                } else {
                    self.ibd_blocks_since_flush += 1;
                }
            }

            return Ok(());
        }

        // --- Synchronous fallback ---
        let t0 = std::time::Instant::now();
        let mut write_txn = crate::begin_write_qr(&self.db)?;

        if !durable_this_block {
            write_txn.set_durability(redb::Durability::None);
        }
        let t_begin = t0.elapsed();

        let t0 = std::time::Instant::now();
        {
            let mut avl_table = write_txn.open_table(AVL_NODES)?;
            for (id, bytes) in &avl_writes {
                avl_table.insert(*id, bytes.as_slice())?;
            }
            for id in &avl_deletes {
                avl_table.remove(*id)?;
            }
        }
        let t_avl = t0.elapsed();

        let t0 = std::time::Instant::now();
        {
            let mut undo_table = write_txn.open_table(UNDO_LOG)?;
            undo_table.insert(undo_key.as_slice(), undo_bytes.as_slice())?;
        }
        let t_undo = t0.elapsed();

        let t0 = std::time::Instant::now();
        {
            let mut chain_table = write_txn.open_table(CHAIN_INDEX)?;
            chain_table.insert(height as u64, header_id.as_slice())?;

            let mut meta_table = write_txn.open_table(STATE_META)?;
            meta_table.insert("root", state_meta_bytes.as_slice())?;
            meta_table.insert("allocator", alloc_meta_bytes.as_slice())?;
            meta_table.insert(NODE_FORMAT_VERSION_KEY, NODE_FORMAT_V2)?;

            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert("chain_state", chain_state_bytes.as_slice())?;

            if best_header_bumped {
                // Test-only: some harnesses apply blocks without running the
                // header pipeline, so HEADER_META may be missing for the
                // applied header. Synthesize a minimal row so the invariant
                // `rewrite_best_chain_into_index` depends on is restored.
                // Production always writes HEADER_META via header_proc before
                // apply_block is called, making this a no-op.
                #[cfg(feature = "test-helpers")]
                {
                    let existing = {
                        let m_table = write_txn.open_table(HEADER_META)?;
                        let present = m_table.get(header_id.as_slice())?.is_some();
                        present
                    };
                    if !existing {
                        let parent_id = if self.chain_state.best_full_block_height == 0 {
                            [0u8; 32]
                        } else {
                            self.chain_state.best_full_block_id
                        };
                        let meta = crate::chain::HeaderMeta {
                            parent_id,
                            height,
                            cumulative_score: vec![height as u8],
                            pow_validity: 1,
                            timestamp: 1_700_000_000 + height as u64,
                        };
                        let mut m_table = write_txn.open_table(HEADER_META)?;
                        m_table.insert(header_id.as_slice(), meta.serialize().as_slice())?;
                    }
                }

                let m_table = write_txn.open_table(HEADER_META)?;
                let mut idx_table = write_txn.open_table(HEADER_CHAIN_INDEX)?;
                rewrite_best_chain_into_index(
                    &mut idx_table,
                    &m_table,
                    *header_id,
                    height,
                    old_best_header_height,
                )?;
            }
        }
        let t_meta = t0.elapsed();

        let t0 = std::time::Instant::now();
        let mut pruned = 0u32;
        if height > self.rollback_window {
            let prune_below = height - self.rollback_window;
            let prune_upper = (prune_below + 1).to_be_bytes();
            let mut undo_table = write_txn.open_table(UNDO_LOG)?;
            let mut to_delete: Vec<Vec<u8>> = Vec::new();
            {
                let range = undo_table.range::<&[u8]>(..prune_upper.as_slice())?;
                for entry in range {
                    let (key, _) = entry?;
                    to_delete.push(key.value().to_vec());
                }
            }
            pruned = to_delete.len() as u32;
            for key in &to_delete {
                undo_table.remove(key.as_slice())?;
            }
        }
        let t_prune = t0.elapsed();

        // Mode 3 Phase 2a — block-section eviction at the sync
        // apply seam. Co-committed with AVL / undo / chain_index /
        // state_meta + voted_params inside the existing write_txn
        // so the chain tip and section deletion advance atomically.
        // No-op when `blocks_to_keep < 0` (archive) or `== 0`
        // (canonical Mode 6 — no full-block applies reach here in
        // production, but the compute helper short-circuits
        // defensively).
        let t0 = std::time::Instant::now();
        let mut sections_evicted = 0u32;
        let mut prune_range_len = 0u32;
        if self.blocks_to_keep > 0 {
            // Read the current sentinel inside the write_txn so a
            // concurrent writer cannot interleave between the read
            // and the advance.
            let current_min: u32 = {
                let meta = write_txn.open_table(STATE_META)?;
                let bytes_opt = meta
                    .get(MINIMAL_FULL_BLOCK_HEIGHT_KEY)?
                    .map(|g| g.value().to_vec());
                drop(meta);
                match bytes_opt {
                    Some(bytes) => {
                        if bytes.len() != 4 {
                            return Err(StateError::DbCorruption {
                                table: "state_meta",
                                key: hex::encode(MINIMAL_FULL_BLOCK_HEIGHT_KEY.as_bytes()),
                                reason: format!(
                                    "minimal_full_block_height payload has unexpected length: {}",
                                    bytes.len()
                                ),
                            });
                        }
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&bytes);
                        u32::from_le_bytes(buf)
                    }
                    None => 1,
                }
            };
            let voting_length = self.voting_settings.voting_length;
            let new_min = crate::store::apply::compute_minimal_full_block_height(
                current_min,
                height,
                self.blocks_to_keep,
                voting_length,
            );
            if new_min > current_min {
                // Scala-parity prune range:
                //   `[max(1, new_min - diff), new_min)`
                // where `diff = height - prev_best_full_block_height`.
                // For a steady-state per-block apply, `diff = 1` so
                // the range is a single height. For the
                // archive→pruned transition (e.g. archive with tip
                // 1000 reopened with `blocks_to_keep = 5`, first
                // applying h=1001): `diff = 1` so the range is
                // [996, 997) — only the new pruning frontier is
                // evicted, the [1, 995] archive prefix stays. Without
                // this `diff`-based clamp, the range would walk from
                // `current_min` (1, the absent-row default) up to
                // `new_min` and retroactively wipe the archive.
                let diff = height.saturating_sub(old_best_full_block_height).max(1);
                let prune_from = new_min.saturating_sub(diff).max(1);
                prune_range_len = new_min - prune_from;
                for h in prune_from..new_min {
                    sections_evicted +=
                        Self::delete_block_sections_at_height_in_txn(&write_txn, h)?;
                }
                Self::advance_minimal_full_block_height_in_txn(&write_txn, new_min)?;
            }
        }
        let t_evict = t0.elapsed();

        // Voted parameters: epoch-start blocks only. Wrap into
        // VotedParamsWriteFailed so the apply-time (op, height)
        // context and typed source are preserved at the boundary.
        if let Some(ref p) = voted_params_row {
            crate::active_params::insert(&write_txn, p).map_err(|e| {
                StateError::VotedParamsWriteFailed {
                    op: "apply",
                    height,
                    source: Box::new(e),
                }
            })?;
        }

        // M5 atomic-commit: wallet apply lands inside the SAME
        // write_txn as chain state. A crash between AVL/undo/chain-
        // index writes and the wallet-table writes is no longer
        // reachable: redb's single-write-txn atomicity covers both.
        // Failure of `apply_block_to_wallet` aborts the whole txn,
        // so chain state does not advance with stale wallet tables.
        // Maturity-promotion at this height is part of the same
        // atomic unit.
        if let Some(payload) = wallet_payload {
            let bound = crate::store::owned_to_block_txs(&payload.block_txs_owned);
            let btxs = bound.as_block_txs();
            // A scan-only payload (no tracked trees/pubkeys) must bypass wallet
            // apply + maturity-promotion: those advance WALLET_SCAN_HEIGHT for
            // blocks the wallet never classified, which would then surface as a
            // bogus walletHeight in /wallet/status + /wallet/balances.
            if payload.has_wallet_tracking() {
                crate::wallet::apply::apply_block_to_wallet(
                    &write_txn,
                    &payload.tracked_p2pk_trees,
                    &payload.cached_pubkeys,
                    height,
                    header_id,
                    &btxs,
                )
                .map_err(|e| StateError::WalletApply {
                    what: "apply hook (atomic)",
                    height,
                    source: Box::new(e),
                })?;
                crate::wallet::maturity::promote_matured_boxes(&write_txn, height).map_err(
                    |e| StateError::WalletApply {
                        what: "maturity promote (atomic)",
                        height,
                        source: Box::new(e),
                    },
                )?;
            }
            // Scan tracking lands in the same atomic write-txn, independent of
            // wallet-key tracking — but only when scans are actually registered.
            // With no scans, skipping avoids opening/creating the scan tables and
            // the per-input spend-index probe (the scan_count==0 fast path).
            if payload.has_registered_scans {
                crate::wallet::apply::apply_block_to_scans(
                    &write_txn,
                    &payload.scan_matches,
                    &btxs,
                    height,
                    header_id,
                )
                .map_err(|e| StateError::WalletApply {
                    what: "scan apply (atomic)",
                    height,
                    source: Box::new(e),
                })?;
            }
        }

        let t0 = std::time::Instant::now();
        write_txn.commit()?;
        let t_commit = t0.elapsed();

        // Update IBD flush counter after successful commit
        if self.ibd_mode {
            if durable_this_block {
                self.ibd_blocks_since_flush = 0;
            } else {
                self.ibd_blocks_since_flush += 1;
            }
        }

        let durability_tag = if !self.ibd_mode {
            "imm"
        } else if durable_this_block {
            "FLUSH"
        } else {
            "none"
        };

        if height.is_multiple_of(1000) || height <= 5 {
            debug!(
                height,
                durability = durability_tag,
                begin_ms = t_begin.as_secs_f64() * 1000.0,
                avl_ms = t_avl.as_secs_f64() * 1000.0,
                avl_structural,
                avl_label_skipped,
                undo_ms = t_undo.as_secs_f64() * 1000.0,
                undo_kb,
                meta_ms = t_meta.as_secs_f64() * 1000.0,
                prune_ms = t_prune.as_secs_f64() * 1000.0,
                pruned,
                evict_ms = t_evict.as_secs_f64() * 1000.0,
                sections_evicted,
                prune_range_len,
                commit_ms = t_commit.as_secs_f64() * 1000.0,
                "perf persist",
            );
        }

        Ok(())
    }

    /// Derive next_id by scanning the AVL_NODES table for the max key.
    /// One-time migration cost when AllocMeta is absent (pre-upgrade DB).
    fn derive_next_id_from_scan(read_txn: &redb::ReadTransaction) -> Result<u64, StateError> {
        let table = read_txn.open_table(AVL_NODES)?;
        let mut max_id = 0u64;
        for entry in table.iter()? {
            let (key, _) = entry?;
            let id = key.value();
            if id > max_id {
                max_id = id;
            }
        }
        Ok(max_id + 1)
    }
}

// AVL node + allocator-metadata byte codecs moved to crate::avl::serialization.
// Re-exported here for compatibility with internal callsites; the canonical
// location is `crate::avl::serialization`.
pub(crate) use crate::avl::serialization::AllocMeta;
pub use crate::avl::serialization::{node_from_bytes, node_to_bytes};

// ---- wallet integration helpers ----

/// Owned per-output data for the wallet hook (avoids lifetime complexity).
#[derive(Clone)]
pub struct OwnedBlockOutput {
    pub box_id: [u8; 32],
    pub output_index: u16,
    pub ergo_tree_bytes: Vec<u8>,
    pub value: u64,
    pub assets: Vec<([u8; 32], u64)>,
    pub miner_reward_pubkey: Option<[u8; 33]>,
    /// Full serialized `ErgoBox` bytes. Populated by BOTH builders:
    /// - the section/replay builder ([`build_wallet_block_txs_from_sections`])
    ///   feeds the rescan read path's registered-scan matching +
    ///   `ScanTrackedBox.box_bytes`;
    /// - the live-apply builder ([`build_owned_tx_data_checked`]) captures it
    ///   for free by reusing the box-id serialization (the id IS
    ///   `blake2b256` of these bytes), so the apply hook can store it in
    ///   `WALLET_BOX_BYTES` for the reserved-scan reads
    ///   (`/scan/{unspent,spent}Boxes/9|10`).
    ///
    /// May still be empty for callers that have no bytes to carry; the apply
    /// hook then skips the `WALLET_BOX_BYTES` row and the read degrades to
    /// empty `bytes` until a `/wallet/rescan` backfills it.
    pub box_bytes: Vec<u8>,
}

/// Owned per-tx data for the wallet hook.
#[derive(Clone)]
pub struct OwnedBlockTxData {
    pub tx_id: [u8; 32],
    pub inputs: Vec<[u8; 32]>,
    pub outputs: Vec<OwnedBlockOutput>,
}

/// Build the wallet-apply input from a slice of `CheckedTransaction`.
/// Computes box_ids from the `ErgoBox` serialization formula.
pub(crate) fn build_wallet_block_txs_checked(
    txs: &[ergo_validation::CheckedTransaction],
    block_height: u32,
) -> Result<Vec<OwnedBlockTxData>, StateError> {
    txs.iter()
        .map(|ct| build_owned_tx_data_checked(ct, block_height))
        .collect()
}

/// Guard the `match_boxes` hook contract: it must return exactly one result
/// per box. A mismatch would make `build_scan_match_records`' `zip` silently
/// drop trailing boxes' scan matches, so treat it as an internal invariant
/// violation rather than a recoverable condition.
fn check_match_count(boxes_len: usize, matches_len: usize, height: u32) -> Result<(), StateError> {
    if matches_len != boxes_len {
        return Err(StateError::InternalInvariantAt {
            what: "match_boxes returned wrong result count",
            height,
        });
    }
    Ok(())
}

/// Build the scan-match records for a block: one per output box whose
/// `ErgoBox` matched ≥1 registered scan (via `hook.match_boxes`). Only called
/// when the hook reports registered scans, so the per-box matcher cost is
/// never paid on a node with no scans. The full serialized box is captured so
/// a later-spent box can still be rendered.
pub(crate) fn build_scan_match_records(
    txs: &[ergo_validation::CheckedTransaction],
    block_height: u32,
    hook: &dyn crate::wallet::WalletApplyHook,
) -> Result<Vec<ScanMatchRecord>, StateError> {
    // Collect every output box of the whole block, then match them all in one
    // hook call so ergo-node loads the scan registry once per block.
    let mut boxes: Vec<ergo_ser::ergo_box::ErgoBox> = Vec::new();
    for ct in txs {
        let modifier_tx_id = ergo_primitives::digest::ModifierId::from_bytes(*ct.tx_id());
        for (idx, candidate) in ct.transaction().output_candidates.iter().enumerate() {
            boxes.push(ergo_ser::ergo_box::ErgoBox {
                candidate: candidate.clone(),
                transaction_id: modifier_tx_id,
                index: idx as u16,
            });
        }
    }

    let matches = hook.match_boxes(&boxes);
    // The hook must return exactly one result per box, in order; the `zip`
    // below would silently truncate (dropping trailing boxes' matches)
    // otherwise. Our only hook satisfies this by construction, so a mismatch
    // is an internal contract violation — surface it, don't swallow it.
    check_match_count(boxes.len(), matches.len(), block_height)?;

    let mut records = Vec::new();
    for (ergo_box, scan_ids) in boxes.iter().zip(matches) {
        if scan_ids.is_empty() {
            continue;
        }
        let box_id = ergo_box
            .box_id()
            .map_err(|e| StateError::Serialization(format!("scan box_id: {e}")))?;
        let box_bytes = ergo_ser::ergo_box::serialize_ergo_box(ergo_box)
            .map_err(|e| StateError::Serialization(format!("scan box serialize: {e}")))?;
        records.push(ScanMatchRecord {
            box_id: *box_id.as_bytes(),
            scan_ids,
            box_bytes,
            inclusion_height: block_height,
            creation_out_index: ergo_box.index,
        });
    }
    Ok(records)
}

fn build_owned_tx_data_checked(
    ct: &ergo_validation::CheckedTransaction,
    block_height: u32,
) -> Result<OwnedBlockTxData, StateError> {
    let tx = ct.transaction();
    let tx_id = *ct.tx_id();
    let modifier_tx_id = ergo_primitives::digest::ModifierId::from_bytes(tx_id);

    let inputs: Vec<[u8; 32]> = tx.inputs.iter().map(|i| *i.box_id.as_bytes()).collect();

    let outputs = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            // Ergo box_id = blake2b256(candidate_bytes || tx_id || index_u16_le)
            // We construct an ErgoBox and hash it.
            let ergo_box = ergo_ser::ergo_box::ErgoBox {
                candidate: candidate.clone(),
                transaction_id: modifier_tx_id,
                index: idx as u16,
            };
            // Serialize once and reuse for BOTH the box id (blake2b256 of the
            // canonical box bytes) AND `box_bytes` below — `box_id()` already
            // serialized internally, so capturing the bytes for the
            // reserved-scan reads (WALLET_BOX_BYTES) costs no extra encode.
            let box_bytes = ergo_ser::ergo_box::serialize_ergo_box(&ergo_box)
                .map_err(|e| StateError::Serialization(format!("box serialize: {e}")))?;
            let box_id = ergo_primitives::digest::blake2b256(&box_bytes);
            let ergo_tree_bytes = candidate.ergo_tree_bytes().to_vec();
            let value = candidate.value;
            let assets: Vec<([u8; 32], u64)> = candidate
                .tokens
                .iter()
                .map(|t| (*t.token_id.as_bytes(), t.amount))
                .collect();
            let miner_reward_pubkey =
                crate::wallet::miner_reward::extract_miner_reward_pubkey(&ergo_tree_bytes);
            Ok(OwnedBlockOutput {
                box_id: *box_id.as_bytes(),
                output_index: idx as u16,
                ergo_tree_bytes,
                value,
                assets,
                miner_reward_pubkey,
                // Captured for free from the box-id serialization above; the
                // apply hook stores it in WALLET_BOX_BYTES for matched wallet
                // boxes (reserved-scan reads). The live scan-match path
                // (`build_scan_match_records`) is separate and re-serializes
                // its own boxes — it does not read this field.
                box_bytes,
            })
        })
        .collect::<Result<Vec<_>, StateError>>()?;

    // Suppress unused variable warning — block_height is intentionally
    // available for future use (e.g. creation_height cross-check).
    let _ = block_height;

    Ok(OwnedBlockTxData {
        tx_id,
        inputs,
        outputs,
    })
}

/// Build wallet-apply input by re-reading raw txs from BLOCK_SECTIONS.
/// Used by the rollback path which has only header_id, not CheckedTransactions.
pub(crate) fn build_wallet_block_txs_from_sections(
    db: &redb::Database,
    header_id: &[u8; 32],
) -> Result<Option<Vec<OwnedBlockTxData>>, StateError> {
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::block_transactions::read_block_transactions;
    use ergo_ser::header::read_header;
    use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
    use ergo_ser::transaction::transaction_id;

    let read_txn = db.begin_read()?;

    // Read header bytes to get transactions_root.
    let header_bytes = match read_txn.open_table(HEADERS) {
        Ok(t) => match t.get(header_id.as_slice())? {
            Some(g) => g.value().to_vec(),
            None => return Ok(None),
        },
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut r = VlqReader::new(&header_bytes);
    let header = read_header(&mut r).map_err(|e| {
        StateError::Serialization(format!("header parse in wallet rollback: {e:?}"))
    })?;

    // Compute the block-transactions modifier_id from the header.
    let bt_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        header_id,
        header.transactions_root.as_bytes(),
    );

    // Read the block-transactions section bytes.
    let bt_bytes = match read_txn.open_table(BLOCK_SECTIONS) {
        Ok(t) => match t.get(bt_id.as_slice())? {
            Some(g) => g.value().to_vec(),
            None => return Ok(None), // section pruned / not yet stored
        },
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    // Parse the block transactions.
    let mut r = VlqReader::new(&bt_bytes);
    let bt = read_block_transactions(&mut r).map_err(|e| {
        StateError::Serialization(format!("block_txs parse in wallet rollback: {e:?}"))
    })?;

    let owned: Vec<OwnedBlockTxData> = bt
        .transactions
        .iter()
        .map(|tx| {
            let tx_id_modifier = transaction_id(tx).map_err(|e| {
                StateError::Serialization(format!("transaction_id in rollback: {e:?}"))
            })?;
            let tx_id = *tx_id_modifier.as_bytes();

            let inputs: Vec<[u8; 32]> = tx.inputs.iter().map(|i| *i.box_id.as_bytes()).collect();

            let outputs = tx
                .output_candidates
                .iter()
                .enumerate()
                .map(|(idx, candidate)| {
                    let ergo_box = ergo_ser::ergo_box::ErgoBox {
                        candidate: candidate.clone(),
                        transaction_id: tx_id_modifier,
                        index: idx as u16,
                    };
                    let box_id = ergo_box.box_id().map_err(|e| {
                        StateError::Serialization(format!("box_id in rollback: {e}"))
                    })?;
                    let ergo_tree_bytes = candidate.ergo_tree_bytes().to_vec();
                    let value = candidate.value;
                    let assets: Vec<([u8; 32], u64)> = candidate
                        .tokens
                        .iter()
                        .map(|t| (*t.token_id.as_bytes(), t.amount))
                        .collect();
                    let miner_reward_pubkey =
                        crate::wallet::miner_reward::extract_miner_reward_pubkey(&ergo_tree_bytes);
                    // Replay/rescan path: carry the full box so the rescan
                    // scan-matcher can re-derive scan membership and so
                    // `ScanTrackedBox.box_bytes` can be reconstructed. The
                    // box is already built (for box_id) — serializing it is
                    // near-free.
                    let box_bytes =
                        ergo_ser::ergo_box::serialize_ergo_box(&ergo_box).map_err(|e| {
                            StateError::Serialization(format!("box serialize in replay: {e}"))
                        })?;
                    Ok(OwnedBlockOutput {
                        box_id: *box_id.as_bytes(),
                        output_index: idx as u16,
                        ergo_tree_bytes,
                        value,
                        assets,
                        miner_reward_pubkey,
                        box_bytes,
                    })
                })
                .collect::<Result<Vec<_>, StateError>>()?;

            Ok(OwnedBlockTxData {
                tx_id,
                inputs,
                outputs,
            })
        })
        .collect::<Result<Vec<_>, StateError>>()?;

    Ok(Some(owned))
}

/// Intermediate binding that keeps per-tx `BlockOutput` vecs alive long
/// enough for `BlockTx<'_>` slices to borrow from them.
///
/// `BlockTx.outputs` is `&'a [BlockOutput<'a>]` — a reference into stable
/// memory — so the intermediate `Vec<BlockOutput>` must outlive the
/// `BlockTx` slice. `BoundBlockTxs` owns both allocations and exposes an
/// `as_block_txs()` method that creates the borrows.
pub struct BoundBlockTxs<'a> {
    // One Vec<BlockOutput<'a>> per tx, in block order.
    outputs: Vec<Vec<crate::wallet::apply::BlockOutput<'a>>>,
    // Parallel tx metadata (tx_id, inputs slice).
    meta: Vec<([u8; 32], &'a [[u8; 32]])>,
}

impl<'a> BoundBlockTxs<'a> {
    pub fn as_block_txs(&self) -> Vec<crate::wallet::apply::BlockTx<'_>> {
        self.meta
            .iter()
            .zip(self.outputs.iter())
            .map(|((tx_id, inputs), outs)| crate::wallet::apply::BlockTx {
                tx_id: *tx_id,
                inputs,
                outputs: outs.as_slice(),
            })
            .collect()
    }
}

/// Convert owned block-tx data into `BoundBlockTxs<'_>` which borrows from
/// `owned`. Call `.as_block_txs()` to get the `&[BlockTx<'_>]` view needed
/// by the wallet-hook functions.
///
/// Two-step construction avoids the lifetime pitfall of creating a
/// `Vec<BlockOutput>` inside a closure that also produces a `BlockTx`
/// holding a reference into that same Vec.
pub fn owned_to_block_txs(owned: &[OwnedBlockTxData]) -> BoundBlockTxs<'_> {
    let outputs: Vec<Vec<crate::wallet::apply::BlockOutput<'_>>> = owned
        .iter()
        .map(|d| {
            d.outputs
                .iter()
                .map(|o| crate::wallet::apply::BlockOutput {
                    box_id: o.box_id,
                    output_index: o.output_index,
                    ergo_tree_bytes: &o.ergo_tree_bytes,
                    value: o.value,
                    assets: o.assets.clone(),
                    miner_reward_pubkey: o.miner_reward_pubkey,
                    box_bytes: &o.box_bytes,
                })
                .collect()
        })
        .collect();
    let meta: Vec<([u8; 32], &[[u8; 32]])> = owned
        .iter()
        .map(|d| (d.tx_id, d.inputs.as_slice()))
        .collect();
    BoundBlockTxs { outputs, meta }
}

/// Read block transactions for the wallet rescan path. Returns `None` when
/// the height has no applied-chain entry (above tip or pruned).
///
/// Reads `CHAIN_INDEX` (full-block applied chain, distinct from
/// `HEADER_CHAIN_INDEX`). Returns `None` when no entry exists for the
/// height, which indicates either: the node hasn't applied a full block
/// at this height yet, or the undo log was pruned below this height.
#[allow(clippy::type_complexity)] // (block_id, txs) pair; a named struct would add indirection
pub fn block_txs_for_wallet_at_height(
    db: &redb::Database,
    height: u32,
) -> Result<Option<([u8; 32], Vec<OwnedBlockTxData>)>, StateError> {
    let read_txn = db.begin_read()?;

    // Read from CHAIN_INDEX (full-block applied chain).
    let header_id: [u8; 32] = match read_txn.open_table(CHAIN_INDEX) {
        Ok(t) => match t.get(height as u64)? {
            Some(g) => {
                let bytes = g.value();
                if bytes.len() != 32 {
                    return Err(StateError::DbCorruption {
                        table: "chain_index",
                        key: hex::encode((height as u64).to_be_bytes()),
                        reason: format!("row has len {} (expected 32)", bytes.len()),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(bytes);
                id
            }
            None => return Ok(None),
        },
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    drop(read_txn);

    match build_wallet_block_txs_from_sections(db, &header_id)? {
        Some(txs) => Ok(Some((header_id, txs))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn fresh_store() -> (StateStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("state.redb");
        let store = StateStore::open(&db_path).expect("open store");
        (store, dir)
    }

    /// Materialize HEADER_CHAIN_INDEX without inserting any rows so
    /// `find_canonical_height_for_id` can be exercised on an empty
    /// (but present) table. `StateStore::open` does not pre-create
    /// the table; it's created lazily on first write.
    fn materialize_empty_header_chain_index(store: &StateStore) {
        let txn = crate::begin_write_qr(&store.db).expect("begin write");
        {
            let _ = txn
                .open_table(HEADER_CHAIN_INDEX)
                .expect("open HEADER_CHAIN_INDEX");
        }
        txn.commit().expect("commit");
    }

    // ----- WalletApplyPayload::has_wallet_tracking -----

    fn payload_with(
        trees: std::collections::BTreeSet<Vec<u8>>,
        pubkeys: std::collections::BTreeMap<u64, [u8; 33]>,
        scan_matches: Vec<ScanMatchRecord>,
    ) -> WalletApplyPayload {
        WalletApplyPayload {
            tracked_p2pk_trees: trees,
            has_registered_scans: !scan_matches.is_empty(),
            cached_pubkeys: pubkeys,
            block_txs_owned: Vec::new(),
            scan_matches,
        }
    }

    fn one_scan_match() -> Vec<ScanMatchRecord> {
        vec![ScanMatchRecord {
            box_id: [0xAB; 32],
            scan_ids: vec![11],
            box_bytes: vec![0x01, 0x02],
            inclusion_height: 100,
            creation_out_index: 0,
        }]
    }

    #[test]
    fn scan_only_payload_is_not_wallet_tracking() {
        // Empty trees + empty pubkeys, but scan matches present: this
        // payload exists ONLY to carry scan tracking. It must NOT count
        // as wallet-active, so the commit sites skip apply_block_to_wallet
        // / promote_matured_boxes (which would otherwise advance
        // WALLET_SCAN_HEIGHT past blocks the wallet never classified).
        let p = payload_with(Default::default(), Default::default(), one_scan_match());
        assert!(!p.has_wallet_tracking());
    }

    #[test]
    fn payload_with_tracked_tree_is_wallet_tracking() {
        let mut trees = std::collections::BTreeSet::new();
        trees.insert(vec![0x00, 0x08, 0xcd]);
        let p = payload_with(trees, Default::default(), one_scan_match());
        assert!(p.has_wallet_tracking());
    }

    #[test]
    fn payload_with_cached_pubkey_is_wallet_tracking() {
        let mut pubkeys = std::collections::BTreeMap::new();
        pubkeys.insert(0u64, [0x02; 33]);
        let p = payload_with(Default::default(), pubkeys, Vec::new());
        assert!(p.has_wallet_tracking());
    }

    #[test]
    fn empty_payload_is_not_wallet_tracking() {
        let p = payload_with(Default::default(), Default::default(), Vec::new());
        assert!(!p.has_wallet_tracking());
    }

    // ----- check_match_count (scan-hook contract guard) -----

    #[test]
    fn check_match_count_ok_when_lengths_match() {
        assert!(check_match_count(3, 3, 100).is_ok());
        assert!(check_match_count(0, 0, 100).is_ok());
    }

    #[test]
    fn check_match_count_errors_when_hook_returns_wrong_count() {
        // A hook returning fewer results than boxes would make the downstream
        // `zip` silently drop trailing boxes' matches. Fail loud instead.
        let err = check_match_count(3, 2, 777).unwrap_err();
        assert!(matches!(
            err,
            StateError::InternalInvariantAt {
                height: 777,
                what: _
            }
        ));
        assert!(check_match_count(2, 3, 100).is_err());
    }

    // ----- happy path -----

    #[test]
    fn find_canonical_height_for_id_unknown_id_returns_none() {
        // HEADER_CHAIN_INDEX exists but has no rows. Scan finds no
        // match → Ok(None). Distinct from "table missing entirely"
        // which routes to DbCorruption.
        let (store, _dir) = fresh_store();
        materialize_empty_header_chain_index(&store);
        let target = [0xaa; 32];
        let got = store
            .find_canonical_height_for_id(&target)
            .expect("scan succeeds");
        assert_eq!(got, None);
    }

    #[test]
    fn find_canonical_height_for_id_present_id_returns_height() {
        let (store, _dir) = fresh_store();
        let target = [0xbb; 32];
        // Insert a single canonical row at height 7 with our target id.
        {
            let txn = crate::begin_write_qr(&store.db).expect("begin write");
            {
                let mut table = txn
                    .open_table(HEADER_CHAIN_INDEX)
                    .expect("open HEADER_CHAIN_INDEX");
                table
                    .insert(7u64, target.as_slice())
                    .expect("insert canonical row");
            }
            txn.commit().expect("commit");
        }
        let got = store
            .find_canonical_height_for_id(&target)
            .expect("scan succeeds")
            .expect("target found");
        assert_eq!(got, 7);
    }

    // ----- error paths -----

    #[test]
    fn find_canonical_height_for_id_malformed_row_routes_to_db_corruption() {
        // A row whose value is not 32 bytes is a HEADER_CHAIN_INDEX
        // invariant violation. The scan must stop with DbCorruption
        // rather than silently skipping.
        let (store, _dir) = fresh_store();
        {
            let txn = crate::begin_write_qr(&store.db).expect("begin write");
            {
                let mut table = txn
                    .open_table(HEADER_CHAIN_INDEX)
                    .expect("open HEADER_CHAIN_INDEX");
                table
                    .insert(11u64, [0u8; 16].as_slice())
                    .expect("insert short-row");
            }
            txn.commit().expect("commit");
        }
        let target = [0xcc; 32];
        let err = store
            .find_canonical_height_for_id(&target)
            .expect_err("malformed row must error");
        match err {
            StateError::DbCorruption { table, key, reason } => {
                assert_eq!(table, "header_chain_index");
                assert_eq!(key, hex::encode(11u64.to_be_bytes()));
                assert!(
                    reason.contains("has len 16"),
                    "row-shape reason should report the actual length; got: {reason}",
                );
            }
            other => panic!("expected DbCorruption, got {other:?}"),
        }
    }

    #[test]
    fn find_canonical_height_for_id_missing_table_routes_to_db_corruption() {
        // StateStore::open creates HEADER_CHAIN_INDEX during init.
        // Drop the table after open to simulate a Dense-mode store
        // whose index table has been deleted — corruption, not
        // "anchor absent". The helper must surface DbCorruption.
        let (store, _dir) = fresh_store();
        {
            let txn = crate::begin_write_qr(&store.db).expect("begin write");
            txn.delete_table(HEADER_CHAIN_INDEX)
                .expect("delete HEADER_CHAIN_INDEX");
            txn.commit().expect("commit");
        }
        let target = [0xdd; 32];
        let err = store
            .find_canonical_height_for_id(&target)
            .expect_err("missing table must error");
        match err {
            StateError::DbCorruption { table, key, reason } => {
                assert_eq!(table, "header_chain_index");
                assert_eq!(key, "");
                assert!(
                    reason.contains("Dense-mode invariant"),
                    "missing-table reason should cite the Dense invariant; got: {reason}",
                );
            }
            other => panic!("expected DbCorruption, got {other:?}"),
        }
    }

    // ----- advance_minimal_full_block_height_in_txn -----

    #[test]
    fn advance_helper_writes_default_value_on_absent_row() {
        // Lower-bound edge: a bootstrap writer with
        // `candidate == 1` (the read-side serve default — e.g.
        // `apply_popow_proof(dense_from_height = 1)` or
        // `install_snapshot_state(snapshot_height = 0)`) MUST
        // materialize the sentinel row, not silently no-op.
        // The helper's absent-vs-present distinction is what
        // prevents that landmine.
        let (store, _dir) = fresh_store();
        assert_eq!(
            store
                .try_read_minimal_full_block_height_raw()
                .expect("peek"),
            None,
            "fresh DB precondition: row absent",
        );
        let txn = crate::begin_write_qr(&store.db).expect("begin write");
        StateStore::advance_minimal_full_block_height_in_txn(&txn, 1)
            .expect("advance writes through on absent row");
        txn.commit().expect("commit");
        assert_eq!(
            store
                .try_read_minimal_full_block_height_raw()
                .expect("peek"),
            Some(1),
            "absent-row + write_height==1 must materialize row at 1",
        );
    }

    #[test]
    fn advance_helper_noops_on_present_row_with_equal_or_lower_height() {
        // Composition guard: with the row already pinned at a
        // higher value, a later writer with a lower candidate
        // must NOT abort the surrounding txn — it silently
        // no-ops. This is what lets Mode 4 + NiPoPoW run both
        // bootstrap writers in either order.
        let (store, _dir) = fresh_store();
        // Stamp the row at 100 via the strict standalone.
        store
            .write_minimal_full_block_height(100)
            .expect("strict write");
        assert_eq!(
            store.try_read_minimal_full_block_height_raw().unwrap(),
            Some(100),
        );

        // Equal candidate: no-op, no error.
        {
            let txn = crate::begin_write_qr(&store.db).expect("begin write");
            StateStore::advance_minimal_full_block_height_in_txn(&txn, 100)
                .expect("equal candidate is a silent no-op");
            txn.commit().expect("commit");
        }
        assert_eq!(
            store.try_read_minimal_full_block_height_raw().unwrap(),
            Some(100),
        );

        // Lower candidate: still no-op.
        {
            let txn = crate::begin_write_qr(&store.db).expect("begin write");
            StateStore::advance_minimal_full_block_height_in_txn(&txn, 50)
                .expect("lower candidate is a silent no-op");
            txn.commit().expect("commit");
        }
        assert_eq!(
            store.try_read_minimal_full_block_height_raw().unwrap(),
            Some(100),
        );

        // Higher candidate: advances.
        {
            let txn = crate::begin_write_qr(&store.db).expect("begin write");
            StateStore::advance_minimal_full_block_height_in_txn(&txn, 150)
                .expect("higher candidate advances");
            txn.commit().expect("commit");
        }
        assert_eq!(
            store.try_read_minimal_full_block_height_raw().unwrap(),
            Some(150),
        );
    }
}
