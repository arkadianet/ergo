//! `StateError` and the redb / `crate::active_params` `From` impls
//! for the persistent state store. Re-exported through `store::mod`
//! so external callers continue to see `ergo_state::store::StateError`.

use std::fmt;

use thiserror::Error;

// Re-export the voted-params writer error so external consumers can
// downcast `StateError::VotedParamsWriteFailed`'s source field to its
// typed inner enum.
pub use crate::active_params::VotedParamsWriteError;

/// Identity carried by `StateError::PopowDataMissing`. Some popow
/// callers look up by height (via `HEADER_CHAIN_INDEX`), others by
/// the parent's header id (walking the interlinks). Both are typed
/// here so operators can pattern-match on the addressing mode
/// without parsing strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopowMissingAt {
    /// Popow header at this block height could not be assembled
    /// (extension data not present locally).
    Height(u32),
    /// Popow header for this 32-byte header id could not be
    /// assembled (extension data not present locally).
    HeaderId([u8; 32]),
}

impl fmt::Display for PopowMissingAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PopowMissingAt::Height(h) => write!(f, "h={h}"),
            PopowMissingAt::HeaderId(id) => write!(f, "id={}", hex::encode(id)),
        }
    }
}

/// Result of `StateStore::popow_header_by_id_strict`. Distinguishes
/// the three reasons a popow lookup can fail so each call site picks
/// the appropriate typed error — `HeaderMissing` is cross-table
/// corruption when the caller obtained the id from
/// `HEADER_CHAIN_INDEX`, while `ExtensionMissing` is archive-data
/// absence on Mode 2-bootstrap / pruned nodes.
#[derive(Debug)]
pub enum PopowByIdLookup {
    /// Header + extension both present, popow assembled.
    /// Boxed because `PoPowHeader` is much larger than the other
    /// variants — clippy's `large_enum_variant` catches the rest
    /// of the enum bloating to match.
    Found(Box<ergo_ser::popow_header::PoPowHeader>),
    /// `HEADERS` table has no row for the requested id.
    HeaderMissing,
    /// Header present but matching extension absent in `BLOCK_SECTIONS`.
    ExtensionMissing,
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("redb error: {0}")]
    Db(#[source] Box<redb::Error>),
    #[error("redb database error: {0}")]
    DatabaseError(#[source] Box<redb::DatabaseError>),
    #[error("redb storage error: {0}")]
    StorageError(#[source] Box<redb::StorageError>),
    #[error("redb transaction error: {0}")]
    TransactionError(#[source] Box<redb::TransactionError>),
    #[error("redb table error: {0}")]
    TableError(#[source] Box<redb::TableError>),
    #[error("redb commit error: {0}")]
    CommitError(#[source] Box<redb::CommitError>),
    #[error("state digest mismatch: computed {computed}, expected {expected}")]
    DigestMismatch { computed: String, expected: String },
    /// Voted-params migrate (v1→v2 row rewrite) reported a failure
    /// in `compute_epoch_votes_via_txn`. The underlying error type
    /// is already stringified at the votes boundary
    /// (`Result<_, String>` in `store/votes.rs`), so this variant
    /// carries `detail: String`. A typed-source version would require
    /// changing the votes signature, which is out of scope here.
    #[error("voted_params migrate {op} failed at h={height}: {detail}")]
    VotedParamsMigrateFailed {
        op: &'static str,
        height: u32,
        detail: String,
    },
    /// Voted-params migrate (v1→v2 row rewrite) `compute_next_params`
    /// returned a typed `ergo_validation::RecomputeError`. Preserved
    /// as `#[source]` so chain-aware reporters can downcast; the
    /// Display chains the leaf cause as well.
    #[error("voted_params migrate compute_next_params failed at h={height}: {source}")]
    VotedParamsRecomputeFailed {
        height: u32,
        #[source]
        source: Box<ergo_validation::RecomputeError>,
    },
    /// `apply_popow_proof` rejected its caller because the store is
    /// not in `HeaderAvailability::Dense` (re-applying on the
    /// sparse-writer mode would clobber). Carries the observed mode
    /// label + `best_header_height` so operators see what the store
    /// was actually in.
    #[error(
        "apply_popow_proof: store must be in Dense mode \
         (got header_availability={mode_description}, best_header_height={best_header_height})"
    )]
    ApplyPopowProofWrongMode {
        mode_description: String,
        best_header_height: u32,
    },
    /// `apply_popow_proof` refused because the store already has
    /// full-block state applied. Phase 1b reciprocal guard:
    /// running the sparse-mode writer after
    /// `install_snapshot_state` would downgrade
    /// `header_availability` to PoPowSparse and could persist
    /// `best_header_height < best_full_block_height` (a
    /// chain-state invariant violation). Operators see the
    /// pre-existing tip height for triage.
    #[error(
        "apply_popow_proof refused: store already has best_full_block_height={current_full_block_height} \
         (running the sparse writer over an installed store would corrupt chain_state)"
    )]
    ApplyPopowProofRefused { current_full_block_height: u32 },
    /// Candidate-block dry-run hydrated an in-memory
    /// `BatchAVLProver`, then the prover rejected a UTXO operation.
    /// This is not byte decoding and not persisted DB corruption: it
    /// means the speculative change-set handed to the prover was not
    /// executable against the hydrated state. `op` is `"remove"` or
    /// `"insert"`, `box_id` is hex for the key being operated on, and
    /// `error` preserves the upstream prover detail.
    #[error("candidate dry-run prover {op} failed for box {box_id}: {error}")]
    CandidateDryRunProverFailed {
        op: &'static str,
        box_id: String,
        error: String,
    },
    /// Background persist worker reported a job failure at the
    /// given block height. The worker converts the underlying
    /// typed error to a `String` before sending it back over the
    /// result channel, so the inner detail is preserved as text
    /// rather than typed. Surfaced when the foreground drains
    /// completed results or flushes the pipeline.
    #[error("background persist failed at h={height}: {error}")]
    PersistFailed { height: u32, error: String },
    /// `install_snapshot_state` refused because the store already
    /// has full-block state applied (Mode 2 bootstrap is meaningful
    /// only on a fresh `data_dir`). Carries the observed
    /// `best_full_block_height` so operators can identify the
    /// pre-existing tip without digging through tracing.
    #[error(
        "install_snapshot_state refused: store already has best_full_block_height={current_height} \
         (bootstrap requires a fresh data_dir)"
    )]
    InstallSnapshotRefused { current_height: u32 },
    /// `install_snapshot_state` reconstructed the AVL+ root from the
    /// snapshot chunks, but it did not equal the expected
    /// `state_root` prefix carried by the snapshot header. Distinct
    /// from `DigestMismatch` (steady-state apply/rollback divergence)
    /// so operator triage can tell a Mode 2 install rejection apart
    /// from a steady-state consensus failure.
    #[error(
        "install_snapshot_state: reconstructed root {computed} != expected state_root prefix {expected}"
    )]
    InstallSnapshotRootMismatch { computed: String, expected: String },
    /// `install_snapshot_state` was called with a `snapshot_height`
    /// above the store's current `best_header_height`. Production
    /// Mode 4 always runs header sync (NiPoPoW prefix or Mode 2's
    /// full header download) BEFORE install at the anchor; this
    /// runtime guard enforces that ordering so an orchestration
    /// bug cannot persist `best_full_block_height >
    /// best_header_height` (a chain-state invariant violation).
    /// The previously documented-only precondition is now a hard
    /// check.
    #[error(
        "install_snapshot_state precondition unmet: snapshot_height={snapshot_height} \
         exceeds best_header_height={best_header_height} (caller must sync headers up to \
         snapshot_height first)"
    )]
    InstallSnapshotPreconditionUnmet {
        snapshot_height: u32,
        best_header_height: u32,
    },
    /// `install_snapshot_state` was called with a `canonical_header_id`
    /// that does not match the header locally indexed at
    /// `snapshot_height`. Defense-in-depth against caller drift:
    /// `best_full_block_id` MUST agree with the canonical id at
    /// `HEADERS_BY_HEIGHT[snapshot_height]` slot 0 (which covers
    /// BOTH the sparse prefix and the dense suffix written by
    /// `apply_popow_proof`), otherwise later reorg / recovery logic
    /// would observe a split between `chain_state` and the header
    /// chain.
    #[error(
        "install_snapshot_state: canonical_header_id mismatch at height {snapshot_height} \
         (caller passed {caller_id}, locally indexed {indexed_id})"
    )]
    InstallSnapshotHeaderIdMismatch {
        snapshot_height: u32,
        caller_id: String,
        indexed_id: String,
    },
    /// `install_snapshot_state` was called with `snapshot_height >
    /// 0` but `HEADERS_BY_HEIGHT` has no canonical row at that
    /// height. Implies the precondition guard
    /// (`snapshot_height <= best_header_height`) passed but the
    /// header-by-height table was not populated at that height — a
    /// caller / orchestration bug. The header-sync seam must stamp
    /// `HEADERS_BY_HEIGHT` for every height from genesis to
    /// `best_header_height` for the cross-check above to succeed.
    #[error(
        "install_snapshot_state: HEADERS_BY_HEIGHT has no canonical row at height \
         {snapshot_height} (caller-side: header sync did not index this height)"
    )]
    InstallSnapshotHeaderNotIndexed { snapshot_height: u32 },
    /// `install_snapshot_state` was called with `snapshot_height ==
    /// 0`. Defensive guard: snapshots at GenesisHeight are
    /// meaningless (no pre-bootstrap state to jump past) and would
    /// leave the store in a half-installed-but-fresh-looking state
    /// — AVL / CHAIN_STATE_META rows + Mode 2 trust sentinel
    /// committed while `best_full_block_height == 0` keeps both
    /// reciprocal bootstrap guards happy, opening a window for a
    /// misordered second writer to overwrite the install.
    #[error(
        "install_snapshot_state refused: snapshot_height == 0 (snapshots target epoch \
         boundaries, the first non-trivial boundary is at 1024 testnet / 52224 mainnet)"
    )]
    InstallSnapshotAtGenesisRefused,
    /// Mode 3 Phase 3a — `store_block_section_typed` rejected a
    /// section write whose parent header is below the current
    /// prune sentinel. Returned to the caller (sync executor)
    /// which logs + silently drops; the peer is NOT penalized
    /// because timing-racy late deliveries are normal during sync.
    /// Defense-in-depth against an executor that bypasses
    /// receive-side gating.
    #[error(
        "store_block_section_typed: section_id={section_id} at height {section_height} \
         is below prune sentinel {sentinel}"
    )]
    PrunedSection {
        section_id: String,
        section_height: u32,
        sentinel: u32,
    },
    /// Mode 3 Phase 4 — `rollback_to` rejected a target height
    /// below the prune sentinel. Section bytes at the target
    /// height have been pruned, so the wallet replay path
    /// cannot reconstruct the rollback. The caller must abort the
    /// reorg attempt. Phase 4's config-load gate enforces
    /// `blocks_to_keep >= ROLLBACK_WINDOW + SAFETY_MARGIN` so
    /// the rollback resolver never needs a pruned block in
    /// practice; this error catches misconfiguration / off-by-one
    /// edge cases at the storage seam before any mutation.
    #[error(
        "rollback_to: target height {target_height} < prune sentinel {sentinel} \
         (sections at the target have been evicted; reorg cannot proceed)"
    )]
    RollbackBelowPruningSentinel { target_height: u32, sentinel: u32 },
    /// The `data_dir` was initialized for one `state_type` (utxo or
    /// digest) but the current config requests the other. The two
    /// modes are not interconvertible in-place; the operator must
    /// start from a fresh `data_dir` for the new mode. Both the
    /// recorded value (from the `data_dir` sentinel) and the
    /// configured value (from the current run's config) are
    /// preserved so operators can identify the misconfiguration
    /// without parsing Display strings.
    #[error(
        "state_type mismatch: data_dir initialized for {recorded:?}, config requests {configured:?} \
         (use a fresh data_dir for the new mode)"
    )]
    StateTypeMismatch {
        configured: String,
        recorded: String,
    },
    /// Caller-side precondition violation. `what` names the contract
    /// the caller broke (e.g. `"persist pipeline already shut down"`,
    /// `"apply_block called before initialize_genesis"`). Distinct
    /// from byte decoding and from internal-bug invariants — operators
    /// can distinguish caller misuse from corruption / our-bug in log
    /// triage.
    #[error("invalid precondition: {what}")]
    InvalidPrecondition { what: &'static str },
    /// Internal invariant we expected to hold has been observed to
    /// fail. Treat as a bug in this codebase, not as bad input or DB
    /// corruption. `what` is a static label so the operator-facing
    /// message stays stable across log lines.
    #[error("internal invariant violated: {what}")]
    InternalInvariant { what: &'static str },
    /// Popow data (PoPoW header constructed from `header` +
    /// `extension`) is not available for a requested location.
    /// Reachable from legitimate states: a Mode 2 bootstrap leaves
    /// the prefix region without block-section data, pruned nodes
    /// may not retain enough extensions to serve a NiPoPoW proof,
    /// and `blocks_to_keep = -1` does not retroactively populate
    /// archive data. Distinct from `InternalInvariantAt` (which
    /// reserves for our-bug invariants whose precondition was just
    /// validated) and from `DbCorruption` (which is on-disk
    /// inconsistency, not absence of historical content).
    ///
    /// `what` names the popow callsite (e.g. `"suffix_head"`,
    /// `"collect_level"`, `"genesis"`); `at` carries the typed
    /// identity (height or header_id) so operators see what was
    /// requested.
    #[error("popow data missing at {at}: {what}")]
    PopowDataMissing {
        what: &'static str,
        at: PopowMissingAt,
    },
    /// Internal invariant violation at a specific block height —
    /// typed-detail companion to [`InternalInvariant`] for sites
    /// where the failure context is a height (e.g. expected
    /// HEADER_CHAIN_INDEX row missing for a height the prover just
    /// validated, voted_params cache reload missing a row the
    /// open-time reconcile was supposed to write). Operators get
    /// the exact `(label, height)` tuple instead of a `format!()`
    /// string.
    #[error("internal invariant violated at h={height}: {what}")]
    InternalInvariantAt { what: &'static str, height: u32 },
    /// Mode 3 — the prune low-water mark
    /// `minimal_full_block_height` is monotonic and must never
    /// move backward. A caller attempted to write a value below
    /// the current sentinel; once block-section data has been
    /// evicted at a height, advertising that we have it again
    /// would lie to peers. Distinct from `InternalInvariantAt`
    /// because the height pair is the actionable detail
    /// (operators see both the current and attempted values).
    #[error("prune sentinel monotonicity violated: current={current}, attempted={attempted}")]
    PruneSentinelMonotonicity { current: u32, attempted: u32 },
    /// Mode 3 — pruned-mode boot reached
    /// `blocks_to_keep > 0` but the `SECTION_HEIGHT_INDEX`
    /// back-fill sentinel is not present. The serve gate keys on
    /// the index; without the back-fill, legacy archive rows
    /// would be indistinguishable from genuinely-pruned rows
    /// (serve gate denies for missing-row, classifying valid
    /// archive data as "pruned"). The Phase 4 activation gate
    /// raises this fail-closed before any pruned-mode logic runs.
    /// Phase 1a delivers the variant + the boot check so the
    /// machinery is in place when Phase 4 drops the config-load
    /// gate.
    #[error(
        "section-height back-fill required before pruned-mode boot: \
         run the open-time back-fill walk (sentinel \
         STATE_META[section_height_backfill_done_v1]) and retry"
    )]
    SectionHeightBackfillRequired,
    /// Mode 3 — `flush_header_batch` / `store_validated_header`
    /// detected a mismatch between the caller-supplied
    /// `HeaderMeta.height` and the height parsed from the
    /// header's own bytes. The two heights MUST match — a
    /// divergence means upstream HeaderMeta construction
    /// disagrees with the bytes the chain validated, which
    /// would let `HEADER_META` / `HEADERS_BY_HEIGHT` and
    /// `SECTION_HEIGHT_INDEX` carry different heights for the
    /// same header (split-brain). Fail loud rather than commit
    /// inconsistent metadata.
    #[error(
        "header height inconsistency: parsed={parsed}, meta={meta}, \
         header_id={header_id}"
    )]
    HeaderHeightMismatch {
        parsed: u32,
        meta: u32,
        header_id: String,
    },
    /// Operation requires the chain tip to be at or above
    /// `needed_min`, but the observed tip is at `observed`. Typical
    /// surfaces: voted-params reconcile windows, popow prover
    /// horizons, header-walk floors. Operators get the exact
    /// shortfall instead of a generic precondition error.
    #[error("early IBD: tip at {observed}, operation requires at least {needed_min}")]
    EarlyIBD { needed_min: u32, observed: u32 },
    /// The applied-chain index (`CHAIN_INDEX`) lacks a row at
    /// `at_height`, but the caller expected one — typically a context
    /// builder reading the last-10 applied headers. Distinct from
    /// `DbCorruption` because legitimate states reach this branch:
    /// after Mode 2 snapshot install the index is intentionally
    /// unpopulated below the install height, and aggressive pruning
    /// can drop applied-chain rows. Distinct from `EarlyIBD` because
    /// the tip is high enough — it's the historical window that's
    /// missing.
    #[error("applied chain has no row at h={at_height}")]
    AppliedChainGap { at_height: u32 },
    /// Byte-level decode failure. Kept for actual serialization
    /// decoders only — non-decode failures use one of the typed
    /// variants above so operators can pattern-match.
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("box not found: {0}")]
    BoxNotFound(String),
    #[error("no committed state")]
    NoCommittedState,
    #[error("reorg too deep: {depth} blocks exceeds rollback window of {max}")]
    ReorgTooDeep { depth: u32, max: u32 },
    #[error("voted_params: extra rows present {extras:?} (rollback bug or db corruption)")]
    VotedParamsExtraRows { extras: Vec<u64> },
    #[error("voted_params reconcile at h={height}: missing chain_index entry")]
    VotedParamsMissingChainIndex { height: u32 },
    #[error("voted_params reconcile at h={height}: missing header for {header_id}")]
    VotedParamsMissingHeader { height: u32, header_id: String },
    #[error("voted_params reconcile at h={height}: missing extension for {section_id}")]
    VotedParamsMissingExtension { height: u32, section_id: String },
    #[error("voted_params reconcile at h={height}: failed to parse extension: {source}")]
    VotedParamsParseFailed {
        height: u32,
        #[source]
        source: ergo_validation::ActiveParamsError,
    },
    #[error("voted_params: row at expected key {height} failed to decode: {source}")]
    VotedParamsRowCorrupt {
        height: u32,
        #[source]
        source: ergo_validation::ActiveParamsError,
    },
    /// Wallet apply / rollback hook (called from the chain-apply
    /// path inside `store/mod.rs`) returned a `redb::Error`. `what`
    /// names the specific hook (e.g. `"apply hook"`,
    /// `"rollback"`, `"abort_in_progress"`), `height` is the block
    /// height where the hook ran, and `source` is the underlying
    /// redb error. Separate from `Db`/`StorageError` etc. so
    /// operators can pattern-match wallet-side failures: the
    /// wallet-apply seam runs in a different write transaction from
    /// chain state, so a crash between chain commit and the wallet
    /// write txn leaves `wallet_scan_height < chain_height` and
    /// requires the rescan-on-restart path to recover.
    #[error("wallet {what} at h={height}: {source}")]
    WalletApply {
        what: &'static str,
        height: u32,
        #[source]
        source: Box<redb::Error>,
    },
    /// `voted_params` writer failed at a specific block height
    /// during reconcile / migrate / apply. The underlying typed
    /// error (`VotedParamsWriteError::Db` for the redb insert path,
    /// or `VotedParamsWriteError::InvalidParams` for the pre-persist
    /// validation path) is preserved as `source` so operators can
    /// downcast via `Error::source()` and pattern-match the cause.
    ///
    /// Use this wrapper at sites that want both the typed-failure
    /// classification AND the contextual `op` + `height` for triage —
    /// operators reading the error surface alone can identify which
    /// voted-params lifecycle stage failed.
    #[error("voted_params {op} failed at h={height}: {source}")]
    VotedParamsWriteFailed {
        op: &'static str,
        height: u32,
        #[source]
        source: Box<crate::active_params::VotedParamsWriteError>,
    },
    /// Wallet apply path's `write_txn.commit()` failed with a
    /// `redb::CommitError`. Separate variant from `WalletApply`
    /// because commit returns a distinct error type; kept distinct
    /// from the generic `CommitError` variant so the wallet-seam
    /// classification (and the block `height`) survive at the type
    /// level.
    ///
    /// Historical: emitted by the pre-M5-final-slice
    /// `flush_chain_then_apply_wallet` path, which committed wallet
    /// writes on a separate write_txn after the queued chain batch
    /// drained. That path is gone now that the worker consumes the
    /// wallet payload inside the batch's write_txn. The variant is
    /// retained for the error-variants exhaustiveness test in
    /// `tests/error_variants.rs` and as a stable wire-API element;
    /// no live code emits it.
    #[error("wallet commit at h={height}: {source}")]
    WalletApplyCommit {
        height: u32,
        #[source]
        source: Box<redb::CommitError>,
    },
    /// `prove_with_db(Some(anchor))` was called with a caller-supplied
    /// header id that does not exist in the canonical chain. The
    /// dispatch path scans `HEADER_CHAIN_INDEX` for the id when
    /// `HEADERS` misses; only an id absent from BOTH `HEADER_CHAIN_INDEX`
    /// and `HEADERS` lands here. An id present in the index but
    /// missing from `HEADERS` is cross-table corruption and routes
    /// through `DbCorruption` instead, so this variant is caller-
    /// misuse-only by construction. The header_id is preserved so
    /// operators can identify which anchor the caller passed without
    /// parsing surrounding context.
    #[error(
        "prove_with_db: caller-supplied anchor header_id not in canonical chain \
         (absent from both HEADER_CHAIN_INDEX and HEADERS): {header_id}"
    )]
    ProveWithDbAnchorNotFound { header_id: String },
    /// On-disk row is inconsistent with itself or with the table key
    /// that holds it — a persisted-state corruption signal. The root
    /// cause may be on-disk damage or a writer bug; either way the
    /// row reached the read path in a state that should not have been
    /// possible. Covers both byte-level decode failures and successful
    /// decodes whose contents disagree with the row key (e.g. a
    /// `voted_params` row whose embedded `epoch_start_height` !=
    /// the row key).
    ///
    /// Fields:
    /// - `table`: the redb table name.
    /// - `key`: the hex-encoded raw on-disk key bytes. Integer-keyed
    ///   tables (e.g. `voted_params` with `u64` keys) use the
    ///   big-endian byte representation; 32-byte ID tables (e.g.
    ///   `header_meta`) hex-encode the id bytes directly.
    /// - `reason`: the underlying decode or consistency failure.
    #[error("db corruption: table=`{table}` key=`{key}`: {reason}")]
    DbCorruption {
        table: &'static str,
        key: String,
        reason: String,
    },
    /// Mode 5: caller asked the digest-store apply seam to advance
    /// to a height other than `self.height + 1`. Digest-mode apply
    /// has no skip-or-replay semantics; an out-of-order call
    /// indicates a Mode 5 orchestrator bug. Session-scoped
    /// invalidity at most.
    #[error("digest-mode apply out of order: expected next height {expected_next}, got {got}")]
    ApplyOutOfOrder { expected_next: u32, got: u32 },
    /// Mode 5: rollback requested a height with no row in
    /// `DIGEST_HISTORY`. The history ledger is written on every
    /// successful apply, so a missing row means the target is
    /// below the store's retained history range or the database
    /// is corrupt.
    #[error("digest history missing for height {height}")]
    DigestHistoryMissing { height: u32 },
    /// Mode 5: rollback target is strictly greater than the
    /// current tip. Indicates a caller bug — rolling FORWARD via
    /// the rollback seam is meaningless.
    #[error("digest-mode rollback target {target} > current tip {tip}")]
    RollbackBeyondTip { target: u32, tip: u32 },
    /// Mode 5: the block's ADProofs section is required to verify the
    /// state transition but is not present in the section store. This
    /// is data-availability, NOT block invalidity — the proof simply
    /// has not been downloaded/stored yet, so the block is neither
    /// applied nor marked invalid.
    #[error(
        "ADProofs section {ad_proofs_id} required for header {header_id} is not present in the store"
    )]
    DigestAdProofsSectionMissing {
        /// Canonical header id of the block being applied.
        header_id: String,
        /// `compute_section_id(TYPE_AD_PROOFS, header_id, ad_proofs_root)`.
        ad_proofs_id: String,
    },
    /// Mode 5: the ADProofs-verified state transition was rejected.
    /// `reason` carries the precise [`crate::digest_apply::DigestApplyError`]
    /// classification (root-hash / section-id / op-replay / final
    /// digest-vs-`state_root` mismatch, or a verifier construction/op
    /// failure). Every arm is treated as SESSION-scoped invalidity for
    /// now: the apply seam marks the header session-invalid but does
    /// NOT persist invalidity, matching the repo invariant that only
    /// PoW invalidity persists (a persistent definitive-invalid store
    /// for digest blocks is a separate, not-yet-built concern).
    #[error("digest-mode apply rejected for header {header_id}: {reason}")]
    DigestApplyRejected {
        /// Canonical header id of the rejected block.
        header_id: String,
        /// `Display` of the underlying `DigestApplyError`.
        reason: String,
    },
    /// Mode 5 (linear-only apply): the block's parent is not the
    /// committed full-block tip, so it is not linearly applicable. This
    /// is a fork / non-tip-parent block — NOT an invalid one (it may be
    /// valid on a chain we have not applied), so it is neither committed
    /// nor marked invalid. Fork apply (sourcing the parent digest from
    /// `DIGEST_HISTORY`) is deferred; this gate keeps the verifier, which
    /// is always seeded with OUR tip root, from misclassifying a
    /// foreign-parent block as session-invalid.
    #[error(
        "digest-mode non-linear parent at height {height}: block parent {got} != committed tip {expected}"
    )]
    DigestNonLinearParent {
        /// Height of the block being applied.
        height: u32,
        /// `best_full_block_id` of the committed tip (the required parent).
        expected: String,
        /// The block header's actual `parent_id`.
        got: String,
    },
}

impl From<redb::Error> for StateError {
    fn from(e: redb::Error) -> Self {
        StateError::Db(Box::new(e))
    }
}

impl From<redb::DatabaseError> for StateError {
    fn from(e: redb::DatabaseError) -> Self {
        StateError::DatabaseError(Box::new(e))
    }
}

impl From<redb::StorageError> for StateError {
    fn from(e: redb::StorageError) -> Self {
        StateError::StorageError(Box::new(e))
    }
}

impl From<redb::TransactionError> for StateError {
    fn from(e: redb::TransactionError) -> Self {
        StateError::TransactionError(Box::new(e))
    }
}

impl From<redb::TableError> for StateError {
    fn from(e: redb::TableError) -> Self {
        StateError::TableError(Box::new(e))
    }
}

impl From<redb::CommitError> for StateError {
    fn from(e: redb::CommitError) -> Self {
        StateError::CommitError(Box::new(e))
    }
}

// No `impl From<VotedParamsWriteError> for StateError`. All call
// sites use explicit `.map_err(...)` into `StateError::VotedParamsWriteFailed`
// (with `op` + `height` context) so the voted-params write-failure
// family is exactly one variant — operators can pattern-match all
// reconcile/migrate/apply write errors with a single arm.

impl From<crate::active_params::ActiveParamsReadError> for StateError {
    fn from(e: crate::active_params::ActiveParamsReadError) -> Self {
        use crate::active_params::ActiveParamsReadError as R;
        match e {
            R::Db(e) => StateError::Db(e),
            R::Decode { height, source } => StateError::VotedParamsRowCorrupt { height, source },
            // Row-key vs embedded-height divergence is a
            // persisted-state corruption signal — either a writer
            // bug at insertion time or on-disk damage after the
            // write; this code path can't tell them apart. Either
            // way the row reached us in a state that should not have
            // been possible. `voted_params` uses `u64` keys, so
            // encode them as big-endian bytes before `hex::encode`
            // to keep `DbCorruption.key` aligned with the on-disk
            // representation; other `DbCorruption` sites (e.g.
            // `header_meta`) start from raw 32-byte ids and
            // hex-encode those directly.
            R::KeyMismatch {
                row_key,
                embedded_height,
            } => StateError::DbCorruption {
                table: "voted_params",
                key: hex::encode(row_key.to_be_bytes()),
                reason: format!(
                    "row key {row_key} != embedded epoch_start_height {embedded_height}"
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_params::ActiveParamsReadError;

    // ----- helpers -----

    // (none — From conversions are constructed inline below)

    // ----- error paths -----

    #[test]
    fn from_active_params_read_key_mismatch_routes_to_db_corruption_with_hex_key() {
        let outer = StateError::from(ActiveParamsReadError::KeyMismatch {
            row_key: 0x0102_0304_0506_0708u64,
            embedded_height: 999,
        });
        match outer {
            StateError::DbCorruption { table, key, reason } => {
                assert_eq!(table, "voted_params");
                // `voted_params` is a u64-keyed table; the on-disk
                // representation is big-endian bytes, so the key
                // field is `hex::encode(row_key.to_be_bytes())`
                // (not decimal).
                assert_eq!(key, "0102030405060708");
                assert!(reason.contains("999"), "got reason: {reason}");
                assert!(
                    reason.contains("72623859790382856"),
                    "expected decimal-rendered row_key in reason; got: {reason}",
                );
            }
            other => panic!("expected DbCorruption, got {other:?}"),
        }
    }

    #[test]
    fn from_active_params_read_decode_routes_to_voted_params_row_corrupt() {
        let inner = ergo_validation::ActiveParamsError::UnexpectedEof;
        let outer = StateError::from(ActiveParamsReadError::Decode {
            height: 1_771_976,
            source: inner,
        });
        match outer {
            StateError::VotedParamsRowCorrupt { height, source } => {
                assert_eq!(height, 1_771_976);
                assert!(matches!(
                    source,
                    ergo_validation::ActiveParamsError::UnexpectedEof
                ));
            }
            other => panic!("expected VotedParamsRowCorrupt, got {other:?}"),
        }
    }
}
